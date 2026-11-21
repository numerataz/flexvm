//! Huge pages for guest memory paged in by a migration or a checkpoint restore (#141).
//!
//! Every page the pager installs is a base host page (4 KiB on 4 KiB hosts), so KVM maps the guest's memory one base
//! page at a time, one exit per page the guest touches. After a migration nothing is mapped in KVM yet, and the guest's
//! first pass over its memory pays for every page: 1 s for 500 MiB under nested virtualization, against 50 ms once
//! mapped. Once the pull is done, a background pass collapses each host PMD huge-page chunk (`util::huge_page_size()`,
//! e.g. 2 MiB on 4 KiB hosts or 512 MiB on 64 KiB hosts) whose pages are all PRESENT into a transparent huge page
//! (`process_madvise(MADV_COLLAPSE)` on Firecracker), which KVM then maps with one PMD entry.
//!
//! The kernel only collapses a chunk of a userfaultfd-registered range whose pages are all mapped, none of them the
//! zero page and none write-protected, and checks again under the mmap write lock before it copies anything. So a
//! collapse never fills a missing page behind the pager's back nor drops a write protection a checkpoint relies on.
//! Contents stay the same, so page states do not change. A discard of a whole chunk (free page reporting and virtio-mem
//! work in 2 MiB blocks or more) frees the huge page; a smaller one splits it, and still raises a REMOVE and later a
//! missing fault as before. Write-protecting a huge page protects it whole; unprotecting part of it splits it.
//!
//! Each call first drains every host CPU's LRU caches (`lru_add_drain_all`), interrupting every other VM's vCPUs, so
//! consecutive collapsible chunks go in one call (`batch_chunks`, #191). The kernel goes on past some failed chunks but
//! stops at others (a zero page in the chunk): a batch that fails is split in halves and each tried again, down to
//! single chunks, so one chunk that cannot collapse costs a few calls more and does not hold back the rest of its
//! batch.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::MutexGuard;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{Pager, PAGE_SIZE, PRESENT};

/// From linux/mman.h (asm-generic).
const MADV_COLLAPSE: libc::c_int = 25;
/// Target bytes per call at most: one LRU drain on every CPU for up to 32 MiB (16 chunks at 2 MiB, 1 chunk at
/// 512 MiB), and a pause waits out at most one call.
const BATCH_BYTES: usize = 32 << 20;

fn batch_chunks(huge_page: usize) -> usize {
    (BATCH_BYTES / huge_page).max(1)
}

/// First guest page in a mapping starting at guest page `first` (`base_host_virt_addr`) whose host address is aligned
/// to `huge_page`.
fn first_aligned_page(first: usize, base_host_virt_addr: u64, huge_page: usize) -> usize {
    let hp = huge_page as u64;
    let rem = base_host_virt_addr % hp;
    if rem == 0 {
        first
    } else {
        first + ((hp - rem) as usize).div_ceil(PAGE_SIZE)
    }
}

/// Next run `(first_page, chunk_count)` of up to `batch_chunks(huge_page)` consecutive collapsible `huge_page`-byte
/// chunks starting at or after `p` (already `huge_page`-aligned) within `..end`, where `chunk_full(c)` reports that all
/// `huge_page / PAGE_SIZE` guest pages starting at `c` are PRESENT.
fn next_collapsible_run(mut p: usize, end: usize, huge_page: usize, chunk_full: impl Fn(usize) -> bool) -> Option<(usize, usize)> {
    let chunk_pages = huge_page / PAGE_SIZE;
    let batch = batch_chunks(huge_page);
    while p + chunk_pages <= end {
        let mut n = 0;
        while n < batch && p + (n + 1) * chunk_pages <= end && chunk_full(p + n * chunk_pages) {
            n += 1;
        }
        if n > 0 {
            return Some((p, n));
        }
        p += chunk_pages;
    }
    None
}
/// Calls that all fail with EINVAL before the pass concludes that the kernel cannot collapse here (THP disabled, or a
/// kernel before 6.1).
const EINVAL_GIVE_UP: usize = 16;
/// No huge page to be had (ENOMEM, a fragmented host): the pass waits before going on, from this long, twice as long
/// after each such call in a row up to `ENOMEM_BACKOFF_MAX` (time for compaction), and gives up after `ENOMEM_GIVE_UP`
/// in a row (about 7 s of waiting).
const ENOMEM_BACKOFF: Duration = Duration::from_millis(100);
const ENOMEM_BACKOFF_MAX: Duration = Duration::from_secs(2);
const ENOMEM_GIVE_UP: usize = 8;
/// Why a pass ends at a checkpoint or migration; one that leaves the VM here (`Pager::unquiesce`) starts it again.
pub(super) const QUIESCED: &str = "checkpoint or migration";

/// The collapse pass's gate, under `Pager::collapse_gate`'s mutex, which the pass holds across each call.
#[derive(Default)]
pub(super) struct Gate {
    /// The VM is (about to be) paused: no call starts until it is cleared (`hold_collapse`).
    held: bool,
    /// A pass is running.
    running: bool,
}

/// What the collapse pass did, for `debug VM status`.
#[derive(Default, Clone)]
pub struct CollapseReport {
    /// Chunks entirely PRESENT, so tried.
    pub tried: usize,
    pub collapsed: usize,
    /// `process_madvise` calls made for them.
    pub calls: usize,
    /// Time spent in the kernel collapsing, and the CPU time of it: the rest is waiting (mostly for every CPU to drain
    /// its LRU caches, once per call).
    pub busy: Duration,
    pub cpu: Duration,
    pub wall: Duration,
    /// Why the pass ended early, if it did.
    pub stopped: Option<String>,
}

impl CollapseReport {
    pub fn json(&self) -> Value {
        json!({
            "tried": self.tried,
            "collapsed": self.collapsed,
            "calls": self.calls,
            "busy_ms": crate::util::ms(self.busy),
            "cpu_ms": crate::util::ms(self.cpu),
            "wall_ms": crate::util::ms(self.wall),
            "stopped": self.stopped,
        })
    }
}

/// What to do after a call.
#[derive(Debug, PartialEq)]
enum Next {
    Go,
    /// Wait this long first.
    Backoff(Duration),
    Stop(String),
}

/// The calls of one pass: runs of up to `batch_chunks` chunks (`first page`, chunks), split when a call fails.
struct Batches {
    chunk_pages: usize,
    todo: Vec<(usize, usize)>,
    collapsed: usize,
    einval: usize,
    enomem: usize,
}

impl Batches {
    fn new(chunk_pages: usize) -> Self {
        Self { chunk_pages, todo: Vec::new(), collapsed: 0, einval: 0, enomem: 0 }
    }

    fn pop(&mut self) -> Option<(usize, usize)> {
        self.todo.pop()
    }

    /// Tries `[first, first + n)` again as two halves, the first half next; a single chunk is left as it is.
    fn split(&mut self, first: usize, n: usize) {
        if n > 1 {
            let h = n / 2;
            self.todo.push((first + h * self.chunk_pages, n - h));
            self.todo.push((first, h));
        }
    }

    /// The call on `n` chunks from `first` returned `res` (an errno on failure).
    fn done(&mut self, first: usize, n: usize, res: Result<(), i32>) -> Next {
        match res {
            Ok(()) => {
                self.collapsed += n;
                self.enomem = 0;
            }
            // A zero page or a page missing again (EBUSY), or one being migrated (EAGAIN): not every chunk collapsed.
            Err(libc::EBUSY | libc::EAGAIN) => self.split(first, n),
            Err(libc::EINVAL) if self.collapsed > 0 || self.einval < EINVAL_GIVE_UP => {
                self.einval += 1;
                self.split(first, n);
            }
            // Usually passing: what did not collapse is tried once more after a while (a single chunk is skipped).
            Err(libc::ENOMEM) => {
                self.enomem += 1;
                if self.enomem >= ENOMEM_GIVE_UP {
                    return Next::Stop(format!("{} (no huge page to be had, {ENOMEM_GIVE_UP} times in a row)", io::Error::from_raw_os_error(libc::ENOMEM)));
                }
                self.split(first, n);
                return Next::Backoff((ENOMEM_BACKOFF * (1 << (self.enomem - 1))).min(ENOMEM_BACKOFF_MAX));
            }
            Err(e) => return Next::Stop(io::Error::from_raw_os_error(e).to_string()),
        }
        Next::Go
    }
}

impl Pager {
    /// The collapse pass: runs of collapsible chunks, `BATCH` at most per call, using at most half a core: after each
    /// call it sleeps as long as the call took (mostly waiting for other CPUs to drain their caches, work this thread's
    /// CPU time does not show). Ends early when the pager stops, a checkpoint or migration starts (`quiesce`), or write
    /// tracking is armed (the kernel refuses write-protected chunks). Once only, unless it ended for `QUIESCED`.
    pub(super) fn collapse(&self) {
        while self.collapse_pass() {}
    }

    /// One pass; true if it ended for `QUIESCED` but an abort has cleared that meanwhile (`unquiesce`, finding the pass
    /// still running, left the restart to it).
    fn collapse_pass(&self) -> bool {
        let Some(pidfd) = self.pidfd.get() else { return false };
        {
            let mut g = self.collapse_gate.0.lock().unwrap();
            let mut report = self.collapse_report.lock().unwrap();
            if g.running || report.as_ref().is_some_and(|r| r.stopped.as_deref() != Some(QUIESCED)) {
                return false;
            }
            // Until this pass ends, there is no report: as before the first.
            *report = None;
            g.running = true;
        }
        let started = Instant::now();
        let cpu0 = thread_cpu();
        let huge_page = crate::util::huge_page_size();
        let chunk_pages = huge_page / PAGE_SIZE;
        let mut report = CollapseReport::default();
        let mut b = Batches::new(chunk_pages);
        let pages = self.pages();
        let full = |p: usize, n: usize| pages.next_not(PRESENT, p, p + n * chunk_pages) == p + n * chunk_pages;
        'regions: for m in self.mappings() {
            let (first, end) = m.span();
            let mut p = first_aligned_page(first, m.base_host_virt_addr, huge_page);
            while let Some((run_start, n)) = next_collapsible_run(p, end, huge_page, |c| full(c, 1)) {
                report.tried += n;
                b.todo.push((run_start, n));
                p = run_start + n * chunk_pages;
                while let Some((c, n)) = b.pop() {
                    let gate = match self.collapse_turn() {
                        Ok(g) => g,
                        Err(why) => {
                            report.stopped = Some(why.into());
                            break 'regions;
                        }
                    };
                    // Paused meanwhile, a chunk may have been discarded (the kernel would refuse it too).
                    if !full(c, n) {
                        drop(gate);
                        b.split(c, n);
                        continue;
                    }
                    let t = Instant::now();
                    let res = self.collapse_chunks(pidfd.as_raw_fd(), c, n, huge_page);
                    drop(gate);
                    let took = t.elapsed();
                    report.calls += 1;
                    report.busy += took;
                    match b.done(c, n, res.map_err(|e| e.raw_os_error().unwrap_or(0))) {
                        Next::Go => thread::sleep(took),
                        Next::Backoff(d) => self.collapse_pause(took.max(d)),
                        Next::Stop(why) => {
                            report.stopped = Some(why);
                            break 'regions;
                        }
                    }
                    // Test gate `collapse_hold`: the pass parks after a call (telling the test it got here) until a
                    // checkpoint or migration cuts it short, or the test disarms it.
                    if crate::host::tripped("collapse_hold") {
                        while self.collapse_halt().is_none() && crate::host::fault("collapse_hold") {
                            self.collapse_pause(Duration::from_millis(20));
                        }
                    }
                }
            }
        }
        report.collapsed = b.collapsed;
        report.wall = started.elapsed();
        report.cpu = thread_cpu().saturating_sub(cpu0);
        if report.tried > 0 {
            crate::log!(
                "uffd: collapsed {} of {} fully paged-in {} MiB chunks into huge pages in {} calls, {:.0} ms ({:.0} ms in the kernel, {:.0} ms CPU){}",
                report.collapsed,
                report.tried,
                huge_page >> 20,
                report.calls,
                crate::util::ms(report.wall),
                crate::util::ms(report.busy),
                crate::util::ms(report.cpu),
                report.stopped.as_deref().map(|s| format!("; stopped: {s}")).unwrap_or_default(),
            );
        }
        let quiesced = report.stopped.as_deref() == Some(QUIESCED);
        let mut g = self.collapse_gate.0.lock().unwrap();
        *self.collapse_report.lock().unwrap() = Some(report);
        g.running = false;
        // Under the gate, as `collapse_quiesced`: either `unquiesce` sees this report, or this sees its cleared flag.
        quiesced && self.collapse_halt().is_none()
    }

    /// Waits while the pass is held (paused, or about to be), until it may make a call (holding the gate meanwhile),
    /// or must end: for the halt that follows a checkpoint or migration, when it resumes or the pager stops.
    fn collapse_turn(&self) -> Result<MutexGuard<'_, Gate>, &'static str> {
        let mut g = self.collapse_gate.0.lock().unwrap();
        loop {
            if let Some(why) = self.collapse_halt() {
                return Err(why);
            }
            if !g.held {
                return Ok(g);
            }
            g = self.collapse_gate.1.wait(g).unwrap();
        }
    }

    /// Sleeps `d`, or less if the pass must end (the pager stops, or `quiesce_export` wakes it): so the pass ends at
    /// the checkpoint or migration that quiesced it, not once a failed one has undone that.
    fn collapse_pause(&self, d: Duration) {
        let g = self.collapse_gate.0.lock().unwrap();
        let _ = self.collapse_gate.1.wait_timeout_while(g, d, |_| self.collapse_halt().is_none());
    }

    fn collapse_halt(&self) -> Option<&'static str> {
        if self.stop.load(Ordering::SeqCst) {
            Some("pager stopped")
        } else if self.quiesce.load(Ordering::SeqCst) {
            Some(QUIESCED)
        } else if self.registered_wp.load(Ordering::SeqCst) {
            Some("write tracking")
        } else {
            None
        }
    }

    /// `MADV_COLLAPSE` on the `n` `huge_page`-byte chunks of Firecracker's memory from `page`: Ok only if all of them
    /// are huge pages now.
    fn collapse_chunks(&self, pidfd: libc::c_int, page: usize, n: usize, huge_page: usize) -> io::Result<()> {
        let iov = libc::iovec { iov_base: self.addr(page)? as *mut libc::c_void, iov_len: n * huge_page };
        match unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, &iov as *const libc::iovec, 1, MADV_COLLAPSE, 0) } {
            r if r == iov.iov_len as libc::c_long => Ok(()),
            r if r >= 0 => Err(io::Error::from_raw_os_error(libc::EBUSY)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Holds the collapse pass off (`true`), waiting out a collapse in flight, or lets it go on (`false`). Before any
    /// pause: a collapse takes the mmap write lock and may compact memory, which a pause must not wait behind. A
    /// checkpoint or migration then ends the pass (`quiesce`).
    pub fn hold_collapse(&self, hold: bool) {
        self.collapse_gate.0.lock().unwrap().held = hold;
        if !hold {
            self.collapse_gate.1.notify_all();
        }
    }

    /// Waits out a collapse call in flight and keeps any from starting until dropped.
    pub(super) fn collapse_barrier(&self) -> MutexGuard<'_, Gate> {
        self.collapse_gate.0.lock().unwrap()
    }

    /// Wakes a held pass, to see that the pager stopped.
    pub(super) fn wake_collapse(&self) {
        drop(self.collapse_gate.0.lock().unwrap());
        self.collapse_gate.1.notify_all();
    }

    /// Whether a pass ended for a checkpoint or migration (and none runs), with the gate held so none starts meanwhile.
    pub(super) fn collapse_quiesced(&self) -> bool {
        let g = self.collapse_gate.0.lock().unwrap();
        !g.running && self.collapse_report.lock().unwrap().as_ref().is_some_and(|r| r.stopped.as_deref() == Some(QUIESCED))
    }

    /// What the collapse pass did, once it ran.
    pub fn collapse_report(&self) -> Option<Value> {
        self.collapse_report.lock().unwrap().as_ref().map(CollapseReport::json)
    }
}

/// This thread's CPU time so far.
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HP_2M: usize = 2 << 20;
    const HP_512M: usize = 512 << 20;

    /// Runs `Batches` over `n` chunks of `huge_page` bytes from page 0, `fails` saying which chunks a call fails at
    /// (with which errno); a call fails with the errno of the first failing chunk in it. Returns the calls made, as
    /// (first chunk, chunks).
    fn drive_with(huge_page: usize, n: usize, fails: impl Fn(usize) -> Option<i32>) -> (Vec<(usize, usize)>, Batches, Vec<Next>) {
        let chunk_pages = huge_page / PAGE_SIZE;
        let mut b = Batches::new(chunk_pages);
        b.todo.push((0, n));
        let (mut calls, mut nexts) = (Vec::new(), Vec::new());
        while let Some((p, n)) = b.pop() {
            assert_eq!(p % chunk_pages, 0);
            let c = p / chunk_pages;
            calls.push((c, n));
            let res = (c..c + n).find_map(&fails).map_or(Ok(()), Err);
            match b.done(p, n, res) {
                Next::Go => {}
                Next::Stop(why) => {
                    nexts.push(Next::Stop(why));
                    break;
                }
                next => nexts.push(next),
            }
        }
        (calls, b, nexts)
    }

    fn drive(n: usize, fails: impl Fn(usize) -> Option<i32>) -> (Vec<(usize, usize)>, Batches, Vec<Next>) {
        drive_with(HP_2M, n, fails)
    }

    #[test]
    fn a_batch_collapses_in_one_call() {
        let batch = batch_chunks(HP_2M);
        assert_eq!(batch, 16);
        let (calls, b, nexts) = drive(batch, |_| None);
        assert_eq!(calls, [(0, batch)]);
        assert_eq!((b.collapsed, nexts), (batch, vec![]));
    }

    #[test]
    fn a_chunk_that_cannot_collapse_is_bisected_out() {
        let (calls, b, _) = drive(16, |c| (c == 5).then_some(libc::EBUSY));
        assert_eq!(b.collapsed, 15);
        // 1 + 2 per level: every chunk but 5 collapses, in 9 calls rather than 16.
        assert_eq!(calls, [(0, 16), (0, 8), (0, 4), (4, 4), (4, 2), (4, 1), (5, 1), (6, 2), (8, 8)]);
    }

    #[test]
    fn einval_gives_up_only_when_nothing_ever_collapsed() {
        let (calls, b, nexts) = drive(4, |_| Some(libc::EINVAL));
        assert_eq!((b.collapsed, calls.len()), (0, 7));
        assert!(nexts.is_empty());
        let mut b = Batches { einval: EINVAL_GIVE_UP, ..Batches::new(HP_2M / PAGE_SIZE) };
        assert!(matches!(b.done(0, 1, Err(libc::EINVAL)), Next::Stop(_)));
        b.collapsed = 1;
        assert_eq!(b.done(0, 1, Err(libc::EINVAL)), Next::Go);
    }

    #[test]
    fn enomem_backs_off_and_gives_up_only_in_a_row() {
        let mut b = Batches::new(HP_2M / PAGE_SIZE);
        let ms = |n| Next::Backoff(Duration::from_millis(n));
        let waits = [100, 200, 400, 800, 1600, 2000, 2000];
        for &w in &waits {
            assert_eq!(b.done(0, 2, Err(libc::ENOMEM)), ms(w));
        }
        assert_eq!(b.done(0, 1, Ok(())), Next::Go);
        for &w in &waits {
            assert_eq!(b.done(0, 1, Err(libc::ENOMEM)), ms(w));
        }
        assert!(matches!(b.done(0, 1, Err(libc::ENOMEM)), Next::Stop(_)));
        // A failed batch is retried in halves.
        let (calls, b, nexts) = drive(2, |c| (c == 0).then_some(libc::ENOMEM));
        assert_eq!((calls, b.collapsed, nexts), (vec![(0, 2), (0, 1), (1, 1)], 1, vec![ms(100), ms(200)]));
    }

    #[test]
    fn other_errors_end_the_pass() {
        let (calls, _, nexts) = drive(8, |c| (c == 3).then_some(libc::EPERM));
        assert_eq!(calls, [(0, 8)]);
        assert!(matches!(&nexts[..], [Next::Stop(_)]));
    }

    #[test]
    fn alignment_and_run_selection_for_2m_and_512m_huge_pages() {
        // 2 MiB huge pages: 512 guest pages per chunk, up to 16 chunks (32 MiB) per call.
        let c2 = HP_2M / PAGE_SIZE;
        assert_eq!(batch_chunks(HP_2M), 16);
        assert_eq!(first_aligned_page(100, 0x2000_0000, HP_2M), 100);
        assert_eq!(first_aligned_page(100, 0x2000_1000, HP_2M), 100 + c2 - 1);
        assert_eq!(first_aligned_page(100, 0x201f_f000, HP_2M), 101);

        let collect_runs = |first: usize, end: usize, base: u64, hp: usize, full: &dyn Fn(usize) -> bool| {
            let cp = hp / PAGE_SIZE;
            let mut out = Vec::new();
            let mut p = first_aligned_page(first, base, hp);
            while let Some((start, n)) = next_collapsible_run(p, end, hp, full) {
                out.push((start, n));
                p = start + n * cp;
            }
            out
        };

        // 20 aligned 2 MiB chunks with chunk 2 missing: [0..2], [3..19] (capped at 16), [19..20].
        let runs_2m = collect_runs(0, 20 * c2, 0x4000_0000, HP_2M, &|p| p != 2 * c2);
        assert_eq!(runs_2m, vec![(0, 2), (3 * c2, 16), (19 * c2, 1)]);

        // 512 MiB huge pages: 131,072 guest pages per chunk, 1 chunk per call so pauses wait at most one 512 MiB collapse.
        let c512 = HP_512M / PAGE_SIZE;
        assert_eq!(c512, 131_072);
        assert_eq!(batch_chunks(HP_512M), 1);
        assert_eq!(first_aligned_page(0, 0x4000_0000, HP_512M), 0);
        // Base skewed by 2 MiB (512 guest pages) past a 512 MiB boundary -> advances 130,560 pages to the next boundary.
        assert_eq!(first_aligned_page(10, 0x4020_0000, HP_512M), 10 + c512 - 512);
        // Mapping smaller than one 512 MiB huge page yields no collapsible runs.
        assert_eq!(collect_runs(0, c512 - 1, 0x4000_0000, HP_512M, &|_| true), vec![]);
        // 3 aligned 512 MiB chunks with chunk 1 missing: each collapsible 512 MiB chunk is its own 1-chunk call.
        let runs_512m = collect_runs(0, 3 * c512, 0x4000_0000, HP_512M, &|p| p != c512);
        assert_eq!(runs_512m, vec![(0, 1), (2 * c512, 1)]);

        // Bisection stride with 512 MiB chunks steps by 131,072 guest pages.
        let (calls, b, _) = drive_with(HP_512M, 4, |c| (c == 1).then_some(libc::EBUSY));
        assert_eq!(b.collapsed, 3);
        assert_eq!(calls, [(0, 4), (0, 2), (0, 1), (1, 1), (2, 2)]);
    }
}
