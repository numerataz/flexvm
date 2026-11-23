//! Guest memory that was mapped in Firecracker before its userfaultfd covered it (#949).
//!
//! Firecracker maps guest memory and only then registers it with the userfaultfd it hands the pager. A process that
//! reads Firecracker's memory in between (`/proc/PID/mem`, `process_vm_readv`: a debugger, a memory scanner; GitHub's
//! runners have an agent that does) faults pages in as for any anonymous memory: the zero page, or, with THP enabled,
//! the huge zero page for a whole huge page (`util::huge_page_size()`, e.g. 2 MiB on 4 KiB hosts or 512 MiB on 64 KiB
//! hosts). Registering the range later leaves them mapped, so the guest never faults on them and the pager never
//! installs them: the guest reads zeroes where the template has data. Firecracker's own write of its vmclock page then
//! copies the huge zero page into a zeroed huge page, and with it the guest's DSDT (in the same first huge page) is
//! gone: the VMGenID notification never runs and the guest never reseeds its RNG.
//!
//! Such pages are mapped while the pager has them BASE or REMOTE (it installs every other page itself, through the
//! userfaultfd), or turn up as EEXIST when it installs them (`Pages::preset`). `Pager::foreign_pages` looks for both
//! once a load is done and before the guest first runs, so the load can be retried on a fresh Firecracker.

use super::{Pager, Pages, BASE, INFLIGHT, PAGE_SIZE, REMOTE};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// `PAGEMAP_SCAN` (`_IOWR('f', 16, struct pm_scan_arg)`, Linux 6.7) and its page categories.
const PAGEMAP_SCAN: libc::c_ulong = 0xC060_6610;
const PAGE_IS_PRESENT: u64 = 1 << 3;
const PAGE_IS_SWAPPED: u64 = 1 << 4;
/// Pagemap entry bits: present, swapped out.
const PM_PRESENT: u64 = 1 << 63;
const PM_SWAP: u64 = 1 << 62;
/// Regions per `PAGEMAP_SCAN` call, and pages per pagemap read where it is missing.
const SCAN_REGIONS: usize = 512;
const READ_PAGES: usize = 64 << 10;
/// Where pagemap entries are read, the most pages between two runs of interest that one read spans.
const READ_GAP: usize = 512;

#[repr(C)]
#[derive(Default)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

/// The pages in `[start, start + len)` (host addresses, page aligned) that `pagemap` (some process's
/// `/proc/PID/pagemap`) has mapped or swapped out, as `[first, end)` page offsets from `start`.
#[cfg(test)]
fn mapped_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    match scan_runs(pagemap, start, len) {
        Err(e) if unsupported(&e) => read_runs(pagemap, start, len),
        r => r,
    }
}

fn unsupported(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL | libc::EOPNOTSUPP))
}

fn scan_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    scan_runs_with(pagemap, start, len, crate::util::host_page_size())
}

fn scan_runs_with(pagemap: &std::fs::File, start: u64, len: u64, host_page: usize) -> io::Result<Vec<(usize, usize)>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let hp = host_page as u64;
    let end = start + len;
    let scan_start = start & !(hp - 1);
    let scan_end = end.next_multiple_of(hp);
    let (mut at, mut runs) = (scan_start, Vec::new());
    let mut regions = [PageRegion::default(); SCAN_REGIONS];
    while at < scan_end {
        let mut arg = PmScanArg {
            size: std::mem::size_of::<PmScanArg>() as u64,
            start: at,
            end: scan_end,
            vec: regions.as_mut_ptr() as u64,
            vec_len: SCAN_REGIONS as u64,
            category_anyof_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            return_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            ..PmScanArg::default()
        };
        // The struct and the regions array outlive the call; the kernel writes only `walk_end` and the regions.
        let n = unsafe { libc::ioctl(pagemap.as_raw_fd(), PAGEMAP_SCAN as _, &mut arg as *mut PmScanArg) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        for r in &regions[..n as usize] {
            let lo = r.start.max(start);
            let hi = r.end.min(end);
            if lo < hi {
                super::push_run(&mut runs, ((lo - start) / PAGE_SIZE as u64) as usize, ((hi - start) / PAGE_SIZE as u64) as usize, 0);
            }
        }
        if arg.walk_end <= at {
            break;
        }
        at = arg.walk_end;
    }
    Ok(runs)
}

/// `scan_runs` for kernels before 6.7: the pagemap entries themselves, indexed by host page.
fn read_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    read_runs_with(pagemap, start, len, crate::util::host_page_size())
}

fn read_runs_with(pagemap: &std::fs::File, start: u64, len: u64, host_page: usize) -> io::Result<Vec<(usize, usize)>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let hp = host_page as u64;
    let end = start + len;
    let aligned_start = start & !(hp - 1);
    let aligned_end = end.next_multiple_of(hp);
    let host_pages = ((aligned_end - aligned_start) / hp) as usize;
    let (mut runs, mut raw) = (Vec::new(), vec![0u8; READ_PAGES.min(host_pages) * 8]);
    let mut first = 0;
    while first < host_pages {
        let n = READ_PAGES.min(host_pages - first);
        std::os::unix::fs::FileExt::read_exact_at(pagemap, &mut raw[..n * 8], (aligned_start / hp + first as u64) * 8)?;
        decode_pagemap_chunk(&raw[..n * 8], aligned_start + first as u64 * hp, start, end, host_page, &mut runs);
        first += n;
    }
    Ok(runs)
}

/// Converts raw `/proc/PID/pagemap` entries (one 8-byte entry per `host_page` starting at `chunk_start`) into
/// guest-page (`PAGE_SIZE`) runs relative to `start`, clamped to `[start, end)`.
fn decode_pagemap_chunk(raw: &[u8], chunk_start: u64, start: u64, end: u64, host_page: usize, runs: &mut Vec<(usize, usize)>) {
    let hp = host_page as u64;
    for (i, e) in raw.chunks_exact(8).enumerate() {
        if u64::from_le_bytes(e.try_into().unwrap()) & (PM_PRESENT | PM_SWAP) != 0 {
            let page_start = chunk_start + i as u64 * hp;
            let lo = page_start.max(start);
            let hi = (page_start + hp).min(end);
            if lo < hi {
                super::push_run(runs, ((lo - start) / PAGE_SIZE as u64) as usize, ((hi - start) / PAGE_SIZE as u64) as usize, 0);
            }
        }
    }
}
/// Whether a page in `state` that Firecracker has mapped holds what the guest should not see: the pager installs
/// every page it moves out of BASE or REMOTE, so mapped in either means mapped behind its back. A template hole
/// (BASE, no data) is zero either way. ZERO is not checked: a REMOVE already applied may not have zapped it yet.
fn foreign(state: u8, has_data: bool) -> bool {
    state == REMOTE || state == BASE && has_data
}

impl Pager {
    /// How many guest pages Firecracker has mapped that the pager never installed and that should hold template or
    /// migrated data (see the module docs). For a load that is done, before the guest first runs.
    pub fn foreign_pages(&self, timeout: Duration) -> (usize, Option<usize>) {
        let deadline = Instant::now() + timeout;
        let pages = self.pages();
        let mut mapped = Vec::new();
        let scan = || -> io::Result<Vec<usize>> {
            let pagemap = self.pagemap_file()?;
            let mut mapped = Vec::new();
            for m in self.mappings() {
                let (first, end) = m.span();
                let end = end.min(pages.len());
                if end <= first {
                    continue;
                }
                // Only pages the pager never installed (claimed ones too, being installed) can be foreign.
                let unsettled = |p: usize| {
                    let state = pages.get(p);
                    state == INFLIGHT || foreign(state, self.base.has_data(p))
                };
                // One PAGEMAP_SCAN of the mapping lists what is mapped, the pager's own pages included: a few
                // calls. Without it, only the runs of unsettled pages are read (8 bytes a page), gaps of up to
                // READ_GAP pages bridged so that a fragmented template takes few reads.
                let found = match scan_runs(pagemap, m.base_host_virt_addr, ((end - first) * PAGE_SIZE) as u64) {
                    Err(e) if unsupported(&e) => {
                        let mut runs: Vec<(usize, usize)> = Vec::new();
                        for p in (first..end).filter(|&p| unsettled(p)) {
                            super::push_run(&mut runs, p, p + 1, READ_GAP);
                        }
                        let mut found = Vec::new();
                        for (a, b) in runs {
                            let start = m.base_host_virt_addr + ((a - first) * PAGE_SIZE) as u64;
                            found.extend(read_runs(pagemap, start, ((b - a) * PAGE_SIZE) as u64)?.into_iter().map(|(lo, hi)| (a - first + lo, a - first + hi)));
                        }
                        found
                    }
                    r => r?,
                };
                for (lo, hi) in found {
                    mapped.extend((first + lo..first + hi).filter(|&p| unsettled(p)));
                }
            }
            Ok(mapped)
        };
        match scan() {
            Ok(found) => mapped = found,
            Err(e) => crate::log!("uffd: checking firecracker's guest memory: {e}; using EEXIST evidence only"),
        }
        // A claimant's copy may map the page itself; wait for its state or EEXIST evidence to settle.
        while mapped.iter().any(|&p| pages.get(p) == INFLIGHT) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())));
        }
        foreign_count(pages, &mapped, |p| self.base.has_data(p))
    }

    /// `foreign_pages` as a load's check: an error, which retrying on a fresh Firecracker gets past, if there are any.
    pub fn check_foreign(&self, timeout: Duration) -> crate::util::Result<()> {
        let (n, first) = self.foreign_pages(timeout);
        if n == 0 {
            return Ok(());
        }
        Err(format!(
            "{FOREIGN}: {n} pages ({} KiB, from guest memory offset {:#x}) were mapped before its userfaultfd covered them",
            n * PAGE_SIZE / 1024,
            first.unwrap_or(0) * PAGE_SIZE
        )
        .into())
    }
}

// Recheck states after waiting: a mapped page claimed since the scan may now be in `preset`.
fn foreign_count(pages: &Pages, mapped: &[usize], has_data: impl Fn(usize) -> bool) -> (usize, Option<usize>) {
    let preset = pages.preset.lock().unwrap();
    let mut found: Vec<_> = mapped.iter().copied().filter(|&p| foreign(pages.get(p), has_data(p))).collect();
    found.extend(preset.iter().filter(|&&(p, from)| foreign(from, has_data(p))).map(|&(p, _)| p));
    found.sort_unstable();
    found.dedup();
    (found.len() + pages.preset_more.load(Ordering::Relaxed), found.first().copied())
}

/// How `check_foreign`'s error starts.
pub const FOREIGN: &str = "another process read firecracker's guest memory while it was being mapped";

#[cfg(test)]
mod tests {
    use super::*;

    /// An anonymous mapping of `host_pages` host pages, of which those in `read` (mapping the zero page) or `write` are touched.
    fn mapping(host_pages: usize, read: &[usize], write: &[usize]) -> (*mut u8, usize) {
        let hp = crate::util::host_page_size();
        let len = host_pages * hp;
        let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        // Base host pages only: one huge page would map all of them.
        unsafe { libc::madvise(p, len, libc::MADV_NOHUGEPAGE) };
        let p = p as *mut u8;
        for &i in read {
            unsafe { std::ptr::read_volatile(p.add(i * hp)) };
        }
        for &i in write {
            unsafe { std::ptr::write_volatile(p.add(i * hp + 7), 1) };
        }
        (p, len)
    }

    #[test]
    fn mapped_runs_see_zero_pages_and_written_ones() {
        let hp = crate::util::host_page_size() as u64;
        let g = crate::util::pages_per_host_page();
        let (p, len) = mapping(64, &[3, 4, 5, 40], &[10, 11, 63]);
        let pagemap = std::fs::File::open("/proc/self/pagemap").unwrap();
        let want = vec![(3 * g, 6 * g), (10 * g, 12 * g), (40 * g, 41 * g), (63 * g, 64 * g)];
        assert_eq!(mapped_runs(&pagemap, p as u64, len as u64).unwrap(), want);
        // The pagemap reads give the same answer as PAGEMAP_SCAN (or are what answered).
        assert_eq!(read_runs(&pagemap, p as u64, len as u64).unwrap(), want);
        // A range from the middle reports offsets from its own start.
        assert_eq!(mapped_runs(&pagemap, p as u64 + 4 * hp, 8 * hp).unwrap(), vec![(0, 2 * g), (6 * g, 8 * g)]);
        unsafe { libc::munmap(p.cast(), len) };
    }

    #[test]
    fn mapped_runs_of_many_regions_go_on_past_a_full_vector() {
        let g = crate::util::pages_per_host_page();
        // Every other host page: more regions than one PAGEMAP_SCAN call returns.
        let n = 3 * SCAN_REGIONS;
        let read: Vec<usize> = (0..n).step_by(2).collect();
        let (p, len) = mapping(n, &read, &[]);
        let pagemap = std::fs::File::open("/proc/self/pagemap").unwrap();
        let runs = mapped_runs(&pagemap, p as u64, len as u64).unwrap();
        assert_eq!(runs, read.iter().map(|&i| (i * g, (i + 1) * g)).collect::<Vec<_>>());
        unsafe { libc::munmap(p.cast(), len) };
    }

    #[test]
    fn decode_pagemap_runs_with_64k_host_pages() {
        let hp = 65536usize;
        let entries = [0u64, PM_PRESENT, PM_SWAP, 0, PM_PRESENT];
        let raw: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        let base = 10 * hp as u64;
        // Full range: host pages 1..3 merged into guest pages 16..48, host page 4 -> 64..80.
        let mut runs = Vec::new();
        decode_pagemap_chunk(&raw, base, base, base + 5 * hp as u64, hp, &mut runs);
        assert_eq!(runs, vec![(16, 48), (64, 80)]);
        // Unaligned subrange starting 3 guest pages into host page 1 and ending 5 guest pages into host page 4.
        let start = base + hp as u64 + 3 * PAGE_SIZE as u64;
        let end = base + 4 * hp as u64 + 5 * PAGE_SIZE as u64;
        let mut clamped = Vec::new();
        decode_pagemap_chunk(&raw, base, start, end, hp, &mut clamped);
        assert_eq!(clamped, vec![(0, 29), (45, 50)]);
    }

    #[test]
    fn only_data_the_pager_never_installed_is_foreign() {
        use super::super::{DISCARDED, INFLIGHT, PRESENT, ZERO};
        assert!(foreign(BASE, true));
        assert!(foreign(REMOTE, false));
        assert!(foreign(REMOTE, true));
        // A template hole is zero anyway; the pager's own pages, and ZERO, are not looked at.
        assert!(!foreign(BASE, false));
        for s in [PRESENT, ZERO, INFLIGHT, DISCARDED] {
            assert!(!foreign(s, true));
        }
    }

    #[test]
    fn mapped_pages_claimed_since_the_scan_are_counted_once() {
        let mut pages = Pages::new(4);
        pages.fill(0, 4, REMOTE);
        assert_eq!(pages.claim(0, 2, REMOTE, |_| true), 2);
        let _ = pages.install(0, 2, REMOTE, None, |_, _| Err(io::Error::from_raw_os_error(libc::EEXIST)));
        assert_eq!(foreign_count(&pages, &[0, 1, 2], |_| true), (3, Some(0)));
        // Without pagemap access, EEXIST still proves these pages foreign.
        assert_eq!(foreign_count(&pages, &[], |_| true), (2, Some(0)));
        assert_eq!(pages.claim(3, 1, REMOTE, |_| true), 1);
        assert_eq!(foreign_count(&pages, &[3], |_| true), (2, Some(0)), "unsettled copies prove nothing");
    }

    #[test]
    fn installs_that_find_a_page_mapped_note_it() {
        use super::super::{Pages, ZERO};
        let pages = Pages::new(8);
        let eexist = || Err(io::Error::from_raw_os_error(libc::EEXIST));
        assert_eq!(pages.claim(0, 2, BASE, |_| true), 2);
        let _ = pages.install(0, 2, BASE, None, |p, _| if p == 1 { eexist() } else { Ok(1) });
        let mut pages = pages;
        pages.fill(4, 2, REMOTE);
        pages.fill(6, 1, ZERO);
        assert_eq!(pages.claim(4, 2, REMOTE, |_| true), 2);
        let _ = pages.install(4, 2, REMOTE, None, |_, _| eexist());
        // A zero-fill that finds the page mapped is the zap race `Pages` describes, not a foreign page.
        assert_eq!(pages.claim(6, 1, ZERO, |_| true), 1);
        let _ = pages.install(6, 1, ZERO, None, |_, _| eexist());
        assert_eq!(*pages.preset.lock().unwrap(), vec![(1, BASE), (4, REMOTE), (5, REMOTE)]);
        // A template hole found mapped is zero either way: not noted, nor counted past the kept ones.
        let _ = pages.base_data.set(Box::new(|p| p != 2));
        pages.fill(2, 2, BASE);
        assert_eq!(pages.claim(2, 2, BASE, |_| true), 2);
        let _ = pages.install(2, 2, BASE, None, |_, _| eexist());
        assert_eq!(*pages.preset.lock().unwrap(), vec![(1, BASE), (4, REMOTE), (5, REMOTE), (3, BASE)]);
        assert_eq!(pages.preset_more.load(Ordering::Relaxed), 0);
    }
}
