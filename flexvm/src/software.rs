//! Named software VM owner using the ordinary name lock and control wire protocol.
use std::io::{BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::host::{Backend, Entry, Host, Ident, NameLock};
use crate::util::{By, Result};
use crate::{bail, guest, image, qemu, software_state, util, vmproc};

const MAX_CONTROL: usize = 64;
const MAX_SESSIONS: usize = 48;
const READING: u8 = 0;
const DETACHED: u8 = 1;
const EXITED: u8 = 2;
const OUTPUT_FAILED: u8 = 3;

/// Admit and protect a software VM's initial boot/restore RAM via a `Hold`
/// until `serve()` is live (and `MemAvailable` reflects the resident pages),
/// then admit elastic virtio-mem growth steps via expiring grants so resident
/// guest RAM is never double-counted against `MemAvailable`.
pub struct Reservation {
    host: Host,
    grant_id: u64,
    hold: Mutex<Option<crate::host::Hold>>,
}

impl Reservation {
    pub fn new(host: &Host, mib: u32, deadline: Instant, processes: &qemu::Processes) -> Result<Self> {
        let (grant_id, hold) = host.grant_start(u64::from(mib), crate::host::Floor::Reserve, true, Some(deadline))?;
        let reservation = Self { host: host.clone(), grant_id, hold: Mutex::new(hold) };
        if let Some(hold) = reservation.hold.lock().unwrap().as_ref() {
            processes.inherit_lease(hold.inherit()?);
        }
        Ok(reservation)
    }

    /// Release the initial boot/restore `Hold` and refund its startup grant once
    /// QEMU is live and its resident pages are reflected in `MemAvailable`.
    /// Dropping `Hold` unlinks the hold file so `live_holds` immediately stops
    /// counting it even while QEMU retains the inherited lease fd.
    pub fn settle_boot(&mut self) {
        self.host.release_hold(&self.hold);
        self.grant_id = 0;
    }

    /// Admit an elastic growth step with an expiring grant (no permanent `Hold`),
    /// bridging the window until the guest faults in the newly plugged pages.
    /// Returns the grant ID (or `0` when `add_mib == 0`) for rollback via `refund`.
    pub fn grow(&self, add_mib: u64, deadline: Instant) -> Result<u64> {
        if add_mib == 0 {
            return Ok(0);
        }
        match self.host.grant(add_mib, Some(deadline))? {
            Some(grant_id) => Ok(grant_id),
            None => bail!("not enough memory here for {add_mib} MiB above the reserve"),
        }
    }

    /// Refund a specific in-flight growth grant when `set_virtio_mem` fails or
    /// the VM pauses/ends before the step is applied.
    pub fn refund(&self, grant_id: u64) {
        if grant_id != 0 {
            self.host.refund_by(grant_id, Some(Instant::now() + Duration::from_secs(2)));
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let _ = self.hold.get_mut().map(Option::take);
        if self.grant_id != 0 {
            self.host.refund_by(self.grant_id, Some(Instant::now() + Duration::from_secs(2)));
        }
    }
}

pub(crate) const SHRINK_COOLDOWN: Duration = Duration::from_secs(15);
pub(crate) const GROW_SETTLE_TIMEOUT: Duration = Duration::from_secs(10);

fn shrink_cooldown_active(last_grow: Option<Instant>, last_shrink_attempt: Option<Instant>, now: Instant) -> bool {
    last_grow.is_some_and(|t| now.saturating_duration_since(t) < SHRINK_COOLDOWN)
        || last_shrink_attempt.is_some_and(|t| now.saturating_duration_since(t) < SHRINK_COOLDOWN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reconcile {
    /// Still waiting for an in-flight growth step to settle.
    Wait,
    /// `actual_mib == plugged_mib`; clear `growing`.
    Synced,
    /// `actual_mib < plugged_mib` while stalled during growth: clamp QEMU's
    /// requested size back to `actual_mib` and update `plugged_mib`.
    ClampDown(u64),
    /// `actual_mib != plugged_mib` outside an active growth: sync `plugged_mib`
    /// to QEMU's actual plugged size (up or down).
    SyncTo(u64),
}

fn reconcile_plugged(actual_mib: u64, plugged_mib: u64, growing: bool, stalled: bool) -> Reconcile {
    match actual_mib.cmp(&plugged_mib) {
        std::cmp::Ordering::Less if growing && !stalled => Reconcile::Wait,
        std::cmp::Ordering::Less if growing => Reconcile::ClampDown(actual_mib),
        std::cmp::Ordering::Less | std::cmp::Ordering::Greater => Reconcile::SyncTo(actual_mib),
        std::cmp::Ordering::Equal => Reconcile::Synced,
    }
}

/// Wait up to `interval` on `changed`, returning `false` as soon as `ended` is set.
fn wait_for_mem_poll(ended: &AtomicBool, entry: &Mutex<Entry>, changed: &Condvar, interval: Duration) -> bool {
    let guard = entry.lock().unwrap();
    if ended.load(Ordering::SeqCst) {
        return false;
    }
    let _ = changed.wait_timeout(guard, interval).unwrap();
    !ended.load(Ordering::SeqCst)
}

/// Record a management kill as `SIGINT`, wake waiters, and stop the engine processes.
fn request_kill(ended: &AtomicBool, entry: &Mutex<Entry>, changed: &Condvar, processes: &qemu::Processes, interrupt: impl FnOnce(i32)) {
    interrupt(libc::SIGINT);
    ended.store(true, Ordering::SeqCst);
    drop(entry.lock().unwrap());
    changed.notify_all();
    processes.stop();
}

/// Decide whether a software VM should plug another 2 MiB-aligned virtio-mem step.
pub(crate) fn elastic_step(avail_mib: u64, total_mib: u64, base_mib: u32, plugged_mib: u64, max_mib: u32) -> Option<u64> {
    let cap = u64::from(max_mib);
    let current = u64::from(base_mib).saturating_add(plugged_mib);
    if current >= cap {
        return None;
    }
    let threshold = guest::headroom(total_mib).min(total_mib);
    if avail_mib >= threshold {
        return None;
    }
    let step = ((current / 2).clamp(128, 1024) / 2) * 2;
    let add = step.min(cap - current);
    (add >= 2).then_some(add)
}

/// Decide whether a software VM has enough excess free memory to unplug 2 MiB-aligned virtio-mem blocks.
pub(crate) fn elastic_shrink_step(avail_mib: u64, total_mib: u64, plugged_mib: u64) -> Option<u64> {
    if plugged_mib < 2 {
        return None;
    }
    let high_water = (total_mib / 2).max(256);
    if avail_mib <= high_water {
        return None;
    }
    let keep_free = guest::headroom(total_mib).max((total_mib / 3).clamp(128, 512));
    let reclaim = (avail_mib.saturating_sub(keep_free) / 2) * 2;
    let sub = reclaim.min((plugged_mib / 2) * 2);
    let min_step = plugged_mib.min(64);
    (sub >= min_step && sub >= 2).then_some(sub)
}

/// Own flags for pipes/ttys; changing the inherited open-file description would
/// also change a shell or another process sharing the original stdout/stderr.
struct OutputTarget {
    file: std::fs::File,
    socket: bool,
    regular: bool,
    capped: Option<util::output::CappedWriter>,
}

impl OutputTarget {
    fn new(fd: i32) -> Result<Self> {
        let fd = util::eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })?;
        let file = util::output::own(unsafe { std::fs::File::from_raw_fd(fd) });
        let kind = file.metadata()?.file_type();
        let (regular, socket) = (kind.is_file(), kind.is_socket());
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if !regular && !socket && flags & libc::O_NONBLOCK == 0 {
            bail!("foreground output cannot be made interruptible");
        }
        let capped = util::output::capped_writer(&file);
        Ok(Self { file, socket, regular, capped })
    }

    fn write(&self, mut bytes: &[u8]) -> Result<()> {
        if let Some(capped) = &self.capped {
            return capped.write(bytes).map_err(Into::into);
        }
        while !bytes.is_empty() {
            crate::template::interrupted()?;
            let fd = self.file.as_raw_fd();
            if !self.regular {
                let mut poll = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                let ready = unsafe { libc::poll(&mut poll, 1, 100) };
                if ready == 0 {
                    continue;
                }
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                if poll.revents & libc::POLLOUT == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
                }
            }
            let piece = &bytes[..bytes.len().min(if self.regular { 65536 } else { 4096 })];
            let written = if self.socket {
                unsafe { libc::send(fd, piece.as_ptr().cast(), piece.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) }
            } else {
                unsafe { libc::write(fd, piece.as_ptr().cast(), piece.len()) }
            };
            if written > 0 {
                bytes = &bytes[written as usize..];
            } else if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            } else {
                let error = std::io::Error::last_os_error();
                if !matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
}

struct Owner {
    machine: Arc<qemu::Machine>,
    processes: Arc<qemu::Processes>,
    name: NameLock,
    host: Host,
    entry: Mutex<Entry>,
    op: RwLock<()>,
    ended: AtomicBool,
    active: AtomicUsize,
    sessions: AtomicUsize,
    epoch: u64,
    generation: u64,
    reset_capable: bool,
    barrier: Mutex<Option<(u64, u64)>>,
    sequence: AtomicU64,
    changed: Condvar,
    main_id: Option<String>,
    offset: AtomicU64,
    drain: AtomicU8,
    resets: AtomicU64,
    main_claim: AtomicU64,
    vm_id: String,
    host_id: String,
    image: image::ImageMeta,
    memory_mib: u32,
    max_memory_mib: u32,
    plugged_mib: AtomicU64,
    growing: AtomicBool,
    last_grow: Mutex<Option<Instant>>,
    last_shrink_attempt: Mutex<Option<Instant>>,
    reservation: Mutex<Reservation>,
    vcpus: u32,
    consumed: Option<software_state::Consumed>,
    pending: Mutex<Option<(PathBuf, String)>>,
    suspended: AtomicBool,
    suspend_reply: AtomicBool,
}

impl Owner {
    fn publish_state(&self, state: &str) -> Result<()> {
        self.entry.lock().unwrap().state = state.into();
        self.changed.notify_all();
        let entry = self.entry.lock().unwrap().clone();
        self.name.publish(&entry)
    }

    /// Returns `false` if the guest agent does not support `MEMINFO` and polling should stop.
    fn adjust_memory(&self) -> bool {
        let (avail_kib, total_kib, actual_bytes) = {
            let Ok(_op) = self.op.try_read() else { return true };
            if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                return true;
            }
            let (avail_kib, total_kib) = match self.machine.meminfo(Instant::now() + Duration::from_secs(2)) {
                Ok(info) => info,
                Err(error) => {
                    if error.to_string().contains("unknown request") {
                        crate::info!("software VM {}: guest agent does not support MEMINFO; disabling elastic memory", self.name.name);
                        return false;
                    }
                    return true;
                }
            };
            let Ok(actual_bytes) = self.machine.virtio_mem_size(Instant::now() + Duration::from_secs(2)) else {
                return true;
            };
            (avail_kib, total_kib, actual_bytes)
        };
        let (avail_mib, total_mib) = (avail_kib >> 10, total_kib >> 10);
        let actual_mib = actual_bytes >> 20;
        let mut plugged = self.plugged_mib.load(Ordering::SeqCst);
        let stalled = self.last_grow.lock().unwrap().is_some_and(|t| t.elapsed() >= GROW_SETTLE_TIMEOUT);
        match reconcile_plugged(actual_mib, plugged, self.growing.load(Ordering::SeqCst), stalled) {
            Reconcile::Wait => return true,
            Reconcile::Synced => {
                self.growing.store(false, Ordering::SeqCst);
            }
            Reconcile::ClampDown(actual) => {
                let Ok(_op) = self.op.try_read() else { return true };
                if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                    return true;
                }
                let _ = self.machine.set_virtio_mem(actual << 20, Instant::now() + Duration::from_secs(2));
                self.growing.store(false, Ordering::SeqCst);
                self.update_plugged(actual);
                plugged = actual;
            }
            Reconcile::SyncTo(actual) => {
                self.growing.store(false, Ordering::SeqCst);
                self.update_plugged(actual);
                if actual > plugged {
                    crate::info!("software VM {}: reconciled memory +{} MiB (plugged {actual} MiB)", self.name.name, actual - plugged);
                } else {
                    crate::info!("software VM {}: reconciled memory -{} MiB (plugged {actual} MiB)", self.name.name, plugged - actual);
                }
                plugged = actual;
            }
        }
        if let Some(add) = elastic_step(avail_mib, total_mib, self.memory_mib, plugged, self.max_memory_mib) {
            let deadline = Instant::now() + Duration::from_secs(5);
            let grant_id = match self.reservation.lock().unwrap().grow(add, deadline) {
                Ok(id) => id,
                Err(error) => {
                    crate::log!("software VM {}: elastic memory +{add} MiB refused: {error}", self.name.name);
                    return true;
                }
            };
            let Ok(_op) = self.op.try_read() else {
                self.reservation.lock().unwrap().refund(grant_id);
                return true;
            };
            if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                self.reservation.lock().unwrap().refund(grant_id);
                return true;
            }
            let next = plugged + add;
            if let Err(error) = self.machine.set_virtio_mem(next << 20, deadline) {
                self.reservation.lock().unwrap().refund(grant_id);
                crate::log!("software VM {}: virtio-mem resize to {} MiB failed: {error}", self.name.name, u64::from(self.memory_mib) + next);
                return true;
            }
            self.growing.store(true, Ordering::SeqCst);
            *self.last_grow.lock().unwrap() = Some(Instant::now());
            self.update_plugged(next);
            crate::info!("software VM {}: grew memory +{add} MiB (plugged {next} MiB, ceiling {} MiB)", self.name.name, self.max_memory_mib);
            return true;
        }
        if shrink_cooldown_active(*self.last_grow.lock().unwrap(), *self.last_shrink_attempt.lock().unwrap(), Instant::now()) {
            return true;
        }
        if let Some(sub) = elastic_shrink_step(avail_mib, total_mib, plugged) {
            let target = plugged - sub;
            let deadline = Instant::now() + Duration::from_secs(5);
            {
                let Ok(_op) = self.op.try_read() else { return true };
                if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                    return true;
                }
                if let Err(error) = self.machine.set_virtio_mem(target << 20, deadline) {
                    crate::log!("software VM {}: virtio-mem shrink to {} MiB failed: {error}", self.name.name, u64::from(self.memory_mib) + target);
                    return true;
                }
            }
            let mut actual = plugged;
            for _ in 0..5 {
                if self.ended.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
                let Ok(_op) = self.op.try_read() else { return true };
                if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                    return true;
                }
                if let Ok(bytes) = self.machine.virtio_mem_size(Instant::now() + Duration::from_secs(2)) {
                    actual = (bytes >> 20).min(plugged);
                    if actual <= target {
                        break;
                    }
                }
            }
            if actual < plugged {
                let freed = plugged - actual;
                self.update_plugged(actual);
                crate::info!("software VM {}: shrunk memory -{freed} MiB (plugged {actual} MiB)", self.name.name);
            }
            if actual > target {
                *self.last_shrink_attempt.lock().unwrap() = Some(Instant::now());
                let Ok(_op) = self.op.try_read() else { return true };
                if !self.ended.load(Ordering::SeqCst) && self.entry.lock().unwrap().state == "running" {
                    let _ = self.machine.set_virtio_mem(actual << 20, Instant::now() + Duration::from_secs(2));
                }
            }
        }
        true
    }

    fn update_plugged(&self, next: u64) {
        self.plugged_mib.store(next, Ordering::SeqCst);
        let entry = {
            let mut entry = self.entry.lock().unwrap();
            if let Backend::QemuTcg { ram_mib, .. } = &mut entry.backend {
                *ram_mib = self.memory_mib.saturating_add(u32::try_from(next).unwrap_or(u32::MAX));
            }
            entry.clone()
        };
        let _ = self.name.publish(&entry);
    }

    fn switch(&self, paused: bool) -> Result<Value> {
        let _op = self.op.write().unwrap();
        self.switch_locked(paused)
    }

    // Caller holds the operation write lock through its entire transition.
    fn switch_locked(&self, paused: bool) -> Result<Value> {
        self.processes.alive()?;
        if self.ended.load(Ordering::SeqCst) {
            bail!("software VM is ending");
        }
        let state = if paused { "paused" } else { "running" };
        if self.entry.lock().unwrap().state != state {
            let deadline = Instant::now() + guest::TIMEOUT;
            let result = if !self.reset_capable {
                // Legacy agents retain their existing live pause support, but
                // cannot establish the transport boundary needed for capture.
                self.machine.switch(if paused { "stop" } else { "cont" }, deadline)
            } else if paused {
                (|| {
                    self.machine.checkpoint_capable(deadline)?;
                    let sequence = self
                        .sequence
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                        .map_err(|_| "software barrier sequence exhausted")?
                        + 1;
                    *self.barrier.lock().unwrap() = Some((self.generation, sequence));
                    self.resets
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                        .map_err(|_| "software transport reset count exhausted")?;
                    self.machine.quiesce_control(self.generation, self.epoch, sequence, deadline)?;
                    while self.drain.load(Ordering::SeqCst) == READING {
                        self.processes.alive()?;
                        if Instant::now() >= deadline {
                            bail!("foreground output did not reach its pause boundary");
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    if self.drain.load(Ordering::SeqCst) != DETACHED {
                        self.ended.store(true, Ordering::SeqCst);
                        bail!("foreground command ended before pause completed");
                    }
                    Ok(())
                })()
            } else {
                (|| {
                    let (saved_generation, sequence) = self.barrier.lock().unwrap().ok_or("paused software VM has no request barrier")?;
                    if self.machine.capture_pending() {
                        let pending = self.pending.lock().unwrap().clone().ok_or("software capture has no publication identity")?;
                        software_state::discard_attempt(&pending.0, &pending.1)?;
                        self.machine.resume_source(deadline)?;
                        *self.pending.lock().unwrap() = None;
                    } else {
                        self.machine.switch("cont", deadline)?;
                    }
                    self.machine.resume_admission(self.generation, self.epoch, saved_generation, sequence, deadline)?;
                    *self.barrier.lock().unwrap() = None;
                    *self.pending.lock().unwrap() = None;
                    Ok(())
                })()
            };
            if let Err(error) = result {
                if self.machine.capture_pending() && self.processes.engine_ident().is_ok() {
                    // Keep a failed capture visibly fenced until its publication
                    // can be invalidated. A normal cont cannot bypass that record.
                    return Err(error);
                }
                // A failed drain still belongs to this owner. Only a confirmed
                // rollback may reopen admission; an ambiguous outcome ends it.
                let rollback = if self.reset_capable && !self.ended.load(Ordering::SeqCst) {
                    self.machine.switch("cont", Instant::now() + guest::TIMEOUT).and_then(|()| {
                        let barrier = *self.barrier.lock().unwrap();
                        if let Some((saved_generation, sequence)) = barrier {
                            self.machine.abort_admission(self.generation, self.epoch, saved_generation, sequence, Instant::now() + guest::TIMEOUT)?;
                        }
                        Ok(())
                    })
                } else {
                    Err("software pause transition could not be resolved".into())
                };
                if rollback.is_ok() {
                    *self.barrier.lock().unwrap() = None;
                    let _ = self.publish_state("running");
                } else {
                    self.ended.store(true, Ordering::SeqCst);
                    self.changed.notify_all();
                    self.processes.stop();
                }
                return Err(error);
            }
        }
        self.publish_state(state)?;
        Ok(json!({"state":state,"name":self.name.name}))
    }

    fn main_output(&self, mut reader: BufReader<UnixStream>) -> Result<i32> {
        let main_id = self.main_id.as_deref().ok_or("software app output has no main session")?;
        let stdout = OutputTarget::new(1)?;
        let stderr = OutputTarget::new(2)?;
        let mut offset = self.offset.load(Ordering::SeqCst);
        let mut handled_reset = 0;
        loop {
            let result = self.machine.finish_exec_at(&mut reader, main_id, &mut offset, |kind, bytes| {
                if kind == guest::FRAME_STDERR {
                    stderr.write(bytes)
                } else {
                    stdout.write(bytes)
                }
            });
            self.offset.store(offset, Ordering::SeqCst);
            let status = match &result {
                Ok(_) => EXITED,
                Err(guest::OutputError::Transport(_)) => DETACHED,
                Err(_) => OUTPUT_FAILED,
            };
            self.drain.store(status, Ordering::SeqCst);
            let error = match result {
                Ok(code) => return Ok(code),
                Err(error) => error,
            };
            if status != DETACHED {
                return Err(error.into_inner());
            }
            loop {
                crate::template::interrupted()?;
                if self.ended.load(Ordering::SeqCst) {
                    return Err(error.into_inner());
                }
                let op = self.op.read().unwrap();
                let mut entry = self.entry.lock().unwrap();
                if matches!(entry.state.as_str(), "paused" | "suspending") {
                    drop(op);
                    entry = self.changed.wait_timeout(entry, Duration::from_millis(250)).unwrap().0;
                    drop(entry);
                    continue;
                }
                let reset = self.resets.load(Ordering::SeqCst);
                if entry.state != "running" || reset <= handled_reset {
                    return Err(error.into_inner());
                }
                drop(entry);
                self.processes.alive()?;
                let claim =
                    self.main_claim.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1)).map_err(|_| "software main claim exhausted")? + 1;
                let deadline = Instant::now() + guest::TIMEOUT;
                let line = guest::attach_line(main_id, offset, claim, self.epoch, guest::AttachForm::Epoch, false)?;
                reader = self.machine.request(&line, deadline)?;
                guest::untimed(&reader)?;
                reader.get_ref().set_read_timeout(Some(Duration::from_millis(250)))?;
                handled_reset = reset;
                self.machine.exec_started(&mut reader, main_id)?;
                // Mark reading before releasing admission's read guard. A new
                // pause must wait for this attachment's final delivered offset.
                self.drain.store(READING, Ordering::SeqCst);
                drop(op);
                break;
            }
        }
    }

    fn distro_output(&self) -> Result<i32> {
        loop {
            crate::template::interrupted()?;
            {
                // Retirement/capture holds the write lock. Never mistake its
                // engine termination for an unexpected guest exit mid-suspend.
                let _op = self.op.read().unwrap();
                if self.ended.load(Ordering::SeqCst) {
                    bail!("software distro lifecycle completed");
                }
                if let Some(code) = self.machine.distro_exit()? {
                    return Ok(code);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn suspend(&self) -> Result<Value> {
        self.machine.checkpoint_supported()?;
        if !self.reset_capable {
            bail!("software suspend requires a current serial guest agent");
        }
        let _op = self.op.write().unwrap();
        if self.machine.capture_pending() || self.pending.lock().unwrap().is_some() {
            bail!("software capture is unresolved; unpause to discard the failed attempt before retrying stop");
        }
        let was_paused = self.entry.lock().unwrap().state == "paused";
        self.switch_locked(true)?;
        if self.ended.load(Ordering::SeqCst) {
            bail!("software VM is ending");
        }
        if self.entry.lock().unwrap().state != "paused" {
            bail!("software VM changed state during suspend; try again");
        }
        if self.drain.load(Ordering::SeqCst) != DETACHED {
            bail!("foreground output is not detached at the capture boundary");
        }
        let (barrier_generation, barrier_sequence) = self.barrier.lock().unwrap().ok_or("software capture has no acknowledged request barrier")?;
        let checkpoint = self.host.suspended(&self.name.name)?;
        software_state::remove_discarded(&checkpoint, &self.vm_id)?;
        let snapshot_id = util::random_hex(16)?;
        *self.pending.lock().unwrap() = Some((checkpoint.clone(), snapshot_id.clone()));
        let result = (|| {
            self.publish_state("suspending")?;
            let staging = software_state::Staging::new(checkpoint.parent().ok_or("software checkpoint has no parent")?)?;
            let blank = software_state::Artifact { bytes: 0, sha256: String::new() };
            let entry = self.entry.lock().unwrap().clone();
            let plugged_mib = if self.max_memory_mib > self.memory_mib {
                let deadline = Instant::now() + guest::TIMEOUT;
                match self.machine.virtio_mem_size(deadline) {
                    Ok(bytes) => {
                        let actual = bytes >> 20;
                        let _ = self.machine.set_virtio_mem(actual << 20, deadline);
                        self.growing.store(false, Ordering::SeqCst);
                        actual
                    }
                    Err(_) => self.plugged_mib.load(Ordering::SeqCst),
                }
            } else {
                0
            };
            let manifest = software_state::Manifest {
                format: 1,
                backend: "qemu-tcg".into(),
                vm_id: self.vm_id.clone(),
                snapshot_id: snapshot_id.clone(),
                identity_generation: entry.gen,
                memory_mib: self.memory_mib,
                max_memory_mib: (self.max_memory_mib > self.memory_mib).then_some(self.max_memory_mib),
                plugged_mib,
                vcpus: self.vcpus,
                paused: was_paused,
                terminal: true,
                host_id: self.host_id.clone(),
                source_owner: Ident::me(),
                source_engine: self.processes.engine_ident()?,
                owner_generation: self.generation,
                saved_epoch: self.epoch,
                barrier_generation,
                barrier_sequence,
                profile: software_state::Profile { architecture: String::new(), arguments: Vec::new() },
                engine_version: Value::Null,
                engine: blank.clone(),
                kernel: blank.clone(),
                rootfs: blank.clone(),
                state: blank,
                firmware: std::collections::BTreeMap::new(),
                parent: None,
                disks: Vec::new(),
                main: match &self.main_id {
                    Some(id) => software_state::Main::App(software_state::Session {
                        id: id.clone(),
                        offset: self.offset.load(Ordering::SeqCst),
                        claim: self.main_claim.load(Ordering::SeqCst),
                    }),
                    None => software_state::Main::Distro(software_state::Distro { boot: self.image.boot }),
                },
                image: self.image.clone(),
            };
            // Rollback may discard a newly published replacement, removing the
            // old consumed bundle as well. The next attempt must use no-replace
            // publication when that slot is empty, rather than exchange a stale
            // consumed directory. No-replace still refuses any concurrent entry.
            let previous = self.consumed.as_ref().filter(|_| checkpoint.exists());
            let published = self.machine.checkpoint(staging, &checkpoint, manifest, previous, Instant::now() + Duration::from_secs(600))?;
            self.machine.retire(&published)?;
            if let Some(consumed) = &self.consumed {
                consumed.complete_import();
                consumed.release_replaced_inputs();
            }
            self.suspended.store(true, Ordering::SeqCst);
            self.ended.store(true, Ordering::SeqCst);
            self.publish_state("suspended")?;
            Ok(json!({"state":"suspended","name":self.name.name,"snapshot_id":snapshot_id}))
        })();
        if result.is_err() {
            if self.processes.engine_ident().is_err() {
                self.ended.store(true, Ordering::SeqCst);
                let _ = self.publish_state("failed");
            } else {
                let _ = self.publish_state("paused");
            }
        }
        result
    }

    fn exec(&self, req: &Value, client: &UnixStream, acknowledged: &mut bool) -> Result<()> {
        let _op = self.op.read().unwrap();
        self.processes.alive()?;
        if self.ended.load(Ordering::SeqCst) {
            bail!("software VM is ending");
        }
        if self.entry.lock().unwrap().state == "paused" {
            bail!("vm {} is paused{} once flexvm unpause resumes it", self.name.name, guest::TRY_AGAIN);
        }
        let id = req["session"].as_str().ok_or("missing session id")?;
        let offset = req["offset"].as_u64().unwrap_or(0);
        let deadline = Instant::now() + guest::TIMEOUT;
        let action = req["action"].as_str().unwrap_or("start");
        let action = if action == "start" && req["cmd"].is_object() { "argv" } else { action };
        let claim = vmproc::Claim::new(id);
        let mut stream = if action == "attach" {
            let line = guest::attach_line(id, offset, claim.n, self.epoch, guest::AttachForm::Epoch, false)?;
            self.machine.request(&line, deadline)?
        } else {
            let body = if matches!(action, "start" | "argv") { guest::command_body(&req["cmd"])? } else { String::new() };
            guest::session_on(action, id, offset, &body, |line| self.machine.request(line, deadline))?
        };
        if action == "close" {
            let reply = guest::read_frame(&mut By { s: &mut stream, at: deadline })?;
            if !matches!(reply, Some((guest::FRAME_MSG, ref body)) if body == b"closed") {
                bail!("session close failed: {reply:?}");
            }
            util::send_json(&mut &*client, &json!({"ok":true}))?;
            *acknowledged = true;
            return Ok(());
        }
        util::send_json(&mut &*client, &json!({"ok":true}))?;
        *acknowledged = true;
        drop(_op);
        let late = vmproc::relay_direct(stream, client, req["interactive"] == true, &claim, &|| self.ended.load(Ordering::SeqCst), &|| {
            self.sessions.load(Ordering::SeqCst) >= MAX_SESSIONS * 3 / 4
        })?;
        if let Some((end, code)) = late {
            // The guest may have stopped waiting for an acknowledgment while a
            // slow client drained output. RELEASE checks delivery/attachment state.
            let _op = self.op.read().unwrap();
            if !self.ended.load(Ordering::SeqCst) && self.entry.lock().unwrap().state == "running" {
                let _ = self.machine.message(&format!("RELEASE {id} {end} {code}"), Instant::now() + guest::TIMEOUT);
            }
        }
        Ok(())
    }

    fn control(&self, mut client: UnixStream) {
        struct Slot<'a>(&'a AtomicUsize);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let mut slot = Some(Slot(&self.active));
        let mut acknowledged = false;
        let mut terminal_reply = false;
        let result = (|| -> Result<Value> {
            let deadline = Instant::now() + guest::TIMEOUT;
            let (wire, fds) = util::recv_with_fds_by(&client, util::MAX_LINE as usize, deadline)?;
            if !fds.is_empty() {
                bail!("software owner does not accept descriptors for this operation");
            }
            let req: Value = serde_json::from_slice(&wire)?;
            match req["op"].as_str().unwrap_or("") {
                "exec" => {
                    let _session = if req["action"] == "close" {
                        None
                    } else {
                        if self.sessions.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
                            self.sessions.fetch_sub(1, Ordering::SeqCst);
                            return Err(vmproc::Busy(format!("software VM sessions are busy{}", guest::TRY_AGAIN)).into());
                        }
                        Some(Slot(&self.sessions))
                    };
                    if req["action"] != "close" {
                        drop(slot.take());
                    }
                    self.exec(&req, &client, &mut acknowledged)?;
                    Ok(Value::Null)
                }
                "signal" if self.main_id.is_none() => {
                    let _op = self.op.read().unwrap();
                    if self.ended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state != "running" {
                        bail!("software distro VM is not running");
                    }
                    let signal = req["signal"].as_i64().and_then(|value| i32::try_from(value).ok()).ok_or("missing signal")?;
                    let reply = self.machine.message(&format!("SIGNAL {signal}"), deadline)?;
                    if reply != b"ok" {
                        bail!("software distro signal refused: {}", String::from_utf8_lossy(&reply));
                    }
                    Ok(json!({"name":self.name.name,"signal":signal}))
                }
                "pause" => self.switch(true),
                "resume" if self.suspended.load(Ordering::SeqCst) || self.entry.lock().unwrap().state == "suspending" => Ok(json!({"suspending":true})),
                "resume" => self.switch(false),
                "suspend" => {
                    terminal_reply = true;
                    self.suspend()
                }
                "kill" => {
                    request_kill(&self.ended, &self.entry, &self.changed, &self.processes, crate::template::interrupt);
                    Ok(json!({"name":self.name.name,"state":"killed"}))
                }
                "debug" if req["what"] == "status" => Ok(serde_json::to_value(&*self.entry.lock().unwrap())?),
                op => bail!("software VM operation {op:?} is not implemented"),
            }
        })();
        if acknowledged {
            if let Err(e) = result {
                crate::info!("software exec relay ended: {e}");
            }
            return;
        }
        let reply = match result {
            Ok(Value::Null) => return,
            Ok(value) => json!({"ok":true,"result":value}),
            Err(e) => json!({"ok":false,"busy":e.is::<vmproc::Busy>(),"error":e.to_string()}),
        };
        let _ = By { s: &mut client, at: Instant::now() + guest::TIMEOUT }.write_all(format!("{reply}\n").as_bytes());
        if terminal_reply && self.suspended.load(Ordering::SeqCst) {
            self.suspend_reply.store(true, Ordering::SeqCst);
            self.changed.notify_all();
        }
    }
}

fn send_notification(file: &std::fs::File, value: &Value) -> Result<()> {
    let socket = UnixStream::from(OwnedFd::from(file.try_clone()?));
    util::send_json(&mut By { s: socket, at: Instant::now() + guest::TIMEOUT }, value)?;
    Ok(())
}

#[derive(Clone)]
struct Startup(Arc<Mutex<Option<std::fs::File>>>);

impl Startup {
    fn send(&self, value: &Value) -> Result<()> {
        match self.0.lock().unwrap().take() {
            Some(file) => send_notification(&file, value),
            None => Ok(()),
        }
    }
}

struct Resume {
    manifest: software_state::Manifest,
    generation: u64,
    consumed: software_state::Consumed,
    notify: Option<Startup>,
}

pub fn run(
    name: NameLock,
    machine: qemu::Machine,
    processes: Arc<qemu::Processes>,
    config: &qemu::Config,
    meta: &image::ImageMeta,
    reservation: Reservation,
) -> Result<i32> {
    if config.parent_kvm.is_some() && !machine.has_parent_fence() {
        bail!("named parent KVM VMs require a worker with hierarchy pause support");
    }
    serve(name, machine, processes, config, meta, reservation, None)
}

fn serve(
    name: NameLock,
    machine: qemu::Machine,
    processes: Arc<qemu::Processes>,
    config: &qemu::Config,
    meta: &image::ImageMeta,
    mut reservation: Reservation,
    resumed: Option<Resume>,
) -> Result<i32> {
    let host = reservation.host.clone();
    let machine = Arc::new(machine);
    let epoch = u64::from_str_radix(&util::random_hex(8)?, 16)?;
    // A restored VM must reconnect its guest transport after device load.
    // Allow the same startup budget as a cold boot for that handoff.
    let timeout = if resumed.is_some() || !meta.boot.is_app() { config.boot_timeout } else { guest::TIMEOUT };
    let deadline = Instant::now() + timeout;
    let max_memory_mib = config.effective_max_mib();
    // QEMU has finished booting (or loading restored RAM via migrate-incoming),
    // so resident pages are already reflected in MemAvailable; release the boot
    // hold so it does not double-count resident guest RAM for the VM's lifetime.
    reservation.settle_boot();
    let initial_plugged = match (&resumed, max_memory_mib > config.mem_mib && config.parent_kvm.is_none()) {
        (Some(r), true) => {
            let actual = machine.virtio_mem_size(deadline).map(|b| b >> 20).unwrap_or(r.manifest.plugged_mib);
            if actual > r.manifest.plugged_mib {
                reservation.grow(actual - r.manifest.plugged_mib, deadline)?;
            }
            actual
        }
        (Some(r), false) => r.manifest.plugged_mib,
        (None, _) => 0,
    };
    let (generation, identity_generation, vm_id, main_id, main_reader, offset, claim, consumed, notify) = match resumed {
        Some(resumed) => {
            // STARTED was synchronized before this first guest instruction.
            // As with the ordinary start command, execution resumes even when
            // the source was paused before it was suspended.
            machine.switch("cont", deadline).map_err(|error| format!("software destination CPU resume failed: {error}"))?;
            machine.resume_admission(resumed.generation, epoch, resumed.manifest.barrier_generation, resumed.manifest.barrier_sequence, deadline)?;
            let (main_id, reader, offset, claim) = match resumed.manifest.main.session() {
                Some(main) => {
                    let claim = main.claim.checked_add(1).ok_or("software main claim exhausted")?;
                    let line = guest::attach_line(&main.id, main.offset, claim, epoch, guest::AttachForm::Epoch, false)?;
                    let mut reader = machine.request(&line, deadline).map_err(|error| format!("software main reattach transport failed: {error}"))?;
                    guest::untimed(&reader)?;
                    reader.get_ref().set_read_timeout(Some(Duration::from_millis(250)))?;
                    machine.exec_started(&mut reader, &main.id)?;
                    (Some(main.id.clone()), Some(reader), main.offset, claim)
                }
                None => {
                    // Admission already proved the restored broker is live.
                    // Keep an existing distro running even if its runtime
                    // service was stopped; APP would replace its cold identity.
                    (None, None, 0, 0)
                }
            };
            (
                resumed.generation,
                resumed.manifest.identity_generation,
                resumed.manifest.vm_id,
                main_id,
                reader,
                offset,
                claim,
                Some(resumed.consumed),
                resumed.notify,
            )
        }
        None => {
            if machine.message(&format!("FENCE 1 {epoch}"), deadline)? != b"ok 1" {
                bail!("named software VM requires guest host-epoch fencing");
            }
            let (id, reader) = if meta.boot.is_app() {
                let (id, mut reader) = machine.start_exec(meta.argv.clone())?;
                machine.exec_started(&mut reader, &id)?;
                (Some(id), Some(reader))
            } else {
                let reply = machine.message(&format!("HOSTNAME {}", name.name), deadline)?;
                if reply != b"ok" {
                    bail!("setting software distro hostname: {}", String::from_utf8_lossy(&reply));
                }
                machine.start_distro(deadline)?;
                (None, None)
            };
            (1, u64::from_str_radix(&util::random_hex(8)?, 16)?.max(1), util::random_hex(16)?, id, reader, 0, 0, None, None)
        }
    };
    let reset_capable = machine.checkpoint_capable(deadline).is_ok();
    let entry = Entry {
        backend: Backend::QemuTcg {
            process: processes.engine_ident()?,
            image: meta.source.clone(),
            digest: meta.digest.clone(),
            argv: meta.argv.clone(),
            ram_mib: config.mem_mib.saturating_add(u32::try_from(initial_plugged).unwrap_or(u32::MAX)),
        },
        name: name.name.clone(),
        ident: Ident::me(),
        ip: Some(machine.ip()),
        gen: identity_generation,
        vcpus: config.vcpus,
        max_mib: u64::from(max_memory_mib),
        state: "running".into(),
        cmd: meta.boot.is_app(),
        ..Default::default()
    };
    let socket = host.sock(&name.name)?;
    let private = crate::host::locks(socket.parent().ok_or("control socket has no directory")?).join(crate::socket::private_name());
    let listener = crate::socket::bind_private(&private, &socket)?;
    listener.set_nonblocking(true)?;
    let local_host_id = software_state::host_id(&host.state)?;
    let owner = Arc::new(Owner {
        machine,
        processes,
        name,
        host,
        entry: Mutex::new(entry),
        op: RwLock::new(()),
        ended: AtomicBool::new(false),
        active: AtomicUsize::new(0),
        sessions: AtomicUsize::new(0),
        epoch,
        generation,
        reset_capable,
        barrier: Mutex::new(None),
        sequence: AtomicU64::new(0),
        changed: Condvar::new(),
        main_id: main_id.clone(),
        offset: AtomicU64::new(offset),
        drain: AtomicU8::new(if main_id.is_some() { READING } else { DETACHED }),
        resets: AtomicU64::new(0),
        main_claim: AtomicU64::new(claim),
        vm_id,
        host_id: local_host_id,
        image: meta.clone(),
        memory_mib: config.mem_mib,
        max_memory_mib,
        plugged_mib: AtomicU64::new(initial_plugged),
        growing: AtomicBool::new(false),
        last_grow: Mutex::new(None),
        last_shrink_attempt: Mutex::new(None),
        reservation: Mutex::new(reservation),
        vcpus: config.vcpus,
        consumed,
        pending: Mutex::new(None),
        suspended: AtomicBool::new(false),
        suspend_reply: AtomicBool::new(false),
    });
    // The caller blocked these before starting its first worker/engine thread.
    let set = util::block_signals(&[libc::SIGTSTP, libc::SIGCONT, libc::SIGTERM]);
    let weak = Arc::downgrade(&owner);
    let signals = std::thread::Builder::new().name("software-signals".into()).spawn(move || {
        while let Some(owner) = weak.upgrade() {
            if owner.ended.load(Ordering::SeqCst) {
                break;
            }
            if let Some(sig) = util::take_signal(&set) {
                if sig == libc::SIGTERM {
                    crate::log!("software VM {}: SIGTERM does not suspend this backend; use flexvm stop", owner.name.name);
                    continue;
                }
                if let Err(e) = owner.switch(sig == libc::SIGTSTP) {
                    crate::log!("software VM {}: {e}", owner.name.name);
                }
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })?;
    let mem_watcher = if max_memory_mib > config.mem_mib && config.parent_kvm.is_none() {
        let weak = Arc::downgrade(&owner);
        Some(std::thread::Builder::new().name("software-mem".into()).spawn(move || {
            while let Some(owner) = weak.upgrade() {
                if owner.ended.load(Ordering::SeqCst) || !owner.adjust_memory() {
                    break;
                }
                if !wait_for_mem_poll(&owner.ended, &owner.entry, &owner.changed, Duration::from_millis(500)) {
                    break;
                }
            }
        })?)
    } else {
        None
    };
    let serving = owner.clone();
    let server = std::thread::Builder::new().name("software-owner".into()).spawn(move || {
        while !serving.ended.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    if serving.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONTROL {
                        serving.active.fetch_sub(1, Ordering::SeqCst);
                        let _ = By { s: &mut client, at: Instant::now() + Duration::from_millis(100) }
                            .write_all(b"{\"ok\":false,\"busy\":true,\"error\":\"software owner is busy\"}\n");
                        continue;
                    }
                    let request = serving.clone();
                    if std::thread::Builder::new().spawn(move || request.control(client)).is_err() {
                        serving.active.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    crate::log!("software owner listener failed: {e}");
                    serving.ended.store(true, Ordering::SeqCst);
                    drop(serving.entry.lock().unwrap());
                    serving.changed.notify_all();
                    serving.processes.stop();
                    break;
                }
            }
        }
    })?;
    let published = {
        let _op = owner.op.write().unwrap();
        let entry = owner.entry.lock().unwrap().clone();
        owner.name.publish(&entry)
    };
    let result = published.and_then(|()| {
        if let Some(notify) = notify {
            notify.send(&json!({"ok":true,"result":owner.name.name}))?;
        }
        match main_reader {
            Some(reader) => owner.main_output(reader),
            None => owner.distro_output(),
        }
    });
    owner.ended.store(true, Ordering::SeqCst);
    drop(owner.entry.lock().unwrap());
    owner.changed.notify_all();
    {
        let _op = owner.op.write().unwrap();
        if !owner.suspended.load(Ordering::SeqCst) {
            let _ = owner.publish_state("ending");
        }
        owner.processes.stop();
    }
    let _ = signals.join();
    if let Some(watcher) = mem_watcher {
        let _ = watcher.join();
    }
    let _ = server.join();
    if owner.suspended.load(Ordering::SeqCst) && crate::template::interrupted_signal().is_none() {
        let deadline = Instant::now() + guest::TIMEOUT;
        while !owner.suspend_reply.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        return Ok(0);
    }
    if result.is_ok() || crate::template::interrupted_signal().is_some() {
        if let Some(consumed) = &owner.consumed {
            consumed.finish(&owner.host.suspended(&owner.name.name)?)?;
        }
    }
    let entry = owner.entry.lock().unwrap().clone();
    let signal = crate::template::interrupted_signal();
    let code = signal.map_or_else(|| result.as_ref().copied().unwrap_or_else(vmproc::exit_code), |signal| 128 + signal);
    crate::containers::record_exit_of(
        &owner.host,
        &owner.name.name,
        &entry.ident,
        entry.ip.map(|ip| crate::Instance { ip, gen: entry.gen }),
        code,
        result.is_ok() && signal.is_none(),
    );
    crate::template::interrupted()?;
    result
}

fn admitted_memory_mib(base_mib: u32, plugged_mib: u64) -> Result<u32> {
    let plugged = u32::try_from(plugged_mib).map_err(|_| format!("software VM plugged_mib {plugged_mib} overflows u32"))?;
    base_mib.checked_add(plugged).ok_or_else(|| format!("software VM memory {base_mib} + {plugged} MiB overflows u32").into())
}

pub fn restore(host: Host, vm_name: &str, bundle: Option<&Path>, notify: Option<std::fs::File>) -> Result<i32> {
    let notify = notify.map(|file| Startup(Arc::new(Mutex::new(Some(file)))));
    let failure_notify = notify.clone();
    let result = (|| {
        let name = host.take_name(vm_name, true)?;
        let path = host.suspended(vm_name)?;
        let metadata = software_state::metadata(&path)?;
        let native = metadata.parent.as_ref().is_some_and(|parent| parent.native);
        let bundle = if native {
            bundle
                .filter(|path| !path.as_os_str().is_empty())
                .ok_or("restoring native parent KVM state requires a local --parent-kvm-bundle DIR")?
                .canonicalize()?
        } else {
            PathBuf::new()
        };
        let processes = Arc::new(qemu::Processes::default());
        setup_signals(processes.clone());
        let mut config = restore_config(&metadata);
        config.parent_kvm = metadata.parent.as_ref().map(|parent| qemu::ParentKvm {
            bundle,
            engine: if parent.native { "kvm" } else { "tcg" }.into(),
            child_mem_mib: parent.child_memory_mib,
        });
        let admitted_mib = admitted_memory_mib(config.mem_mib, metadata.plugged_mib)?;
        let reservation = Reservation::new(&host, admitted_mib, Instant::now() + config.boot_timeout, &processes)?;
        let profiles = config.profiles_for_disk_ids(metadata.disks.iter().map(|disk| disk.volume_id.as_str()))?;
        let verified = software_state::open(&path, profiles)?;
        let disks = verified.manifest.open_disks(&host.state)?;
        let manifest = verified.manifest.clone();
        let prepared = verified.prepare(&name, &software_state::host_id(&host.state)?)?;
        let generation = prepared.generation;
        let machine = config.restore(verified, processes.clone(), disks)?;
        let consumed = prepared.grant(processes.engine_ident()?)?;
        let meta = manifest.image.clone();
        serve(name, machine, processes, &config, &meta, reservation, Some(Resume { manifest, generation, consumed, notify }))
    })();
    if let (Err(error), Some(file)) = (&result, failure_notify) {
        let _ = file.send(&json!({"ok":false,"error":error.to_string()}));
    }
    result
}

fn restore_config(manifest: &software_state::Manifest) -> qemu::Config {
    qemu::Config {
        control: qemu::Control::Serial,
        kernel: PathBuf::new(),
        qemu: String::new(),
        vsock_backend: String::new(),
        mem_mib: manifest.memory_mib,
        max_mib: manifest.max_memory_mib.unwrap_or(manifest.memory_mib),
        vcpus: manifest.vcpus,
        boot_timeout: Duration::from_secs(120),
        parent_kvm: None,
    }
}

pub fn activate(host: Host, vm: &str, offer: &Path, trusted_engine: &Path) -> Result<i32> {
    let name = host.take_name(vm, false)?;
    let activation = software_state::transfer::bundle::activate::Activation::prepare(&name, offer)?;
    let manifest = activation.manifest().clone();
    let config = restore_config(&manifest);
    let processes = Arc::new(qemu::Processes::default());
    setup_signals(processes.clone());
    let admitted_mib = admitted_memory_mib(config.mem_mib, manifest.plugged_mib)?;
    let reservation = Reservation::new(&host, admitted_mib, Instant::now() + config.boot_timeout, &processes)?;
    let verified = activation.verify_inputs(&config.profiles()?, trusted_engine)?;
    let machine = config.restore(verified, processes.clone(), Vec::new())?;
    let (generation, consumed) = activation.grant(processes.engine_ident()?)?;
    let meta = manifest.image.clone();
    serve(name, machine, processes, &config, &meta, reservation, Some(Resume { manifest, generation, consumed, notify: None }))
}

pub fn setup_signals(processes: Arc<qemu::Processes>) {
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGQUIT, libc::SIG_DFL);
    }
    util::block_signals(&[libc::SIGTSTP, libc::SIGCONT, libc::SIGTERM]);
    util::on_signal(&[libc::SIGINT, libc::SIGQUIT, libc::SIGHUP], move |signal| {
        crate::template::interrupt(signal);
        processes.stop();
        // Keep a thread with these signals unblocked until process exit, so a
        // second interrupt can terminate even if ordinary cleanup stalls.
        loop {
            std::thread::park();
        }
    });
}

pub fn stop(host: &Host, name: &str, expected: &Ident) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(600);
    let owner = crate::host::PidFd::open(expected)?;
    let mut check = |client: &UnixStream| {
        if !expected.is(util::peer_pid(client)?) {
            bail!("software VM owner was replaced before suspend");
        }
        Ok(())
    };
    let result = vmproc::connect(host, name, &json!({"op":"suspend"}), &[], deadline, Some(&mut check))
        .and_then(|stream| util::answer(util::recv_json(&mut BufReader::new(By { s: stream, at: deadline }))?, "software VM", "suspend refused"));
    let checkpoint = host.suspended(name)?;
    let local_host = software_state::host_id(&host.state)?;
    if result.is_err() && !software_state::retired_for(&checkpoint, expected, &local_host).unwrap_or(false) {
        let gone = owner.as_ref().is_none_or(|owner| owner.wait(Duration::from_millis(250)));
        if gone
            && crate::containers::exit_record(host, name).is_some_and(|exit| exit.ident == *expected && exit.app == Some(true))
            && !host.has_record(name, "failed")
            && !host.has_record(name, "lost")
        {
            return Ok(());
        }
        return result.map(|_| ());
    }
    if let Some(owner) = owner {
        if !owner.wait(deadline.saturating_duration_since(Instant::now())) {
            bail!("software VM has not finished suspending");
        }
    }
    if software_state::retired_for(&checkpoint, expected, &local_host).unwrap_or(false) {
        return Ok(());
    }
    match result {
        Err(error) => Err(error),
        Ok(_) => Err("software VM did not publish a verified retirement".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elastic_step_grows_under_pressure_and_respects_ceiling() {
        // Plenty of free RAM (headroom(512) == 256): no growth.
        assert_eq!(elastic_step(300, 512, 512, 0, 2048), None);
        assert_eq!(elastic_step(256, 512, 512, 0, 2048), None);
        // Under guest headroom (256 MiB for 512 MiB total): grows by 256 MiB (half of 512).
        assert_eq!(elastic_step(200, 512, 512, 0, 2048), Some(256));
        // Large guest (headroom(4096) == 1024): grows before guest memory.high throttles.
        assert_eq!(elastic_step(500, 4096, 512, 3584, 8192), Some(1024));
        // Near ceiling: clamped to remaining room (even 2 MiB multiple).
        assert_eq!(elastic_step(32, 1900, 512, 1400, 2048), Some(136));
        // At ceiling: no growth.
        assert_eq!(elastic_step(16, 2048, 512, 1536, 2048), None);
        // Fixed RAM (max == base): never grows.
        assert_eq!(elastic_step(16, 512, 512, 0, 512), None);
    }

    #[test]
    fn elastic_shrink_unplugs_excess_and_avoids_thrashing() {
        // Nothing plugged: nothing to shrink.
        assert_eq!(elastic_shrink_step(400, 512, 0), None);
        // Below 50% available: do not shrink.
        assert_eq!(elastic_shrink_step(400, 1024, 512), None);
        // 800 MiB free out of 1024 MiB (keep headroom(1024) == 512 MiB -> reclaim 288 MiB, 2 MiB aligned).
        assert_eq!(elastic_shrink_step(800, 1024, 512), Some(288));
        // Clamped to plugged_mib.
        assert_eq!(elastic_shrink_step(900, 1024, 128), Some(128));
    }

    #[test]
    fn admitted_memory_mib_rejects_overflow() {
        assert_eq!(admitted_memory_mib(512, 1024).unwrap(), 1536);
        assert!(admitted_memory_mib(512, u64::from(u32::MAX) + 1).is_err());
        assert!(admitted_memory_mib(u32::MAX, 1).is_err());
    }

    #[test]
    fn reservation_settles_boot_hold_and_uses_expiring_grants_for_growth() {
        let base = crate::test_util::TempDir::new("software-reservation");
        let host = Host::open(&base.join("state"), &base.join("run")).unwrap();
        let holds_dir = crate::host::locks(&host.run).join("holds");
        let hold_count = || std::fs::read_dir(&holds_dir).map(|entries| entries.flatten().count()).unwrap_or(0);
        let grant_ids = || -> Vec<u64> {
            let Ok(bytes) = std::fs::read(host.grants()) else { return Vec::new() };
            serde_json::from_slice::<Vec<(u64, u64, u64)>>(&bytes).unwrap_or_default().into_iter().map(|(_, _, id)| id).collect()
        };

        let processes = qemu::Processes::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut reservation = Reservation::new(&host, 1, deadline, &processes).unwrap();
        let boot_id = reservation.grant_id;
        assert_eq!(hold_count(), 1, "boot reservation should hold a lock file until settled");
        assert!(grant_ids().contains(&boot_id));

        // Settling unlinks the hold file and refunds the startup grant even though
        // `processes` still holds the inherited lease fd.
        reservation.settle_boot();
        assert_eq!(hold_count(), 0, "settle_boot must unlink the boot hold so resident RAM is not double-counted");
        assert!(!grant_ids().contains(&boot_id));

        // Elastic growth uses an expiring grant (no permanent Hold) and supports
        // targeted rollback via refund(grant_id).
        assert_eq!(reservation.grow(0, deadline).unwrap(), 0);
        let grow_id = reservation.grow(1, deadline).unwrap();
        assert_ne!(grow_id, 0);
        assert_eq!(hold_count(), 0, "elastic growth must not create a permanent Hold");
        assert!(grant_ids().contains(&grow_id));

        reservation.refund(grow_id);
        assert!(!grant_ids().contains(&grow_id));
        drop(reservation);

        // Dropping an unsettled reservation also cleans up its hold and grant.
        let unsettled = Reservation::new(&host, 1, deadline, &processes).unwrap();
        let unsettled_id = unsettled.grant_id;
        assert_eq!(hold_count(), 1);
        assert!(grant_ids().contains(&unsettled_id));
        drop(unsettled);
        assert_eq!(hold_count(), 0);
        assert!(!grant_ids().contains(&unsettled_id));
    }

    #[test]
    fn reconcile_plugged_syncs_when_actual_exceeds_plugged() {
        // #1698: when QEMU's actual plugged size exceeds our tracked `plugged_mib`,
        // reconcile up to `actual_mib` regardless of `growing` so `elastic_step`
        // never computes `next < actual_mib`.
        assert_eq!(reconcile_plugged(512, 256, false, false), Reconcile::SyncTo(512));
        assert_eq!(reconcile_plugged(512, 256, true, false), Reconcile::SyncTo(512));
        // Equal clears growing without changing plugged_mib.
        assert_eq!(reconcile_plugged(256, 256, true, false), Reconcile::Synced);
        assert_eq!(reconcile_plugged(256, 256, false, false), Reconcile::Synced);
        // Less waits while an active growth has not stalled, clamps when stalled,
        // and syncs down when not growing.
        assert_eq!(reconcile_plugged(128, 256, true, false), Reconcile::Wait);
        assert_eq!(reconcile_plugged(128, 256, true, true), Reconcile::ClampDown(128));
        assert_eq!(reconcile_plugged(128, 256, false, false), Reconcile::SyncTo(128));
    }

    #[test]
    fn wait_for_mem_poll_wakes_immediately_on_ended() {
        let ended = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(Mutex::new(Entry::default()));
        let changed = Arc::new(Condvar::new());

        let (e, m, c) = (ended.clone(), entry.clone(), changed.clone());
        let start = Instant::now();
        let handle = std::thread::spawn(move || wait_for_mem_poll(&e, &m, &c, Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        ended.store(true, Ordering::SeqCst);
        drop(entry.lock().unwrap());
        changed.notify_all();

        assert!(!handle.join().unwrap());
        assert!(start.elapsed() < Duration::from_millis(500), "mem_watcher wait should wake immediately on shutdown");
        // Already ended returns false without waiting.
        assert!(!wait_for_mem_poll(&ended, &entry, &changed, Duration::from_secs(5)));
    }

    #[test]
    fn request_kill_records_sigint_and_wakes_waiters() {
        let ended = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(Mutex::new(Entry::default()));
        let changed = Arc::new(Condvar::new());
        let processes = qemu::Processes::default();
        let recorded = std::sync::atomic::AtomicI32::new(0);

        let (e, m, c) = (ended.clone(), entry.clone(), changed.clone());
        let start = Instant::now();
        let handle = std::thread::spawn(move || wait_for_mem_poll(&e, &m, &c, Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        request_kill(&ended, &entry, &changed, &processes, |sig| recorded.store(sig, Ordering::SeqCst));

        assert_eq!(recorded.load(Ordering::SeqCst), libc::SIGINT);
        assert!(ended.load(Ordering::SeqCst));
        assert!(!handle.join().unwrap());
        assert!(start.elapsed() < Duration::from_millis(500), "request_kill must wake waiters immediately");
    }

    #[test]
    fn shrink_cooldown_holds_off_aggressive_shrinking() {
        assert!(SHRINK_COOLDOWN >= Duration::from_secs(15));
        assert!(SHRINK_COOLDOWN > GROW_SETTLE_TIMEOUT);

        let t0 = Instant::now();
        assert!(!shrink_cooldown_active(None, None, t0));
        assert!(shrink_cooldown_active(Some(t0), None, t0 + Duration::from_secs(5)));
        assert!(shrink_cooldown_active(Some(t0), None, t0 + Duration::from_secs(14)));
        assert!(!shrink_cooldown_active(Some(t0), None, t0 + SHRINK_COOLDOWN));
        assert!(shrink_cooldown_active(None, Some(t0), t0 + Duration::from_secs(10)));
        assert!(!shrink_cooldown_active(None, Some(t0), t0 + SHRINK_COOLDOWN));
    }
}
