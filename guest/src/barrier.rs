//! Admission for serial control requests, separate from filesystem QUIESCE.
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

#[derive(Default)]
pub struct Gate {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    active: usize,
    highest: (u64, u64),
    closed: Option<(u64, u64)>,
    resumed: Option<(u64, u64)>,
}

pub struct Permit(Arc<Gate>);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.active -= 1;
        self.0.changed.notify_all();
    }
}

impl Gate {
    pub fn enter(self: &Arc<Self>) -> io::Result<Permit> {
        let mut state = self.state.lock().unwrap();
        if state.closed.is_some() {
            return Err(io::Error::other("request admission is quiesced; try again after resume"));
        }
        state.active += 1;
        Ok(Permit(self.clone()))
    }

    pub fn begin(&self, generation: u64, sequence: u64) -> io::Result<()> {
        let id = (generation, sequence);
        let mut state = self.state.lock().unwrap();
        match state.closed {
            Some(current) if current != id => return Err(io::Error::other("another request barrier is active")),
            Some(_) => {}
            None => {
                if sequence == 0 || id <= state.highest {
                    return Err(io::Error::other("request barrier is superseded"));
                }
                state.highest = id;
                state.closed = Some(id);
            }
        }
        Ok(())
    }

    pub fn quiesce(&self, generation: u64, sequence: u64, deadline: Instant) -> io::Result<()> {
        self.begin(generation, sequence)?;
        let id = (generation, sequence);
        let mut state = self.state.lock().unwrap();
        while state.active != 0 {
            if state.closed != Some(id) {
                return Err(io::Error::other("request barrier was resumed before acknowledgment"));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                // Remain closed on failure; an explicit, fenced RESUME is needed.
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request barrier timed out"));
            }
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
        if state.closed != Some(id) {
            return Err(io::Error::other("request barrier was resumed before acknowledgment"));
        }
        Ok(())
    }

    pub fn resume(&self, generation: u64, saved_generation: u64, sequence: u64) -> io::Result<()> {
        let id = (saved_generation, sequence);
        let mut state = self.state.lock().unwrap();
        if generation < saved_generation || generation < state.highest.0 {
            return Err(io::Error::other("request barrier generation went backwards"));
        }
        if generation > saved_generation && state.active != 0 {
            return Err(io::Error::other("cannot transfer a barrier with active requests"));
        }
        match state.closed {
            Some(current) if current == id => {
                state.closed = None;
                state.resumed = Some(id);
                state.highest = state.highest.max((generation, 0));
                self.changed.notify_all();
                Ok(())
            }
            None if state.resumed == Some(id) => Ok(()),
            _ => Err(io::Error::other("request barrier identity does not match")),
        }
    }

    pub fn maintenance(&self) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        if state.closed.is_some() && state.active == 0 {
            Ok(())
        } else {
            Err(io::Error::other("request barrier has not drained"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn admission_closes_before_wait_and_acknowledges_only_after_permits_finish() {
        let gate = Arc::new(Gate::default());
        let permit = gate.enter().unwrap();
        let waiting = gate.clone();
        let (done, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(waiting.quiesce(1, 1, Instant::now() + Duration::from_secs(2))).unwrap();
        });
        let until = Instant::now() + Duration::from_secs(1);
        while gate.state.lock().unwrap().closed.is_none() {
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        assert!(gate.enter().is_err());
        assert!(gate.maintenance().is_err());
        assert!(received.try_recv().is_err());
        drop(permit);
        received.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        worker.join().unwrap();
        gate.maintenance().unwrap();
        gate.resume(1, 1, 1).unwrap();
        gate.enter().unwrap();
    }

    #[test]
    fn timeout_stays_closed_and_old_resume_cannot_open_a_new_barrier() {
        let gate = Arc::new(Gate::default());
        let permit = gate.enter().unwrap();
        assert_eq!(gate.quiesce(1, 1, Instant::now()).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(gate.enter().is_err());
        assert!(gate.resume(2, 1, 1).is_err());
        drop(permit);
        gate.quiesce(1, 1, Instant::now()).unwrap();
        gate.resume(1, 1, 1).unwrap();
        gate.resume(1, 1, 1).unwrap();
        assert!(gate.quiesce(1, 1, Instant::now()).is_err());
        gate.quiesce(1, 2, Instant::now()).unwrap();
        assert!(gate.resume(1, 1, 1).is_err());
        gate.resume(2, 1, 2).unwrap();
        assert!(gate.quiesce(1, 3, Instant::now()).is_err());
        gate.quiesce(2, 1, Instant::now()).unwrap();
        assert!(gate.resume(1, 2, 1).is_err());
    }
}
