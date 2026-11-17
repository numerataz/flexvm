# Capturing VM test failures

The end-to-end harness passes `--failure-dir` to `scripts/faults.py`. When a
scenario fails, it captures evidence before disarming faults or removing VMs:

- The scenario's registry entries and live owner/VMM thread states.
- Logs from the isolated host run directories, including the VMM consoles.
- A JSON report describing copied files, offsets, truncation and capture errors.

Logs retain up to 64 MiB per file and 256 MiB per failed scenario. Smaller logs
are copied completely; larger logs retain their tail and report its offset.
Special files are refused without blocking. Capture is best effort and does not
replace the scenario's failure result. Existing deleted-VM log tail retention
and cleanup/isolation checks remain active. CI collects the evidence beneath
its existing end-to-end log artifacts.

For a failed `software-boot.py --checkpoint` run, the software execution artifact
also retains:

- `checkpoint`: the outer QEMU migration stream.
- `checkpoint-state.json`: migration and source/target run-state observations.
- `replay-kernel` and `replay-initramfs.cpio`: the original boot inputs.
- `replay.json`: relative boot arguments, input/stream digests, QEMU binary digest
  and the input-gate release token.

Check that migration completed in `checkpoint-state.json` and that the file
hashes match `replay.json` before interpreting a stream as a replayable checkpoint.
Use a compatible QEMU build and firmware; the captured QEMU version is in the
state observations. From the artifact directory, use the recorded machine/CPU
and boot parameters with an incoming checkpoint and a fresh QMP socket. Wait
until incoming migration finishes in the paused state, continue through QMP,
then send the recorded `C` followed by a newline to the restored serial input.
The guest should continue its inner timer ticks without repeating either boot.
These files are test diagnostics and do not grant production restore authority.

Successful runs remove the migration stream after every acceptance assertion
passes and do not create replay input copies. Failure retention does not change
execution deadlines or turn a failed/interrupted run into a pass. The native
restore stalls in #1417 and nested software watchdog issue #1423 remain separate
correctness investigations.
