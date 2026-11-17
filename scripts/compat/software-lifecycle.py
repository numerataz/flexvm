#!/usr/bin/env python3
"""Exercise software suspend and fresh-owner restore with host virtualization devices masked."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / 'software-boot.py'))
IMAGE = runpy.run_path(str(ROOT / 'software-kvm.py'))['image']


def exercise(args):
    base = [str(args.bin), '--state', str(args.state / 'state'), '--run', str(args.state / 'run')]
    deadline = time.monotonic() + args.timeout
    owners = []

    def owner_environment():
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(args.output / 'fail-parent-sync.so')
        env['FLEXVM_TEST_FAIL_PARENT_SYNC'] = str(args.output / 'fail-parent-sync')
        env['FLEXVM_TEST_KILL_PARENT_SYNC'] = str(args.output / 'kill-parent-sync')
        return env

    def cli(*words, env=None, pending=False):
        result = subprocess.run([*base, *words], capture_output=True, text=True,
                                timeout=max(.1, deadline - time.monotonic()), env=env)
        if pending and result.returncode == 1:
            return None
        if result.returncode:
            raise RuntimeError(f'{words}: exit {result.returncode}: {result.stdout} {result.stderr}')
        return result.stdout

    def live():
        return next((e for e in json.loads(cli('ps', '--json')) if e['name'] == 'state-test'), None)

    def launch(*words, workload_log="workload.log"):
        env = owner_environment()
        with (args.output / workload_log).open('ab') as out, (args.output / f'owner-{len(owners)}.log').open('wb') as err:
            proc = subprocess.Popen([*base, *words], stdout=out, stderr=err, env=env)
        owners.append(proc)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f'owner exited {proc.returncode}; see owner-{len(owners)-1}.log')
            entry = live()
            if entry:
                return proc, entry
            time.sleep(.05)
        raise TimeoutError('owner did not publish')

    def observation():
        until = min(deadline, time.monotonic() + 30)
        while time.monotonic() < until:
            data = cli('exec', 'state-test', '/state-probe', 'status', pending=args.firecracker is not None)
            if data is not None:
                values = [int(v) for v in data.split()]
                if len(values) != 5:
                    raise RuntimeError(f'invalid workload observation: {data}')
                return values
            time.sleep(.1)
        raise TimeoutError('workload did not publish its initial observation')

    def nested_observation(control=cli, vm='state-test'):
        values = [int(v) for v in control('exec', vm, '/state-probe', 'status-full').split()]
        if len(values) != 12:
            raise RuntimeError(f'invalid nested observation: {values}')
        return values

    def nested_mode(mode):
        before = nested_observation()
        cli('exec', 'state-test', '/state-probe', 'mode', mode)
        until = min(deadline, time.monotonic() + 10)
        while time.monotonic() < until:
            seen = nested_observation()
            if seen[10] == (1 if mode == 'spin' else 0) and seen[8] > before[8] and (mode != 'spin' or seen[11] > before[11]):
                return seen
            time.sleep(.1)
        raise RuntimeError(f'inner guest did not enter {mode} mode with forward progress')

    def nested_restored(before, identity, observe=nested_observation):
        initial = observe()
        until = min(deadline, time.monotonic() + 5)
        while time.monotonic() < until:
            time.sleep(.15)
            seen = observe()
            if initial[:8] != identity[:8] or seen[:8] != identity[:8] or seen[10] != before[10]:
                raise RuntimeError(f'inner process/RAM/mode continuity lost: {before} -> {seen}')
            if seen[10] == 0 and (initial[11] != before[11] or seen[11] != before[11]):
                raise RuntimeError('timer workload unexpectedly executed the CPU spin loop')
            if seen[8] >= initial[8] + 2 and seen[8] > before[8] and seen[9] > initial[9] and seen[9] > before[9]:
                if seen[10] == 0 or (seen[11] > initial[11] and seen[11] > before[11]):
                    return seen
        raise RuntimeError('inner CPU/timer did not make fresh post-restore progress')

    def advancing_observation():
        initial = observation()
        until = min(deadline, time.monotonic() + 3)
        while time.monotonic() < until:
            time.sleep(.15)
            latest = observation()
            if latest[:3] != initial[:3] or latest[4] < initial[4]:
                raise RuntimeError('restored workload identity or monotonic clock changed')
            if latest[3] > initial[3] and latest[4] > initial[4]:
                return latest
        raise RuntimeError('restored workload timers did not make forward progress')

    def engine_gone(ident):
        try:
            pidfd = os.pidfd_open(ident['pid'])
        except ProcessLookupError:
            return
        try:
            try:
                fields = Path(f'/proc/{ident["pid"]}/stat').read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return
            if int(fields[19]) != ident['start']:
                return
            # A zombie leader can precede its last exiting worker thread.
            waiter = select.poll()
            waiter.register(pidfd, select.POLLIN)
            if not waiter.poll(max(1, int(min(5, deadline - time.monotonic()) * 1000))):
                raise RuntimeError('software engine thread group survived its owner')
        finally:
            os.close(pidfd)

    boot = ('software', '--name', 'state-test', '--control', 'serial', '--kernel', str(args.kernel),
            '--mem', '512', '--vcpus', '2' if args.firecracker else '1', str(args.output / 'image.tar'))

    def transfer_retirement():
        destination_state = args.state / 'target'
        destination_base = [str(args.bin), '--state', str(destination_state), '--run', str(args.state / 'target-run')]
        target = [*destination_base, 'software-transfer']

        def destination(*words):
            return json.loads(subprocess.check_output([*target, *words], timeout=max(.1, deadline - time.monotonic())))

        cli('rm', '-f', 'state-test', pending=True)
        owner, entry = launch(*boot, workload_log='transfer-workload.log')
        before = observation()
        nested_before = nested_mode('spin') if args.firecracker else None
        cli('stop', 'state-test')
        if owner.wait(timeout=10) != 0:
            raise RuntimeError('transfer source owner did not retire')
        engine_gone(entry['backend']['process'])

        def key_pair(secret):
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-outform', 'DER', '-out', secret], check=True, timeout=10)
            secret.chmod(0o600)
            public_der = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', secret, '-pubout', '-outform', 'DER'], timeout=10)
            return base64.b64encode(public_der[-32:]).decode()

        secret = args.state / 'signing-key.der'
        public_key = key_pair(secret)
        destination_secret = args.state / 'destination-key.der'
        destination_key = key_pair(destination_secret)
        offer = args.state / 'offer.json'
        receipt = args.state / 'receipt.json'
        target_id = destination('id')['host_id']

        def prepare_and_retire():
            proposal = cli('software-transfer', 'offer', 'state-test', target_id)
            offer.write_text(proposal)
            if destination('prepare', offer, '--source-key', public_key)['status'] != 'pending':
                raise RuntimeError('transfer destination did not prepare')
            retire = ('software-transfer', 'retire', 'state-test', offer, '--signing-key', secret, '--destination-key', destination_key)
            receipt.write_text(cli(*retire))
            if json.loads(cli(*retire)) != json.loads(receipt.read_text()):
                raise RuntimeError('transfer receipt retry changed the signed offer')
            return json.loads(proposal)['generation']

        def require_refused(*words, error):
            refused = subprocess.run([*base, *words], capture_output=True, text=True, timeout=30)
            if refused.returncode == 0 or error not in refused.stderr:
                raise RuntimeError(f'transfer operation was accepted or failed for another reason: {refused}')

        aborted_generation = prepare_and_retire()
        require_refused('start', 'state-test', error='source cannot restart')
        ack = args.state / 'abort-receipt.json'
        ack.write_text(json.dumps(destination('acknowledge-abort', offer, '--signing-key', destination_secret)))
        if json.loads(cli('software-transfer', 'recover', ack))['status'] != 'recovered':
            raise RuntimeError('the source rejected the signed abort')
        cli('start', 'state-test', env=owner_environment())
        after = advancing_observation()
        if after[:3] != before[:3] or after[3] < before[3]:
            raise RuntimeError('transfer recovery lost the source workload identity')
        nested_source = nested_restored(nested_before, nested_before) if nested_before else None
        cli('stop', 'state-test')
        checkpoint = args.state / 'state' / 'suspended' / 'state-test' / 'manifest.json'
        if json.loads(checkpoint.read_text())['owner_generation'] <= aborted_generation:
            raise RuntimeError('recovered owner did not advance the fenced generation')

        prepare_and_retire()
        require_refused('software-transfer', 'recover', ack, error='does not match a source fence')
        with (args.output / 'transfer-send.log').open('wb') as errors:
            source = subprocess.Popen([*base, 'software-transfer', 'send', 'state-test', offer], stdout=subprocess.PIPE, stderr=errors)
            try:
                received = json.loads(subprocess.check_output([*target, 'receive', offer], stdin=source.stdout,
                                                             timeout=max(.1, deadline - time.monotonic())))
                if source.wait(timeout=10) != 0 or received['status'] != 'received' or received['bytes'] <= 0:
                    raise RuntimeError('software checkpoint bundle did not transfer; see transfer-send.log')
            finally:
                source.stdout.close()
                if source.poll() is None:
                    source.kill()
                    source.wait(timeout=10)
        engine = shutil.which('qemu-system-' + platform.machine())
        if engine is None:
            raise RuntimeError('trusted local QEMU was not found')
        remote = 'received-test'
        intermediary_base = [str(args.bin), '--state', str(args.state / 'intermediary'),
                             '--run', str(args.state / 'intermediary-run')]

        def target_cli(*words):
            return subprocess.check_output([*destination_base, *words], text=True, timeout=max(.1, deadline - time.monotonic()))

        def denied_activation(expected, vm=remote, qemu=engine):
            result = subprocess.run([*target, 'activate', offer, vm, '--qemu', qemu], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 or expected not in result.stderr:
                raise RuntimeError(f'destination activation accepted or failed for the wrong reason: {result}')

        def destination_progress(previous, control=target_cli, vm=remote):
            def guest_observation():
                return [int(value) for value in control('exec', vm, '/state-probe', 'status').split()]

            initial = guest_observation()
            until = min(deadline, time.monotonic() + 15)
            while time.monotonic() < until:
                seen = guest_observation()
                if initial[:3] != previous[:3] or seen[:3] != previous[:3] or seen[4] < previous[4]:
                    raise RuntimeError('destination lost guest process, RAM or monotonic time')
                if seen[3] > max(initial[3], previous[3]) and seen[4] > initial[4]:
                    return seen
                time.sleep(.15)
            raise RuntimeError('destination guest did not make fresh progress')

        def repeat_transfer(sender, receiver, old_name, new_name, sender_key, receiver_key,
                            signer, previous, destination_host, *, abort_first=False, finalize_with=None, handoff_chain=None):
            proposed = args.state / f'{new_name}-offer.json'
            accepted = args.state / f'{new_name}-receipt.json'
            previous_offer = None
            for abort in ([True, False] if abort_first else [False]):
                offer_text = subprocess.check_output([*sender, 'software-transfer', 'offer', old_name, destination_host],
                                                     text=True, timeout=30)
                proposed.write_text(offer_text)
                current_offer = json.loads(offer_text)
                if previous_offer and current_offer['generation'] <= previous_offer['generation']:
                    raise RuntimeError('return offer did not advance the aborted generation')
                prepare = [*receiver, 'software-transfer', 'prepare', proposed, '--source-key', sender_key]
                if handoff_chain:
                    denied = subprocess.run(prepare, capture_output=True, text=True, timeout=30)
                    if denied.returncode == 0 or 'does not extend the pinned outgoing handoff' not in denied.stderr:
                        raise RuntimeError(f'return from an unrecognized source unexpectedly prepared: {denied}')
                    prepare += ['--handoff-chain', handoff_chain]
                prepared = json.loads(subprocess.check_output(prepare, timeout=30))
                if prepared['status'] != 'pending':
                    raise RuntimeError('return transfer did not prepare')
                accepted.write_bytes(subprocess.check_output([*sender, 'software-transfer', 'retire', old_name, proposed,
                                                             '--signing-key', signer, '--destination-key', receiver_key], timeout=30))
                if abort:
                    abort_receipt = args.state / f'{new_name}-abort.json'
                    abort_receipt.write_bytes(subprocess.check_output([*receiver, 'software-transfer', 'acknowledge-abort',
                                                                      proposed, '--signing-key', secret], timeout=30))
                    subprocess.check_call([*sender, 'software-transfer', 'recover', abort_receipt], timeout=30, stdout=subprocess.DEVNULL)
                    previous_offer = current_offer

            with (args.output / f'{new_name}-send.log').open('wb') as errors:
                with subprocess.Popen([*sender, 'software-transfer', 'send', old_name, proposed],
                                      stdout=subprocess.PIPE, stderr=errors) as source:
                    try:
                        subprocess.check_call([*receiver, 'software-transfer', 'receive', proposed], stdin=source.stdout,
                                              stdout=subprocess.DEVNULL, timeout=max(.1, deadline - time.monotonic()))
                        if source.wait(timeout=10) != 0:
                            raise RuntimeError(f'return checkpoint failed to transfer to {new_name}')
                    finally:
                        if source.poll() is None:
                            source.kill()
            subprocess.check_call([*receiver, 'software-transfer', 'commit', accepted], timeout=30, stdout=subprocess.DEVNULL)
            proof = None
            if finalize_with:
                acknowledgment = args.state / f'{new_name}-commit-ack.json'
                acknowledgment.write_bytes(subprocess.check_output([*receiver, 'software-transfer', 'acknowledge-commit',
                                                                   proposed, '--signing-key', finalize_with], timeout=30))
                proof = json.loads(subprocess.check_output([*sender, 'software-transfer', 'finalize', acknowledgment,
                                                          '--signing-key', signer], timeout=30))
            with (args.output / f'{new_name}-owner.log').open('wb') as log:
                activated = subprocess.Popen([*receiver, 'software-transfer', 'activate', proposed, new_name, '--qemu', engine],
                                             stdout=log, stderr=log)
            owners.append(activated)

            def control(*words):
                return subprocess.check_output([*receiver, *words], text=True, timeout=max(.1, deadline - time.monotonic()))

            while time.monotonic() < deadline and activated.poll() is None:
                if any(entry['name'] == new_name and entry['state'] == 'running' for entry in json.loads(control('ps', '--json'))):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError(f'return owner failed to publish {new_name}')
            seen = destination_progress(previous, control, new_name)
            control('stop', new_name)
            if activated.wait(timeout=15) != 0:
                raise RuntimeError(f'return owner failed to stop {new_name}')
            return (seen, proof)

        denied_activation('requires a committed destination transfer')
        if destination('commit', receipt)['status'] != 'committed':
            raise RuntimeError('transfer destination did not commit')
        commit_ack = args.state / 'commit-ack.json'
        commit_ack.write_text(json.dumps(destination('acknowledge-commit', offer, '--signing-key', destination_secret)))
        finalize = ('software-transfer', 'finalize', commit_ack, '--signing-key', secret)
        proof = json.loads(cli(*finalize))
        if proof['handoff']['offer'] != json.loads(offer.read_text()) or proof['handoff']['destination_key'] != destination_key:
            raise RuntimeError('finalized proof did not bind the exact offer and destination key')
        if proof != json.loads(cli(*finalize)):
            raise RuntimeError('finalized proof changed after a retry')
        evidence['finalized_transfer_proof'] = 'passed'
        denied_activation('trusted local QEMU does not match', qemu='/bin/true')
        try:
            with (args.output / 'transfer-target.log').open('wb') as log:
                activated = subprocess.Popen([*target, 'activate', offer, remote, '--qemu', engine], stdout=log, stderr=log)
            owners.append(activated)
            while time.monotonic() < deadline and activated.poll() is None:
                if any(entry['name'] == remote and entry['state'] == 'running' for entry in json.loads(target_cli('ps', '--json'))):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('destination owner failed to publish; see transfer-target.log')
            activated_state = destination_progress(after)
            denied_activation('already granted execution', vm='duplicate')
            require_refused('start', 'state-test', error='source cannot restart')
            if live() is not None:
                raise RuntimeError('the committed transfer source is running')
            if nested_source:
                def observe_target():
                    return nested_observation(target_cli, remote)

                nested_after = nested_restored(nested_source, nested_before, observe_target)
                target_cli('exec', remote, '/state-probe', 'mode', 'quit')
                if activated.wait(timeout=30) != 23:
                    raise RuntimeError('transferred inner guest did not shut down cleanly')
                denied_activation('already granted execution', vm='duplicate')
                evidence['nested_transfer'] = {'before': nested_source, 'after': nested_after, 'graceful_shutdown': 'passed'}
                return
            target_cli('pause', remote)
            target_cli('unpause', remote)
            target_cli('stop', remote)
            if activated.wait(timeout=15) != 0:
                raise RuntimeError('destination owner failed to stop after activation')
            restored = json.loads((destination_state / 'suspended' / remote / 'manifest.json').read_text())
            if restored['host_id'] != target_id or restored['owner_generation'] <= json.loads(offer.read_text())['generation']:
                raise RuntimeError('destination checkpoint lacked its local host identity or newer generation')
            activated_offer = json.loads(offer.read_text())
            imported = destination_state / 'software-incoming' / f"{activated_offer['vm_id']}-{activated_offer['transfer_id']}"
            if not imported.is_dir():
                raise RuntimeError('destination import disappeared before collection')
            target_cli('debug', 'gc')
            if imported.exists():
                raise RuntimeError('collection retained a cleanly retired import')
            denied_activation('already granted execution', vm='duplicate')
            evidence['retired_import_collection'] = 'passed'
            target_cli('start', remote)
            activated_state = destination_progress(activated_state)
            target_cli('stop', remote)
            # Retain each host's original checkpoint while the new owner returns
            # under another name, then prove both old checkpoints remain fenced.
            local_id = json.loads(cli('software-transfer', 'id'))['host_id']
            returned, _ = repeat_transfer(destination_base, base, remote, 'returned-test', destination_key, public_key,
                                          destination_secret, activated_state, local_id, abort_first=True)
            require_refused('start', 'state-test', error='predates the return transfer grant')
            back_on_peer, _ = repeat_transfer(base, destination_base, 'returned-test', 'received-again', public_key, destination_key,
                                              secret, returned, target_id)
            refused = subprocess.run([*destination_base, 'start', remote], capture_output=True, text=True, timeout=30)
            if refused.returncode == 0 or 'predates the return transfer grant' not in refused.stderr:
                raise RuntimeError(f'old destination checkpoint was not fenced: {refused}')
            denied_activation('does not match a prepared destination', vm='duplicate')
            evidence['repeated_transfer'] = 'passed'

            intermediary_secret = args.state / 'intermediary-key.der'
            intermediary_key = key_pair(intermediary_secret)
            intermediary = json.loads(subprocess.check_output([*intermediary_base, 'software-transfer', 'id'], timeout=30))['host_id']
            on_intermediary, proof = repeat_transfer(destination_base, intermediary_base, 'received-again', 'third-host',
                                                       destination_key, intermediary_key, destination_secret, back_on_peer,
                                                       intermediary, finalize_with=intermediary_secret)
            chain = args.state / 'handoff-chain.json'
            chain.write_text(json.dumps([proof]))
            repeat_transfer(intermediary_base, base, 'third-host', 'returned-via-third', intermediary_key, public_key,
                            intermediary_secret, on_intermediary, local_id, handoff_chain=chain)
            require_refused('start', 'returned-test', error='predates the return transfer grant')
            evidence['intermediary_transfer'] = 'passed'
        finally:
            for name in (remote, 'received-again'):
                subprocess.run([*destination_base, 'rm', '-f', name], capture_output=True, timeout=20)
            subprocess.run([*intermediary_base, 'rm', '-f', 'third-host'], capture_output=True, timeout=20)
            cli('rm', '-f', 'returned-test', 'returned-via-third', pending=True)
            cli('rm', '-f', 'state-test', pending=True)

    evidence = {'cycles': []}
    try:
        owner, entry = launch(*boot)
        first = observation()
        identity = entry['gen']
        nested_identity = nested_observation() if args.firecracker else None
        for cycle in range(2):
            nested_before = None
            if args.firecracker:
                mode = 'spin' if cycle == 0 else 'timer'
                nested_before = nested_mode(mode)
                cli('pause', 'state-test')
                if live()['state'] != 'paused':
                    raise RuntimeError('nested pause did not confirm outer CPU state')
                cli('unpause', 'state-test')
                advancing_observation()
            before = observation()
            if args.firecracker:
                nested_before = nested_observation()
            if cycle == 1:
                # Fail the parent directory fsync after the replacement rename.
                # Roll back explicitly, then capture again from the same engine.
                marker = args.output / 'fail-parent-sync'
                marker.touch()
                refused = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=60)
                if refused.returncode == 0 or marker.exists() or live()['state'] != 'paused':
                    raise RuntimeError(f'publication fault was not fenced: {refused}')
                retried = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=10)
                if retried.returncode == 0 or 'unresolved' not in retried.stderr:
                    raise RuntimeError('retried stop overwrote the pending capture identity')
                cli('unpause', 'state-test')
                # The rollback keeps the consumed inputs at an exchange name.
                # A sweep must preserve their links while QEMU still uses them.
                hidden = list((args.state / 'state' / 'suspended').glob('.software-stage-v2-*'))
                if not hidden:
                    raise RuntimeError('replacement rollback did not retain the consumed inputs')
                pinned = {str(path): (path.stat().st_ino, (path / 'kernel').stat().st_ino) for path in hidden}
                cli('debug', 'gc')
                if any(not Path(path).exists() or (Path(path).stat().st_ino, (Path(path) / 'kernel').stat().st_ino) != inode
                       for path, inode in pinned.items()):
                    raise RuntimeError('garbage collection removed live exchanged inputs')
                evidence['live_input_gc'] = 'passed'
                rolled_back = observation()
                if rolled_back[:3] != first[:3] or rolled_back[3] < before[3]:
                    raise RuntimeError('publication rollback lost source identity')
                evidence['publication_rollback'] = {'error': refused.stderr, 'source': rolled_back}
                if args.firecracker:
                    nested_before = nested_observation()
                cli('pause', 'state-test')
            cli('stop', 'state-test')
            if owner.wait(timeout=10) != 0:
                raise RuntimeError('suspend owner failed')
            engine_gone(entry['backend']['process'])
            if list((args.state / 'state' / 'suspended').glob('.software-stage-*')):
                raise RuntimeError('retired owner left a replaced checkpoint bundle')
            stopped = next(e for e in json.loads(cli('ps', '-a', '--json')) if e['name'] == 'state-test')
            if stopped['state'] != 'suspended' or stopped['backend']['kind'] != 'qemu-tcg':
                raise RuntimeError(f'wrong suspended identity: {stopped}')
            if cycle == 0:
                # Corrupt a pinned input: restore must refuse before granting CPU
                # authority, and the unconsumed checkpoint must remain usable.
                kernel = args.state / 'state' / 'suspended' / 'state-test' / 'kernel'
                original = kernel.read_bytes()
                kernel.chmod(0o600)
                kernel.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                kernel.chmod(0o400)
                try:
                    refused = subprocess.run([*base, 'start', '--attach', 'state-test'],
                                             capture_output=True, text=True, timeout=30)
                    if refused.returncode == 0 or live() is not None:
                        raise RuntimeError('corrupt kernel was accepted')
                    evidence['corrupt_kernel_refused'] = refused.stderr
                finally:
                    kernel.chmod(0o600)
                    kernel.write_bytes(original)
                    kernel.chmod(0o400)
            owner, entry = launch('start', '--attach', 'state-test')
            after = advancing_observation()
            if after[:3] != first[:3] or after[3] < before[3] or after[4] < before[4] or entry['gen'] != identity:
                raise RuntimeError(f'workload continuity lost: {before} -> {after}; {entry}')
            cycle_evidence = {'before': before, 'after': after, 'entry': entry}
            if args.firecracker:
                nested_after = nested_restored(nested_before, nested_identity)
                cycle_evidence.update(nested_mode=mode, nested_before=nested_before, nested_after=nested_after)
            evidence['cycles'].append(cycle_evidence)
        # Exercise the normal detached start notification and owner handoff too.
        before = observation()
        nested_before = nested_observation() if args.firecracker else None
        cli('stop', 'state-test')
        if owner.wait(timeout=10) != 0:
            raise RuntimeError('last attached owner failed to suspend')
        engine_gone(entry['backend']['process'])
        cli('start', 'state-test', env=owner_environment())
        entry = live()
        after = advancing_observation()
        if not entry or after[:3] != first[:3] or after[3] < before[3] or entry['gen'] != identity:
            raise RuntimeError('detached start lost workload identity')
        evidence['detached_start'] = {'before': before, 'after': after, 'entry': entry}
        if args.firecracker:
            evidence['detached_start'].update(nested_before=nested_before, nested_after=nested_restored(nested_before, nested_identity))
        # Kill the owner after exchange, before parent fsync/RETIRED. The new
        # complete checkpoint must survive collection and recover on this host.
        checkpoint = args.state / 'state' / 'suspended' / 'state-test'
        old_snapshot = json.loads((checkpoint / 'manifest.json').read_text())['snapshot_id']
        before = observation()
        nested_before = nested_observation() if args.firecracker else None
        marker = args.output / 'kill-parent-sync'
        owner_pidfd = os.pidfd_open(entry['pid'])
        try:
            marker.touch()
            crashed = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=60)
            if crashed.returncode == 0 or marker.exists():
                raise RuntimeError('replacement owner-death fault did not execute')
            waiter = select.poll()
            waiter.register(owner_pidfd, select.POLLIN)
            if not waiter.poll(5000):
                raise RuntimeError('publication owner thread group did not exit')
        finally:
            os.close(owner_pidfd)
        engine_gone(entry['backend']['process'])
        published = json.loads((checkpoint / 'manifest.json').read_text())
        if published['snapshot_id'] == old_snapshot or (checkpoint / 'RETIRED').exists() or (checkpoint / 'STARTED').exists():
            raise RuntimeError('replacement crash did not leave the expected unretired publication')
        cli('debug', 'gc')
        if list(checkpoint.parent.glob('.software-stage-v2-*')):
            raise RuntimeError('dead replacement owner retained hidden input bundles')
        if json.loads((checkpoint / 'manifest.json').read_text()) != published:
            raise RuntimeError('collection changed the last complete checkpoint')
        cli('start', 'state-test', env=owner_environment())
        entry = live()
        after = advancing_observation()
        if not entry or after[:3] != first[:3] or after[3] < before[3] or entry['gen'] != identity:
            raise RuntimeError('commit-before-retirement recovery lost workload continuity')
        evidence['publication_owner_death'] = {'snapshot_id': published['snapshot_id'], 'before': before, 'after': after,
                                               'runtime_and_staging_cleanup': 'passed'}
        if args.firecracker:
            evidence['publication_owner_death'].update(nested_before=nested_before, nested_after=nested_restored(nested_before, nested_identity))
        cli('kill', 'state-test')
        if cli('wait', 'state-test').strip() != '130':
            raise RuntimeError('detached owner lost kill status')
        engine_gone(entry['backend']['process'])
        ended = next((e for e in json.loads(cli('ps', '-a', '--json')) if e['name'] == 'state-test'), None)
        if ended and ended['state'] == 'quarantined':
            raise RuntimeError('explicit kill retained a replay-quarantined checkpoint')
        lines = (args.output / 'workload.log').read_text().splitlines()
        ticks = [int(line.split()[1]) for line in lines if line.startswith('STATE_TICK ')]
        if lines.count('STATE_WORKLOAD_BOOT') != 1 or not ticks or ticks != list(range(ticks[-1] + 1)):
            raise RuntimeError(f'foreground output duplicated or skipped: {lines}')
        if args.firecracker:
            if lines.count('NESTED_INNER_BOOT') != 1 or lines.count('NESTED_INNER_READY') != 1:
                raise RuntimeError('nested Firecracker guest booted repeatedly or never completed startup')
            evidence['nested_firecracker'] = {'boots': 1, 'identity': nested_identity[:8], 'cpu_and_timer_restore': 'passed'}
        transfer_retirement()
        evidence['source_transfer_retirement'] = 'passed'
        evidence['destination_transfer_activation'] = 'passed'
        evidence.update(status='passed', boots=1, delivered_ticks=len(ticks))
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        try:
            subprocess.run([*base, 'kill', 'state-test'], capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for owner in owners:
            if owner.poll() is None:
                owner.send_signal(signal.SIGINT)
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--firecracker', type=Path, help='run a live inner Linux VM through the normal software owner')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.bin, args.kernel, args.output = (p.resolve() for p in (args.bin, args.kernel, args.output))
    if args.firecracker:
        args.firecracker = args.firecracker.resolve(strict=True)
    if args.worker:
        exercise(args)
        return 0
    if os.geteuid() != 0:
        parser.error('run as root for image preparation and private device masking')
    if not 1 <= args.timeout <= 3600:
        parser.error('--timeout must be 1..3600 seconds')
    args.output.mkdir(parents=True, exist_ok=True)
    report_path = args.output / 'report.json'
    if report_path.exists():
        parser.error('use an output directory without an existing report')
    report = {'schema_version': 1, 'status': 'running', 'scope': 'software lifecycle continuity',
              'binary_sha256': HELPERS['digest'](args.bin), 'kernel_sha256': HELPERS['digest'](args.kernel)}
    started = time.monotonic()
    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        engine = shutil.which('qemu-system-' + platform.machine())
        if engine is None:
            raise FileNotFoundError('native QEMU is required for lifecycle acceptance')
        report['qemu_sha256'] = HELPERS['digest'](Path(engine).resolve())
        report['qemu_version'] = subprocess.check_output([engine, '--version'], text=True, timeout=10).splitlines()[0]
        probe = args.output / 'state-probe'
        source = ROOT / ('nested-state.c' if args.firecracker else 'state-probe.c')
        HELPERS['run']([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread', str(source), '-o', str(probe)],
                       60, args.output / 'compile.log')
        HELPERS['run']([args.cc, '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        str(ROOT / 'fail-parent-sync.c'), '-ldl', '-o', str(args.output / 'fail-parent-sync.so')],
                       60, args.output / 'compile-fault.log')
        files = {'state-probe': (probe.read_bytes(), 0o755), 'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644),
                 'etc/group': (b'root:x:0:\n', 0o644)}
        if args.firecracker:
            config = {'boot-source': {'kernel_image_path': '/inner-kernel', 'initrd_path': '/inner-initramfs.cpio',
                                      'boot_args': 'console=ttyS0 quiet panic=1 rdinit=/init' + (' reboot=k' if platform.machine() == 'x86_64' else '')},
                      'machine-config': {'vcpu_count': 1, 'mem_size_mib': 128}, 'drives': [], 'network-interfaces': []}
            files.update({'firecracker': (args.firecracker.read_bytes(), 0o755), 'inner-kernel': (args.kernel.read_bytes(), 0o600),
                          'inner-initramfs.cpio': (HELPERS['initramfs'](probe.read_bytes()), 0o600),
                          'firecracker.json': (json.dumps(config).encode(), 0o600)})
            report.update(scope='nested Firecracker through named software lifecycle',
                          firecracker_sha256=HELPERS['digest'](args.firecracker), inner_kernel_sha256=HELPERS['digest'](args.kernel))
        IMAGE(args.output / 'image.tar', 'amd64' if platform.machine() == 'x86_64' else 'arm64', files, ['/state-probe'])
        with tempfile.TemporaryDirectory(prefix='flexvm-software-lifecycle-', dir='/var/lib') as state:
            mask = args.output / 'unusable-device'
            mask.touch(mode=0o600)
            trace = args.output / 'files.strace'
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                       'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                       'sh', str(mask), 'strace', '-f', '-e', 'trace=file', '-o', str(trace), sys.executable, str(Path(__file__).resolve()),
                       '--worker', '--bin', str(args.bin), '--kernel', str(args.kernel), '--output', str(args.output), '--state', state,
                       '--timeout', str(args.timeout)]
            if args.firecracker:
                command += ['--firecracker', str(args.firecracker)]
            HELPERS['run'](command, args.timeout, args.output / 'worker.log')
            if any(f'"{dev}"' in trace.read_text(errors='replace') for dev in ('/dev/kvm', '/dev/vhost-vsock')):
                raise RuntimeError('host virtualization device access; see files.strace')
        report.update(status='passed', owner=json.loads((args.output / 'owner.json').read_text()), kvm_access=False, vhost_vsock_access=False)
    except HELPERS['Interrupted'] as exc:
        report.update(status='interrupted', signal=exc.number, error=str(exc))
    except Exception as exc:
        report.update(status='failed', error=str(exc))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    report['elapsed_s'] = round(time.monotonic() - started, 3)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report_path}")
    return 128 + report['signal'] if report['status'] == 'interrupted' else (0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
