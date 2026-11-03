#!/usr/bin/env python3
"""Release pin tests: temporary checkouts and fake downloads, no network or VMs."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class Pins(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('scripts', 'firecracker', '.github', 'flexvm', 'guest'):
            (self.root / name).mkdir()
        for name in ('versions.sh', 'fetch.sh', 'pin-artifacts.sh', 'release-assets.sh', 'build-firecracker.sh'):
            shutil.copy2(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        shutil.copytree(ROOT / 'firecracker', self.root / 'firecracker', dirs_exist_ok=True)
        shutil.copytree(ROOT / '.github/workflows', self.root / '.github/workflows')
        for name in ('flexvm', 'guest'):
            (self.root / name / 'Cargo.toml').write_text('version = "0.2.1"\n')
        self.checksums = self.root / 'scripts/checksums.sha256'
        self.checksums.write_text('')
        # x86_64 unless a test says otherwise, whatever this host is.
        self.env = dict(os.environ, ARTIFACTS_TAG='v0.2.1', FC_VERSION='v1.17.0', CI_VERSION='v1.15', KERNEL='vmlinux-6.1.155',
                        ARCH='x86_64')
        self.url = 'https://github.com/numerataz/flexvm/releases/download/v0.2.1'
        self.kernels = {arch: f'https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/{arch}/vmlinux-6.1.155'
                        for arch in ('x86_64', 'aarch64')}
        self.kernel = self.kernels['x86_64']
        self.digest = 'a' * 64
        # Each architecture's assets in a release: x86_64's keep their names.
        self.assets = {'x86_64': ('firecracker', 'vmlinux', 'inputs.txt'),
                       'aarch64': ('firecracker-aarch64', 'vmlinux-aarch64', 'inputs-aarch64.txt')}

    def run_script(self, name, *args):
        return subprocess.run(['bash', str(self.root / 'scripts' / name), *args], env=self.env, text=True, capture_output=True)

    def pinned(self):
        return subprocess.run(['bash', '-c', 'root=$1; source "$root/scripts/versions.sh"; pinned "$2"',
                               'test', str(self.root), self.url], env=self.env, text=True, capture_output=True)

    def test_validator(self):
        for data, status in [('', 2), (f'{self.digest} {self.url}\n', 0),
                             (f'{self.digest.upper()}\t{self.url}\n', 0),
                             (f'# unrelated\n{self.digest} {self.url}/other\n', 2),
                             (f'{self.url}\n', 1), (f'bad {self.url}\n', 1),
                             (f'{self.url} {self.digest}\n', 1), (f'extra {self.digest} {self.url}\n', 1),
                             (f'{self.digest} {self.url} extra\n', 1),
                             (f'{self.digest} {self.url}\n' * 2, 1),
                             (f'{self.digest} {self.url}\n{self.url}\n', 1)]:
            with self.subTest(data=data):
                self.checksums.write_text(data)
                result = self.pinned()
                self.assertEqual(result.returncode, status, result.stderr)
                if status == 0:
                    self.assertEqual(result.stdout.strip().lower(), self.digest)
        self.checksums.unlink()
        self.assertEqual(self.pinned().returncode, 1)

    def test_fetch_fallback(self):
        for arch, (firecracker, vmlinux, _) in self.assets.items():
            with self.subTest(arch=arch):
                self.env['ARCH'] = arch
                self.checksums.write_text('')
                result = self.run_script('fetch.sh', '--urls')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'firecracker-v1.17.0-{arch}.tgz', result.stdout)
                self.assertIn(self.kernels[arch], result.stdout)
                self.assertIn(f'/v1.15/{arch}/ubuntu-24.04.squashfs', result.stdout)
                # Another architecture's pins are not this one's.
                other = next(a for a in self.assets if a != arch)
                self.checksums.write_text(''.join(f'{self.digest} {self.url}/{asset}\n' for asset in self.assets[other][:2]))
                result = self.run_script('fetch.sh', '--urls')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'firecracker-v1.17.0-{arch}.tgz', result.stdout)
                self.checksums.write_text(''.join(f'{self.digest} {self.url}/{asset}\n' for asset in (firecracker, vmlinux)))
                result = self.run_script('fetch.sh', '--urls')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'firecracker {self.url}/{firecracker}\n', result.stdout)
                self.assertIn(f'vmlinux {self.url}/{vmlinux}\n', result.stdout)

    def test_unknown_arch(self):
        for arch in ('arm64', 'x86_64 aarch64', 'x86'):
            for script, args in (('fetch.sh', ['--urls']), ('pin-artifacts.sh', ['--inputs'])):
                with self.subTest(arch=arch, script=script):
                    self.env['ARCH'] = arch
                    result = self.run_script(script, *args)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('ARCH must be one of x86_64 aarch64', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_malformed_release_never_falls_back(self):
        for arch, assets in self.assets.items():
            for asset in assets[:2]:
                for line in (f'bad {self.url}/{asset}\n', f'{self.url}/{asset}\n',
                             f'{self.digest} {self.url}/{asset}\n' * 2):
                    with self.subTest(arch=arch, asset=asset, line=line):
                        self.env['ARCH'] = arch
                        self.checksums.write_text(line)
                        result = self.run_script('fetch.sh', '--urls')
                        self.assertEqual(result.returncode, 1)
                        self.assertIn('Malformed SHA256', result.stderr)
                        self.assertEqual(result.stdout, '')

    def test_inputs_reject_bad_kernel(self):
        self.checksums.write_text(f'{self.digest} {self.kernel}\n' * 2)
        result = self.run_script('pin-artifacts.sh', '--inputs')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Malformed SHA256', result.stderr)

    def test_check_pins(self):
        upstream = ''.join(f'{"b" * 64 if arch == "aarch64" else self.digest} {kernel}\n' for arch, kernel in self.kernels.items())
        self.checksums.write_text(upstream)
        pins = {}
        for arch, (firecracker, vmlinux, inputs) in self.assets.items():
            self.env['ARCH'] = arch
            result = self.run_script('pin-artifacts.sh', '--inputs')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith(f'firecracker v1.17.0 {arch}\n'), result.stdout)
            self.assertIn(f'vmlinux {"b" * 64 if arch == "aarch64" else self.digest} vmlinux-6.1.155\n', result.stdout)
            digest = hashlib.sha256(result.stdout.encode()).hexdigest()
            pins[arch] = f'{self.digest} {self.url}/{firecracker}\n{self.digest} {self.url}/{vmlinux}\n{digest} {self.url}/{inputs}\n'
        everything = upstream + pins['x86_64'] + pins['aarch64']
        # The same answer on either host.
        for arch in self.assets:
            with self.subTest(arch=arch):
                self.env['ARCH'] = arch
                self.checksums.write_text(everything)
                result = self.run_script('pin-artifacts.sh', '--check')
                self.assertEqual(result.returncode, 0, result.stderr)
                # A release pinned for one architecture only is broken.
                self.checksums.write_text(upstream + pins['x86_64'])
                result = self.run_script('pin-artifacts.sh', '--check')
                self.assertEqual(result.returncode, 1)
                self.assertIn('pins only some', result.stderr)
                # Each architecture's inputs are its own.
                swapped = everything.replace(pins['aarch64'].split()[-2], pins['x86_64'].split()[-2])
                self.checksums.write_text(swapped)
                result = self.run_script('pin-artifacts.sh', '--check')
                self.assertEqual(result.returncode, 1)
                self.assertIn('built (aarch64) from other inputs', result.stderr)
                for asset in self.assets['x86_64'] + self.assets['aarch64']:
                    self.checksums.write_text(everything + f'{self.url}/{asset}\n')
                    result = self.run_script('pin-artifacts.sh', '--check')
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('Malformed SHA256', result.stderr)

    def test_atomic_pins(self):
        assets = self.root / 'assets'
        assets.mkdir()
        original = ''
        for arch, (firecracker, vmlinux, _) in self.assets.items():
            (assets / firecracker).write_text(f'not executable {arch}')
            (assets / vmlinux).write_text(f'kernel {arch}')
            original += f'{hashlib.sha256(f"kernel {arch}".encode()).hexdigest()} {self.kernels[arch]}\n'
        original += f'{self.digest} https://unrelated\n'
        self.checksums.write_text(original)
        self.checksums.chmod(0o644)
        for arch, (_, _, inputs_name) in self.assets.items():
            # Run on any host, for each architecture.
            self.env['ARCH'] = arch
            inputs = self.run_script('pin-artifacts.sh', '--inputs')
            self.assertEqual(inputs.returncode, 0, inputs.stderr)
            (assets / inputs_name).write_text(inputs.stdout)
        self.env['ARCH'] = 'x86_64'
        commands = self.root / 'bin'
        commands.mkdir()
        self.env.update(PATH=f'{commands}:{os.environ["PATH"]}', TEST_ASSETS=str(assets))
        mocks = {
            'curl': 'cp "$TEST_ASSETS/${4##*/}" "$3"',
            'gh': 'exit 0',
            'git': 'case " $* " in *" ls-remote "*) printf "%040d\\trefs/tags/v0.2.1\\n" 1;; *" merge-base "*) exit 0;; *) exit 1;; esac',
            'mv': 'echo simulated-rename-failure >&2; exit 1',
        }
        for name, body in mocks.items():
            path = commands / name
            path.write_text('#!/usr/bin/env bash\nset -eu\n' + body + '\n')
            path.chmod(0o755)
        result = self.run_script('pin-artifacts.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('simulated-rename-failure', result.stderr)
        self.assertEqual(self.checksums.read_text(), original)
        self.assertEqual(list(self.checksums.parent.glob('checksums.sha256.*')), [])
        (commands / 'mv').unlink()
        result = self.run_script('pin-artifacts.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.checksums.read_text().startswith(original))
        self.assertEqual(self.checksums.stat().st_mode & 0o777, 0o644)
        for asset in self.assets['x86_64'] + self.assets['aarch64']:
            digest = hashlib.sha256((assets / asset).read_bytes()).hexdigest()
            self.assertIn(f'{digest} {self.url}/{asset}\n', self.checksums.read_text())
        # A release whose aarch64 kernel is not the pinned upstream one is never pinned.
        (assets / 'vmlinux-aarch64').write_text('another kernel')
        self.checksums.write_text(original)
        result = self.run_script('pin-artifacts.sh')
        self.assertEqual(result.returncode, 1)
        self.assertIn('vmlinux-aarch64 is not the pinned', result.stderr)
        self.assertEqual(self.checksums.read_text(), original)


if __name__ == '__main__':
    unittest.main()
