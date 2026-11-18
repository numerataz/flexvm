"""Exercise public signed transfer between separate FlexVM host identities."""
import base64
import json
from pathlib import Path
import runpy
import subprocess
import tempfile

HELPERS = runpy.run_path(str(Path(__file__).with_name("software-boot.py")))


def move_public(binary, state, name, qemu, output, target_log, *, target_prefix=()):
    def key_pair(secret):
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", secret], check=True, timeout=10)
        secret.chmod(0o600)
        public = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-in", secret, "-pubout", "-outform", "DER"], timeout=10)
        return base64.b64encode(public[-32:]).decode()

    def transfer(command, *args, stdin=None):
        return subprocess.check_output([*command, *args], stdin=stdin, timeout=90)

    def verify_source_fenced():
        blocked = subprocess.run([binary, "--state", state, "start", "-a", name], capture_output=True, timeout=15)
        if blocked.returncode == 0 or b"source cannot restart" not in blocked.stderr:
            raise RuntimeError(f"checkpoint transfer did not fence source restart: {blocked.stderr.decode(errors='replace')}")

    with tempfile.TemporaryDirectory(prefix="flexvm-parent-move-", dir=Path(state).parent) as directory:
        work = Path(directory)
        source = [binary, "--state", state, "software-transfer"]
        destination = [binary, "--state", work / "destination", "--run", work / "run", "software-transfer"]
        source_secret, target_secret = work / "source.der", work / "target.der"
        source_key, target_key = key_pair(source_secret), key_pair(target_secret)
        destination_id = json.loads(transfer(destination, "id"))["host_id"]
        offer = work / "offer.json"
        offer.write_bytes(transfer(source, "offer", name, destination_id))
        transfer(destination, "prepare", offer, "--source-key", source_key)
        receipt = work / "receipt.json"
        receipt.write_bytes(transfer(source, "retire", name, offer, "--signing-key", source_secret, "--destination-key", target_key))

        verify_source_fenced()
        with (output / "transfer-send.log").open("wb") as errors:
            sender = subprocess.Popen([*source, "send", name, offer], stdout=subprocess.PIPE, stderr=errors)
            try:
                received = json.loads(transfer(destination, "receive", offer, stdin=sender.stdout))
                if sender.wait(timeout=15) or received["status"] != "received":
                    raise RuntimeError("checkpoint transfer failed")
            finally:
                sender.stdout.close()
                if sender.poll() is None:
                    sender.kill()
                    sender.wait(timeout=10)

        transfer(destination, "commit", receipt)
        ack = work / "commit-ack.json"
        ack.write_bytes(transfer(destination, "acknowledge-commit", offer, "--signing-key", target_secret))
        transfer(source, "finalize", ack, "--signing-key", source_secret)
        verify_source_fenced()
        HELPERS["run"]([*target_prefix, *destination, "activate", offer, "moved-" + name, "--qemu", qemu], 150, target_log)
