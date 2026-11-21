"""Exercise the documented Compose profile with a newly generated EML."""

import json
import os
from pathlib import Path
import socket
import subprocess
from zipfile import ZipFile


ISOLATION_PROBE = """
import errno
import os
from pathlib import Path
import socket
import sys

assert (os.getuid(), os.getgid()) == (1000, 1000)
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
assert status['NoNewPrivs'].strip() == '1'
for key in ('CapEff', 'CapPrm', 'CapBnd'):
    assert int(status[key], 16) == 0, key
assert {name for _, name in socket.if_nameindex()} == {'lo'}

try:
    socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=2).close()
except ConnectionRefusedError:
    pass
else:
    raise AssertionError('Container reached a TCP listener on the host')

for directory in ('/input', '/opt/paw'):
    try:
        Path(directory, 'compose-write-probe').touch(exist_ok=False)
    except OSError as exc:
        assert exc.errno == errno.EROFS, (directory, exc)
    else:
        raise AssertionError(f'{directory} is writable')

assert any(line.split()[1:3] == ['/tmp', 'tmpfs']
           for line in Path('/proc/mounts').read_text().splitlines())
Path('/tmp/compose-write-probe').write_text('tmpfs is writable')
print('Compose runtime: non-root, no capabilities, no-new-privileges, isolated network and read-only mounts')
"""


def main():
    compose = ["docker", "compose", "-f", "compose.offline.yaml", "run", "--rm", "-T"]
    input_file = Path(os.environ["PAW_INPUT_DIR"], "sample.eml")
    output = Path(os.environ["PAW_OUTPUT_DIR"])

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        _, port = listener.getsockname()
        original = (
            "From: Sender <sender@example.invalid>\r\n"
            "To: Recipient <recipient@example.invalid>\r\n"
            "Subject: Offline Compose integration fixture\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            f"Local test endpoint http://127.0.0.1:{port}/fixture\r\n"
        ).encode("ascii")
        input_file.write_bytes(original)
        subprocess.run(
            [*compose, "--entrypoint", "/opt/paw/bin/python", "paw", "-c", ISOLATION_PROBE, str(port)],
            check=True,
        )
        subprocess.run([*compose, "paw", "full", "/input/sample.eml", "--no-egress"], check=True)
        listener.setblocking(False)
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            connection.close()
            raise AssertionError("The runtime contacted the host fixture")

    case, = (path for path in (output / "cases").glob("case-*") if path.is_dir())
    stored_input = case / "input.eml"
    assert input_file.read_bytes() == stored_input.read_bytes() == original
    assert json.loads((case / "execution.json").read_text())["no_egress"] is True

    container_case = f"/data/cases/{case.name}"
    subprocess.run([*compose, "paw", "verify", "--case", container_case], check=True)
    subprocess.run([*compose, "paw", "export", "--case", container_case, "--format", "zip"], check=True)
    with ZipFile(case.with_suffix(".zip")) as archive:
        assert archive.testzip() is None
        assert archive.read(f"{case.name}/input.eml") == original
    print("Compose case: original preserved, offline policy recorded, seal and ZIP verified")


if __name__ == "__main__":
    main()
