import os
import pwd
import grp
import stat
import json
import subprocess
from pathlib import Path
from datetime import datetime

SSH_DIR = Path.home() / ".ssh"
TARGET_FILES = ["known_hosts", "known_hosts.old"]


def get_file_metadata(path: Path):
    st = path.stat()

    return {
        "path": str(path),
        "owner": pwd.getpwuid(st.st_uid).pw_name,
        "uid": st.st_uid,
        "group": grp.getgrgid(st.st_gid).gr_name,
        "gid": st.st_gid,
        "permissions_octal": oct(st.st_mode & 0o777),
        "permissions_string": stat.filemode(st.st_mode),
        "last_accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
        "last_modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "metadata_changed": datetime.fromtimestamp(st.st_ctime).isoformat(),
    }


def ssh_keygen_info(key_line: str):
    """
    Uses ssh-keygen -l to extract algorithm, key size, fingerprint
    """
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-l", "-f", "/dev/stdin"],
            input=key_line,
            text=True,
            capture_output=True,
            check=True
        )
        # Example output:
        # 256 SHA256:abc123... hostname (ED25519)
        parts = proc.stdout.strip().split()
        return {
            "key_size": parts[0],
            "fingerprint": parts[1],
            "algorithm": parts[-1].strip("()"),
        }
    except subprocess.CalledProcessError as e:
        return {
            "error": "ssh-keygen failed",
            "details": e.stderr.strip()
        }


def parse_known_hosts(path: Path):
    entries = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            hosts, key_type, key_data = parts[:3]

            key_line = f"{key_type} {key_data}"

            key_info = ssh_keygen_info(key_line)

            entries.append({
                "line_number": lineno,
                "hosts": hosts.split(","),
                "key_type": key_type,
                "raw_key": key_data,
                "key_info": key_info,
            })

    return entries


def collect_inventory():
    inventory = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "ssh_directory": str(SSH_DIR),
        "files": []
    }

    for filename in TARGET_FILES:
        path = SSH_DIR / filename
        if not path.exists():
            continue

        file_block = {
            "file_metadata": get_file_metadata(path),
            "entries": parse_known_hosts(path)
        }

        inventory["files"].append(file_block)

    return inventory


def main():
    inventory = collect_inventory()

    output_path = Path.cwd() / "ssh_known_hosts_inventory.json"
    with output_path.open("w") as f:
        json.dump(inventory, f, indent=2)

    print(f"[+] Inventory written to {output_path}")


if __name__ == "__main__":
    main()
