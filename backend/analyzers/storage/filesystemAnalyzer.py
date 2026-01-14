import os
import stat
import json
import time
from pathlib import Path
from typing import Dict, List, Set
import re

CRYPTO_EXTENSIONS = {
    '.pem', '.cer', '.crt', '.der', '.p7b', '.p7c', '.p7s', '.p12', '.pfx',
    '.key', '.pub', '.csr', '.jks', '.keystore', '.truststore', '.asc', '.gpg',
    '.pgp', '.kdb', '.kdbx', '.ovpn', '.ppk', '.ssh'
}

CRYPTO_DIRECTORIES = {
    '.ssh', '.gnupg', '.gpg', 'ssl', 'tls', 'certs', 'certificates', 'keys',
    'private', 'public', 'ca-certificates', 'pki', 'x509'
}

PEM_HEADERS = {
    'BEGIN CERTIFICATE',
    'BEGIN PRIVATE KEY',
    'BEGIN PUBLIC KEY',
    'BEGIN RSA PRIVATE KEY',
    'BEGIN RSA PUBLIC KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN EC PUBLIC KEY',
    'BEGIN DSA PRIVATE KEY',
    'BEGIN DSA PUBLIC KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'BEGIN OPENSSH PUBLIC KEY',
    'BEGIN PGP PRIVATE KEY',
    'BEGIN PGP PUBLIC KEY',
    'BEGIN PGP MESSAGE',
    'BEGIN PGP SIGNATURE',
    'BEGIN CERTIFICATE REQUEST',
    'BEGIN X509 CERTIFICATE',
    'BEGIN ENCRYPTED PRIVATE KEY',
    'BEGIN TRUSTED CERTIFICATE'
}

def safe_stat(path: Path):
    try:
        return path.lstat()
    except Exception:
        return None


def detect_crypto_content(file_path: Path) -> Dict:
    """Detect cryptographic content in a file."""
    crypto_info = {
        "is_crypto_file": False,
        "crypto_type": None,
        "pem_headers": [],
        "file_size_kb": 0
    }

    try:
        # Check if file is readable and not too large (limit to 1MB for content scanning)
        stat_info = safe_stat(file_path)
        if not stat_info or stat_info.st_size > 1024 * 1024:
            return crypto_info

        crypto_info["file_size_kb"] = round(stat_info.st_size / 1024, 2)

        # Read file content to detect PEM headers
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)  # Read first 8KB


            found_headers = []
            for header in PEM_HEADERS:
                if f'-----{header}-----' in content:
                    found_headers.append(header)
                    crypto_info["is_crypto_file"] = True

            crypto_info["pem_headers"] = found_headers

            # Determine crypto type based on headers
            if found_headers:
                if any('PRIVATE KEY' in h for h in found_headers):
                    crypto_info["crypto_type"] = "private_key"
                elif any('PUBLIC KEY' in h for h in found_headers):
                    crypto_info["crypto_type"] = "public_key"
                elif any('CERTIFICATE' in h for h in found_headers):
                    crypto_info["crypto_type"] = "certificate"
                elif any('PGP' in h for h in found_headers):
                    crypto_info["crypto_type"] = "pgp"
                else:
                    crypto_info["crypto_type"] = "crypto_other"

        except (IOError, OSError, UnicodeDecodeError):
            print("Error reading file for crypto content detection.")
            pass

    except Exception:
        print("General error during crypto content detection.")
        pass

    return crypto_info


def is_crypto_directory(path: Path) -> bool:
    """Check if directory name suggests crypto content."""
    dir_name = path.name.lower()
    return dir_name in CRYPTO_DIRECTORIES


def has_crypto_extension(path: Path) -> bool:
    """Check if file has a crypto-related extension."""
    return path.suffix.lower() in CRYPTO_EXTENSIONS


def file_metadata(path: Path) -> Dict:
    st = safe_stat(path)
    if not st:
        return {}

    is_symlink = path.is_symlink()
    is_directory = stat.S_ISDIR(st.st_mode)

    metadata = {
        "path": str(path.resolve(strict=False)),
        "name": path.name,
        "extension": path.suffix.lower(),
        "type": (
            "symlink" if is_symlink
            else "directory" if is_directory
            else "file"
        ),
        "size_bytes": st.st_size,
        "timestamps": {
            "created": st.st_ctime,
            "modified": st.st_mtime,
            "accessed": st.st_atime,
        },
        "permissions": {
            "mode": oct(st.st_mode & 0o777),
            "is_executable": bool(st.st_mode & stat.S_IXUSR),
        },
        "ownership": {
            "uid": getattr(st, "st_uid", None),
            "gid": getattr(st, "st_gid", None),
        },
        "filesystem": {
            "inode": getattr(st, "st_ino", None),
            "device": getattr(st, "st_dev", None),
        },
        "symlink_target": (
            os.readlink(path) if is_symlink else None
        ),
    }

    if is_directory:
        metadata["crypto_analysis"] = {
            "is_crypto_directory": is_crypto_directory(path),
            "directory_type": "crypto" if is_crypto_directory(path) else "normal"
        }
    else:
        has_crypto_ext = has_crypto_extension(path)
        crypto_content = detect_crypto_content(path) if has_crypto_ext or path.suffix.lower() in ['.txt', '.conf', '.config', ''] else {
            "is_crypto_file": False,
            "crypto_type": None,
            "pem_headers": [],
            "file_size_kb": round(st.st_size / 1024, 2)
        }

        metadata["crypto_analysis"] = {
            "has_crypto_extension": has_crypto_ext,
            "crypto_content": crypto_content,
            "is_potential_crypto": has_crypto_ext or crypto_content["is_crypto_file"]
        }

    return metadata


def scan_filesystem(
    root: str,
    follow_symlinks: bool = False
) -> List[Dict]:
    results = []
    root_path = Path(root).expanduser().resolve()

    for dirpath, dirnames, filenames in os.walk(
        root_path,
        followlinks=follow_symlinks
    ):
        dirpath = Path(dirpath)

        dir_meta = file_metadata(dirpath)
        if dir_meta:
            results.append(dir_meta)

        for name in filenames:
            file_path = dirpath / name
            print(f"Scanning file: {file_path}")
            meta = file_metadata(file_path)
            if meta:
                results.append(meta)

    return results


def main():
    root = "~/"
    output_file = "results/filesystem_inventory.json"
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    print("Starting filesystem scan with crypto detection...")
    start_time = time.time()

    entries = scan_filesystem(root)

    crypto_summary = {
        "total_crypto_files": 0,
        "total_crypto_directories": 0,
        "crypto_types": {},
        "crypto_extensions": {},
        "crypto_directories_found": []
    }

    for entry in entries:
        crypto_analysis = entry.get("crypto_analysis", {})

        if entry["type"] == "directory":
            if crypto_analysis.get("is_crypto_directory"):
                crypto_summary["total_crypto_directories"] += 1
                crypto_summary["crypto_directories_found"].append(entry["path"])
        else:
            if crypto_analysis.get("is_potential_crypto"):
                crypto_summary["total_crypto_files"] += 1

                crypto_content = crypto_analysis.get("crypto_content", {})
                crypto_type = crypto_content.get("crypto_type")
                if crypto_type:
                    crypto_summary["crypto_types"][crypto_type] = crypto_summary["crypto_types"].get(crypto_type, 0) + 1

                ext = entry.get("extension", "")
                if ext:
                    crypto_summary["crypto_extensions"][ext] = crypto_summary["crypto_extensions"].get(ext, 0) + 1

    inventory = {
        "scan_root": root,
        "scan_time": time.time(),
        "scan_duration_seconds": round(time.time() - start_time, 2),
        "crypto_summary": crypto_summary,
        "entries": entries
    }

    with open(output_file, "w") as f:
        json.dump(inventory, f, indent=2)

    print(f"Scan complete: {len(inventory['entries'])} entries")
    print(f"Crypto files found: {crypto_summary['total_crypto_files']}")
    print(f"Crypto directories found: {crypto_summary['total_crypto_directories']}")
    print(f"Scan duration: {inventory['scan_duration_seconds']} seconds")


if __name__ == "__main__":
    main()
