import os
import re
from pathlib import Path

KEEP_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
IGNORE_FOLDERS = {"node_modules", "dist"}

CRYPTO_PATTERNS = {
    "aes": [
        r"\baes\b",
        r"aes-?\d+",
        r"AESKey",
        r"AES\.encrypt",
        r"AES\.decrypt",
    ],
    "rsa": [
        r"\brsa\b",
        r"rsa-?\d+",
        r"RSAPublicKey",
        r"RSAPrivateKey",
        r"RSAKey",
    ],
    "signing": [
        r"sign(ing)?",
        r"verify(ing)?",
        r"signature",
        r"digital[_ ]signature",
    ],
    "cert": [
        r"certificate",
        r"x\.509",
        r"public[_ ]?key",
        r"private[_ ]?key",
        r"pem",
        r"der",
    ],
    "hash": [
        r"sha-?\d+",
        r"hash",
        r"pbkdf2",
        r"scrypt",
        r"bcrypt",
        r"HMAC",
    ],
    "keys": [
        r"api[_ ]?key",
        r"secret",
        r"token",
    ]
}


def scan_and_filter_repo(repo_path: str | Path) -> dict:
    """
    Returns { kept: [...], deleted: [...] }
    """
    repo_path = Path(repo_path).resolve()

    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"Invalid repo path: {repo_path}")

    kept_files = []
    deleted_files = []

    for root, _, files in os.walk(repo_path):
        root_path = Path(root)

        if any(ignore in root_path.parts for ignore in IGNORE_FOLDERS):
            continue

        for filename in files:
            file_path = root_path / filename
            extension = file_path.suffix.lower()

            if extension in KEEP_EXTENSIONS:
                kept_files.append(str(file_path))
            else:
                try:
                    file_path.unlink()
                    deleted_files.append(str(file_path))
                except Exception as e:
                    print(f"Warning: Failed to delete {file_path}: {e}")

    delete_empty_dirs(repo_path, IGNORE_FOLDERS)

    return {
        "kept": kept_files,
        "deleted": deleted_files
    }


def delete_empty_dirs(path: Path, ignore_folders: set[str]):
    """
    Recursively removes empty folders, except ignored ones.
    """
    for root, dirs, _ in os.walk(path, topdown=False):
        root_path = Path(root)

        if any(ignore in root_path.parts for ignore in ignore_folders):
            continue

        for d in dirs:
            dir_path = root_path / d

            if d in ignore_folders:
                continue

            try:
                if not any(dir_path.iterdir()):
                    dir_path.rmdir()
            except Exception as e:
                print(f"Warning: Failed to remove empty directory {dir_path}: {e}")


def trimmer(repo_path: str | Path) -> dict:
    """
    Reads all .js/.jsx/.ts/.tsx files in repo, runs them against crypto regex patterns,
    and deletes any file that does *not* match at least one pattern.

    Returns:
        {
            "kept_crypto_files": [...],
            "removed_non_crypto_files": [...],
        }
    """
    repo_path = Path(repo_path).resolve()

    kept = []
    deleted = []

    compiled_patterns = []
    for category, patterns in CRYPTO_PATTERNS.items():
        for pattern in patterns:
            compiled_patterns.append((category, re.compile(pattern, flags=re.IGNORECASE)))

    for root, _, files in os.walk(repo_path):
        root_path = Path(root)

        if any(ignore in root_path.parts for ignore in IGNORE_FOLDERS):
            continue

        for filename in files:
            file_path = root_path / filename

            if file_path.suffix.lower() not in KEEP_EXTENSIONS:
                continue

            try:
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue

            has_crypto_match = False

            for category, regex in compiled_patterns:
                if regex.search(content):
                    has_crypto_match = True
                    break

            if has_crypto_match:
                kept.append(str(file_path))
            else:
                try:
                    file_path.unlink()
                    deleted.append(str(file_path))
                except Exception as e:
                    print(f"Warning: Failed to delete {file_path}: {e}")

    delete_empty_dirs(repo_path, IGNORE_FOLDERS)

    return {
        "kept_crypto_files": kept,
        "removed_non_crypto_files": deleted,
    }
