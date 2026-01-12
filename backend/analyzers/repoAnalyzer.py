import os
import shutil
import subprocess
import uuid
from pathlib import Path
from backend.queries import insert_project, insert_file, insert_ast
import re
import json

TEMP_ROOT = Path(__file__).resolve().parent / "tmp"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)

KEEP_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
IGNORE_FOLDERS = {"node_modules", "dist"}
IMPORT_RE = re.compile(
    r"""(?:import\s+(?:.+?\s+from\s+)?|require\()\s*['"](.+?)['"]""",
    re.MULTILINE
)
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

class RepoCloneError(Exception):
    """Custom error type for repo clone failures."""
    pass


def _validate_git_url(url: str):
    """
    Basic validation for URLs that support git clone.
    HTTPS recommended. SSH optional.
    """
    if not isinstance(url, str):
        raise ValueError("Repo URL must be a string")

    if url.startswith("http://") or url.startswith("https://") or url.startswith("git@"):
        return url

    raise ValueError(f"Unsupported repo URL format: {url}")


def _build_temp_path(project_id: str):
    """
    Returns a unique new directory path under TEMP_ROOT.
    """
    path = TEMP_ROOT / project_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def clone_repo(repo_url: str) -> tuple[Path, str]:
    """
    Clones a public repository into a fresh UUID temp dir and returns its path.

    Parameters:
        repo_url (str): URL for cloning (https://..., http://..., or git@...)

    Returns:
        Path: location of the cloned repo
    """
    repo_url = _validate_git_url(repo_url)
    project_id = insert_project(repo_url)
    working_dir = _build_temp_path(project_id)
    repo_path = working_dir / "repo"

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            text=True,
        )

        if result.returncode != 0:
            shutil.rmtree(working_dir, ignore_errors=True)
            raise RepoCloneError(f"Git clone failed: {result.stderr}")

        return (repo_path, project_id)

    except Exception as e:
        shutil.rmtree(working_dir, ignore_errors=True)
        raise RepoCloneError(str(e))


def remove_repo_path(path: Path):
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)

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

def resolve_imports_for_repo(repo_path: str | Path) -> dict:
    """
    Returns:
    {
        file_path: {
            "merged_source": "<string>",
            "dependencies": [file_paths...]
        }
    }
    """
    repo_path = Path(repo_path).resolve()

    compiled_patterns = [
        (category, re.compile(pattern, re.IGNORECASE))
        for category, patterns in CRYPTO_PATTERNS.items()
        for pattern in patterns
    ]

    augmented = {}

    for root, _, files in os.walk(repo_path):
        root_path = Path(root)

        if any(ignore in root_path.parts for ignore in IGNORE_FOLDERS):
            continue

        for filename in files:
            file_path = root_path / filename

            if file_path.suffix.lower() not in KEEP_EXTENSIONS:
                continue

            if not file_matches_crypto(file_path, compiled_patterns):
                continue

            visited: set[Path] = set()
            deps = resolve_local_dependency_closure(
                file_path, compiled_patterns, visited
            )

            header_blocks = []
            for dep in deps:
                try:
                    dep_content = dep.read_text(errors="ignore")
                    header_blocks.append(
                        f"\n/* === DEPENDENCY: {dep} === */\n{dep_content}"
                    )
                except Exception:
                    continue

            original = file_path.read_text(errors="ignore")

            merged_source = (
                "/* === BEGIN IMPORTED DEPENDENCIES === */\n"
                + "\n".join(header_blocks)
                + "\n/* === END IMPORTED DEPENDENCIES === */\n\n"
                + original
            )

            augmented[str(file_path)] = {
                "merged_source": merged_source,
                "dependencies": [str(p) for p in deps],
            }

    return augmented

def resolve_local_dependency_closure(
    entry_file: Path,
    compiled_patterns,
    visited: set[Path]
) -> list[Path]:
    """
    Recursively resolves local imports reachable from entry_file.
    """
    resolved = []

    if entry_file in visited:
        return resolved

    visited.add(entry_file)

    for dep in extract_local_imports(entry_file):
        if dep in visited:
            continue

        resolved.append(dep)

        resolved.extend(
            resolve_local_dependency_closure(dep, compiled_patterns, visited)
        )

    return resolved

def file_matches_crypto(file_path: Path, compiled_patterns) -> bool:
    try:
        content = file_path.read_text(errors="ignore")
    except Exception:
        return False

    return any(regex.search(content) for _, regex in compiled_patterns)

def extract_local_imports(file_path: Path) -> list[Path]:
    """
    Extracts relative import paths from a JS/TS file.
    Returns resolved file paths if they exist.
    """
    try:
        content = file_path.read_text(errors="ignore")
    except Exception:
        return []

    imports = []
    for match in IMPORT_RE.findall(content):
        if match.startswith("."):
            resolved = (file_path.parent / match).resolve()

            for ext in ["", ".ts", ".tsx", ".js", ".jsx"]:
                candidate = resolved.with_suffix(ext)
                if candidate.exists() and candidate.is_file():
                    imports.append(candidate)
                    break

    return imports


def trimmer(repo_path: str | Path, project_id: str) -> dict:
    """
    Reads all .js/.jsx/.ts/.tsx files, matches against crypto regex patterns,
    deletes non-matching files, and makes db record.

    Returns:
        {
            "kept_crypto_files": { file_path: { "categories": [...], "fileId": <uuid> } },
            "removed_non_crypto_files": [...],
            "matches_by_category": { category: [file_paths...] }
        }
    """
    repo_path = Path(repo_path).resolve()

    kept_by_file = {}          # file_path → { categories: [...], fileId: <uuid> }
    removed_files = []         # list of deleted files
    matches_by_category = {}   # category → [file_paths...]

    for category in CRYPTO_PATTERNS.keys():
        matches_by_category[category] = []

    compiled_patterns = [
        (category, re.compile(pattern, flags=re.IGNORECASE))
        for category, patterns in CRYPTO_PATTERNS.items()
        for pattern in patterns
    ]

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

            matched_categories = [
                category for category, regex in compiled_patterns if regex.search(content)
            ]

            if matched_categories:
                file_id = insert_file(project_id, str(file_path))

                kept_by_file[str(file_path)] = {
                    "categories": matched_categories,
                    "fileId": file_id,
                }

                for category in matched_categories:
                    matches_by_category[category].append(str(file_path))

            else:
                try:
                    file_path.unlink()
                    removed_files.append(str(file_path))
                except Exception as e:
                    print(f"Warning: Failed to delete {file_path}: {e}")

    delete_empty_dirs(repo_path, IGNORE_FOLDERS)

    return {
        "kept_crypto_files": kept_by_file,
        "removed_non_crypto_files": removed_files,
        "matches_by_category": matches_by_category,
    }

def attach_asts_to_results(results_json_path: str | Path, kept_crypto_files: dict) -> dict:
    """
    Converts crypto file paths into ASTs and makes db record.

    kept_crypto_files format example:
    {
        "/path/to/file.ts": {
            "categories": ["aes", "rsa"],
            "fileId": "uuid4"
        }
    }

    Returns:
        {
            "files_annotated": <int>,
            "failures": <list>
        }
    """
    results_path = Path(results_json_path).resolve()

    results = json.loads(results_path.read_text())

    file_paths: set[str] = set()
    for category, files in results.items():
        if isinstance(files, list):
            for fp in files:
                file_paths.add(fp)

    script = Path(__file__).resolve().parent / "jsParser.js"

    failures = []
    inserted_count = 0

    for file_path in file_paths:
        if file_path not in kept_crypto_files:
            failures.append({
                "file_path": file_path,
                "error": "No fileId entry found"
            })
            continue

        fileId = kept_crypto_files[file_path]["fileId"]

        try:
            output = subprocess.check_output(
                ["node", str(script), file_path],
                text=True
            )
            ast_json = json.loads(output)

            insert_ast(fileId, json.dumps(ast_json))

            inserted_count += 1

        except Exception as e:
            failures.append({
                "file_path": file_path,
                "error": str(e)
            })

    return {
        "files_annotated": inserted_count,
        "failures": failures,
    }
