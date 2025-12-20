from frontend.repoParser import clone_repo, remove_repo_path
from frontend.usageScanner import scan_and_filter_repo, trimmer

url="https://github.com/editorconfig/editorconfig-core-js.git"
if __name__ == "__main__":
    repo = None
    try:
        repo = clone_repo(url)
        print("Repo cloned at:", repo)
        result = scan_and_filter_repo(repo)
        print("Kept files after initial scan:", len(result["kept"]))
        print("Deleted files after initial scan:", len(result["deleted"]))

        print(repo)
        trimRes = trimmer(repo)
        print("Kept files after trimming:", len(trimRes["kept_crypto_files"]))
        print("Deleted files after trimming:", len(trimRes["removed_non_crypto_files"]))

    except Exception as err:
        print("Error in main:", err)

    finally:
        if not repo:
            exit()
        remove_repo_path(repo.parent)