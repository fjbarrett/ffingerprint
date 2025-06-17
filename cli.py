import os, json, argparse
from datetime import datetime
from fingerprint.byte_hash import compute_byte_hash
import glob


try:
    # tqdm is optional, used for progress bars
    from tqdm import tqdm
except ImportError:
    tqdm = None


# Traverse files in a directory tree, yielding full paths to regular files
def traverse_directory(root):
    # Yield every *regular* file under input dir (no dirs, no broken links).
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            if os.path.isfile(full_path):  # Skip dangling links / sockets
                yield full_path


# Compute the hash of a file, return None if the file can’t be read
def safe_hash(path, algo):
    try:
        return compute_byte_hash(path, algo)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def directory_hash(root_path, algo):
    files = traverse_directory(root_path)
    if tqdm:
        files = tqdm(files, unit="file", desc="Hashing")

    hashes = {}
    skipped = 0
    for filepath in files:
        hash = safe_hash(filepath, algo)
        if hash:
            rel = os.path.relpath(filepath, start=root_path)
            hashes[rel] = hash
        else:
            skipped += 1

    return hashes, skipped


def write_hashes(hashes, skipped, root_path, args):
    if os.path.isdir(root_path):
        parent_directory = os.path.basename(os.path.normpath(root_path)) or "root"
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")  # Add time for granularity
        os.makedirs("hashes", exist_ok=True)
        outfile = os.path.join("hashes", f"hashes_{parent_directory}_{date_str}.json")
        with open(outfile, "w") as f:
            json.dump(hashes, f, indent=2)

        print(f"Hashes written to {outfile}")
        if skipped:
            print(f"Skipped {skipped} unreadable item(s).")

            # ---------- single file ----------
        else:
            hash = safe_hash(root_path, args.algo)
            if hash:
                print(f"{args.algo}({root_path}) = {hash}")
            else:
                print(f"Unable to read {root_path!r}")


def find_latest_hash_files(directory):
    # Find all hash files for this directory
    parent = os.path.basename(os.path.normpath(directory)) or "root"
    pattern = os.path.join("hashes", f"hashes_{parent}_*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    return files[:2]  # Return the two most recent


def compare_hashes(directory):
    files = find_latest_hash_files(directory)
    if len(files) < 2:
        print("Not enough hash files to compare.")
        return

    with open(files[0]) as f:
        new_hashes = json.load(f)
    with open(files[1]) as f:
        old_hashes = json.load(f)

    added = set(new_hashes) - set(old_hashes)
    removed = set(old_hashes) - set(new_hashes)
    modified = {
        k for k in new_hashes if k in old_hashes and new_hashes[k] != old_hashes[k]
    }

    print(f"Comparing: {os.path.basename(files[1])} -> {os.path.basename(files[0])}")
    if added:
        print("Added files:")
        for f in sorted(added):
            print(f"  + {f}")
    if removed:
        print("Removed files:")
        for f in sorted(removed):
            print(f"  - {f}")
    if modified:
        print("Modified files:")
        for f in sorted(modified):
            print(f"  * {f}")
    if not (added or removed or modified):
        print("No changes detected.")


def main():
    # Build parser
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    byte_parser = sub.add_parser("byte_hash")
    group = byte_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("filepath", nargs="?")
    group.add_argument("--drive", action="store_true")
    byte_parser.add_argument("--algo", choices=["sha256", "md5"], default="sha256")
    byte_parser.add_argument("--compare", action="store_true")  # <-- Add this line
    args = parser.parse_args()

    # Conditional for args
    if args.command == "byte_hash":
        if args.compare:
            compare_hashes(args.filepath)
            return
        root_path = os.path.abspath(os.sep) if args.drive else args.filepath

        hashes, skipped = directory_hash(root_path, args.algo)

        write_hashes(hashes, skipped, root_path, args)


if __name__ == "__main__":
    main()
