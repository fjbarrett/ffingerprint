import os, json, argparse, time, sys, glob, fnmatch
from datetime import datetime
from fingerprint.byte_hash import compute_byte_hash

try:
    # tqdm is optional, used for progress bars
    from tqdm import tqdm
except ImportError:
    tqdm = None


# Traverse files in a directory tree, yielding full paths of regular files
def traverse_directory(root, ignore_patterns=None):
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            if os.path.isfile(full_path):
                if ignore_patterns and should_ignore(full_path, ignore_patterns, root):
                    continue
                yield full_path


# Safely compute the hash of a file, return None if the file can’t be read
def safe_hash(path, algo):
    try:
        return compute_byte_hash(path, algo)
    except (FileNotFoundError, PermissionError, OSError):
        return None


# Compute hashes for all files in a directory tree, return a dict of relative paths to hashes
def directory_hash(root_path, algo):
    ignore_patterns = load_ignore_patterns("ignores/mac-user.ignore")
    files = traverse_directory(root_path, ignore_patterns)
    if tqdm:
        files = tqdm(files, unit="file", desc="Hashing")

    hashes = {}
    skipped = 0
    unreadable_files = []  # Track unreadable files
    for filepath in files:
        hash = safe_hash(filepath, algo)
        if hash:
            rel = os.path.relpath(filepath, start=root_path)
            hashes[rel] = hash
        else:
            skipped += 1
            unreadable_files.append(filepath)  # Add to list

    return hashes, skipped, unreadable_files


def write_hashes(hashes, skipped, root_path, args):
    if os.path.isdir(root_path):
        parent_directory = os.path.basename(os.path.normpath(root_path)) or "root"
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("hashes", exist_ok=True)
        outfile = os.path.join("hashes", f"hashes_{parent_directory}_{date_str}.json")
        with open(outfile, "w") as f:
            json.dump(hashes, f, indent=2)

        print(f"Hashes written to {outfile}")
        if skipped:
            print(f"Skipped {skipped} unreadable item(s).")
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
    # Return the two most recent files as basis for comparison
    return files[:2]


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


def load_ignore_patterns(ignore_file="ignores/mac-user.ignore"):
    patterns = []
    if os.path.exists(ignore_file):
        with open(ignore_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


def should_ignore(path, patterns, root):
    rel_path = os.path.relpath(path, root)
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(
            os.path.basename(rel_path), pattern
        ):
            return True
    return False


def main():
    # Build parser
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    byte_parser = sub.add_parser("byte_hash")
    group = byte_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("filepath", nargs="?")
    group.add_argument("--drive", action="store_true")
    byte_parser.add_argument("--algo", choices=["sha256", "md5"], default="sha256")
    byte_parser.add_argument("--compare", action="store_true")
    args = parser.parse_args()

    # Conditional for args
    if args.command == "byte_hash":
        if args.compare:
            compare_hashes(args.filepath)
            return
        root_path = os.path.abspath(os.sep) if args.drive else args.filepath

        try:
            start_time = time.time()
            hashes, skipped, unreadable_files = directory_hash(root_path, args.algo)
            elapsed = time.time() - start_time
            write_hashes(hashes, skipped, root_path, args)
            if unreadable_files:
                print("Unreadable files:")
                for f in unreadable_files:
                    print(f"  {f}")
            print(f"Hashing completed in {elapsed:.2f} seconds.")
        except PermissionError:
            print(
                "Permission denied. Try running this command with elevated privileges (e.g., using 'sudo')."
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
