import hashlib


def compute_byte_hash(filepath: str, algo: str = "sha256") -> str:
    # Pick a hashlib constructor
    if algo == "sha256":
        hasher = hashlib.sha256()
    elif algo == "md5":
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

    # Open file in binary mode
    with open(filepath, "rb") as f:
        # Read loop
        while True:
            chunk = f.read(4096)  # why 4096?
            if not chunk:
                break
            # Update the hash
            hasher.update(chunk)

    # Return the hex digest
    return hasher.hexdigest()
