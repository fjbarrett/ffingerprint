import hashlib


def compute_byte_hash(filepath: str, algo: str = "sha256") -> str:
    # Select a hashing algorithm constructor
    if algo == "sha256":
        hash = hashlib.sha256()
    elif algo == "md5":
        hash = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

    # Open file in binary mode
    with open(filepath, "rb") as f:
        # Read loop
        while True:
            # Create chunk from file
            chunk = f.read(4096)
            if not chunk:
                break
            # Update the hash
            hash.update(chunk)

    # Return the hex digest
    return hash.hexdigest()
