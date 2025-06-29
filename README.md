# Ffingerprint

## File hashing tool

Usage

`cli.py <directory/file>`

The above command traverses a directory or file and creates a .json file of a key/value object in the following format:

`filename => hash_value_of_file`

The hash of a half-full 512 GB drive yielded a ~300MB .json file so watch out for that.

Use `--drive` to hash the entire system drive. There is also a `--compare` flag to compare changes in the hashes. A second (or more) hash needs to be created before using the `--compare` flag.
