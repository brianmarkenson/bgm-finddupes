#!/usr/bin/env python3.9
import os
import hashlib
import zlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import logging
import sys
import argparse

# Setup logging
logging.basicConfig(filename='duplicate_finder.log', level=logging.INFO)

# Commit threshold and initial hash size
COMMIT_THRESHOLD = 100
INITIAL_HASH_SIZE = 1024 * 1024  # 1 MB

# Initialize database
def init_db():
    logging.info("Initializing database.")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, initial_hash TEXT, crc32_hash TEXT, sha256_hash TEXT, inode INTEGER)''')
    conn.commit()
    logging.info("Database initialized.")
    conn.close()

# Hash the first x bytes of a file using CRC32 for faster hashing
def hash_initial_bytes(path, size, debug):
    crc32 = 0
    try:
        with open(path, 'rb') as f:
            chunk = f.read(min(size, INITIAL_HASH_SIZE))
            crc32 = zlib.crc32(chunk)
        initial_hash = f"{crc32 & 0xFFFFFFFF:08x}"
        if debug:
            logging.debug(f"Initial hash for {path}: {initial_hash}")
        return initial_hash
    except Exception as e:
        logging.error(f"Error hashing initial bytes of file {path}: {e}")
        return None

# Hash the entire file using CRC32 for faster initial duplicate detection
def hash_crc32(path, debug):
    crc32 = 0
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)  # Read in 64 KB chunks
                if not chunk:
                    break
                crc32 = zlib.crc32(chunk, crc32)
        crc32_hash = f"{crc32 & 0xFFFFFFFF:08x}"
        if debug:
            logging.debug(f"CRC32 hash for {path}: {crc32_hash}")
        return crc32_hash
    except Exception as e:
        logging.error(f"Error hashing file {path} with CRC32: {e}")
        return None

# Hash the entire file using SHA-256 for robust verification
def hash_sha256(path, debug):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)  # Read in 64 KB chunks
                if not chunk:
                    break
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()
        if debug:
            logging.debug(f"SHA-256 hash for {path}: {sha256_hash}")
        return sha256_hash
    except Exception as e:
        logging.error(f"Error hashing file {path} with SHA-256: {e}")
        return None

# Scan a directory
def scan_directory(directory, verbose, debug):
    logging.info(f"Scanning directory: {directory}")
    file_info = []
    inode_to_path = {}
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            try:
                if os.path.islink(path):
                    target_path = os.readlink(path)
                    if os.path.exists(target_path):
                        if verbose:
                            print(f"softlink: {path} -> {target_path}")
                        logging.info(f"softlink: {path} -> {target_path}")
                        continue
                    else:
                        logging.warning(f"Softlink target does not exist: {path} -> {target_path}")
                        if verbose:
                            print(f"Softlink target does not exist: {path} -> {target_path}")
                stat = os.stat(path)
                inode = stat.st_ino
                if inode in inode_to_path:
                    hard_link_path = inode_to_path[inode]
                    if verbose:
                        print(f"{path} is hardlinked to {hard_link_path}")
                    logging.info(f"{path} is hardlinked to {hard_link_path}")
                    continue  # Skip files that are hard linked
                inode_to_path[inode] = path
                size = stat.st_size
                mtime = stat.st_mtime
                file_info.append((path, size, mtime, inode))
                if debug:
                    logging.debug(f"Found file {path} with size {size}, mtime {mtime}, inode {inode}")
            except Exception as e:
                logging.error(f"Error getting info for file {path}: {e}")
    if verbose:
        print(f"{directory}: {len(file_info)} files.")
    logging.info(f"{directory}: {len(file_info)} files.")
    return file_info

# Process files
def process_files(file_info, verbose, debug):
    logging.info(f"Processing {len(file_info)} files:")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    processed_count = 0
    commit_count = 0
    for path, size, mtime, inode in file_info:
        c.execute("SELECT mtime, initial_hash FROM files WHERE path=?", (path,))
        result = c.fetchone()
        if debug:
            logging.debug(f"{path}: {result}")
        if not result or result[0] != mtime:
            initial_hash = hash_initial_bytes(path, size, debug)
            if initial_hash:
                try:
                    c.execute("REPLACE INTO files (path, size, mtime, initial_hash, inode) VALUES (?, ?, ?, ?, ?)",
                              (path, size, mtime, initial_hash, inode))
                    if debug:
                        logging.debug(f"Inserted/Updated file {path} with initial hash {initial_hash}")
                    commit_count += 1
                    processed_count += 1
                    if commit_count >= COMMIT_THRESHOLD:
                        conn.commit()
                        commit_count = 0
                        logging.info(f"Committed changes after {COMMIT_THRESHOLD} operations")
                    if verbose:
                        print(f"{path}: {processed_count} files.")
                    logging.info(f"{path}: {processed_count} files.")
                except sqlite3.Error as e:
                    logging.error(f"Database error for file {path}: {e}")
                    conn.rollback()
    if commit_count > 0:
        conn.commit()
        logging.info(f"Final commit for remaining {commit_count} operations.")
    if verbose:
        print(f"Final commit for remaining {commit_count} operations.")
    conn.close()
    if verbose:
        print(f"Processed {processed_count} files.")
    logging.info(f"Processed {processed_count} files.")

# Count entries in the table
def count_entries():
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM files")
    count = c.fetchone()[0]
    conn.close()
    logging.info(f"Database contains {count} entries.")
    return count

# Verify database contents
def verify_database(verbose, debug):
    if debug:
        count = count_entries()
        if verbose:
            print(f"Database contains {count} entries.")
        logging.debug(f"Database contains {count} entries.")
    return count

# Find duplicates
def find_duplicates(verbose, debug):
    logging.info("Finding duplicates.")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute("SELECT size, initial_hash, GROUP_CONCAT(path) FROM files GROUP BY size, initial_hash HAVING COUNT(*) > 1")
    potential_duplicates = c.fetchall()

    duplicates = []
    crc32_hash_dict = {}
    for size, initial_hash, paths in potential_duplicates:
        files = paths.split(',')
        if verbose or debug:
            print(f"Possible duplicate found with size {size} and initial hash {initial_hash}: {files}")
            logging.info(f"Possible duplicate found with size {size} and initial hash {initial_hash}: {files}")
        for file in files:
            crc32_hash = hash_crc32(file, debug)
            if crc32_hash in crc32_hash_dict:
                crc32_hash_dict[crc32_hash].append(file)
            else:
                crc32_hash_dict[crc32_hash] = [file]
        for crc32_hash, crc32_files in crc32_hash_dict.items():
            if len(crc32_files) > 1:
                if verbose or debug:
                    print(f"Possible duplicate found with CRC32 hash {crc32_hash}: {crc32_files}")
                    logging.info(f"Possible duplicate found with CRC32 hash {crc32_hash}: {crc32_files}")
                sha256_hash_dict = {}
                for file in crc32_files:
                    sha256_hash = hash_sha256(file, debug)
                    if sha256_hash in sha256_hash_dict:
                        sha256_hash_dict[sha256_hash].append(file)
                    else:
                        sha256_hash_dict[sha256_hash] = [file]
                for sha256_hash_files in sha256_hash_dict.values():
                    if len(sha256_hash_files) > 1:
                        duplicates.append(sha256_hash_files)
                        if verbose or debug:
                            print(f"Duplicate group confirmed with SHA-256 hash {sha256_hash}: {sha256_hash_files}")
                            logging.info(f"Duplicate group confirmed with SHA-256 hash {sha256_hash}: {sha256_hash_files}")

    conn.close()
    if verbose:
        print(f"Found {len(duplicates)} duplicate groups.")
    logging.info(f"Found {len(duplicates)} duplicate groups.")
    return duplicates

# Generate linking script
def generate_link_script(duplicates, verbose, debug):
    logging.info("Generating linking script.")
    with open('link_script.sh', 'w') as f:
        for files in duplicates:
            keep = files[0]
            for file in files[1:]:
                if os.path.samefile(os.path.dirname(keep), os.path.dirname(file)):
                    f.write(f"ln -f {keep} {file}\n")
                else:
                    f.write(f"ln -sf {keep} {file}\n")
    if verbose:
        print(f"Linking script generated with {len(duplicates)} duplicate groups.")
    logging.info(f"Linking script generated with {len(duplicates)} duplicate groups.")

# Main function
def main(directories, verbose, debug):
    if debug:
        logging.debug("Starting main function.")
    init_db()
    count_entries()
    with ThreadPoolExecutor() as executor:
        futures = []
        for directory in directories:
            file_info = scan_directory(directory, verbose, debug)
            futures.append(executor.submit(process_files, file_info, verbose, debug))
        for future in futures:
            future.result()
    if debug:
        verify_database(verbose, debug)
    duplicates = find_duplicates(verbose, debug)
    generate_link_script(duplicates, verbose, debug)
    if debug:
        logging.debug("Completed main function.")

    # Force disk sync and perform VACUUM
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute("PRAGMA wal_checkpoint(FULL)")
    c.execute("PRAGMA synchronous = FULL")
    c.execute("VACUUM")
    conn.close()
    if debug:
        logging.debug("Performed PRAGMA wal_checkpoint, synchronous, and VACUUM.")

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate files and generate linking script.")
    parser.add_argument("directories", nargs='+', help="Directories to scan for duplicate files.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        main(args.directories, args.verbose, args.debug)
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        print(f"Unhandled exception: {e}")
