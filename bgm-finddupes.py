#!/usr/bin/env python3.9
import os
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import logging
import sys
import argparse

# Setup logging
logging.basicConfig(filename='duplicate_finder.log', level=logging.INFO)

# Commit threshold
COMMIT_THRESHOLD = 100

# Initialize database
def init_db():
    logging.info("Initializing database.")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, hash TEXT)''')
    conn.commit()
    logging.info("Database initialized.")
    conn.close()

# Hash a file
def hash_file(path, debug):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        if debug:
            logging.debug(f"Hash for {path}: {file_hash}")
        return file_hash
    except Exception as e:
        logging.error(f"Error hashing file {path}: {e}")
        return None

# Scan a directory
def scan_directory(directory, verbose, debug):
    logging.info(f"Scanning directory: {directory}")
    file_info = []
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            try:
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
                file_info.append((path, size, mtime))
                if debug:
                    logging.debug(f"Found file {path} with size {size} and mtime {mtime}")
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
    for path, size, mtime in file_info:
        c.execute("SELECT mtime FROM files WHERE path=?", (path,))
        result = c.fetchone()
        if debug:
            logging.debug(f"{path}: {result}")
        if not result or result[0] != mtime:
            file_hash = hash_file(path, debug)
            if file_hash:
                try:
                    c.execute("REPLACE INTO files (path, size, mtime, hash) VALUES (?, ?, ?, ?)", (path, size, mtime, file_hash))
                    if debug:
                        logging.debug(f"Inserted/Updated file {path} with hash {file_hash}")
                    commit_count += 1
                    processed_count += 1
                    if commit_count >= COMMIT_THRESHOLD:
                        conn.commit()
                        commit_count = 0
                        logging.info(f"Committed changes after {COMMIT_THRESHOLD} operations")
                    if verbose:
                        print(f"{path}: {processed_count} files.")
                    logging.info(f"{path}: {processed_count} files.")
                    # Verify the insertion if debugging
                    if debug:
                        count = count_entries()
                        if count == 0:
                            logging.error(f"Failed to insert file {path}")
                        verify_database(verbose, debug)
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
    c.execute("SELECT hash, GROUP_CONCAT(path) FROM files GROUP BY hash HAVING COUNT(*) > 1")
    duplicates = c.fetchall()
    conn.close()
    if verbose:
        print(f"Found {len(duplicates)} duplicate groups.")
    logging.info(f"Found {len(duplicates)} duplicate groups.")
    return duplicates

# Generate linking script
def generate_link_script(duplicates, verbose, debug):
    logging.info("Generating linking script.")
    with open('link_script.sh', 'w') as f:
        for file_hash, paths in duplicates:
            files = paths.split(',')
            if len(files) > 1:
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
