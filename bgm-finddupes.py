#!/usr/bin/env python3.9
import os
import hashlib
import zlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import logging
from logging.handlers import RotatingFileHandler
import sys
import argparse
import signal
from PIL import Image
import imagehash
import magic
import cv2
import numpy as np
from scenedetect import VideoManager, SceneManager
from scenedetect.detectors import ContentDetector


# Create a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# Create handlers
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
rotating_file_handler = RotatingFileHandler('duplicate_finder.log', maxBytes=5000000, backupCount=5)
rotating_file_handler.setLevel(logging.DEBUG)
# Create formatters and add them to handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)
rotating_file_handler.setFormatter(formatter)
# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(rotating_file_handler)

rotating_file_handler.doRollover()

logging.basicConfig(
    level=logging.INFO
    handlers=[console_handler, rotating_file_handler],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Commit threshold and initial hash size
COMMIT_THRESHOLD = 100
INITIAL_HASH_SIZE = 1024 * 1024  # 1 MB
MIN_FILE_SIZE = 1024  # Default minimum file size: 1 KB
FUZZY_MATCH_THRESHOLD = 5  # Maximum allowed hamming distance for fuzzy match

# Global connection and cursor
main_conn = None
main_cursor = None

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    global main_conn
    if main_conn:
        logger.info("Interrupted! Committing pending changes and closing database.")
        main_conn.commit()
        main_conn.close()
    logger.info("Exiting gracefully.")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

# Initialize database
def init_db():
    global main_conn, main_cursor
    logger.info("Initializing database.")
    main_conn = sqlite3.connect('file_hashes.db')
    main_cursor = main_conn.cursor()
    main_cursor.execute('''CREATE TABLE IF NOT EXISTS files
                 (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, initial_hash TEXT, crc32_hash TEXT, sha256_hash TEXT, inode INTEGER, perceptual_hash TEXT, video_hash TEXT, processed BOOLEAN)''')
    main_cursor.execute('''CREATE TABLE IF NOT EXISTS duplicates
                 (group_id INTEGER PRIMARY KEY AUTOINCREMENT, sha256_hash TEXT, paths TEXT)''')
    main_conn.commit()
    logger.info("Database initialized.")

# Hash the first x bytes of a file using CRC32 for faster hashing
def hash_initial_bytes(path, size, debug):
    crc32 = 0
    try:
        with open(path, 'rb') as f:
            chunk = f.read(min(size, INITIAL_HASH_SIZE))
            crc32 = zlib.crc32(chunk)
        initial_hash = f"{crc32 & 0xFFFFFFFF:08x}"
        if debug:
            print(f"Initial hash for {path}: {initial_hash}")
            logger.debug(f"Initial hash for {path}: {initial_hash}")
        return initial_hash
    except Exception as e:
        logger.error(f"Error hashing initial bytes of file {path}: {e}")
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
            print(f"CRC32 hash for {path}: {crc32_hash}")
            logger.debug(f"CRC32 hash for {path}: {crc32_hash}")
        return crc32_hash
    except Exception as e:
        logger.error(f"Error hashing file {path} with CRC32: {e}")
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
            print(f"SHA-256 hash for {path}: {sha256_hash}")
            logger.debug(f"SHA-256 hash for {path}: {sha256_hash}")
        return sha256_hash
    except Exception as e:
        logger.error(f"Error hashing file {path} with SHA-256: {e}")
        return None

# Generate a perceptual hash for image files
def hash_perceptual(path, debug):
    try:
        image = Image.open(path)
        perceptual_hash = str(imagehash.phash(image))
        if debug:
            logger.debug(f"Perceptual hash for {path}: {perceptual_hash}")
        return perceptual_hash
    except Exception as e:
        logger.error(f"Error generating perceptual hash for {path}: {e}")
        return None

# Generate a perceptual hash for video files
def hash_video(path, debug):
    try:
        # Initialize VideoManager and SceneManager.
        video_manager = VideoManager([path])
        scene_manager = SceneManager()
        scene_manager.add_detector(ContentDetector(threshold=30.0))

        # Base timestamp at which each scene starts, and store a perceptual hash for the first frame.
        video_manager.set_downscale_factor()
        video_manager.start()
        scene_manager.detect_scenes(frame_source=video_manager)
        scene_list = scene_manager.get_scene_list()

        video_manager.release()

        cap = cv2.VideoCapture(path)
        video_hashes = []
        for scene in scene_list:
            start, _ = scene
            cap.set(cv2.CAP_PROP_POS_FRAMES, start.get_frames())
            ret, frame = cap.read()
            if ret:
                img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                video_hashes.append(str(imagehash.phash(img)))
        cap.release()

        video_hash = ''.join(video_hashes)
        if debug:
            logger.debug(f"Video hash for {path}: {video_hash}")
        return video_hash
    except Exception as e:
        logger.error(f"Error generating video hash for {path}: {e}")
        return None

# Determine the file type
def get_file_type(path):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(path)
    return file_type

# Scan a directory
def scan_directory(directory, verbose, debug):
    logger.info(f"Scanning directory: {directory}")
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
                            print(f"SOFTLINK: {path} -> {target_path}")
                        logger.info(f"SOFTLINK: {path} -> {target_path}")
                        continue
                    else:
                        logger.info(f"Softlink target does not exist: {path} -> {target_path}")
                        if verbose:
                            print(f"Softlink target does not exist: {path} -> {target_path}")
                stat = os.stat(path)
                inode = stat.st_ino
                inode_to_path[inode] = path
                size = stat.st_size
                if size < MIN_FILE_SIZE:
                    continue  # Skip files smaller than the minimum size
                mtime = stat.st_mtime
                file_info.append((path, size, mtime, inode))
                if debug:
                    logger.debug(f"Found file {path} with size {size}, mtime {mtime}, inode {inode}")
            except Exception as e:
                logger.error(f"Error getting info for file {path}: {e}")
    if verbose:
        print(f"{directory}: {len(file_info)} files.")
    logger.info(f"{directory}: {len(file_info)} files.")
    return file_info

# Process files
def process_files(file_info, verbose, debug):
    logger.info(f"Processing {len(file_info)} files:")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    processed_count = 0
    commit_count = 0
    for path, size, mtime, inode in file_info:
        c.execute("SELECT mtime, initial_hash FROM files WHERE path=?", (path,))
        result = c.fetchone()
        if debug:
            logger.debug(f"{path}: {result}")
        if not result or result[0] != mtime:
            initial_hash = hash_initial_bytes(path, size, debug)
            perceptual_hash = None
            video_hash = None
            file_type = get_file_type(path)
            if initial_hash:
                if 'image' in file_type:
                    perceptual_hash = hash_perceptual(path, debug)
                elif 'video' in file_type:
                    video_hash = hash_video(path, debug)
                try:
                    c.execute("REPLACE INTO files (path, size, mtime, initial_hash, crc32_hash, sha256_hash, inode, perceptual_hash, video_hash, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (path, size, mtime, initial_hash, None, None, inode, perceptual_hash, video_hash, False))
                    if debug:
                        logger.debug(f"Inserted/Updated file {path} with initial hash {initial_hash}")
                    commit_count += 1
                    processed_count += 1
                    if commit_count >= COMMIT_THRESHOLD:
                        conn.commit()
                        commit_count = 0
                        logger.info(f"Committed changes after {COMMIT_THRESHOLD} operations")
                    if verbose:
                        print(f"{path}: {processed_count} files.")
                    logger.info(f"{path}: {processed_count} files.")
                except sqlite3.Error as e:
                    logger.error(f"Database error for file {path}: {e}")
                    conn.rollback()
    if commit_count > 0:
        conn.commit()
        logger.info(f"Final commit for remaining {commit_count} operations.")
    if verbose:
        print(f"Final commit for remaining {commit_count} operations.")
    if verbose:
        print(f"Processed {processed_count} files.")
    logger.info(f"Processed {processed_count} files.")
    conn.close()

# Count entries in the table
def count_entries():
    global main_conn, main_cursor
    main_cursor.execute("SELECT COUNT(*) FROM files")
    count = main_cursor.fetchone()[0]
    logger.info(f"Database contains {count} entries.")
    return count

# Verify database contents
def verify_database(verbose, debug):
    if debug:
        count = count_entries()
        if verbose:
            print(f"Database contains {count} entries.")
        logger.debug(f"Database contains {count} entries.")
    return count

# Save duplicates in the database
def save_duplicates(duplicates, conn, verbose, debug):
    c = conn.cursor()
    for duplicate_group in duplicates:
        sha256_hash = duplicate_group[0]  # Assuming the first entry's hash represents the group
        paths = "|||".join(duplicate_group)
        try:
            c.execute("INSERT INTO duplicates (sha256_hash, paths) VALUES (?, ?)", (sha256_hash, paths))
            if debug:
                logger.debug(f"Saved duplicate group with SHA-256 hash {sha256_hash}: {paths}")
        except sqlite3.Error as e:
            logger.error(f"Error saving duplicate group {paths}: {e}")
    conn.commit()
    if verbose:
        print(f"Saved {len(duplicates)} duplicate groups.")
    logger.info(f"Saved {len(duplicates)} duplicate groups.")

# Find duplicates
def find_duplicates(verbose, debug):
    logger.info("Finding duplicates.")
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    # Ensure we process any files that were marked as unprocessed before duplicate detection
    c.execute("SELECT size, initial_hash, GROUP_CONCAT(path, '|||') FROM files WHERE processed = 0 GROUP BY size, initial_hash HAVING COUNT(*) > 1")
    potential_duplicates = c.fetchall()

    duplicates = []
    total_files = len(potential_duplicates)
    for i, (size, initial_hash, paths) in enumerate(potential_duplicates):
        files = paths.split('|||')
        crc32_hash_dict = {}
        sha256_hash_dict = {}

        if verbose or debug:
            print(f"{files}: {size} {initial_hash}...", end="")
            logger.info(f"{files}: {size} {initial_hash}:")

        for file in files:
            file = file.strip()
            c.execute("SELECT crc32_hash FROM files WHERE path=?", (file,))
            result = c.fetchone()
            if result and result[0]:
                crc32_hash = result[0]
            else:
                crc32_hash = hash_crc32(file, debug)
                c.execute("UPDATE files SET crc32_hash = ? WHERE path = ?", (crc32_hash, file))
                conn.commit()
            if crc32_hash:
                if crc32_hash in crc32_hash_dict:
                    crc32_hash_dict[crc32_hash].append(file)
                else:
                    crc32_hash_dict[crc32_hash] = [file]
            else:
                logger.error(f"  Failed to compute CRC32 hash for {file}")

        for crc32_hash, crc32_files in crc32_hash_dict.items():
            if len(crc32_files) > 1:
                if verbose or debug:
                    print(f"CRC32 Full hash {crc32_hash}...", end="")
                    logger.info(f"  CRC32 Full hash {crc32_hash}...")

                for file in crc32_files:
                    file = file.strip()
                    c.execute("SELECT sha256_hash FROM files WHERE path=?", (file,))
                    result = c.fetchone()
                    if result and result[0]:
                        sha256_hash = result[0]
                    else:
                        sha256_hash = hash_sha256(file, debug)
                        c.execute("UPDATE files SET sha256_hash = ? WHERE path = ?", (sha256_hash, file))
                        conn.commit()
                    if sha256_hash:
                        if sha256_hash in sha256_hash_dict:
                            sha256_hash_dict[sha256_hash].append(file)
                        else:
                            sha256_hash_dict[sha256_hash] = [file]
                    else:
                        logger.error(f"  Failed to compute SHA-256 hash for {file}")

                for sha256_hash, sha256_hash_files in sha256_hash_dict.items():
                    if len(sha256_hash_files) > 1:
                        duplicates.append(sha256_hash_files)
                        if verbose or debug:
                            print(f"confirmed SHA-256 {sha256_hash}")
                            logger.info(f"  Duplicate group confirmed with SHA-256 hash {sha256_hash}: {sha256_hash_files}")

                        # Mark duplicates as processed to avoid reprocessing them
                        c.executemany("UPDATE files SET processed = 1 WHERE path = ?", [(f,) for f in sha256_hash_files])
                        conn.commit()
                    else:
                        logger.info(f"  Duplicate group with SHA-256 hash {sha256_hash} is false")
            else:
                logger.info(f"  Duplicate group with CRC32 {crc32_hash} is false")

        # Fuzzy matching for all unmatched images and videos
        for file in files:
            file = file.strip()
            c.execute("SELECT perceptual_hash, video_hash FROM files WHERE path=?", (file,))
            result = c.fetchone()
            perceptual_hash, video_hash = result
            if not perceptual_hash and not video_hash:
                continue

            for other_file in files:
                other_file = other_file.strip()
                if file == other_file:
                    continue
                c.execute("SELECT perceptual_hash, video_hash FROM files WHERE path=?", (other_file,))
                other_result = c.fetchone()
                other_perceptual_hash, other_video_hash = other_result

                # Fuzzy match images
                if perceptual_hash and other_perceptual_hash and abs(int(perceptual_hash, 16) - int(other_perceptual_hash, 16)) <= FUZZY_MATCH_THRESHOLD:
                    duplicates.append([file, other_file])
                    if verbose or debug:
                        print(f"fuzzy matched image {file} and {other_file}")
                        logger.info(f"  Fuzzy matched image {file} and {other_file}")

                # Fuzzy match videos
                if video_hash and other_video_hash and video_hash == other_video_hash:
                    duplicates.append([file, other_file])
                    if verbose or debug:
                        print(f"fuzzy matched video {file} and {other_file}")
                        logger.info(f"  Fuzzy matched video {file} and {other_file}")

        # Progress reporting
        if verbose:
            print(f"Processed {i + 1} out of {total_files} potential duplicate groups")
        logger.info(f"Processed {i + 1} out of {total_files} potential duplicate groups")

    # Save duplicates in the database
    save_duplicates(duplicates, conn, verbose, debug)

    # Mark all files as processed
    c.execute("UPDATE files SET processed = 1 WHERE processed = 0")
    conn.commit()

    if verbose:
        print(f"Found {len(duplicates)} duplicate groups.")
    logger.info(f"Found {len(duplicates)} duplicate groups.")
    conn.close()
    return duplicates

# Generate linking script
def generate_link_script(duplicates, verbose, debug):
    logger.info("Generating linking script.")
    with open('link_script.sh', 'w') as f:
        for files in duplicates:
            keep = files[0]
            for file in files[1:]:
                if os.path.samefile(os.path.dirname(keep), os.path.dirname(file)):
                    f.write(f"ln -f \"{keep}\" \"{file}\"\n")
                else:
                    f.write(f"ln -sf \"{keep}\" \"{file}\"\n")
    if verbose:
        print(f"Linking script generated with {len(duplicates)} duplicate groups.")
    logger.info(f"Linking script generated with {len(duplicates)} duplicate groups.")

# Function to reset the processed flag
def reset_processed():
    global main_conn, main_cursor
    logger.info("Resetting processed flag for all files.")
    main_cursor.execute("UPDATE files SET processed = 0")
    main_conn.commit()
    logger.info("Processed flag reset.")

# Reprocess files that are not marked as duplicates
def reprocess_unprocessed_files(verbose, debug):
    global main_conn, main_cursor
    logger.info("Reprocessing files that are not marked as duplicates.")
    c = main_cursor
    c.execute("SELECT path, size, mtime, inode FROM files WHERE processed = 0")
    file_info = c.fetchall()
    if verbose:
        print(f"Found {len(file_info)} unprocessed files.")
    process_files(file_info, verbose, debug)

# Output list of detected duplicates
def output_duplicates():
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute("SELECT sha256_hash, paths FROM duplicates")
    duplicates = c.fetchall()
    for sha256_hash, paths in duplicates:
        print(f"SHA-256: {sha256_hash}")
        print(f"Paths: {paths}")
        print("="*40)
    conn.close()

# Main function
def main(directories, verbose, debug, reset, list_duplicates, generate_links, reprocess):
    global main_conn, main_cursor
    if debug:
        logger.debug("Starting main function.")
    if list_duplicates:
        output_duplicates()
        return
    init_db()
    if reset:
        reset_processed()
    if reprocess:
        reprocess_unprocessed_files(verbose, debug)
        return
    if not generate_links:
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
        save_duplicates(duplicates, main_conn, verbose, debug)
    else:
        duplicates = []
        conn = sqlite3.connect('file_hashes.db')
        c = conn.cursor()
        c.execute("SELECT sha256_hash, paths FROM duplicates")
        duplicates = c.fetchall()
        conn.close()
    generate_link_script(duplicates, verbose, debug)
    if debug:
        logger.debug("Completed main function.")

    # Force disk sync and perform VACUUM
    main_cursor.execute("PRAGMA wal_checkpoint(FULL)")
    main_cursor.execute("PRAGMA synchronous = FULL")
    main_cursor.execute("VACUUM")
    main_conn.close()
    if debug:
        logger.debug("Performed PRAGMA wal_checkpoint, synchronous, and VACUUM.")

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate files and generate linking script.")
    parser.add_argument("directories", nargs='*', help="Directories to scan for duplicate files.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    parser.add_argument("--min-size", type=int, default=MIN_FILE_SIZE, help="Minimum file size for duplicate detection.")
    parser.add_argument("--reset", action="store_true", help="Reset the processed flag for all files.")
    parser.add_argument("--list-duplicates", action="store_true", help="Output list of detected duplicates.")
    parser.add_argument("--generate-links", action="store_true", help="Generate link script from detected duplicates.")
    parser.add_argument("--reprocess", action="store_true", help="Reprocess files that are not marked as duplicates without re-walking the file system.")
    args = parser.parse_args()

    # Use the provided min size or default to MIN_FILE_SIZE
    MIN_FILE_SIZE = args.min_size

    logger.getLogger().setLevel(logger.DEBUG if args.debug else logger.INFO)

    try:
        main(args.directories, args.verbose, args.debug, args.reset, args.list_duplicates, args.generate_links, args.reprocess)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        print(f"Unhandled exception: {e}")
