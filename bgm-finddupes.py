#!/usr/bin/env python3.9
import os
import hashlib
import zlib
import sqlite3
import shlex
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

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create logging handlers
console_handler = logging.StreamHandler()
rotating_file_handler = RotatingFileHandler('duplicate_finder.log', maxBytes=5000000, backupCount=5)
rotating_file_handler.setLevel(logging.DEBUG)

# Create formatters and add to handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)
rotating_file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(rotating_file_handler)

rotating_file_handler.doRollover()

# Constants
COMMIT_THRESHOLD = 100  # Threshold for database commits
INITIAL_HASH_SIZE = 1024 * 1024  # Initial hash size: 1 MB
MIN_FILE_SIZE = 1024  # Minimum file size: 1 KB
FUZZY_MATCH_THRESHOLD = 5  # Maximum allowed Hamming distance for fuzzy match

# Global database connection and cursor
main_conn = None
main_cursor = None

def signal_handler(sig, frame):
    """
    Handle system signals for graceful shutdown.
    """
    global main_conn
    if main_conn:
        logger.info("Interrupted! Committing pending changes and closing database.")
        main_conn.commit()
        main_conn.close()
    logger.info("Exiting gracefully.")
    sys.exit(0)

# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def init_db():
    """
    Initialize the SQLite database and create necessary tables.
    """
    global main_conn, main_cursor
    try:
        logger.info("Initializing database.")
        main_conn = sqlite3.connect('file_hashes.db')
        main_cursor = main_conn.cursor()
        main_cursor.execute('''CREATE TABLE IF NOT EXISTS files
                     (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, initial_hash TEXT, crc32_hash TEXT, sha256_hash TEXT, inode INTEGER, perceptual_hash TEXT, video_hash TEXT, processed BOOLEAN, hardlinked BOOLEAN DEFAULT 0)''')
        main_cursor.execute('''CREATE TABLE IF NOT EXISTS duplicates
                     (group_id INTEGER PRIMARY KEY AUTOINCREMENT, sha256_hash TEXT, paths TEXT)''')
        main_conn.commit()
        logger.info("Database initialized.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        sys.exit(1)

def hash_initial_bytes(path, size, debug):
    """
    Hash the first x bytes of a file using CRC32 for faster hashing.
    
    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    debug (bool): Enable debug logging.
    
    Returns:
    str: Initial hash as a hexadecimal string.
    """
    crc32 = 0
    try:
        with open(path, 'rb') as f:
            chunk = f.read(min(size, INITIAL_HASH_SIZE))
            crc32 = zlib.crc32(chunk)
        initial_hash = f"{crc32 & 0xFFFFFFFF:08x}"
        if debug:
            logger.debug(f"Initial hash for {path}: {initial_hash}")
        return initial_hash
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except Exception as e:
        logger.error(f"Error hashing initial bytes of file {path}: {e}")
    return None

def hash_crc32(path, debug):
    """
    Hash the entire file using CRC32 for faster initial duplicate detection.
    
    Parameters:
    path (str): Path to the file.
    debug (bool): Enable debug logging.
    
    Returns:
    str: CRC32 hash as a hexadecimal string.
    """
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
            logger.debug(f"CRC32 hash for {path}: {crc32_hash}")
        return crc32_hash
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except Exception as e:
        logger.error(f"Error hashing file {path} with CRC32: {e}")
    return None

def hash_sha256(path, debug):
    """
    Hash the entire file using SHA-256 for robust verification.
    
    Parameters:
    path (str): Path to the file.
    debug (bool): Enable debug logging.
    
    Returns:
    str: SHA-256 hash as a hexadecimal string.
    """
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()
        if debug:
            logger.debug(f"SHA-256 hash for {path}: {sha256_hash}")
        return sha256_hash
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except Exception as e:
        logger.error(f"Error hashing file {path} with SHA-256: {e}")
    return None

def hash_perceptual(path, debug):
    """
    Generate a perceptual hash for image files.
    
    Parameters:
    path (str): Path to the image file.
    debug (bool): Enable debug logging.
    
    Returns:
    str: Perceptual hash as a hexadecimal string.
    """
    try:
        image = Image.open(path)
        perceptual_hash = str(imagehash.phash(image))
        if debug:
            logger.debug(f"Perceptual hash for {path}: {perceptual_hash}")
        return perceptual_hash
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except IOError as e:
        logger.error(f"IO error generating perceptual hash for {path}: {e}")
    except Exception as e:
        logger.error(f"Error generating perceptual hash for {path}: {e}")
    return None

def hash_video(path, debug, frame_intervals=[150, 300, 450]):
    """
    Generate a perceptual hash for video files by analyzing frames at specified intervals.
    
    Parameters:
    path (str): Path to the video file.
    debug (bool): Enable debug logging.
    frame_intervals (list): List of frame intervals (in seconds) to analyze.
    
    Returns:
    str: Combined perceptual hash of the analyzed frames.
    """
    try:
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            logger.error(f"Error opening video file: {path}")
            return None

        video_hashes = []
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)

        for interval in frame_intervals:
            frame_interval = int(fps * (interval / 30))  # Convert to frame numbers assuming 30fps
            for frame_num in range(0, frame_count, frame_interval):
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
                ret, frame = cap.read()
                if ret:
                    img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                    frame_hash = str(imagehash.phash(img))
                    video_hashes.append(frame_hash)

        cap.release()
        combined_hash = ''.join(video_hashes)
        if debug:
            logger.debug(f"Video hash for {path}: {combined_hash}")
        return combined_hash
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except cv2.error as e:
        logger.error(f"OpenCV error generating video hash for {path}: {e}")
    except Exception as e:
        logger.error(f"Error generating video hash for {path}: {e}")
    return None

def scan_directory(directory, verbose, debug):
    """
    Scan a directory for files and gather their information.

    Parameters:
    directory (str): Directory to scan.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.

    Returns:
    list: List of tuples containing file information (path, size, mtime, inode).
    """
    logger.info(f"Scanning directory: {directory}")
    file_info = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                
                # Skip symbolic links
                if os.path.islink(path):
                    if debug:
                        logger.debug(f"Skipping symbolic link: {path}")
                    continue
                
                try:
                    # Get file statistics
                    stat = os.stat(path)
                    
                    # Skip files smaller than the minimum size
                    if stat.st_size < MIN_FILE_SIZE:
                        continue
                    
                    # Append file information to the list
                    file_info.append((path, stat.st_size, stat.st_mtime, stat.st_ino))
                    
                    if debug:
                        logger.debug(f"Found file {path} with size {stat.st_size}, mtime {stat.st_mtime}, inode {stat.st_ino}")
                
                except (FileNotFoundError, PermissionError) as e:
                    logger.error(f"File error {path}: {e}")
                except Exception as e:
                    logger.error(f"Error getting info for file {path}: {e}")
        
        logger.info(f"Total files processed in {directory}: {len(file_info)}")
    
    except Exception as e:
        logger.error(f"Error scanning directory {directory}: {e}")
    
    return file_info

def process_files(file_info, verbose, debug, enable_perceptual_hashing):
    """
    Process the list of files by hashing and storing their information in the database.
    
    Parameters:
    file_info (list): List of tuples containing file information (path, size, mtime, inode).
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    logger.info(f"Processing {len(file_info)} files:")
    try:
        conn = sqlite3.connect('file_hashes.db')
        c = conn.cursor()
        processed_count = 0
        commit_count = 0
        total_files = len(file_info)
        for path, size, mtime, inode in file_info:
            try:
                process_single_file(path, size, mtime, inode, c, debug, enable_perceptual_hashing)
                commit_count += 1
                processed_count += 1
                if commit_count >= COMMIT_THRESHOLD:
                    conn.commit()
                    commit_count = 0
                    logger.info(f"Committed changes: {processed_count}/{total_files}")
            except sqlite3.Error as e:
                logger.error(f"Database error processing file {path}: {e}")
            except Exception as e:
                logger.error(f"Error processing file {path}: {e}")

        if commit_count > 0:
            conn.commit()
            logger.info(f"Final commit for remaining {commit_count} operations.")
        logger.info(f"Processed {processed_count} files.")
    except Exception as e:
        logger.error(f"Error in process_files: {e}")
    finally:
        conn.close()

def process_single_file(path, size, mtime, inode, cursor, debug, enable_perceptual_hashing):
    """
    Process a single file by hashing and storing its information in the database.
    
    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    mtime (float): Last modified time of the file.
    inode (int): Inode number of the file.
    cursor (sqlite3.Cursor): Database cursor.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    try:
        cursor.execute("SELECT mtime, initial_hash, inode, hardlinked FROM files WHERE path=?", (path,))
        result = cursor.fetchone()
        if debug:
            logger.debug(f"{path}: {result}")
        
        if not result or result[0] != mtime:
            cursor.execute("SELECT path FROM files WHERE inode=?", (inode,))
            hardlink_paths = cursor.fetchall()
            if hardlink_paths:
                # Mark current file as hardlinked
                cursor.execute("REPLACE INTO files (path, size, mtime, initial_hash, crc32_hash, sha256_hash, inode, perceptual_hash, video_hash, processed, hardlinked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (path, size, mtime, None, None, None, inode, None, None, True, True))
                if debug:
                    logger.debug(f"HARDLINK: {inode}: {path} -> {hardlink_paths}")
                return  # Skip further processing for hardlinked file

            initial_hash = hash_initial_bytes(path, size, debug)
            if initial_hash:
                insert_or_update_file(path, size, mtime, inode, initial_hash, cursor, debug, enable_perceptual_hashing)
    except sqlite3.Error as e:
        logger.error(f"Database error querying file {path}: {e}")
    except Exception as e:
        logger.error(f"Error processing file {path}: {e}")

def insert_or_update_file(path, size, mtime, inode, initial_hash, cursor, debug, enable_perceptual_hashing):
    """
    Insert or update a file's information in the database.
    
    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    mtime (float): Last modified time of the file.
    inode (int): Inode number of the file.
    initial_hash (str): Initial hash of the file.
    cursor (sqlite3.Cursor): Database cursor.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    try:
        crc32_hash = None
        sha256_hash = None
        perceptual_hash = None
        video_hash = None
        if enable_perceptual_hashing:
            file_type = get_file_type(path)
            if 'image' in file_type:
                perceptual_hash = hash_perceptual(path, debug)
            elif 'video' in file_type:
                video_hash = hash_video(path, debug)
        cursor.execute("REPLACE INTO files (path, size, mtime, initial_hash, crc32_hash, sha256_hash, inode, perceptual_hash, video_hash, processed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (path, size, mtime, initial_hash, crc32_hash, sha256_hash, inode, perceptual_hash, video_hash, False))
        if debug:
            logger.debug(f"Inserted/Updated file {path} with initial hash {initial_hash}")
    except sqlite3.Error as e:
        logger.error(f"Database error for file {path}: {e}")
        cursor.connection.rollback()

def count_entries():
    """
    Count the number of entries in the files table.
    
    Returns:
    int: Number of entries in the files table.
    """
    global main_conn, main_cursor
    main_cursor.execute("SELECT COUNT(*) FROM files")
    count = main_cursor.fetchone()[0]
    logger.info(f"Database contains {count} entries.")
    return count

def verify_database(verbose, debug):
    """
    Verify the database contents.
    
    Parameters:
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    
    Returns:
    int: Number of entries in the files table.
    """
    if debug:
        count = count_entries()
        logger.debug(f"Database contains {count} entries.")
    return count

def save_duplicates(duplicates, conn, verbose, debug):
    """
    Save duplicate file groups in the database.
    
    Parameters:
    duplicates (list): List of duplicate file groups.
    conn (sqlite3.Connection): Database connection.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    """
    c = conn.cursor()
    try:
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
        logger.info(f"Saved {len(duplicates)} duplicate groups.")
    except sqlite3.Error as e:
        logger.error(f"Database error while saving duplicates: {e}")
        conn.rollback()
    except Exception as e:
        logger.error(f"Error saving duplicates: {e}")
        conn.rollback()

def find_duplicates(verbose, debug, enable_perceptual_hashing):
    """
    Find duplicate files in the database.
    
    Parameters:
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    
    Returns:
    list: List of duplicate file groups.
    """
    logger.info("Finding duplicates.")
    try:
        conn = sqlite3.connect('file_hashes.db')
        c = conn.cursor()
        c.execute("SELECT size, initial_hash, GROUP_CONCAT(path, '|||'), GROUP_CONCAT(inode, '|||') FROM files WHERE processed = 0 AND hardlinked != 1 GROUP BY size, initial_hash HAVING COUNT(*) > 1")
        potential_duplicates = c.fetchall()
        duplicates = []
        for size, initial_hash, paths, inodes in potential_duplicates:
            process_duplicate_group(size, initial_hash, paths, inodes, duplicates, conn, c, verbose, debug, enable_perceptual_hashing)
        save_duplicates(duplicates, conn, verbose, debug)
        c.execute("UPDATE files SET processed = 1 WHERE processed = 0")
        conn.commit()
        logger.info(f"Found {len(duplicates)} duplicate groups.")
    except sqlite3.Error as e:
        logger.error(f"Database error during duplicate finding: {e}")
    except Exception as e:
        logger.error(f"Error in find_duplicates: {e}")
    finally:
        conn.close()
    return duplicates

def process_duplicate_group(size, initial_hash, paths, inodes, duplicates, conn, cursor, verbose, debug, enable_perceptual_hashing):
    """
    Process a group of potential duplicate files.
    
    Parameters:
    size (int): Size of the files.
    initial_hash (str): Initial hash of the files.
    paths (str): Concatenated file paths.
    inodes (str): Concatenated inode numbers.
    duplicates (list): List of duplicate file groups.
    conn (sqlite3.Connection): Database connection.
    cursor (sqlite3.Cursor): Database cursor.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    files = paths.split('|||')
    inode_list = inodes.split('|||')
    inode_dict = dict(zip(files, inode_list))
    crc32_hash_dict = {}  # Reinitialize for each group
    if verbose or debug:
        logger.debug(f"Processing group: {files}, size: {size}, initial hash: {initial_hash}")

    # Process each unique file for CRC32 and SHA-256 hashing
    for file in files:
        crc32_hash = hash_crc32(file.strip(), debug)  # Ensure to strip any extra spaces
        if crc32_hash:
            if crc32_hash in crc32_hash_dict:
                crc32_hash_dict[crc32_hash].append(file.strip())
            else:
                crc32_hash_dict[crc32_hash] = [file.strip()]
        else:
            logger.error(f"Failed to compute CRC32 hash for {file.strip()}")

    for crc32_hash, crc32_files in crc32_hash_dict.items():
        if len(crc32_files) > 1:
            sha256_hash_dict = {}
            for file in crc32_files:
                sha256_hash = hash_sha256(file.strip(), debug)
                if sha256_hash:
                    if sha256_hash in sha256_hash_dict:
                        sha256_hash_dict[sha256_hash].append(file.strip())
                    else:
                        sha256_hash_dict[sha256_hash] = [file.strip()]
                else:
                    logger.error(f"Failed to compute SHA-256 hash for {file.strip()}")
            for sha256_hash, sha256_hash_files in sha256_hash_dict.items():
                if len(sha256_hash_files) > 1:
                    duplicates.append(sha256_hash_files)
                    if verbose or debug:
                        logger.debug(f"Duplicate group confirmed with SHA-256 hash {sha256_hash}: {sha256_hash_files}")
                    cursor.executemany("UPDATE files SET processed = 1 WHERE path = ?", [(f,) for f in sha256_hash_files])
                    conn.commit()
                else:
                    if enable_perceptual_hashing:
                        file_type = get_file_type(file.strip())
                        if 'image' in file_type:
                            perceptual_hash = hash_perceptual(file.strip(), debug)
                            for other_file in sha256_hash_files:
                                other_perceptual_hash = hash_perceptual(other_file.strip(), debug)
                                if perceptual_hash and other_perceptual_hash and perceptual_hash - other_perceptual_hash <= FUZZY_MATCH_THRESHOLD:
                                    duplicates.append([file.strip(), other_file.strip()])
                                    if verbose or debug:
                                        logger.info(f"Fuzzy matched image {file.strip()} and {other_file.strip()}")
                        elif 'video' in file_type:
                            video_hash = hash_video(file.strip(), debug)
                            for other_file in sha256_hash_files:
                                other_video_hash = hash_video(other_file.strip(), debug)
                                if video_hash and other_video_hash and video_hash == other_video_hash:
                                    duplicates.append([file.strip(), other_file.strip()])
                                    if verbose or debug:
                                        logger.info(f"Fuzzy matched video {file.strip()} and {other_file.strip()}")
        else:
            if verbose or debug:
                logger.debug(f"Duplicate group with CRC32 {crc32_hash} is false")

def generate_link_script(duplicates, verbose, debug):
    """
    Generate a script to create hardlinks for duplicate files.
    
    Parameters:
    duplicates (list): List of duplicate file groups.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    """
    logger.info("Generating linking script.")
    try:
        with open('link_script.sh', 'w') as f:
            for sha256_hash, paths in duplicates:
                files = paths.split('|||')
                if not files:
                    continue

                keep = files[0]
                keep_inode = os.stat(keep).st_ino
                keep_fs = os.stat(keep).st_dev

                for file in files[1:]:
                    file_inode = os.stat(file).st_ino
                    if file_inode == keep_inode:
                        if verbose or debug:
                            logger.info(f"Skipping hardlinked file: {file}")
                        continue

                    file_fs = os.stat(file).st_dev
                    escaped_keep = shlex.quote(keep)
                    escaped_file = shlex.quote(file)
                    if keep_fs == file_fs:
                        f.write(f'ln -f {escaped_keep} {escaped_file}\n')
                    else:
                        f.write(f'ln -sf {escaped_keep} {escaped_file}\n')
        logger.info(f"Linking script generated with {len(duplicates)} duplicate groups.")
    except IOError as e:
        logger.error(f"IO error while generating linking script: {e}")
    except Exception as e:
        logger.error(f"Error generating linking script: {e}")

def reset_processed():
    """
    Reset the processed flag for all files in the database.
    """
    global main_conn, main_cursor
    try:
        logger.info("Resetting processed flag for all files.")
        main_cursor.execute("UPDATE files SET processed = 0")
        main_conn.commit()
        logger.info("Processed flag reset.")
    except sqlite3.Error as e:
        logger.error(f"Database error during reset: {e}")
        main_conn.rollback()
    except Exception as e:
        logger.error(f"Error resetting processed flag: {e}")
        main_conn.rollback()

def reprocess_unprocessed_files(verbose, debug):
    """
    Reprocess files that are not marked as duplicates without re-walking the file system.
    
    Parameters:
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    """
    global main_conn, main_cursor
    try:
        logger.info("Reprocessing files that are not marked as duplicates.")
        c = main_cursor
        c.execute("SELECT path, size, mtime, inode FROM files WHERE processed = 0")
        file_info = c.fetchall()
        logger.info(f"Found {len(file_info)} unprocessed files.")
        process_files(file_info, verbose, debug, enable_perceptual_hashing)
        main_conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error during reprocessing: {e}")
        main_conn.rollback()
    except Exception as e:
        logger.error(f"Error reprocessing unprocessed files: {e}")
        main_conn.rollback()

def output_duplicates():
    """
    Output the list of detected duplicates from the database.
    """
    try:
        conn = sqlite3.connect('file_hashes.db')
        c = conn.cursor()
        c.execute("SELECT sha256_hash, paths FROM duplicates")
        duplicates = c.fetchall()
        for sha256_hash, paths in duplicates:
            print(f"SHA-256: {sha256_hash}")
            print(f"Paths: {paths}")
            print("="*40)
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database error while outputting duplicates: {e}")
    except Exception as e:
        logger.error(f"Error outputting duplicates: {e}")

def main(directories, verbose, debug, reset, list_duplicates, generate_links, reprocess, enable_perceptual_hashing):
    """
    Main function to execute the duplicate finder script.
    
    Parameters:
    directories (list): List of directories to scan.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    reset (bool): Reset the processed flag for all files.
    list_duplicates (bool): Output list of detected duplicates.
    generate_links (bool): Generate link script from detected duplicates.
    reprocess (bool): Reprocess files that are not marked as duplicates.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    global main_conn, main_cursor
    try:
        configure_logging(verbose, debug)
        if list_duplicates:
            output_duplicates()
            return
        init_db()
        if reset:
            reset_processed()
        elif reprocess:
            reprocess_unprocessed_files(verbose, debug)
        if not generate_links:
            process_directories(directories, verbose, debug, enable_perceptual_hashing)
        duplicates = load_duplicates_from_db()
        if generate_links:
            generate_link_script(duplicates, verbose, debug)
        finalize_database(debug)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        if main_conn:
            main_conn.close()

def configure_logging(verbose, debug):
    """
    Configure logging settings.
    
    Parameters:
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

def process_directories(directories, verbose, debug, enable_perceptual_hashing):
    """
    Process the list of directories to find duplicate files.
    
    Parameters:
    directories (list): List of directories to scan.
    verbose (bool): Enable verbose logging.
    debug (bool): Enable debug logging.
    enable_perceptual_hashing (bool): Enable perceptual hashing for images and videos.
    """
    count_entries()
    with ThreadPoolExecutor() as executor:
        futures = []
        for directory in directories:
            file_info = scan_directory(directory, verbose, debug)
            futures.append(executor.submit(process_files, file_info, verbose, debug, enable_perceptual_hashing))
        for future in futures:
            future.result()
    if debug:
        verify_database(verbose, debug)
    duplicates = find_duplicates(verbose, debug, enable_perceptual_hashing)
    save_duplicates(duplicates, main_conn, verbose, debug)

def load_duplicates_from_db():
    """
    Load duplicate file groups from the database.
    
    Returns:
    list: List of duplicate file groups.
    """
    try:
        conn = sqlite3.connect('file_hashes.db')
        c = conn.cursor()
        c.execute("SELECT sha256_hash, paths FROM duplicates")
        duplicates = c.fetchall()
        conn.close()
        return duplicates
    except sqlite3.Error as e:
        logger.error(f"Database error while loading duplicates: {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading duplicates: {e}")
        return []

def finalize_database(debug):
    """
    Perform final database operations such as checkpointing and vacuuming.
    
    Parameters:
    debug (bool): Enable debug logging.
    """
    try:
        main_cursor.execute("PRAGMA wal_checkpoint(FULL)")
        main_cursor.execute("PRAGMA synchronous = FULL")
        main_cursor.execute("VACUUM")
    except sqlite3.Error as e:
        logger.error(f"Database error during finalization: {e}")
    except Exception as e:
        logger.error(f"Error finalizing database: {e}")
    if debug:
        logger.debug("Performed PRAGMA wal_checkpoint, synchronous, and VACUUM.")

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
    parser.add_argument("--enable-perceptual-hashing", action="store_true", help="Enable perceptual hashing for images and videos.")
    args = parser.parse_args()

    # Use the provided min size or default to MIN_FILE_SIZE
    MIN_FILE_SIZE = args.min_size

    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        main(args.directories, args.verbose, args.debug, args.reset, args.list_duplicates, args.generate_links, args.reprocess, args.enable_perceptual_hashing)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
