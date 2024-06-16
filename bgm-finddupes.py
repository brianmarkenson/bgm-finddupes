#!/usr/bin/env python3.9
import os
import time
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

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create logging handlers
console_handler = logging.StreamHandler()
rotating_file_handler = RotatingFileHandler('duplicate_finder.log', maxBytes=50000000, backupCount=5)
rotating_file_handler.setLevel(logging.DEBUG)

# Create formatters and add to handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)
rotating_file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(rotating_file_handler)

# Always rotate the file at the start of the script
rotating_file_handler.doRollover()

# Constants
COMMIT_THRESHOLD = 100  # Threshold for database commits
MIN_FILE_SIZE = 1024  # Minimum file size: 1 KB

# Global flags for use in multiple functions without having to pass them around
verbose = False
debug = False

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

def log(message, log_level='debug'):
    """
    Log a message based on the specified log level.

    Parameters:
    message (str): The message to log.
    log_level (str): The logging level ('debug', 'verbose', 'both').
    """
    if log_level == 'both' and (debug or verbose):
        logger.info(message)
    elif log_level == 'debug' and debug:
        logger.debug(message)
    elif log_level == 'verbose' and verbose:
        logger.info(message)

def init_db():
    """
    Initialize the SQLite database and create necessary tables.
    """
    global main_conn, main_cursor
    try:
        logger.info("Initializing database.")
        main_conn = sqlite3.connect('file_hashes.db', timeout=30.0)
        main_cursor = main_conn.cursor()
        main_cursor.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode
        main_cursor.execute('''CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            size INTEGER,
            mtime REAL,
            md5_hash TEXT,
            inode INTEGER,
            processed BOOLEAN,
            hardlinked BOOLEAN DEFAULT 0,
            group_id INTEGER
        )''')
        main_cursor.execute('''CREATE TABLE IF NOT EXISTS duplicates (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            md5_hash TEXT,
            paths TEXT
        )''')
        main_cursor.execute('''CREATE TABLE IF NOT EXISTS manual_check_duplicates (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            paths TEXT
        )''')
        main_conn.commit()
        logger.info("Database initialized.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        sys.exit(1)

def create_db_connection():
    conn = sqlite3.connect('file_hashes.db', timeout=30.0)
    c = conn.cursor()
    c.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode for this connection
    return conn, c

def execute_with_retry(c, query, params=(), retries=5, delay=1):
    """
    Execute a database query with retry logic to handle locking issues.

    Parameters:
    c (sqlite3.Cursor): Database cursor.
    query (str): SQL query to execute.
    params (tuple): Parameters for the SQL query.
    retries (int): Number of times to retry the operation.
    delay (int): Delay (in seconds) between retries.
    """
    for attempt in range(retries):
        try:
            c.execute(query, params)
            return
        except sqlite3.OperationalError as e:
            if 'locked' in str(e):
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    raise
            else:
                raise

def calculate_md5_middle_dynamic(path, size):
    """
    Calculate MD5 hash of a dynamically sized middle subset of a file.

    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    """

    # Calculate subset size as 1% of the file size, with a minimum of 1MB and a maximum of 10MB
    subset_size = min(max(size // 100, 1024 * 1024), 10 * 1024 * 1024)
    middle_start = (size // 2) - (subset_size // 2)
    hash_md5 = hashlib.md5()
    try: 
        with open(path, "rb") as f:
            f.seek(middle_start)
            chunk = f.read(subset_size)
            hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied: {path}")
    except Exception as e:
        logger.error(f"Error hashing {subset_size} bytes of file {path}: {e}")
    return None

def scan_directory(directory):
    """
    Scan a directory for files and gather their information.

    Parameters:
    directory (str): Directory to scan.

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
                    log(f"Skipping symbolic link: {path}", 'debug')
                    continue
                
                try:
                    # Get file statistics
                    stat = os.stat(path)
                    
                    # Skip files smaller than the minimum size
                    if stat.st_size < MIN_FILE_SIZE:
                        continue
                    
                    # Append file information to the list
                    file_info.append((path, stat.st_size, stat.st_mtime, stat.st_ino))
                    
                    log(f"Found file {path} with size {stat.st_size}, mtime {stat.st_mtime}, inode {stat.st_ino}", 'debug')
                
                except (FileNotFoundError, PermissionError) as e:
                    logger.error(f"File error {path}: {e}")
                except Exception as e:
                    logger.error(f"Error getting info for file {path}: {e}")
        
        logger.info(f"Total files processed in {directory}: {len(file_info)}")
    
    except Exception as e:
        logger.error(f"Error scanning directory {directory}: {e}")
    
    return file_info

def process_files(file_info):
    """
    Process the list of files by hashing and storing their information in the database.
    
    Parameters:
    file_info (list): List of tuples containing file information (path, size, mtime, inode).
    """
    logger.info(f"Processing {len(file_info)} files:")
    try:
        conn, c = create_db_connection()
        processed_count = 0
        commit_count = 0
        total_files = len(file_info)
        for path, size, mtime, inode in file_info:
            try:
                process_single_file(path, size, mtime, inode, c)
                commit_count += 1
                processed_count += 1
                if commit_count >= COMMIT_THRESHOLD:
                    conn.commit()
                    commit_count = 0
                    log(f"Committed changes: {processed_count}/{total_files}", 'both')
            except sqlite3.Error as e:
                logger.error(f"Database error processing file {path}: {e}")
            except Exception as e:
                logger.error(f"Error processing file {path}: {e}")

        if commit_count > 0:
            conn.commit()
            log(f"Final commit for remaining {commit_count} operations.", 'both')
        log(f"Processed {processed_count} files.", 'both')
    except Exception as e:
        logger.error(f"Error in process_files: {e}")
    finally:
        conn.close()

def process_single_file(path, size, mtime, inode, c):
    """
    Process a single file by hashing and storing its information in the database.
    
    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    mtime (float): Last modified time of the file.
    inode (int): Inode number of the file.
    c (sqlite3.Cursor): Database cursor.
    """
    try:
        execute_with_retry(c, "SELECT mtime, md5_hash, inode, hardlinked FROM files WHERE path=?", (path,))
        result = c.fetchone()
        log(f"{path}: {result}", 'debug')

        # Check to see if file already exists in the database
        if not result or result[0] != mtime:
            execute_with_retry(c, "SELECT path FROM files WHERE inode=?", (inode,))
            hardlink_paths = c.fetchall()
            if hardlink_paths:
                # Mark current file as hardlinked


                ####################################################################################################################################################
                ################  Need to also mark the other files that are hardlinked as hardlinked if they're not already #######################################
                ####################################################################################################################################################
                execute_with_retry(c, "REPLACE INTO files (path, size, mtime, md5_hash, inode, processed, hardlinked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (path, size, mtime, None, inode, True, True))
                log(f"HARDLINK: {inode}: {path} -> {hardlink_paths}", 'both')
                return  # Skip further processing for hardlinked file

            md5_hash = calculate_md5_middle_dynamic(path, size)

	    ###################################################################################################
            #### Understand why this 'if' is here, and what the consequence will be if it fails ###############
            ###################################################################################################
            if md5_hash:
                insert_or_update_file(path, size, mtime, inode, initial_hash, c)
        elif not debug:
            log(f"{path} exists in DB", 'verbose')
            
    except sqlite3.Error as e:
        logger.error(f"Database error querying file {path}: {e}")
    except Exception as e:
        logger.error(f"Error processing file {path}: {e}")

def insert_or_update_file(path, size, mtime, inode, md5_hash, c):
    """
    Insert or update a file's information in the database.
    
    Parameters:
    path (str): Path to the file.
    size (int): Size of the file.
    mtime (float): Last modified time of the file.
    inode (int): Inode number of the file.
    md5_hash (str): Initial hash of the file.
    c (sqlite3.Cursor): Database cursor
    """
    try:
        execute_with_retry(c, "REPLACE INTO files (path, size, mtime, md5_hash, inode, processed, hardlinked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (path, size, mtime, initial_hash, inode, False, False))
        log(f"{path}: {md5_hash} inserted/updated", 'debug')
    except sqlite3.Error as e:
        logger.error(f"Database error for file {path}: {e}")
        c.connection.rollback()

def count_entries():
    """
    Count the number of entries in the files table.
    
    Returns:
    int: Number of entries in the files table.
    """
    global main_conn, main_cursor
    c = main_cursor
    execute_with_retry(c, "SELECT COUNT(*) FROM files")
    count = c.fetchone()[0]
    logger.info(f"Database contains {count} entries.")
    return count

def verify_database():
    """
    Verify the database contents.
    
    Returns:
    int: Number of entries in the files table.
    """
    count = count_entries()
    log(f"Database contains {count} entries.", 'both')
    return count

def save_duplicates(duplicates, conn):
    """
    Save duplicate file groups in the database.
    
    Parameters:
    duplicates (list): List of duplicate file groups.
    """
    c = conn.cursor()
    try:
        for duplicate_group in duplicates:
            md5_hash = duplicate_group[0]  # Assuming the first entry's hash represents the group
            paths = "|||".join(duplicate_group)
            try:
                execute_with_retry(c, "INSERT INTO duplicates (md5_hash, paths) VALUES (?, ?)", (md5_hash, paths))
                log(f"DUPLICATES FOUND: {paths}: {md5_hash}", 'debug')
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

def find_duplicates():
    """
    Find duplicate files in the database.
    
    Returns:
    list: List of duplicate file groups.
    """
    logger.info("Finding duplicates.")
    try:
        conn, c = create_db_connection()
        execute_with_retry(c, "SELECT size, GROUP_CONCAT(md5_hash, '|||'), GROUP_CONCAT(path, '|||'), GROUP_CONCAT(inode, '|||') FROM files WHERE processed = 0 AND hardlinked != 1 GROUP BY size HAVING COUNT(*) > 1")
        potential_duplicates = c.fetchall()
        total_groups = len(potential_duplicates)  # Determine the total number of groups
        duplicates = []
        #####################################################################################################################################################################################################
        ##############################################  Update manual check to first check other portions of the file (last 10MB, first 10MB) before putting into manual verification #######################
        #####################################################################################################################################################################################################
        manual_check_duplicates = []
        for group_num, (size, md5_hashes, paths, inodes) in enumerate(potential_duplicates, start=1):
            log(f"Processing group {group_num}/{total_groups}", 'both')
            process_duplicate_group(size, md5_hashes, paths, inodes, duplicates, manual_check_duplicates, conn, c)
        save_duplicates(duplicates, conn)
        execute_with_retry(c, "UPDATE files SET processed = 1 WHERE processed = 0")
        conn.commit()
        logger.info(f"Found {len(duplicates)} duplicate groups.")
        if manual_check_duplicates:
            logger.info(f"Found {len(manual_check_duplicates)} possible duplicate groups. Run the script with --manual-verification to verify these groups.")
    except sqlite3.Error as e:
        logger.error(f"Database error during duplicate finding: {e}")
    except Exception as e:
        logger.error(f"Error in find_duplicates: {e}")
    return duplicates

def output_manual_check_duplicates():
    """
    Output the list of possible duplicates for manual verification.
    """
    try:
        conn, c = create_db_connection()
        execute_with_retry(c, "SELECT group_id, paths FROM manual_check_duplicates")
        manual_check_duplicates = c.fetchall()
        for group_id, paths in manual_check_duplicates:
            print(f"Possible duplicate group {group_id}:\n")
            for file in paths.split('|||'):
                print(f"{file}\n")
            print("="*40 + "\n")
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database error during output of possible duplicates: {e}")
    except Exception as e:
        logger.error(f"Error outputting possible duplicates: {e}")

def process_duplicate_group(size, md5_hashes, paths, inodes, duplicates, manual_check_duplicates, conn, c):
    """
    Process a group of potential duplicate files.

    Parameters:
    size (int): Size of the files.
    md5_hashes (str): Initial hash of the files.
    paths (str): Concatenated file paths.
    inodes (str): Concatenated inode numbers.
    duplicates (list): List of duplicate file groups.
    manual_check_duplicates (list): List of manual check duplicate file groups.
    conn (sqlite3.Connection): Database connection.
    c (sqlite3.Cursor): Database cursor.
    """
    files = paths.split('|||')  # Split the concatenated file paths by '|||'
    sorted_paths = sort_paths("|||".join(files))  # Sort the paths

    log(f"Processing group: {files}, size: {size}, md5 hashes: {md5_hashes}", 'both')

    all_files_in_group = set(files)
    confirmed_duplicates = set()

    if len(md5_hashes) == 1:
        duplicates.append(files.strio())
        confirmed_duplicates.update(files)
        log(f"Duplicate group confirmed with md5 hash {md5_hashes}: {files}", 'both')
                c.executemany("UPDATE files SET processed = 1 WHERE path = ?", [(f,) for f in files])
                conn.commit()
        files_needing_verification = set()
    else:
        # Files need manual verification if md5_hashes differ
        files_needing_verification = all_files_in_group

    if files_needing_verification:
        execute_with_retry(c, "INSERT INTO manual_check_duplicates (paths) VALUES (?)",
                       ("|||".join(files_needing_verification),))
        log(f"Manual check duplicate group: {list(files_needing_verification)}", 'both')

        group_id = c.lastrowid
        c.executemany("UPDATE files SET group_id = ? WHERE path = ?", [(group_id, f) for f in files_needing_verification])
        conn.commit()

    log(f"Processing group: {files}, size: {size}, md5 hashes: {md5_hashes}", 'both')

def sort_paths(paths):
    """
    Sorts the paths within the string separated by '|||'.
    """
    path_list = paths.split('|||')
    path_list.sort()
    return '|||'.join(path_list)

def verify_manual_check_duplicates():
    """
    Interactively verify possible duplicates stored in the database.
    """
    try:
        conn, c = create_db_connection()
        execute_with_retry(c, "SELECT group_id, paths FROM manual_check_duplicates")
        manual_check_duplicates = c.fetchall()

        if not manual_check_duplicates:
            print("No possible duplicates found for verification.")
            return

        for group_id, paths in manual_check_duplicates:
            print(f"\nPossible duplicate group {group_id}:\n")
            files = paths.split('|||')
            for file in files:
                execute_with_retry(c, "SELECT size, mtime FROM files WHERE path = ?", (file,))
                file_info = c.fetchone()
                if file_info:
                    size, mtime = file_info
                    mtime_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                    print(f"Path: {file}\nSize: {size} bytes\nLast Modified: {mtime_str}\n")
            
            user_input = input("Are these files duplicates? (y/n): ").strip().lower()
            if user_input == 'y':
                duplicates = [file.strip() for file in files]
                log(f"Manually confirmed duplicate group: {duplicates}", 'both')
                
                # Check if the group already exists in the duplicates table
                execute_with_retry(c, "SELECT group_id FROM duplicates WHERE paths = ?", ("|||".join(duplicates),))
                result = c.fetchone()
                if result is None:
                    # Save duplicates to the duplicates table
                    execute_with_retry(c, "INSERT INTO duplicates (paths) VALUES (?)",
                              ("|||".join(duplicates),))
                    duplicate_group_id = c.lastrowid

                    # Update the files table
                    c.executemany("UPDATE files SET processed = 1, group_id = ? WHERE path = ?", 
                                  [(duplicate_group_id, f) for f in duplicates])

                # Commit the changes immediately
                conn.commit()

            else:
                print(f"Group {group_id} marked as not duplicates.")

            # Remove the group from manual_check_duplicates after verification
            execute_with_retry(c, "DELETE FROM manual_check_duplicates WHERE group_id = ?", (group_id,))
            conn.commit()

        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error during manual verification: {e}")
    except Exception as e:
        logger.error(f"Error in verify_manual_check_duplicates: {e}")
    finally:
        conn.close()

def generate_link_script():
    """
    Generate a script to create hardlinks or softlinks for duplicate files.
    
    """
    try:
        conn, c = create_db_connection()

        # Retrieve all duplicates from the duplicates table
        execute_with_retry(c, "SELECT group_id, paths FROM duplicates")
        duplicates = c.fetchall()

        if not duplicates:
            print("No duplicates found.")
            return

        # Dictionary to store the preferred filesystem for each pair
        fs_pairs = {}

        with open('link_script.sh', 'w') as f:
            for group_id, paths in duplicates:
                files = paths.split('|||')
                if not files:
                    continue

                keep = files[0]
                keep_inode = os.stat(keep).st_ino
                keep_fs = os.stat(keep).st_dev

                for file in files[1:]:
                    file_inode = os.stat(file).st_ino
                    if file_inode == keep_inode:
                        log(f"Skipping hardlinked file: {file}", 'both')
                        continue

                    file_fs = os.stat(file).st_dev
                    escaped_keep = shlex.quote(keep)
                    escaped_file = shlex.quote(file)

                    if keep_fs == file_fs:
                        # Check if the target file is a softlink
                        if os.path.islink(file):
                            logger.warning(f"Target file {file} is a softlink. Skipping link creation.")
                            continue
                        f.write(f'ln -f {escaped_keep} {escaped_file}\n')
                    else:
                        # Sort the filesystem IDs to maintain consistent order
                        fs_pair = tuple(sorted((keep_fs, file_fs)))
                        if fs_pair not in fs_pairs:
                            print(f"1: {keep}")
                            print(f"2: {file}")
                            choice = input("Choose the filesystem to maintain (1 or 2): ").strip()
                            if choice == '1':
                                fs_pairs[fs_pair] = keep
                            elif choice == '2':
                                fs_pairs[fs_pair] = file
                            else:
                                print("Invalid choice. Skipping this pair.")
                                continue

                        target_filesystem = fs_pairs[fs_pair]
                        if target_filesystem == keep:
                            # Check if the target file is a softlink
                            if os.path.islink(keep):
                                logger.warning(f"Target file {keep} is a softlink. Skipping link creation.")
                                continue
                            f.write(f'ln -sf {escaped_file} {escaped_keep}\n')
                        else:
                            # Check if the target file is a softlink
                            if os.path.islink(file):
                                logger.warning(f"Target file {file} is a softlink. Skipping link creation.")
                                continue
                            f.write(f'ln -sf {escaped_keep} {escaped_file}\n')
        
        logger.info(f"Linking script generated with {len(duplicates)} duplicate groups.")
        print(f"Linking script generated with {len(duplicates)} duplicate groups.")
    except IOError as e:
        logger.error(f"IO error while generating linking script: {e}")
    except Exception as e:
        logger.error(f"Error generating linking script: {e}")
    finally:
        conn.close()

def reset_processed():
    """
    Reset the processed flag for all files in the database.
    """
    global main_conn, main_cursor
    c = main_cursor
    try:
        logger.info("Resetting processed flag for all files.")
        execute_with_retry(c, "UPDATE files SET processed = 0")
        main_conn.commit()
        logger.info("Processed flag reset.")
    except sqlite3.Error as e:
        logger.error(f"Database error during reset: {e}")
        main_conn.rollback()
    except Exception as e:
        logger.error(f"Error resetting processed flag: {e}")
        main_conn.rollback()

def reprocess_unprocessed_files():
    """
    Reprocess files that are not marked as duplicates without re-walking the file system.
    
    """
    global main_conn, main_cursor
    c = main_cursor
    try:
        logger.info("Reprocessing files that are not marked as duplicates.")
        execute_with_retry(c, "SELECT path, size, mtime, inode FROM files WHERE processed = 0")
        file_info = c.fetchall()
        logger.info(f"Found {len(file_info)} unprocessed files.")
        process_files(file_info)
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
        global main_conn, main_cursor
        c = main_cursor
        execute_with_retry(c, "SELECT sha256_hash, paths FROM duplicates")
        duplicates = c.fetchall()
        for sha256_hash, paths in duplicates:
            print(f"SHA-256: {sha256_hash}")
            print(f"Paths: {paths}")
            print("="*40)
    except sqlite3.Error as e:
        logger.error(f"Database error while outputting duplicates: {e}")
    except Exception as e:
        logger.error(f"Error outputting duplicates: {e}")

def main(directories, verbose_flag, debug_flag, reset, list_duplicates, generate_links, reprocess, manual_verification, cleanup_flag):
    """
    Main function to execute the duplicate finder script.

    Parameters:
    directories (list): List of directories to scan.
    verbose_flag (bool): Enable verbose logging.
    debug_flag (bool): Enable detailed debug logging.
    reset (bool): Reset the processed flag for all files.
    list_duplicates (bool): Output list of detected duplicates.
    generate_links (bool): Generate link script from detected duplicates.
    reprocess (bool): Reprocess files that are not marked as duplicates.
    manual_verification (bool): Interactively verify possible duplicates.
    cleanup_flag (bool): Perform cleanup of duplicates after verification.
    """
    global verbose, debug, main_conn, main_cursor, enable_perceptual_hashing

    verbose = verbose_flag
    debug = debug_flag

    try:
        configure_logging()
        init_db()

        if reset:
            reset_processed()

        if list_duplicates:
            output_duplicates()
            return
        if generate_links:
            generate_link_script()
            return
        if reprocess:
            reprocess_unprocessed_files()
            return
        if manual_verification:
            verify_manual_check_duplicates()
            return
        if cleanup_flag:
            cleanup()
            return

        process_directories(directories)
        duplicates = find_duplicates()
        save_duplicates(duplicates, main_conn)
        finalize_database()
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        if main_conn:
            main_conn.close()

def process_directories(directories):
    """
    Process the list of directories to find duplicate files.

    Parameters:
    directories (list): List of directories to scan.
    """
    count_entries()
    with ThreadPoolExecutor() as executor:
        futures = []
        for directory in directories:
            futures.append(executor.submit(scan_and_process_directory, directory))
        for future in futures:
            future.result()
    if debug:
        verify_database()
    duplicates = find_duplicates()
    save_duplicates(duplicates, main_conn)

def scan_and_process_directory(directory):
    """
    Scan and process a single directory.

    Parameters:
    directory (str): The directory to scan and process.
    """
    file_info = scan_directory(directory)
    process_files(file_info)

def configure_logging():
    """
    Configure logging settings.
    
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

def cleanup():
    """
    Re-check the files in the duplicate groups to see if they are now correctly hardlinked or softlinked.
    If they are, remove them from the duplicates table.
    """
    try:
        conn, c = create_db_connection()
        execute_with_retry(c, "SELECT group_id, paths FROM duplicates")
        duplicates = c.fetchall()

        if not duplicates:
            print("No duplicates found in the database.")
            return

        for group_id, paths in duplicates:
            files = paths.split('|||')
            if not files:
                continue

            keep = files[0]
            keep_inode = os.stat(keep).st_ino
            keep_fs = os.stat(keep).st_dev
            keep_target = os.path.realpath(keep)

            all_linked = True
            for file in files[1:]:
                file_inode = os.stat(file).st_ino
                file_fs = os.stat(file).st_dev
                file_target = os.path.realpath(file)

                # Check if the file is either hardlinked or softlinked to the keep file
                if (file_inode != keep_inode or file_fs != keep_fs) and file_target != keep_target:
                    all_linked = False
                    break

            if all_linked:
                execute_with_retry(c, "DELETE FROM duplicates WHERE group_id = ?", (group_id,))
                log(f"Removed group {group_id} from duplicates as they are now hardlinked/softlinked.", 'both')
        
        conn.commit()
        logger.info("Cleanup completed.")
    except sqlite3.Error as e:
        logger.error(f"Database error during cleanup: {e}")
    except Exception as e:
        logger.error(f"Error in cleanup: {e}")
    finally:
        conn.close()

def finalize_database():
    """
    Perform final database operations such as checkpointing and vacuuming.
    
    """
    global main_conn, main_cursor
    c = main_cursor
    try:
        execute_with_retry(c, "PRAGMA wal_checkpoint(FULL)")
        execute_with_retry(c, "PRAGMA synchronous = FULL")
        execute_with_retry(c, "VACUUM")
    except sqlite3.Error as e:
        logger.error(f"Database error during finalization: {e}")
    except Exception as e:
        logger.error(f"Error finalizing database: {e}")
    log("Performed PRAGMA wal_checkpoint, synchronous, and VACUUM.", 'debug')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate files and generate linking script.")
    
    # Define mutually exclusive group
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list-duplicates", action="store_true", help="Output list of detected duplicates.")
    group.add_argument("--generate-links", action="store_true", help="Generate link script from detected duplicates.")
    group.add_argument("--reprocess", action="store_true", help="Reprocess files that are not marked as duplicates.")
    group.add_argument("--manual-verification", action="store_true", help="Interactively verify possible duplicates.")
    group.add_argument("--cleanup", action="store_true", help="Perform cleanup of duplicates after verification.")
    
    parser.add_argument("directories", nargs='*', help="Directories to scan for duplicate files.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    parser.add_argument("--min-size", type=int, default=MIN_FILE_SIZE, help="Minimum file size for duplicate detection.")
    parser.add_argument("--reset", action="store_true", help="Reset the processed flag for all files.")
    parser.add_argument("--enable-perceptual-hashing", action="store_true", help="Enable perceptual hashing for images and videos.")
    
    args = parser.parse_args()

    if not (args.list_duplicates or args.generate_links or args.reprocess or args.manual_verification or args.cleanup or args.reset) and not args.directories:
        parser.error("directories argument is required unless one of --list-duplicates, --generate-links, --reprocess, --manual-verification, --cleanup, or --reset is specified")

    # Use the provided min size or default to MIN_FILE_SIZE
    MIN_FILE_SIZE = args.min_size

    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        main(args.directories, args.verbose, args.debug, args.reset, args.list_duplicates, args.generate_links, args.reprocess, args.manual_verification, args.enable_perceptual_hashing, args.cleanup)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")

