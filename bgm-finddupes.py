import os
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import logging

# Setup logging
logging.basicConfig(filename='duplicate_finder.log', level=logging.INFO)

# Initialize database
def init_db():
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (path TEXT PRIMARY KEY, size INTEGER, hash TEXT)''')
    conn.commit()
    conn.close()

# Hash a file
def hash_file(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error hashing file {path}: {e}")
        return None

# Scan a directory
def scan_directory(directory):
    file_info = []
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            try:
                size = os.path.getsize(path)
                file_info.append((path, size))
            except Exception as e:
                logging.error(f"Error getting size for file {path}: {e}")
    return file_info

# Process files
def process_files(file_info):
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    for path, size in file_info:
        c.execute("SELECT hash FROM files WHERE path=?", (path,))
        result = c.fetchone()
        if not result:
            file_hash = hash_file(path)
            if file_hash:
                c.execute("INSERT INTO files (path, size, hash) VALUES (?, ?, ?)", (path, size, file_hash))
                logging.info(f"Processed file {path}")
    conn.commit()
    conn.close()

# Find duplicates
def find_duplicates():
    conn = sqlite3.connect('file_hashes.db')
    c = conn.cursor()
    c.execute("SELECT hash, GROUP_CONCAT(path) FROM files GROUP BY hash HAVING COUNT(*) > 1")
    duplicates = c.fetchall()
    conn.close()
    return duplicates

# Generate linking script
def generate_link_script(duplicates):
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

# Main function
def main(directories):
    init_db()
    with ThreadPoolExecutor() as executor:
        for directory in directories:
            file_info = scan_directory(directory)
            executor.submit(process_files, file_info)
    duplicates = find_duplicates()
    generate_link_script(duplicates)

# Example usage
if __name__ == "__main__":
    directories = ['/path/to/fs1', '/path/to/fs2']
    main(directories)
