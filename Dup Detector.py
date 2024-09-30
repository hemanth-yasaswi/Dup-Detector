import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import threading
import logging
import os
import shutil
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib

# Configure logging
logging.basicConfig(filename='file_monitor.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(console_handler)

def calculate_hash(file_path, algorithm="sha256", retries=3, delay=0.5):
    """
    Calculate the hash of a file with retry logic in case of permission issues.
    """
    attempt = 0
    while attempt < retries:
        try:
            hash_func = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash_func.update(byte_block)
            return hash_func.hexdigest()
        except FileNotFoundError:
            logging.error(f"File not found for hashing: {file_path}")
            return None
        except PermissionError:
            logging.warning(f"Permission denied when accessing {file_path}. Retrying...")
            attempt += 1
            time.sleep(delay)  # Wait for the file to become available
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return None
    logging.error(f"Failed to calculate hash after {retries} attempts: {file_path}")
    return None

# Function to show a popup in the main thread, ensuring it appears on top of all other windows
def show_duplicate_warning(new_file, existing_file, callback):
    # Create a hidden root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # Create a new Toplevel window to hold the popup
    top_window = tk.Toplevel(root)
    top_window.withdraw()  # Initially hide the window

    # Set the top window attributes to ensure it stays on top of all other windows
    top_window.attributes("-topmost", True)
    top_window.lift()

    # Function to ask user for input
    def ask_user():
        response = messagebox.askyesnocancel("Duplicate Detected",
                                             f"A file with the same content already exists.\n\n"
                                             f"New File: {new_file}\n"
                                             f"Existing File: {existing_file}\n\n"
                                             f"Do you want to keep both files?",
                                             parent=top_window)
        top_window.destroy()  # Close the popup window
        root.destroy()  # Destroy the root window
        callback(response, new_file)

    # Use 'after' to schedule the popup in the main loop
    top_window.after(0, ask_user)

    # Make sure the top window appears now
    top_window.deiconify()
    top_window.grab_set()  # Ensure the popup grabs focus and prevents interaction with other windows
    root.mainloop()

# Event handler class to detect file creations and modifications
class MyHandler(FileSystemEventHandler):
    def __init__(self, folder_to_monitor, hash_algorithm="sha256"):
        super().__init__()
        self.folder_to_monitor = folder_to_monitor
        self.file_hashes = {}  # Dictionary to store file hashes and their paths
        self.hash_algorithm = hash_algorithm
        self.processing_files = set()  # Set to keep track of files being processed to avoid duplicates
        # Initialize file hashes with existing files
        self._scan_existing_files()

    def _scan_existing_files(self):
        # Update file_hashes with the current state of files in the monitored folder
        self.file_hashes = {}  # Clear old entries
        for root, _, files in os.walk(self.folder_to_monitor):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path, self.hash_algorithm)
                if file_hash:
                    self.file_hashes[file_hash] = file_path
                    logging.info(f"Existing file hashed: {file_path} - Hash: {file_hash}")

    # Updated _handle_duplicate method to avoid deleting the original file
    def _handle_duplicate(self, new_file, existing_file):
        logging.info(f"Duplicate detected. Hash matches existing file: {existing_file}")

        def handle_response(response, new_file):
            if response:  # User chose to keep both files
                logging.info(f"Keeping both files: {new_file} and {existing_file}")
            else:  # User chose not to keep the new file
                try:
                    # Instead of deleting the duplicate, move it back to its original location
                    if os.path.exists(new_file):
                        # Ensure that we don't delete the original file
                        if new_file != existing_file:
                            logging.info(f"Removing duplicate file: {new_file}")
                            os.remove(new_file)  # Delete the duplicate file
                        else:
                            logging.warning(f"Duplicate file is the same as the existing file: {new_file}")
                    else:
                        logging.warning(f"Duplicate file not found when trying to delete: {new_file}")
                except Exception as e:
                    logging.error(f"Error handling the duplicate file: {e}")

        # Show the popup for duplicate detection
        show_duplicate_warning(new_file, existing_file, handle_response)

    def _process_file_event(self, file_path):
        if file_path in self.processing_files:
            return  # Already processing this file, avoid duplicate processing
        self.processing_files.add(file_path)

        # Add a delay to prevent immediate processing of files in the middle of operations
        time.sleep(1)  # Small delay to let file operations settle

        # Calculate the file hash
        file_hash = calculate_hash(file_path, self.hash_algorithm)
        if not file_hash:
            self.processing_files.discard(file_path)
            return  # If we failed to calculate the hash, stop processing

        if file_hash in self.file_hashes:
            existing_file = self.file_hashes[file_hash]
            if file_path != existing_file:  # Avoid comparing the same file
                self._handle_duplicate(file_path, existing_file)
        else:
            self.file_hashes[file_hash] = file_path
            logging.info(f"New file detected and hashed: {file_path}")

        self.processing_files.discard(file_path)  # Remove from the processing set

    def on_created(self, event):
        if not event.is_directory:
            logging.debug(f"File created: {event.src_path}")
            self._process_file_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            logging.debug(f"File modified: {event.src_path}")
            self._process_file_event(event.src_path)

# Function to start monitoring the folder
def start_monitoring(folder_to_monitor, hash_algorithm="sha256", recursive=True):
    event_handler = MyHandler(folder_to_monitor, hash_algorithm)
    observer = Observer()
    observer.schedule(event_handler, folder_to_monitor, recursive=recursive)
    observer.start()
    logging.info(f"Monitoring folder: {folder_to_monitor} (recursive={recursive})")
    try:
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        logging.info("Stopping monitoring...")
        observer.stop()
    observer.join()

# GUI for the application
class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dup Detector")
        self.root.geometry("400x200")
        self.root.resizable(False, False)

        # Create a stylish frame
        frame = ttk.Frame(root, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        # Title label
        self.title_label = ttk.Label(frame, text="Dup Detector", font=("Helvetica", 14))
        self.title_label.pack(pady=10)

        # Description label
        self.desc_label = ttk.Label(frame, text="Select a folder to monitor for duplicate files:")
        self.desc_label.pack(pady=5)

        # Select folder button
        self.select_button = ttk.Button(frame, text="Select Folder", command=self.select_folder)
        self.select_button.pack(pady=5)

        # Start monitoring button
        self.start_button = ttk.Button(frame, text="Start Monitoring", command=self.start_monitoring, state=tk.DISABLED)
        self.start_button.pack(pady=5)

        # Status label
        self.status_label = ttk.Label(frame, text="", font=("Helvetica", 10))
        self.status_label.pack(pady=10)

    def select_folder(self):
        folder_path = filedialog.askdirectory(title="Select Folder to Monitor")
        if folder_path:
            self.folder_to_monitor = folder_path
            self.start_button.config(state="normal")
            self.status_label.config(text=f"Selected Folder: {folder_path}")
        else:
            self.status_label.config(text="No folder selected.")

    def start_monitoring(self):
        if hasattr(self, 'folder_to_monitor'):
            self.status_label.config(text="Monitoring started...")
            monitoring_thread = threading.Thread(target=start_monitoring, args=(self.folder_to_monitor,))
            monitoring_thread.daemon = True  # Allow the thread to exit when the main program exits
            monitoring_thread.start()
        else:
            messagebox.showerror("Error", "No folder selected to monitor.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()
    