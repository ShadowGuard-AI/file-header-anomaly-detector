#!/usr/bin/env python3

import argparse
import logging
import pathlib
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes file headers for anomalies.")
    parser.add_argument("filepath", help="Path to the file to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-l", "--log-file", help="Path to save log output to.", default=None)
    return parser.parse_args()


def analyze_file_header(filepath):
    """
    Analyzes the file header of a given file.
    This is a basic implementation, and more file format signatures can be added.
    """
    try:
        with open(filepath, "rb") as f:  # Open in binary mode for header analysis
            header = f.read(32)  # Read the first 32 bytes (adjust as needed)

        # Example: Check for known file format signatures (can be extended)
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            logging.info(f"File {filepath} appears to be a PNG image.")
            # Further analysis can be added here, like checking IHDR chunk
        elif header.startswith(b"\xFF\xD8\xFF"):
            logging.info(f"File {filepath} appears to be a JPEG image.")
             # Further analysis can be added here, like checking for valid EXIF data markers
        elif header.startswith(b"%PDF-"):
            logging.info(f"File {filepath} appears to be a PDF document.")
            # Check for a valid PDF version
        elif header.startswith(b"MZ"):  # Check for Windows executable (MZ header)
            logging.info(f"File {filepath} might be a Windows executable.")
             # Perform more in depth checking on PE structure if suspected
        elif header.startswith(b"\x7FELF"):  # Check for ELF (Linux executable)
            logging.info(f"File {filepath} might be an ELF executable.")
        else:
            logging.warning(f"File {filepath} has an unrecognized header.")

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return False
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return False

    return True


def main():
    """
    Main function to parse arguments and run the file header analysis.
    """
    args = setup_argparse()

    # Configure Logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    filepath = args.filepath

    # Input Validation
    if not isinstance(filepath, str):
        logging.error("Filepath must be a string.")
        return

    file_path_obj = pathlib.Path(filepath)

    if not file_path_obj.exists():
        logging.error(f"File does not exist: {filepath}")
        return
    
    if not file_path_obj.is_file():
        logging.error(f"Path is not a file: {filepath}")
        return

    if not os.access(filepath, os.R_OK):  #Check file is readable
        logging.error(f"File {filepath} is not readable (check permissions).")
        return
    
    logging.info(f"Analyzing file: {filepath}")
    analyze_file_header(filepath)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a file: python file_header_anomaly_detector.py /path/to/your/file.txt
# 2. Enable verbose output: python file_header_anomaly_detector.py -v /path/to/your/file.txt
# 3. Log output to a file: python file_header_anomaly_detector.py -l output.log /path/to/your/file.txt
# 4. Analyze and debug file: python file_header_anomaly_detector.py -v -l debug.log /path/to/your/file.txt