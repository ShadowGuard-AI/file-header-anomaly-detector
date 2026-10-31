#!/usr/bin/env python3

import argparse
import logging
import pathlib
import os
import sys

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


FORMATS = [
    {
        "name": "PNG image",
        "signature": b"\x89PNG\r\n\x1a\n",
        "extensions": {".png"},
        "minimum": 16,
    },
    {
        "name": "JPEG image",
        "signature": b"\xFF\xD8\xFF",
        "extensions": {".jpg", ".jpeg"},
        "minimum": 3,
    },
    {
        "name": "PDF document",
        "signature": b"%PDF-",
        "extensions": {".pdf"},
        "minimum": 8,
    },
    {
        "name": "Windows executable",
        "signature": b"MZ",
        "extensions": {".exe", ".dll"},
        "minimum": 64,
    },
    {
        "name": "ELF executable",
        "signature": b"\x7FELF",
        "extensions": {".elf", ".so", ".axf"},
        "minimum": 5,
    },
]

KNOWN_EXTENSIONS = set()
for _fmt in FORMATS:
    KNOWN_EXTENSIONS.update(_fmt["extensions"])


def _structure_anomaly(fmt, header):
    """Returns a structure problem string for a matched format, or None."""
    name = fmt["name"]
    if name == "PNG image":
        if header[12:16] != b"IHDR":
            return "PNG header has no IHDR chunk name at bytes 12 to 15"
    elif name == "JPEG image":
        if not (header.startswith(b"\xFF\xD8") and len(header) > 2 and header[2] == 0xFF):
            return "JPEG header is not an SOI followed by a marker byte 0xFF"
    elif name == "PDF document":
        version = header[5:8]
        if len(version) < 3 or not version[0:1].isdigit() or version[1:2] != b"." or not version[2:3].isdigit():
            return "PDF header has no version after %PDF-"
    elif name == "Windows executable":
        if len(header) < 64:
            return "MZ header is shorter than the 64 bytes needed to hold the PE offset field"
    elif name == "ELF executable":
        if len(header) < 5:
            return "ELF header has no class byte at offset 4"
    return None


def analyze_file_header(filepath):
    """
    Analyzes the file header of a given file.

    Returns:
        str: "clean" for a clean identification or an unrecognized
            header, "anomaly" when an anomaly is detected, and
            "error" when the file cannot be read.
    """
    try:
        with open(filepath, "rb") as f:  # Open in binary mode for header analysis
            header = f.read(256)
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return "error"
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return "error"

    suffix = pathlib.Path(filepath).suffix.lower()

    for fmt in FORMATS:
        signature = fmt["signature"]
        if header.startswith(signature):
            logging.info(f"File {filepath} appears to be a {fmt['name']}.")
            anomalies = []
            if len(header) < fmt["minimum"]:
                anomalies.append(
                    f"truncated {fmt['name']} header: {len(header)} bytes is shorter than the minimum structure of {fmt['minimum']} bytes"
                )
            else:
                problem = _structure_anomaly(fmt, header)
                if problem:
                    anomalies.append(problem)
            if suffix in KNOWN_EXTENSIONS and suffix not in fmt["extensions"]:
                anomalies.append(
                    f"extension {suffix} does not match the {fmt['name']} signature"
                )
            for anomaly in anomalies:
                logging.error(f"Anomaly detected: {anomaly} in file {filepath}.")
            return "anomaly" if anomalies else "clean"

    # A file that is a proper prefix of a known signature is truncated.
    for fmt in FORMATS:
        signature = fmt["signature"]
        if header and signature.startswith(header):
            logging.error(
                f"Anomaly detected: truncated {fmt['name']} header: file is shorter than the {len(signature)} byte signature in file {filepath}."
            )
            return "anomaly"

    logging.warning(f"File {filepath} has an unrecognized header.")
    return "clean"


def main():
    """
    Main function to parse arguments and run the file header analysis.
    """
    args = setup_argparse()

    # Configure Logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    filepath = args.filepath

    # Input Validation
    if not isinstance(filepath, str):
        logging.error("Filepath must be a string.")
        sys.exit(1)

    file_path_obj = pathlib.Path(filepath)

    if args.log_file:
        # Settled ruling, applied to the log path: never write log
        # output into the file being analyzed.
        if pathlib.Path(args.log_file).resolve() == file_path_obj.resolve():
            logging.error(f"Log file is the file being analyzed, refusing: {args.log_file}")
            sys.exit(1)
        try:
            file_handler = logging.FileHandler(args.log_file)
        except OSError as e:
            logging.error(f"Error opening log file {args.log_file}: {e}")
            sys.exit(1)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    if not file_path_obj.exists():
        logging.error(f"File does not exist: {filepath}")
        sys.exit(1)

    if not file_path_obj.is_file():
        logging.error(f"Path is not a file: {filepath}")
        sys.exit(1)

    if not os.access(filepath, os.R_OK):  #Check file is readable
        logging.error(f"File {filepath} is not readable (check permissions).")
        sys.exit(1)

    logging.info(f"Analyzing file: {filepath}")
    result = analyze_file_header(filepath)
    if result != "clean":
        sys.exit(1)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a file: python file_header_anomaly_detector.py /path/to/your/file.txt
# 2. Enable verbose output: python file_header_anomaly_detector.py -v /path/to/your/file.txt
# 3. Log output to a file: python file_header_anomaly_detector.py -l output.log /path/to/your/file.txt
# 4. Analyze and debug file: python file_header_anomaly_detector.py -v -l debug.log /path/to/your/file.txt