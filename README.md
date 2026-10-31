![Banner](banner.png)

# file-header-anomaly-detector
Analyzes file headers for unexpected or malformed data structures based on common file format specifications, signaling potential tampering or exploitation attempts. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowStrikeHQ/file-header-anomaly-detector`

## Usage
`python3 main.py <filepath> [-v] [-l log_file]`

The tool identifies five signatures (PNG, JPEG, PDF, MZ, and ELF) and checks for anomalies. Anomaly lines start with "Anomaly detected:" and any anomaly makes the run exit 1. A clean identification exits 0.

Exactly what is checked:

- Extension against signature, for the mapped extensions: `.png` for PNG, `.jpg` and `.jpeg` for JPEG, `.pdf` for PDF, `.exe` and `.dll` for MZ, and `.elf`, `.so`, and `.axf` for ELF. A file whose extension is in that map but does not match its signature is an anomaly. An unmapped or missing extension gets identification only, with no mismatch claim.
- Minimum structure per format: PNG needs the IHDR chunk name at bytes 12 to 15; JPEG needs an SOI followed by a marker byte 0xFF; PDF needs a version after `%PDF-`; an MZ file must be at least 64 bytes, long enough to hold the PE offset field; an ELF file must have the class byte at offset 4.
- Truncated headers: a file shorter than a signature it prefixes, or shorter than the minimum structure for its format, is an anomaly.

A missing path, a path that is not a file, and an unreadable file exit 1. Naming the input as the `-l` log file is refused at exit 1, and a log file that cannot be opened gives a plain error line at exit 1 with no traceback.

## Parameters
- `filepath`: Path to the file to analyze (required, positional)
- `-h`: Show help message and exit
- `-v`: Enable verbose output
- `-l`: Path to save log output to.

## License
Copyright (c) ShadowStrikeHQ
