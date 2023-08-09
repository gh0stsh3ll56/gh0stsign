# gh0stsign
Thick Client Digital Signature Checking Tool

## Overview

`gh0stsign` is a command-line tool designed to check the digital signatures of files within a specified directory or a single file. It helps users identify whether files have valid digital signatures or are unsigned. The tool is cross-platform and can be used on both Windows and Linux operating systems.

## Requirements
- For Windows: Ensure you have the `sigcheck` utility available in your system's PATH. You can download it from Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- For Linux: Ensure you have the `codesign` utility available in your system's PATH. This utility is typically included in the `osslsigncode` package. Install it using your package manager if needed.


## Features

- Check the digital signatures of individual files or all files within a directory.
- Cross-platform support for both Windows and Linux.
- Option to enable verbose mode to display detailed verification information.
- Generate a detailed findings report containing verification results.
- Display detailed findings including signature status, verification output, signer, digest algorithm, and timestamp (on Windows).

## Getting Started

1. Clone this repository or download the `gh0stsign.py` script.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the script using the command: `python gh0stsign.py`

## Usage

1. Run the script: `python gh0stsign.py`
2. Enter the path to a single file or a directory when prompted.
3. Choose whether to enable verbose mode to see detailed verification information (optional).
4. The tool will display the findings and generate a detailed findings report.

## Example

To check the digital signatures of a single file:
python gh0stsign.py /path/to/single/file.exe - Windows
python3 gh0stsign.py /path/to/single/file.exe - Linux

To check the digital signatures of files within a directory:
python gh0stsign.py /path/to/directory/ - Windows
python3 gh0stsign.py /path/to/directory/ - Linux


## Report

After running the tool, a detailed findings report will be generated. The report will include information about each file's status, verification output, and a summary of signed and unsigned files.

The default report filename is `gh0stsign_findings_report.txt`, but you can provide a custom name when prompted.

## Author

Created by: gh0stsh3ll5619
GitHub: gh0stsh3ll5619
Company: Aressec.com

## License

This project is licensed under the [MIT License](LICENSE).
