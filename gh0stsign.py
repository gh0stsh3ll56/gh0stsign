import os
import sys
import subprocess
import ctypes
from datetime import datetime

def is_file_signed(file_path):
    if sys.platform.startswith('win'):
        try:
            result = subprocess.run(['sigcheck', '-q', '-nobanner', '-a', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout.strip() + result.stderr.strip()  # Combine both output streams
            is_signed = 'Verified:' in output
            verification_output = output
            if is_signed:
                signer, digest_algorithm, timestamp = get_signature_properties(file_path)
                verification_output += f"\nSigner: {signer}\nDigest Algorithm: {digest_algorithm}\nTimestamp: {timestamp}"
            return is_signed, verification_output
        except FileNotFoundError:
            return False, "sigcheck utility not found"
    elif sys.platform.startswith('linux'):
        try:
            result = subprocess.run(['codesign', '--display', '--verbose=4', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout.strip() + result.stderr.strip()  # Combine both output streams
            is_signed = 'satisfies its Designated Requirement' in output
            verification_output = output
            if is_signed:
                signer, digest_algorithm, timestamp = get_signature_properties(file_path)
                verification_output += f"\nSigner: {signer}\nDigest Algorithm: {digest_algorithm}\nTimestamp: {timestamp}"
            return is_signed, verification_output
        except FileNotFoundError:
            return False, "codesign utility not found"
    else:
        print("Unsupported platform.")
        return False, "Unsupported platform"

def get_signature_properties(file_path):
    if sys.platform.startswith('win'):
        try:
            pinfo = os.path.abspath(file_path)
            data = ctypes.windll.version.GetFileVersionInfoW(pinfo, "\\")
            for language, codepage in data:
                if language == 0x409 and codepage == 1200:
                    break
            else:
                raise ValueError("English (United States) language codepage 1200 not found")

            struct = (ctypes.c_ushort * 4)()
            ctypes.windll.version.VerQueryValueW(data, u"\\VarFileInfo\\Translation", ctypes.byref(struct), None)
            lang, codepage = struct[:2]
            fmt = u"\\StringFileInfo\\{:04x}{:04x}\\{}"

            properties = [
                ("CompanyName", "Signer"),
                ("FileDescription", "Description"),
                ("ProductName", "Product"),
                ("ProductVersion", "Version")
            ]
            
            signer = None
            for prop, label in properties:
                prop_path = fmt.format(lang, codepage, prop)
                size = ctypes.c_uint()
                ctypes.windll.version.VerQueryValueW(data, prop_path, None, ctypes.byref(size))
                buf = ctypes.create_unicode_buffer(size.value)
                ctypes.windll.version.VerQueryValueW(data, prop_path, ctypes.byref(buf), None)
                if label == "Signer":
                    signer = buf.value

            try:
                timestamp = datetime.utcfromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                timestamp = "N/A"

            return signer, "SHA256", timestamp

        except Exception as e:
            print("Error retrieving signature properties:", e)
            return None, None, None

    elif sys.platform.startswith('linux'):
        return None, None, None

def check_directory(directory_path, verbose):
    if not os.path.exists(directory_path):
        print("Directory not found.")
        return

    findings = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            is_signed, verification_output = is_file_signed(file_path)
            signature_properties = get_signature_properties(file_path)
            
            if is_signed:
                status = 'Signed'
            else:
                status = 'Not signed'

            finding = {
                'file_path': file_path,
                'status': status,
                'verification_output': verification_output,
                'signature_properties': signature_properties
            }

            findings.append(finding)

            if verbose:
                print(f"File: {file_path}\nStatus: {status}")
                if verification_output:
                    print(verification_output)
                if signature_properties:
                    print(signature_properties)
                print()

    return findings


def generate_report(report_file, findings):
    with open(report_file, 'w') as f:
        f.write("Detailed Findings Report:\n")
        for finding in findings:
            f.write(f"File: {finding['file_path']}\nStatus: {finding['status']}\n")
            if finding['verification_output']:
                f.write("Verification Output:\n")
                f.write(finding['verification_output'])
            f.write("\n\n")

        num_signed = sum(1 for finding in findings if finding['status'] == 'Signed')
        num_unsigned = sum(1 for finding in findings if finding['status'] == 'Not signed')

        f.write("Summary Report:\n\n")
        f.write(f"Signed Files ({num_signed}):\n")
        for finding in findings:
            if finding['status'] == 'Signed':
                f.write(f"- {finding['file_path']}\n")
        f.write("\n")

        f.write(f"Not Signed Files ({num_unsigned}):\n")
        for finding in findings:
            if finding['status'] == 'Not signed':
                f.write(f"- {finding['file_path']}\n")
        f.write("\n")

        f.write(f"Number of Signed Files: {num_signed}\n")
        f.write(f"Number of Not Signed Files: {num_unsigned}\n")

def print_banner():
    banner = r"""
               ('-. .-.              .-')     .-') _      .-')                                .-') _  
             ( OO )  /             ( OO ).  (  OO) )    ( OO ).                             ( OO ) ) 
  ,----.     ,--. ,--.   .----.   (_)---\_) /     '._  (_)---\_)   ,-.-')    ,----.     ,--./ ,--,'  
 '  .-./-')  |  | |  |  /  ..  \  /    _ |  |'--...__) /    _ |    |  |OO)  '  .-./-')  |   \ |  |\  
 |  |_( O- ) |   .|  | .  /  \  . \  :` `.  '--.  .--' \  :` `.    |  |  \  |  |_( O- ) |    \|  | ) 
 |  | .--, \ |       | |  |  '  |  '..`''.)    |  |     '..`''.)   |  |(_/  |  | .--, \ |  .     |/  
(|  | '. (_/ |  .-.  | '  \  /  ' .-._)   \    |  |    .-._)   \  ,|  |_.' (|  | '. (_/ |  |\    |   
 |  '--'  |  |  | |  |  \  `'  /  \       /    |  |    \       / (_|  |     |  '--'  |  |  | \   |   
  `------'   `--' `--'   `---''    `-----'     `--'     `-----'    `--'      `------'   `--'  `--'  
                                                             
    """
    description = "A tool to check digital signatures of files in a directory."
    print(banner)
    print(description)

def main():
    print_banner()

    input_path = input("Enter the path to the file or directory: ").strip()

    if not input_path:
        print("Invalid input.")
        return

    verbose = input("Enable verbose mode? (y/n): ").strip().lower() == 'y'

    if os.path.isfile(input_path):
        findings = []
        is_signed, verification_output = is_file_signed(input_path)
        if is_signed:
            status = 'Signed'
        else:
            status = 'Not signed'

        finding = {
            'file_path': input_path,
            'status': status,
            'verification_output': verification_output
        }

        findings.append(finding)

        if verbose:
            print(f"File: {input_path}\nStatus: {status}")
            if verification_output:
                print(verification_output)
            print()
    elif os.path.isdir(input_path):
        findings = check_directory(input_path, verbose)
    else:
        print("Path not found.")
        return

    custom_report_name = input("Enter a custom name for the report (or press Enter to use default name): ").strip()
    report_file = custom_report_name if custom_report_name else "gh0stsign_findings_report.txt"
    generate_report(report_file, findings)

    signed_files = [finding for finding in findings if finding['status'] == 'Signed']
    unsigned_files = [finding for finding in findings if finding['status'] == 'Not signed']

    print("\nDetailed Findings Report generated:", report_file)
    print(f"Total Files: {len(findings)}")
    print(f"Number of Signed Files: {len(signed_files)}")
    print(f"Number of Unsigned Files: {len(unsigned_files)}")

if __name__ == "__main__":
    main()
