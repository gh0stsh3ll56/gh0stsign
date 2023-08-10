import os
import sys
import subprocess
import ctypes
from datetime import datetime
import win32security
import pywintypes

def get_permissions(file_path):
    try:
        permissions = os.stat(file_path)
        return {
            'Owner Readable': bool(permissions.st_mode & 0o400),
            'Owner Writable': bool(permissions.st_mode & 0o200),
            'Owner Executable': bool(permissions.st_mode & 0o100),
            'Group Readable': bool(permissions.st_mode & 0o040),
            'Group Writable': bool(permissions.st_mode & 0o020),
            'Group Executable': bool(permissions.st_mode & 0o010),
            'Others Readable': bool(permissions.st_mode & 0o004),
            'Others Writable': bool(permissions.st_mode & 0o002),
            'Others Executable': bool(permissions.st_mode & 0o001),
        }
    except Exception as e:
        return None

def is_file_signed(file_path):
    if sys.platform.startswith('win'):
        try:
            result = subprocess.run(['sigcheck', '-q', '-nobanner', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            is_signed = result.returncode == 0
            verification_output = result.stdout if is_signed else result.stderr
            signature_properties = get_signature_properties(file_path) if is_signed else None
            return is_signed, verification_output, signature_properties
        except FileNotFoundError:
            return False, "sigcheck utility not found", None
    elif sys.platform.startswith('linux'):
        try:
            result = subprocess.run(['codesign', '--verify', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            is_signed = result.returncode == 0
            verification_output = result.stdout if is_signed else result.stderr
            signature_properties = get_signature_properties(file_path) if is_signed else None
            return is_signed, verification_output, signature_properties
        except FileNotFoundError:
            return False, "codesign utility not found", None
    else:
        print("Unsupported platform.")
        return False, "Unsupported platform", None

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
                ("Signer", "Signer"),
                ("SignatureDigestAlgorithm", "Digest Algorithm"),
                ("Timestamp", "Timestamp")
            ]
            
            signer = None
            digest_algorithm = None
            timestamp = None
            for prop, label in properties:
                prop_path = fmt.format(lang, codepage, prop)
                size = ctypes.c_uint()
                ctypes.windll.version.VerQueryValueW(data, prop_path, None, ctypes.byref(size))
                buf = ctypes.create_unicode_buffer(size.value)
                ctypes.windll.version.VerQueryValueW(data, prop_path, ctypes.byref(buf), None)
                value = buf.value
                if label == "Signer":
                    signer = value if value else "None"
                elif label == "Digest Algorithm":
                    digest_algorithm = value if value else "None"
                elif label == "Timestamp":
                    timestamp = value if value else "None"

            try:
                timestamp = datetime.utcfromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                timestamp = "N/A"

            return signer, digest_algorithm, timestamp

        except Exception as e:
            print("Error retrieving signature properties:", e)
            return None, None, None

    elif sys.platform.startswith('linux'):
        return None, None, None


def get_security_properties(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            permissions = []
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                trustee = ace[2]
                if isinstance(trustee, pywintypes.SID):
                    account, domain, _type = win32security.LookupAccountSid(None, trustee)
                    access_mask = ace[1]
                    permission = win32security.ConvertAccessMaskToString(access_mask)

                    if permission == "DELETE" or permission == "WRITE_DAC":
                        permissions.append(f"{account}@{domain}: {permission} (High-Risk)")
                    else:
                        permissions.append(f"{account}@{domain}: {permission}")

            if permissions:
                return "\n".join(permissions)

        writable_by_users = is_writable_by_users(file_path)
        writable_by_admins = is_writable_by_admins(file_path)

        if writable_by_users:
            writable_info = "Yes (User)"
        elif writable_by_admins:
            writable_info = "Yes (Admin)"
        else:
            writable_info = "No"

        return f"Writable: {writable_info}"

    except Exception as e:
        return f"Error retrieving security properties: {str(e)}"

def is_writable_by_users(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                trustee = ace[2]
                if isinstance(trustee, (pywintypes.SID,)):
                    account, domain, _type = win32security.LookupAccountSid(None, trustee)
                    access_mask = ace[1]
                    if (account == "Users" or domain == "Users") and (access_mask & win32security.FILE_GENERIC_WRITE):
                        return True
        return False
    except Exception as e:
        return False

def is_writable_by_admins(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                trustee = ace[2]
                if isinstance(trustee, (pywintypes.SID,)):
                    account, domain, _type = win32security.LookupAccountSid(None, trustee)
                    access_mask = ace[1]
                    if (account == "Administrators" or domain == "Administrators") and (access_mask & win32security.FILE_GENERIC_WRITE):
                        return True
        return False
    except Exception as e:
        return False



def is_writable(file_path):
    if sys.platform.startswith('win'):
        try:
            return ctypes.windll.kernel32.GetFileAttributesW(file_path) & 0x1 == 0
        except Exception:
            return False
    elif sys.platform.startswith('linux'):
        return os.access(file_path, os.W_OK)

def check_directory(directory_path, verbose):
    if not os.path.exists(directory_path):
        print("Directory not found.")
        return

    findings = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            is_signed, verification_output, signature_properties = is_file_signed(file_path)
            security_properties = get_security_properties(file_path)
            writable = is_writable(file_path)
            permissions = get_permissions(file_path)
            writable_permissions = get_permissions(file_path) if writable else None
            if is_signed:
                status = 'Signed'
            else:
                status = 'Not signed'
            
            finding = {
                'file_path': file_path,
                'status': status,
                'verification_output': verification_output,
                'signature_properties': signature_properties,
                'security_properties': security_properties,
                'writable': writable,
                'permissions': permissions,
                'writable_permissions': writable_permissions
            }

            findings.append(finding)

            if verbose:
                print(f"File: {file_path}\nStatus: {status}")
                if verification_output:
                    print(verification_output)
                if signature_properties:
                    print(signature_properties)
                if security_properties:
                    print(security_properties)
                if writable:
                    print(f"Writable: Yes\nWritable Permissions:\n{writable_permissions}")
                else:
                    print("Writable: No")
                print()

    return findings


def generate_report(report_file, findings):
    with open(report_file, 'w') as f:
        f.write("Summary Report:\n")
        f.write("=" * 60 + "\n\n")

        num_signed = sum(1 for finding in findings if finding['status'] == 'Signed')
        num_unsigned = sum(1 for finding in findings if finding['status'] == 'Not signed')
        f.write(f"Total Files: {len(findings)}\n")
        f.write(f"Number of Signed Files: {num_signed}\n")
        f.write(f"Number of Unsigned Files: {num_unsigned}\n")
        f.write("=" * 60 + "\n\n")

        f.write("Signed Files:\n")
        f.write("-" * 60 + "\n")
        for finding in findings:
            if finding['status'] == 'Signed':
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"Status: {finding['status']}\n")
                if finding['verification_output']:
                    f.write("Verification Output:\n")
                    f.write(finding['verification_output'])
                if finding['signature_properties']:
                    f.write("Signature Properties:\n")
                    f.write(f"Signer: {finding['signature_properties'][0]}\n")
                    f.write(f"Digest Algorithm: {finding['signature_properties'][1]}\n")
                    f.write(f"Timestamp: {finding['signature_properties'][2]}\n")
                f.write("Permissions:\n")
                if finding['permissions']:
                    for permission, value in finding['permissions'].items():
                        f.write(f"{permission}: {'Yes' if value else 'No'}\n")
                f.write("-" * 60 + "\n")

        f.write("Unsigned Files:\n")
        f.write("-" * 60 + "\n")
        for finding in findings:
            if finding['status'] == 'Not signed':
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"Status: {finding['status']}\n")
                f.write("Permissions:\n")
                if finding['permissions']:
                    for permission, value in finding['permissions'].items():
                        f.write(f"{permission}: {'Yes' if value else 'No'}\n")
                f.write("-" * 60 + "\n")

        f.write("Writable Files (User):\n")
        f.write("-" * 60 + "\n")
        for finding in findings:
            if finding['writable'] and finding['permissions'] and "WRITE_DAC" in finding['permissions']:
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"Writable Permissions:\n")
                f.write(finding['writable_permissions'] + "\n")
                f.write("-" * 60 + "\n")

    print(f"Summary Report generated: {report_file}")




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
        is_signed, verification_output, signature_properties = is_file_signed(input_path)
        if is_signed:
            status = 'Signed'
        else:
            status = 'Not signed'

        security_properties = get_security_properties(input_path)
        writable = is_writable(input_path)
        permissions = get_permissions(input_path)
        writable_permissions = get_writable_permissions(input_path)

        finding = {
            'file_path': input_path,
            'status': status,
            'verification_output': verification_output,
            'signature_properties': signature_properties,
            'security_properties': security_properties,
            'writable': writable,
            'permissions': permissions,
            'writable_permissions': writable_permissions
        }

        findings.append(finding)

        if verbose:
            print(f"File: {input_path}\nStatus: {status}")
            if verification_output:
                print(verification_output)
            if signature_properties:
                print(signature_properties)
            if security_properties:
                print(security_properties)
            if writable:
                print(f"Writable: Yes\nWritable Permissions:\n{writable_permissions}")
            else:
                print("Writable: No")
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
