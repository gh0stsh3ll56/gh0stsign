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
            if is_signed:
                signature_properties = get_security_properties(file_path)
            else:
                signature_properties = None
            return is_signed, verification_output, signature_properties
        except FileNotFoundError:
            return False, "sigcheck utility not found", None
    elif sys.platform.startswith('linux'):
        try:
            result = subprocess.run(['codesign', '--verify', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            is_signed = result.returncode == 0
            verification_output = result.stdout if is_signed else result.stderr
            if is_signed:
                signature_properties = get_security_properties(file_path)
            else:
                signature_properties = None
            return is_signed, verification_output, signature_properties
        except FileNotFoundError:
            return False, "codesign utility not found", None
    else:
        print("Unsupported platform.")
        return False, "Unsupported platform", None



def get_security_properties(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            security_properties = []
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                trustee = ace[2]
                if isinstance(trustee, pywintypes.SID):
                    account, domain, _type = win32security.LookupAccountSid(None, trustee)
                    access_mask = ace[1]
                    permissions = win32security.ConvertAccessMaskToString(access_mask)
                    security_properties.append(f"Account: {account}@{domain}\nPermissions: {permissions}")
            return "\n".join(security_properties)
        return "No explicit security properties found."
    except Exception as e:
        return f"Error retrieving security properties: {str(e)}"

def is_writable(file_path):
    return os.access(file_path, os.W_OK)

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
                    if account != "Administrators" and domain != "Administrators" and access_mask & win32security.FILE_GENERIC_WRITE:
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
                    if (account == "Administrators" or domain == "Administrators") and access_mask & win32security.FILE_GENERIC_WRITE:
                        return True
        return False
    except Exception as e:
        return False

def check_directory(directory_path, verbose):
    if not os.path.exists(directory_path):
        print("Directory not found.")
        return

    findings = []
    num_signed_files = 0
    num_signed_dll_exe = 0
    num_unsigned_dll_exe = 0
    num_files_with_user_write = 0

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            is_signed, verification_output, signature_properties = is_file_signed(file_path)
            if is_signed:
                status = 'Signed'
                num_signed_files += 1
                if file_path.lower().endswith(('.dll', '.exe')):
                    num_signed_dll_exe += 1
            else:
                status = 'Not signed'

            sp = get_security_properties(file_path)  # Get security properties
            if is_writable(file_path):
                num_files_with_user_write += 1

            permissions = get_permissions(file_path) if is_writable(file_path) else None

            finding = {
                'file_path': file_path,
                'status': status,
                'verification_output': verification_output,
                'signature_properties': signature_properties,
                'security_properties': sp,
                'writable': is_writable(file_path),
                'permissions': permissions,
                'writable_permissions': get_permissions(file_path) if is_writable(file_path) else None
            }

            findings.append(finding)

            if verbose:
                print(f"File: {file_path}\nStatus: {status}")
                if verification_output:
                    print(verification_output)
                if signature_properties:
                    print(f"Signature Properties:\nSigner: {signature_properties[0]}\nDigest Algorithm: {signature_properties[1]}\nTimestamp: {signature_properties[2]}")
                if sp:
                    print("Security Properties:")
                    print(sp)
                if is_writable(file_path):
                    print(f"Writable: Yes\nWritable Permissions:\n{finding['writable_permissions']}")
                else:
                    print("Writable: No")
                print()

    return findings, num_signed_files, num_signed_dll_exe, num_unsigned_dll_exe, num_files_with_user_write

def generate_report(report_file, findings, num_signed_files, num_signed_dll_exe, num_unsigned_dll_exe, num_files_with_user_write):
    with open(report_file, 'w') as f:
        f.write("Summary Report:\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Total Files Checked: {len(findings)}\n")
        f.write(f"Number of Signed Files: {num_signed_files}\n")
        f.write(f"Number of Signed DLL/EXE Files: {num_signed_dll_exe}\n")
        f.write(f"Number of Unsigned DLL/EXE Files: {num_unsigned_dll_exe}\n")
        f.write(f"Number of Files with User Write Permissions: {num_files_with_user_write}\n")
        f.write("=" * 60 + "\n\n")

        f.write("Files with User Write Permissions:\n")
        f.write("-" * 60 + "\n")
        for finding in findings:
            if finding['permissions'] and 'Others Writable' in finding['permissions'] and finding['permissions']['Others Writable']:
                f.write(f"File: {finding['file_path']}\n")
                f.write("Writable Permissions:\n")
                f.write(f"{finding['permissions']}\n")
                f.write("-" * 60 + "\n")

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
                    f.write(f"Signer: {finding['signature_properties'][0]}\nDigest Algorithm: {finding['signature_properties'][1]}\nTimestamp: {finding['signature_properties'][2]}\n")
                f.write("-" * 60 + "\n")

        f.write("Unsigned Files:\n")
        f.write("-" * 60 + "\n")
        for finding in findings:
            if finding['status'] == 'Not signed':
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"Status: {finding['status']}\n")
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
(|  | '. (_/ |  .-.  | '  \  /  ' .-._)   \    |  |    .-._)   \  ,|  |     |  '--'  |  |  | \   |   
 |  '--'  |  |  | |  |  \  `'  /  \       /    |  |    \       / (_|  |     |  '--'  |  |  |  \  |   
  `------'   `--' `--'   `---''    `-----'     `--'     `-----'    `--'      `------'   `--'  `--'  
                                                             
    """
    description = "A tool to check digital signatures and security properties of files in a directory."
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

        finding = {
            'file_path': input_path,
            'status': status,
            'verification_output': verification_output,
            'signature_properties': signature_properties
        }

        findings.append(finding)

        if verbose:
            print(f"File: {input_path}\nStatus: {status}")
            if verification_output:
                print(verification_output)
            if signature_properties:
                print(f"Signature Properties:\nSigner: {signature_properties[0]}\nDigest Algorithm: {signature_properties[1]}\nTimestamp: {signature_properties[2]}")
            print()
    elif os.path.isdir(input_path):
        findings, num_signed_files, num_signed_dll_exe, num_unsigned_dll_exe, num_files_with_user_write = check_directory(input_path, verbose)
    else:
        print("Path not found.")
        return

    custom_report_name = input("Enter a custom name for the report (or press Enter to use default name): ").strip()
    report_file = custom_report_name if custom_report_name else "gh0stsign_findings_report.txt"
    generate_report(report_file, findings, num_signed_files, num_signed_dll_exe, num_unsigned_dll_exe, num_files_with_user_write)

    print("\nDetailed Findings Report generated:", report_file)
    print(f"Total Files Checked: {len(findings)}")
    print(f"Number of Signed Files: {num_signed_files}")
    print(f"Number of Signed DLL/EXE Files: {num_signed_dll_exe}")
    print(f"Number of Unsigned DLL/EXE Files: {num_unsigned_dll_exe}")
    print(f"Number of Files with User Write Permissions: {num_files_with_user_write}")

if __name__ == "__main__":
    main()
