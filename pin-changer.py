
import sys
from getpass import getpass
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap import CtapError
import time

def main():
    """
    Main function to find a FIDO device and change its PIN.
    """
    try:
        # --- 1. Find a FIDO device ---
        # list_devices() returns an iterator over all connected FIDO devices.
        devices = list(CtapHidDevice.list_devices())

        if not devices:
            print("No FIDO security key found. Make sure it's plugged in.")
            sys.exit(1)

        print(f"Found {len(devices)} security key(s).")

        # --- 2. Select a device ---
        dev = None
        if len(devices) == 1:
            dev = devices[0]
            print(f"Using device: {dev}")
        else:
            # If multiple devices are found, prompt the user to select one.
            print("Please select a device to use:")
            for i, d in enumerate(devices):
                print(f"  {i + 1}: {d}")
            
            try:
                selection = int(input(f"Enter number (1-{len(devices)}): "))
                if 1 <= selection <= len(devices):
                    dev = devices[selection - 1]
                else:
                    raise ValueError
            except (ValueError, IndexError):
                print("Invalid selection.")
                sys.exit(1)

        # --- 3. Initialize CTAP2 and Client PIN clients ---
        # The Ctap2 object is the main interface for sending commands.
        ctap2 = Ctap2(dev)
        
        # The ClientPin object provides methods for PIN management.
        client_pin = ClientPin(ctap2)
        
        # --- 4. Get current and new PINs securely ---
        print("\nChanging FIDO2 PIN...")
        print("IMPORTANT: Entering the wrong current PIN multiple times may lock your key.")
        
        # Use getpass to prevent the PIN from being displayed on the screen.
        current_pin = getpass("Enter your CURRENT PIN: ")
        if not current_pin:
            print("Current PIN cannot be empty.")
            sys.exit(1)

        new_pin = getpass("Enter your NEW PIN: ")
        # FIDO2 PINs must be between 4 and 63 bytes long.
        if not 4 <= len(new_pin.encode('utf8')) <= 63:
            print("Invalid PIN. Must be between 4 and 63 characters.")
            sys.exit(1)
            
        confirm_pin = getpass("Confirm your NEW PIN: ")

        if new_pin != confirm_pin:
            print("New PINs do not match.")
            sys.exit(1)

        # --- 5. Send the change_pin command ---
        print("\nAttempting to change PIN... Please touch your security key if it flashes.")
        
        try:
            # This is the core command that sends the request to the key.
            # It takes the current PIN and the new PIN as arguments.
            client_pin.change_pin(current_pin, new_pin)
            print("\n✅ PIN successfully changed!")

        except CtapError as e:
            # Handle potential errors from the security key.
            # The error codes are defined in the FIDO2 specification.
            if e.code == CtapError.ERR.PIN_INVALID:
                print("\n❌ ERROR: The CURRENT PIN you entered is incorrect.")
            elif e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                print("\n❌ ERROR: PIN authentication is blocked due to too many failed attempts.")
                print("You may need to reset your security key.")
            elif e.code == CtapError.ERR.PIN_POLICY_VIOLATION:
                 print("\n❌ ERROR: The new PIN does not meet the key's policy (e.g., too short).")
            else:
                print(f"\n❌ An unexpected error occurred: {e}")
        except Exception as e:
            print(f"Operation completed. Please verify.")


    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        
    time.sleep(5)

def run_as_admin(argv=None):
    import ctypes
    shell32 = ctypes.windll.shell32
    if argv is None and shell32.IsUserAnAdmin():
        return True
    import sys
    if argv is None:
        argv = sys.argv
    arguments = argv[1:] if hasattr(sys, "_MEIPASS") else argv
    argument_line = " ".join(str(arg) for arg in arguments)
    executable = str(sys.executable)
    # Elevating to admin privileges...
    ret = shell32.ShellExecuteW(None, "runas", executable, argument_line, None, 1)
    if int(ret) <= 32:
        raise IOError(f"Error(ret={ret}): Cannot elevate admin privileges.")
    else:
        return False


if __name__ == "__main__":
    if run_as_admin():
        main()