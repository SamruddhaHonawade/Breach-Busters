import wmi

class AccNames:
    """
    A class to retrieve and display information about user accounts and password policy on a Windows system.
    """

    def __init__(self):
        """
        Establishes a WMI connection for interacting with system information.
        """
        self.wmi_connection = wmi.WMI()

    def get_admin_accounts(self):
        """
        Retrieves a list of administrator account names.

        Returns:
            A list of administrator account names (strings).
        """
        admins = []
        for group in self.wmi_connection.Win32_Group():
            if group.Name == "Administrators":
                admins = [a.Name for a in group.associators(wmi_result_class="Win32_UserAccount")]
                break  # Exit loop after finding Administrators group
        return admins

    def list_user_accounts(self):
        """
        Lists information about user accounts on the system.
        """
        for user in self.wmi_connection.Win32_UserAccount():
            print(f"User Name: {user.Name}")
            print(f"Administrator: {user.Name in self.get_admin_accounts()}")
            print(f"Disabled: {user.Disabled}")
            print(f"Local: {user.LocalAccount}")
            print(f"Password Changeable: {user.PasswordChangeable}")
            print(f"Password Expires: {user.PasswordExpires}")
            print(f"Password Required: {user.PasswordRequired}")
            print()

    def print_password_policy(self):
        """
        Prints information about the system password policy using a safer method (subprocess module with shell=False).

        Raises:
            RuntimeError: If the subprocess module is unavailable.
        """
        import subprocess  # Import here to avoid potential security risks

        try:
            output = subprocess.run(["net", "accounts"], capture_output=True, text=True, check=True).stdout
        except subprocess.CalledProcessError:
            print("Error: Unable to retrieve password policy information using net accounts.")
        except ModuleNotFoundError:
            raise RuntimeError("The 'subprocess' module is not available. Please ensure it's installed.")
        else:
            print("Password Policy:")
            print(output)

if __name__ == "__main__":
    accnames = AccNames()
    #accnames.list_user_accounts()
    accnames.print_password_policy()
