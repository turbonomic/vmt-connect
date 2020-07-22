import base64
from cryptography.fernet import Fernet
import getpass
from pathlib import Path
import os



UPROMPT = 'Username: '
PPROMPT = 'Password: '



class Credential:
    """Credentials for authenticating to the Turbonomic API.

    Upon initialization :py:class:`~vmtconnect.Credential` will check the key
    filepath, and if present the key will be read into memory; otherwise a new
    key will be randomly generated.

    Args:
        path (str, optional): Home path for all credentials.
        key (str, optional): Path to the key file.
        cred (str, optional): Path to the credential token.
    """
    default_home = os.path.join(os.path.expanduser('~'), '.turbo_services_api_creds')
    default_key_file = os.path.join(default_home, '.key')
    default_msg_file =  os.path.join(default_home, '.cred')

    def __init__(self, key=None, cred=None):
        self.__key_file = key if key else self.default_key_file
        self.__msg_file = cred if cred else self.default_msg_file

        if os.path.exists(self.__key_file):
            self.__key = self.read_value(self.__key_file)
            self.existing_key = True
        else:
            self.__key = self._gen_key()
            self.existing_key = False

    @property
    def _key(self):
        return self.__key

    def _gen_key(self):
        return Fernet.generate_key()

    def get(self):
        """Retrieve and decrypt credentials

        Returns:
            Credentials in the form of a Base64 auth string.
        """
        return self.decrypt(self.read_value(self.__key_file),
                            self.read_value(self.__msg_file))

    def set(self, message, key=None, overwrite=False):
        """Encrypt the given message with the specified key, and save each to
        their respective files.

        Args:
            message (str): Data to be encrypted.
            key (str, optional): Cipher key to encrypt the message with.
            overwrite (bool): If ``True`` existing key or message data will be
                overwritten. (default: ``False``)
        """
        if not key:
            key = self.__key

        if not self.existing_key or overwrite:
            self.write_value(self.__key_file, key)

        if not os.path.exists(self.__msg_file) or overwrite:
            self.write_value(self.__msg_file, self.encrypt(key, message))

    def get_cipher(self, key=None):
        """Returns a Fernet cipher for the given key"""
        if not key:
            key = self.__key

        return Fernet(key)

    def prompt_credentials(self):
        """Retrieves a new set of credentials from the user, returning a Base64
        auth string response."""
        u = input(UPROMPT)
        p = getpass.getpass(PPROMPT, stream=None)

        return base64.b64encode(f"{u}:{p}".encode()).decode()

    def encrypt(self, message, key=None):
        """Encrypt the given message with the given key and return the token.

        Args:
            message (str): Message or data to be encrypted.
            key (str, optional): Cipher key to use for encryption.

        Returns:
            The encrypted token.
        """
        if not key:
            key = self.__key

        return self.get_cipher(key).encrypt(message.encode()).decode()

    def decrypt(self, token=None, key=None):
        """Decrypt the token using the given key, and return the message. If the
        token file was provided at init, it will be used here, otherwise a valid
        token must be supplied.

        Args:
            token (str, optional): Encrypted token to decrypt.
            key (str, optional): Cipher key to use for decryption.

        Returns:
            The decrypted message.
        """
        if not key:
            key = self.__key

        if not token and os.path.exists(self.__msg_file):
            token = self.read_value(self.__msg_file)

        return self.get_cipher(key).decrypt(token.encode()).decode()

    def create(self, message=None, key=None, overwrite=False):
        """Create and save to file a new cipher key and encrypted message.

        Args:
            key (str): Cipher key to use for encryption. If null, a new key will
                be generated. (default: ``None``)
            message (str): Message to be encrypted. If null, you will be prompted
                for a username and password pair interactively.
            overwrite (bool): If ``True`` existing key or message data will be
                overwritten. (default: ``False``)
        """
        if not key:
            key = self.__key

        msg = message if message else self.prompt_credentials()

        self.set(key, msg, overwrite)

    def read_value(self, value):
        if os.path.exists(value):
            with open(value, 'rb') as fp:
                return fp.read().decode()

        return value

    def write_value(self, path, value):


        with open(path, 'wb') as fp:
            fp.write(value.encode())
