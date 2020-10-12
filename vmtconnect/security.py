# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        key (str, optional): Path to the key file.
        cred (str, optional): Path to the credential token.

    Attributes:
        uid (int): User id to set new files to.
        gid (int): Group id to set new files to.
        mode (int): File mode (octal format 0oNNN is ok), to apply to new files.
    """
    default_home = Path('~/.turbo_services_api_creds').expanduser()
    default_key_file = Path(default_home, '.key')
    default_msg_file =  Path(default_home, '.cred')

    def __init__(self, key=None, cred=None):
        self.__key_file = key if key else self.default_key_file
        self.__msg_file = cred if cred else self.default_msg_file

        if Path(self.__key_file).exists():
            self.__key = self.read_value(self.__key_file).decode()
            self.existing_key = True
        else:
            self.new_key()

        self.uid = -1
        self.gid = -1
        self.mode = 0o600

    @property
    def _key(self):
        return self.__key

    def _gen_key(self):
        return Fernet.generate_key().decode()

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
        if overwrite:
            self.new_key()
            key = self.__key
        elif not key:
            key = self.__key

        msg = message if message else self.prompt_credentials()
        self.set(msg, key, overwrite)

    def decrypt(self, token=None, key=None):
        """Decrypt the token using the given key, and return the message. If the
        token file was provided at init, it will be used here, otherwise a valid
        token must be supplied.

        Args:
            token (bytes, optional): Encrypted token to decrypt.
            key (str, optional): Cipher key to use for decryption.

        Returns:
            The decrypted message.
        """
        if not key:
            key = self.__key

        if not token and Path(self.__msg_file).exists():
            token = self.read_value(self.__msg_file)

        return self.get_cipher(key).decrypt(token).decode()

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

    def get(self):
        """Retrieve and decrypt credentials

        Returns:
            Credentials in the form of a Base64 auth string.
        """
        return self.decrypt(self.read_value(self.__msg_file))

    def get_cipher(self, key=None):
        """Returns a Fernet cipher for the given key"""
        if not key:
            key = self.__key

        return Fernet(key)

    def new_key(self):
        """Generate a new key."""
        self.__key = self._gen_key()
        self.existing_key = False

    def prompt_credentials(self):
        """Retrieves a new set of credentials from the user, returning a Base64
        auth string response."""
        u = input(UPROMPT)
        p = getpass.getpass(PPROMPT, stream=None)

        return base64.b64encode(f"{u}:{p}".encode()).decode()

    def read_value(self, value):
        if Path(value).exists():
            return Path(value).read_bytes()

        return value

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

        if not Path(self.__msg_file).exists() or overwrite:
            self.write_value(self.__msg_file, self.encrypt(message, key))

    def write_value(self, path, value):
        path = Path(path)

        try:
            value = value.encode()
        except AttributeError:
            pass

        if path.exists():
            path.write_bytes(value)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)

            if self.uid > -1 or self.gid > -1:
                os.chown(str(path), self.uid, self.gid)

            os.chmod(str(path), self.mode)
