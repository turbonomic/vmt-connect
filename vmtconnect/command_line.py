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
# libraries

import argparse
import base64
import json
import os
from pathlib import Path
import sys

from vmtconnect.security import Credential



def cmd():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--basepath',
                        default=os.path.join('.', '.turbo_services_api_creds'),
                        help='Base path for files')
    parser.add_argument('-k', '--keyfile',
                        default='.key',
                        help='Key filename')
    parser.add_argument('-c', '--credfile',
                        default='.cred',
                        help='Credential filename')
    parser.add_argument('-u', '--username',
                        default=None,
                        help='Username')
    parser.add_argument('-p', '--password',
                        default=None,
                        help='Password')
    parser.add_argument('-f', '--force',
                        action='store_true',
                        default=False,
                        help='Replaces the key and credential files if either exists.'
                        )

    args = parser.parse_args()
    cred = Credential(Path(args.basepath, args.keyfile),
                      Path(args.basepath, args.credfile))

    if args.username and args.password:
        msg = base64.b64encode(f"{args.username}:{args.password}".encode()).decode()
    else:
        msg = None

    cred.create(message=msg, overwrite=args.force)



if __name__ == '__main__':
    cmd()
