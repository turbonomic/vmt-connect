# vmt-connect: Turbonomic API Connection Wrapper

*vmt-connect* is a user-friendly wrapper around the second generation Turbonomic
API. The wrapper provides useful helper functions for handling general tasks within
the API, such as searching, filtering, and error checking. This module is not
intended to be a full API client implementation.


## Installation

```bash
pip install vmtconnect
```

## Usage

```python
import vmtconnect as vc

conn = vc.Connection('localhost', 'administrator', '<password>')
vms = conn.get_virtualmachines()
print([x['displayName'] for x in vms])
```

## Documentation

The [user guide](https://turbonomic.github.io/vmt-connect/userguide.html) is a
good place to start. Detailed documentation is also available [here](https://turbonomic.github.io/vmt-connect).
