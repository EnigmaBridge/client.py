# [Enigma Bridge] Python client

With this repo you can use [Enigma Bridge] encryption service.

## Usage

Calling processData():

```python
from ebclient.process_data import ProcessData
from ebclient.uo import Configuration, Endpoint, SimpleRetry, UO
from ebclient.crypto_util import *

# Construct general configuration (endpoint, request config)
cfg = Configuration()
cfg.endpoint_process = Endpoint.url('https://site2.enigmabridge.com:11180')
cfg.api_key = 'API_TEST'
cfg.retry = SimpleRetry()

# UO you want to work with
uo_aes = UO(uo_id=0xee01,
            uo_type=0x4,
            enc_key=from_hex('e134567890123456789012345678901234567890123456789012345678901234'),
            mac_key=from_hex('e224262820223456789012345678901234567890123456789012345678901234'),
            configuration=cfg)

# ProcessData itself
pd = ProcessData(uo=uo_aes, config=cfg)
result = pd.call(from_hex('6bc1bee22e409f96e93d7e117393172a'))
```

For more usage examples please refer to tests.

## Dependencies

```bash
pip install pycrypto requests
```

Or to install to home directory

```bash
pip install --user pycrypto requests
```

If the error `ImportError: No module named Crypto` is thrown it's needed to run pip with `--upgrade` and update pycrypto
to the latest version.

## Compatibility
We should be compatible with Python 2.6+ and Python 3+.

[Enigma Bridge]: https://www.enigmabridge.com
