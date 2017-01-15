`Enigma Bridge <https://www.enigmabridge.com>`__ Python client
==============================================================

With this repo you can use `Enigma
Bridge <https://www.enigmabridge.com>`__ encryption service.

Installation
------------

.. code:: bash

    pip install ebclient.py

Usage
-----

Calling processData():

.. code:: python

    from ebclient.process_data import ProcessData
    from ebclient.uo import Configuration, Endpoint, SimpleRetry, UO
    from ebclient.crypto_util import *

    # Construct general configuration (endpoint, request config)
    cfg = Configuration()
    cfg.endpoint_process = Endpoint.url('https://site2.enigmabridge.com:11180')
    cfg.api_key = 'API_TEST'

    # UO you want to work with
    uo_aes = UO(uo_id=0xee01,
                uo_type=0x4,
                enc_key=from_hex('e134567890123456789012345678901234567890123456789012345678901234'),
                mac_key=from_hex('e224262820223456789012345678901234567890123456789012345678901234'),
                configuration=cfg)

    # ProcessData itself
    pd = ProcessData(uo=uo_aes, config=cfg)
    result = pd.call(from_hex('6bc1bee22e409f96e93d7e117393172a'))
    print(from_hex('95c6bb9b6a1c3835f98cc56087a03e82') == result)

For more usage examples please refer to tests and our `API
documentation <https://api.enigmabridge.com/api/?python>`__.

Dependencies
------------

.. code:: bash

    pip install pycrypto requests

Or to install to home directory

.. code:: bash

    pip install --user pycrypto requests

If the error ``ImportError: No module named Crypto`` is thrown it's
needed to run pip with ``--upgrade`` and update pycrypto to the latest
version.

Compatibility
-------------

We should be compatible with Python 2.6+ and Python 3+.

Troubleshooting
---------------

Error in installation of dependencies (cryptography, pyOpenSSL):
``sorry, but this version only supports 100 named groups``
[`100-named-groups <https://community.letsencrypt.org/t/certbot-auto-fails-while-setting-up-virtual-environment-complains-about-package-hashes/20529/18>`__]

Solution: Install downgraded version of pycparser and pyOpenSSL:

::

    pip install pycparser==2.13
    pip install pyOpenSSL==0.13
    pip install cryptography

You may need to install some deps for the python packages

::

    yum install gcc g++ openssl-devel libffi-devel python-devel

SNI on Python < 2.7.9
~~~~~~~~~~~~~~~~~~~~~

TLS SNI support was added to Python. For earlier versions SNI needs to
be added to Requests networking library.

::

    pip install urllib3
    pip install pyopenssl
    pip install ndg-httpsclient
    pip install pyasn1

Mac OSX installation
~~~~~~~~~~~~~~~~~~~~

For new OSX versions (El Capitan and above) the default system python
installation cannot be modified with standard means. There are some
workarounds, but one can also use ``--user`` switch for pip.

::

    pip install --user cryptography