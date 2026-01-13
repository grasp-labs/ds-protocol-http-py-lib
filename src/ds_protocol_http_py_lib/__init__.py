"""
A Python package from the ds-common library collection.

**File:** ``__init__.py``
**Region:** ``ds-protocol-http-py-lib``

Example:

.. code-block:: python

    from ds_protocol_http_py_lib import __version__

    print(f"Package version: {__version__}")
"""

from importlib.metadata import version


__version__ = version("ds-protocol-http-py-lib")
__all__ = ["__version__"]