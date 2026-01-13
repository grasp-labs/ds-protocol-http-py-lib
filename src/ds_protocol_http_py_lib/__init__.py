"""
A Python package from the ds-protocol library collection.

**File:** ``__init__.py``
**Region:** ``ds-protocol-http-py-lib``

Example:

.. code-block:: python

    from ds_protocol_http_py_lib import __version__

    print(f"Package version: {__version__}")
"""

from importlib.metadata import version

PACKAGE_NAME = "ds-protocol-http-py-lib"
__version__ = version(PACKAGE_NAME)

from .dataset import HttpDataset, HttpDatasetTypedProperties  # noqa: E402
from .linked_service import HttpLinkedService, HttpLinkedServiceTypedProperties  # noqa: E402

__all__ = [
    "HttpDataset",
    "HttpDatasetTypedProperties",
    "HttpLinkedService",
    "HttpLinkedServiceTypedProperties",
    "__version__",
]
