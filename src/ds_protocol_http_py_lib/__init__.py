"""
A Python package from the ds-protocol library collection.

**File:** ``__init__.py``
**Region:** ``ds-protocol-http-py-lib``

Example:

.. code-block:: python

    from ds_protocol_http_py_lib import __version__

    print(f"Package version: {__version__}")
"""

from pathlib import Path

PACKAGE_NAME = "ds-protocol-http-py-lib"
_VERSION_FILE = Path(__file__).parent.parent.parent / "VERSION.txt"
__version__ = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "0.0.0"

from .dataset import HttpDataset, HttpDatasetTypedProperties  # noqa: E402
from .linked_service import HttpLinkedService, HttpLinkedServiceTypedProperties  # noqa: E402

__all__ = [
    "HttpDataset",
    "HttpDatasetTypedProperties",
    "HttpLinkedService",
    "HttpLinkedServiceTypedProperties",
]
