"""
A Python package from the ds-common library collection.

**File:** ``__init__.py``
**Region:** ``{{GITHUB_REPO}}``

Example:

.. code-block:: python

    from {{PYTHON_MODULE_NAME}} import __version__

    print(f"Package version: {__version__}")
"""
from pathlib import Path


_VERSION_FILE = Path(__file__).parent.parent.parent / "VERSION.txt"
__version__ = _VERSION_FILE.read_text().strip(
) if _VERSION_FILE.exists() else "0.0.0"

__all__ = ["__version__"]
