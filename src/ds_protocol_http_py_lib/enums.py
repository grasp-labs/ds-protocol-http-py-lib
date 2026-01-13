"""
**File:** ``enums.py``
**Region:** ``ds_protocol_http_py_lib/enums``

Constants for HTTP protocol.

Example:
    >>> ResourceKind.LINKED_SERVICE
    'DS.RESOURCE.LINKED_SERVICE.HTTP'
    >>> ResourceKind.DATASET
    'DS.RESOURCE.DATASET.HTTP'
"""

from enum import StrEnum


class ResourceKind(StrEnum):
    """
    Constants for HTTP protocol.
    """

    LINKED_SERVICE = "DS.RESOURCE.LINKED_SERVICE.HTTP"
    DATASET = "DS.RESOURCE.DATASET.HTTP"
