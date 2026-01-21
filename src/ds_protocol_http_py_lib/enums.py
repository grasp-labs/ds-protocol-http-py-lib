"""
**File:** ``enums.py``
**Region:** ``ds_protocol_http_py_lib/enums``

Constants for HTTP protocol.

Example:
    >>> ResourceType.LINKED_SERVICE
    'DS.RESOURCE.LINKED_SERVICE.HTTP'
    >>> ResourceType.DATASET
    'DS.RESOURCE.DATASET.HTTP'
"""

from enum import StrEnum


class ResourceType(StrEnum):
    """
    Constants for HTTP protocol.
    """

    LINKED_SERVICE = "DS.RESOURCE.LINKED_SERVICE.HTTP"
    DATASET = "DS.RESOURCE.DATASET.HTTP"
