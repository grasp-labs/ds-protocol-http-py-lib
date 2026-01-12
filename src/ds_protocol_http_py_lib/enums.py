"""
Constants for HTTP protocol.
"""

from enum import StrEnum


class ResourceKind(StrEnum):
    """
    Constants for HTTP protocol.
    """

    LINKED_SERVICE = "DS.RESOURCE.LINKED-SERVICE.HTTP"
    DATASET = "DS.RESOURCE.DATASET.HTTP"
