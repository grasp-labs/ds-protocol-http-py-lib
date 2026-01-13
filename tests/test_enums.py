"""
**File:** ``test_enums.py``
**Region:** ``tests/test_enums``

Enum contract tests.

Covers:
- Stability of ResourceKind string values.
- String-like behavior for serialization and logging.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.enums import ResourceKind


def test_resource_kind_values_are_stable() -> None:
    """
    It defines stable string values for resource kinds.
    """

    assert ResourceKind.LINKED_SERVICE == "DS.RESOURCE.LINKED_SERVICE.HTTP"
    assert ResourceKind.DATASET == "DS.RESOURCE.DATASET.HTTP"


def test_resource_kind_is_string_like() -> None:
    """
    It behaves like a string for serialization purposes.
    """

    assert str(ResourceKind.DATASET) == "DS.RESOURCE.DATASET.HTTP"
