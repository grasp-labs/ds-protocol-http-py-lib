"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental``

Incremental rulesets for Paginate (shifting-scope watermark instruction).
"""

from .enums import IncrementalStrategy
from .registry import get_rules, register
from .rules import IncrementalRules
from .settings import IncrementalSettings
from .strategies import NoIncrementalRules, WatermarkRules

__all__ = [
    "IncrementalRules",
    "IncrementalSettings",
    "IncrementalStrategy",
    "NoIncrementalRules",
    "WatermarkRules",
    "get_rules",
    "register",
]
