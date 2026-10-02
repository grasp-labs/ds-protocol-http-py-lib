"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/strategies``
"""

from .none import NoIncrementalRules
from .watermark import WatermarkRules

__all__ = [
    "NoIncrementalRules",
    "WatermarkRules",
]
