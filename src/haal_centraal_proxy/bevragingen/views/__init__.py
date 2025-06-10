"""Access to all BRP views"""

# Split in a package for easier maintenance
from .bewoningen import BrpBewoningenHealthView, BrpBewoningenView
from .index import IndexView
from .personen import BrpPersonenHealthView, BrpPersonenView
from .verblijfplaatshistorie import (
    BrpVerblijfplaatshistorieHealthView,
    BrpVerblijfplaatshistorieView,
)

__all__ = (
    "IndexView",
    "BrpPersonenView",
    "BrpBewoningenView",
    "BrpBewoningenHealthView",
    "BrpPersonenHealthView",
    "BrpVerblijfplaatshistorieView",
    "BrpVerblijfplaatshistorieHealthView",
)
