"""Access to all BRP views"""

# Split in a package for easier maintenance
from .bewoningen import BrpBewoningenView
from .index import IndexView
from .personen import BrpPersonenView
from .verblijfplaatshistorie import BrpVerblijfplaatshistorieView

__all__ = (
    "IndexView",
    "BrpPersonenView",
    "BrpBewoningenView",
    "BrpVerblijfplaatshistorieView",
)
