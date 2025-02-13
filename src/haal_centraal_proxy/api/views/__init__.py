"""Access to all BRP views"""

# Split in a package for easier maintenance
from .bewoningen import BrpBewoningenView
from .personen import BrpPersonenView
from .verblijfplaatshistorie import BrpVerblijfsplaatsHistorieView

__all__ = (
    "BrpPersonenView",
    "BrpBewoningenView",
    "BrpVerblijfsplaatsHistorieView",
)
