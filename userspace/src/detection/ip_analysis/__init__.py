"""IP behavioral analysis: threat profiling and scoring"""

from .analyzer import IPAnalyzer
from .models import IPProfile

__all__ = [
    "IPAnalyzer",
    "IPProfile",
]
