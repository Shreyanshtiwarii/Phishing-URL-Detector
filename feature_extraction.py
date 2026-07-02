"""
Shared URL feature-extraction logic.

IMPORTANT: This module is imported by BOTH the training script
(train_url_model.py) and the runtime detector (ml_detector.py) so that
the model is always trained and scored on identically-computed features.

Previously, the runtime detector defined its own copy of this logic while
the model was trained on the dataset's own pre-computed columns (built with
a different, unknown methodology). That mismatch meant the model was being
fed feature values at prediction time that did not resemble anything it saw
during training, which is why real-world URLs were being classified almost
at random (in practice, nearly always "Legitimate"). Centralizing the logic
here and retraining against it (see train_url_model.py) fixes that at the
source.
"""

import re
from urllib.parse import urlparse

import pandas as pd

FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]

_IP_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}")


def extract_features_dict(url: str) -> dict:
    """Compute the numeric feature dict for a single URL."""

    parsed = urlparse(url)
    domain = parsed.netloc
    length = len(url) if url else 1  # guard against div-by-zero below

    return {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": 1 if _IP_PATTERN.search(domain) else 0,
        "TLDLength": len(domain.split(".")[-1]) if "." in domain else 0,
        "NoOfSubDomain": max(0, len(domain.split(".")) - 2),
        "HasObfuscation": 1 if "%" in url else 0,
        "NoOfObfuscatedChar": url.count("%"),
        "ObfuscationRatio": url.count("%") / length,
        "NoOfLettersInURL": sum(c.isalpha() for c in url),
        "LetterRatioInURL": sum(c.isalpha() for c in url) / length,
        "NoOfDegitsInURL": sum(c.isdigit() for c in url),
        "DegitRatioInURL": sum(c.isdigit() for c in url) / length,
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": sum(not c.isalnum() for c in url),
        "SpacialCharRatioInURL": sum(not c.isalnum() for c in url) / length,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }


def extract_features(url: str) -> pd.DataFrame:
    """Compute the feature row as a single-row DataFrame, ready for the model."""
    return pd.DataFrame([extract_features_dict(url)], columns=FEATURE_COLUMNS)
