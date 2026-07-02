"""
Multi-signal URL risk engine.

Combines several independent detection techniques into one score, instead
of relying on a single model or a single rule:

  1. The trained ML model (RandomForestClassifier over URL-structure
     features - see feature_extraction.py / train_url_model.py).
  2. Rule-based heuristics: HTTPS presence, IP-based hosts, URL length,
     subdomain count, hyphen/dot counts, suspicious keywords, known
     high-abuse TLDs, URL-shortener/redirect services, obfuscation and
     digit ratios.
  3. Typosquatting detection against a small list of frequently-impersonated
     brands (edit-distance + "brand name appears outside the real domain").
  4. A small allowlist of well-known, unambiguous domains, used only to
     damp obvious false positives on very well-known sites.

Domain age / live blacklist / reputation-API lookups are intentionally left
as an optional extension point (see check_external_reputation below): doing
this for real requires a paid/keyed API (e.g. Google Safe Browsing,
VirusTotal) and outbound network access, neither of which is guaranteed in
every deployment environment. Wiring in a real key later is a one-function
change and does not require touching the rest of the scoring pipeline.
"""

import os
import re
from urllib.parse import urlparse

import joblib

from feature_extraction import extract_features

_MODEL = joblib.load("url_model.pkl")

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "signin", "password",
    "account", "confirm", "banking", "wallet", "billing", "invoice",
    "suspend", "unlock", "reset", "gift", "bonus", "free", "prize",
]

HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "link", "zip", "mov", "loan", "win", "party", "review",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
}

# Free/instant hosting platforms are legitimately used by many hobbyists and
# small projects, but their disposable, auto-generated subdomains are also
# heavily abused for throwaway phishing pages. This contributes a moderate
# (not decisive on its own) signal rather than an outright flag.
FREE_HOSTING_PLATFORMS = {
    "firebaseapp.com", "web.app", "weeblysite.com", "000webhostapp.com",
    "herokuapp.com", "glitch.me", "repl.co", "pages.dev", "netlify.app",
    "vercel.app", "wixsite.com", "xsph.ru", "lima-city.de", "freehostia.com",
}

# Well-known, unambiguous domains used only to damp false positives.
TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "wikipedia.org",
    "apple.com", "amazon.com", "paypal.com", "facebook.com",
    "instagram.com", "netflix.com", "linkedin.com", "twitter.com", "x.com",
    "youtube.com", "mozilla.org", "wordpress.com", "cloudflare.com",
    "adobe.com", "salesforce.com", "dropbox.com", "stackoverflow.com",
}

# Brands frequently impersonated in phishing domains, mapped to their real
# registrable domain(s) for the typosquatting check.
PROTECTED_BRANDS = {
    "google": "google.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "github": "github.com",
    "linkedin": "linkedin.com",
    "outlook": "outlook.com",
    "office365": "office.com",
}

_IP_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
_REDIRECT_PARAM_PATTERN = re.compile(
    r"[?&](redirect|url|next|continue|return|dest|destination)=https?", re.I
)


def _registrable_domain(netloc: str) -> str:
    """Best-effort strip of a leading 'www.' / port for whitelist matching."""
    host = netloc.split("@")[-1].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def check_external_reputation(domain: str):
    """
    Optional extension point for a real domain-age / blacklist / reputation
    API (e.g. Google Safe Browsing, VirusTotal, WHOIS). Only runs if an API
    key is configured via environment variable; otherwise it's a no-op so
    the app never depends on outbound network access to function.

    Returns None (no data) or a dict with keys like
    {"malicious": bool, "score": 0-100, "source": "..."}.
    """
    if not os.environ.get("SAFE_BROWSING_API_KEY"):
        return None

    try:
        import requests  # local import: optional dependency

        # Placeholder for a real Safe Browsing / VirusTotal call.
        # Left unimplemented deliberately - no API key is configured in
        # this environment, and guessing at a paid API's request format
        # would be worse than not calling it.
        return None
    except Exception:
        return None


def _heuristic_score(url: str, parsed, domain: str):
    """Rule-based scoring. Returns (score_0_100, list_of_reason_strings)."""
    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 12
        reasons.append("Connection is not secured with HTTPS")

    if _IP_PATTERN.search(domain):
        score += 20
        reasons.append("Uses a raw IP address instead of a domain name")

    if "@" in url:
        score += 18
        reasons.append("Contains an '@' symbol, often used to disguise the true destination")

    length = len(url)
    if length > 100:
        score += 10
        reasons.append("Unusually long URL")
    elif length > 75:
        score += 5
        reasons.append("Longer than typical URL")

    subdomain_count = max(0, len(domain.split(".")) - 2)
    if subdomain_count >= 3:
        score += 10
        reasons.append("Excessive number of subdomains")

    if url.count("-") >= 3:
        score += 6
        reasons.append("Many hyphens in the URL (common in disguised domains)")

    hits = [w for w in SUSPICIOUS_KEYWORDS if w in url.lower()]
    if hits:
        score += min(12, 4 * len(hits))
        reasons.append(
            "Contains sensitive-sounding keyword(s): " + ", ".join(sorted(set(hits))[:4])
        )

    tld = domain.split(".")[-1].lower() if "." in domain else ""
    if tld in HIGH_ABUSE_TLDS:
        score += 14
        reasons.append(f"Uses a top-level domain (.{tld}) frequently associated with abuse")

    registrable = _registrable_domain(domain)
    if registrable in URL_SHORTENERS:
        score += 12
        reasons.append("Uses a URL-shortening service, which hides the real destination")

    # A domain ending in a free/instant hosting platform's own domain (i.e.
    # the site doesn't have its own registered domain at all).
    for platform in FREE_HOSTING_PLATFORMS:
        if registrable == platform or registrable.endswith("." + platform):
            score += 15
            reasons.append(
                f"Hosted on a free/instant hosting platform ({platform}) rather than its own domain"
            )
            break

    if _REDIRECT_PARAM_PATTERN.search(url):
        score += 8
        reasons.append("Contains a redirect-style parameter pointing to another URL")

    if length > 0:
        digit_ratio = sum(c.isdigit() for c in url) / length
        special_ratio = sum(not c.isalnum() for c in url) / length
        if digit_ratio > 0.3:
            score += 6
            reasons.append("Unusually high proportion of digits")
        if special_ratio > 0.25:
            score += 6
            reasons.append("Unusually high proportion of special characters")

    # Typosquatting: brand name appears in the URL but the registrable
    # domain isn't the brand's real domain (either as a look-alike or as a
    # brand name stuffed into a subdomain/path to look legitimate).
    lowered_domain = registrable
    for brand, real_domain in PROTECTED_BRANDS.items():
        if registrable == real_domain:
            continue
        if brand in url.lower():
            score += 20
            reasons.append(f"Mentions '{brand}' but is not the official {real_domain} domain")
            break
        # near-miss lookalike, e.g. "paypa1.com" vs "paypal.com"
        domain_root = lowered_domain.split(".")[0]
        if domain_root and 0 < _levenshtein(domain_root, brand) <= 2 and len(domain_root) >= 4:
            score += 22
            reasons.append(f"Domain closely resembles '{real_domain}' (possible typosquatting)")
            break

    return min(score, 100), reasons


def analyze_url(url: str) -> dict:
    """
    Run the full multi-signal analysis on a URL and return a result dict:

    {
      "verdict": "Safe" | "Medium Risk" | "Unsafe",
      "emoji": "...",
      "color": bootstrap color name,
      "threat_score": 0-100,
      "confidence_score": 0-100,
      "reasons": [...],
      "explanation": "...",
    }
    """
    url = (url or "").strip()
    parsed = urlparse(url)
    domain = parsed.netloc
    registrable = _registrable_domain(domain)

    try:
        features = extract_features(url)
        proba = _MODEL.predict_proba(features)[0]
        # model.classes_ == [0, 1] -> index 0 = phishing, index 1 = legitimate
        ml_phishing_pct = float(proba[0]) * 100
        ml_ok = True
    except Exception:
        ml_phishing_pct = 50.0  # unknown -> neutral
        ml_ok = False

    heuristic_pct, reasons = _heuristic_score(url, parsed, domain)

    external = check_external_reputation(registrable)
    if external and external.get("malicious"):
        heuristic_pct = max(heuristic_pct, external.get("score", 90))
        reasons.append(f"Flagged by external reputation source ({external.get('source')})")

    # Weighted blend of the ML model and the rule engine. The ML model is
    # very confident even on URLs unlike anything in its training set, so
    # it is deliberately not given a majority weight - a high ML score
    # needs at least some structural corroboration to reach "Unsafe".
    if ml_ok:
        threat_score = round(0.5 * ml_phishing_pct + 0.5 * heuristic_pct)
    else:
        threat_score = round(heuristic_pct)
        reasons.append("ML model unavailable for this URL - relying on rule-based analysis")

    trusted_override = False
    if registrable in TRUSTED_DOMAINS:
        threat_score = min(threat_score, 5)
        trusted_override = True
        reasons.insert(0, "Recognized as a well-known, trusted domain")

    threat_score = max(0, min(100, threat_score))

    # Confidence: how much the ML model and heuristics agree, boosted when
    # a trusted-domain override applies or the ML signal is very decisive.
    if trusted_override:
        confidence_score = 97
    elif ml_ok:
        agreement = 100 - abs(ml_phishing_pct - heuristic_pct)
        decisiveness = abs(ml_phishing_pct - 50) * 2  # 0-100
        confidence_score = round(0.6 * agreement + 0.4 * decisiveness)
    else:
        confidence_score = 55
    confidence_score = max(40, min(99, confidence_score))

    if threat_score < 25:
        verdict, emoji, color = "Safe", "🟢", "success"
    elif threat_score < 60:
        verdict, emoji, color = "Medium Risk", "🟡", "warning"
    else:
        verdict, emoji, color = "Unsafe", "🔴", "danger"

    if not reasons:
        reasons.append("No notable risk indicators were found")

    top_reasons = reasons[:4]
    explanation = "; ".join(top_reasons) + "."

    return {
        "verdict": verdict,
        "emoji": emoji,
        "color": color,
        "threat_score": threat_score,
        "confidence_score": confidence_score,
        "reasons": top_reasons,
        "explanation": explanation,
    }
