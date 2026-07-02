from urllib.parse import urlparse
import re

def check_url(url):
    score = 0

    parsed = urlparse(url)

    # HTTPS check
    if parsed.scheme != "https":
        score += 2

    # URL length
    if len(url) > 75:
        score += 1

    # @ symbol
    if '@' in url:
        score += 2

    # Too many hyphens
    if url.count('-') >= 3:
        score += 1

    # Too many dots
    if url.count('.') >= 4:
        score += 1

    # IP address detection
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        score += 2

    # Suspicious words
    suspicious_words = [
        'login',
        'verify',
        'update',
        'secure',
        'signin',
        'password'
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 1

    if score >= 5:
        return "Risk Factors Found: ✓ No HTTPS \n ✓ Contains login keyword \n✓ Contains verify keyword - Phishing Website"
    elif score >= 2:
        return "🟡 Medium Risk - Suspicious Website"
    else:
        return "✅ Low Risk - Likely Safe"