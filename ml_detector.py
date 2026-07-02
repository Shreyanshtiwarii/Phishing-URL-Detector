"""
Thin wrapper around the trained model, kept for backward compatibility
(used by test_ml.py). For the full multi-signal analysis used by the web
app, see risk_engine.analyze_url().
"""

import joblib

from feature_extraction import extract_features

# Load trained model
model = joblib.load("url_model.pkl")


def predict_url(url: str) -> str:
    try:
        features = extract_features(url)
        prediction = model.predict(features)[0]
    except Exception:
        return "⚠️ Unable to Analyze URL"

    # model.classes_ == [0, 1] -> 1 = legitimate, 0 = phishing
    if prediction == 1:
        return "🟢 Legitimate URL"
    else:
        return "🔴 Phishing URL Detected"
