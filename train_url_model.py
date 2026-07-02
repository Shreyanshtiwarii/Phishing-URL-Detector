import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

from feature_extraction import extract_features_dict, FEATURE_COLUMNS

# Load dataset (only the columns we actually need)
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])

# IMPORTANT: compute features with the SAME function used at inference time
# (feature_extraction.extract_features_dict), instead of relying on the
# dataset's own pre-computed columns. Those were built with an unknown,
# different methodology, which caused a severe train/inference mismatch -
# the model was effectively being asked to score feature vectors that
# looked nothing like what it was trained on.
feature_rows = [extract_features_dict(u) for u in df["URL"].astype(str)]
X = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)

# Target: PhiUSIIL convention -> 1 = legitimate, 0 = phishing
y = df["label"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

# Train model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train)

# Test model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"\nURL Model Accuracy: {accuracy * 100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Phishing (0)", "Legitimate (1)"]))

# Save model
joblib.dump(model, "url_model.pkl")

print("Saved as url_model.pkl")
