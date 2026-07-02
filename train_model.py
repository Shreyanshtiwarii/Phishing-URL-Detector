import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

# Remove text columns
df = df.drop(columns=[
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
])

# Features
X = df.drop("label", axis=1)

# Target
y = df["label"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, "model.pkl")

print("Model saved as model.pkl")