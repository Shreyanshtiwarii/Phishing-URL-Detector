import pandas as pd

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

print(df["label"].value_counts())
