import pandas as pd

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

df = df.drop(columns=[
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
])

print(df.columns)