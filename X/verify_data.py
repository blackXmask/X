import pandas as pd

# =========================
# 1. Load dataset
# =========================
df = pd.read_csv("data/raw/web_attack_dataset.csv")

# =========================
# 2. Preview data
# =========================
print("\n🔵 FIRST 5 ROWS:\n")
print(df.head())

# =========================
# 3. Check shape
# =========================
print("\n🔵 DATASET SHAPE (rows, columns):")
print(df.shape)

# =========================
# 4. Check columns
# =========================
print("\n🔵 COLUMNS IN DATASET:")
print(df.columns)

# =========================
# 5. Label distribution
# =========================
print("\n🔵 LABEL DISTRIBUTION:")
print(df["label_name"].value_counts())

# =========================
# 6. Basic statistics
# =========================
print("\n🔵 DATASET STATISTICS:")
print(df.describe())

# =========================
# 7. Check missing values
# =========================
print("\n🔵 MISSING VALUES:")
print(df.isnull().sum())

# =========================
# 8. Check feature uniqueness (VERY IMPORTANT)
# =========================
print("\n🔵 UNIQUE VALUES PER COLUMN (top 10):")
print(df.nunique().sort_values(ascending=False).head(10))

# =========================
# 9. Check feature variation by class
# =========================
print("\n🔵 MEAN payload_length PER CLASS:")
if "payload_length" in df.columns:
    print(df.groupby("label_name")["payload_length"].mean())

# =========================
# 10. Check correlation with label
# =========================
print("\n🔵 FEATURE CORRELATION WITH LABEL:")
print(df.corr(numeric_only=True)["label"].sort_values(ascending=False))