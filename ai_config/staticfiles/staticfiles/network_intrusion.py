import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# 1. Tentukan folder dataset
dataset_folder = "dataset/dataset CIC-IDS- 2017"

# 2. Ambil semua file CSV di folder
csv_files = [os.path.join(dataset_folder, file) for file in os.listdir(dataset_folder) if file.endswith(".csv")]

# 3. Gabungkan semua CSV jadi satu dataset
df_list = []
for file in csv_files:
    print(f"Loading {file} ...")
    df = pd.read_csv(file, sep=None, engine='python') 
    # print(f"Columns in {file}:", df.columns)  # low_memory=False untuk mencegah warning
    df_list.append(df)



df = pd.concat(df_list, ignore_index=True)
print(f"Total data setelah digabung: {df.shape}")


# 4. Hapus kolom yang tidak relevan (jika ada)
columns_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
df = df.drop(columns=[col for col in columns_to_drop if col in df.columns], errors='ignore')

# 5. Encoding fitur kategorikal (jika ada)
df.columns = df.columns.str.strip()  # Remove leading/trailing spaces
df.columns = df.columns.str.lower()  # Convert to lowercase for consistency

categorical_columns = ['Protocol', 'Flow Flags']
for col in categorical_columns:
    if col in df.columns:
        df[col] = LabelEncoder().fit_transform(df[col])

if 'label' not in df.columns:
    raise KeyError("The column 'Label' was not found in the dataset. Check column names:", df.columns)


# 6. Encoding label (BENIGN = 0, serangan lain = 1)
df['label'] = df['label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# 7. Pisahkan fitur (X) dan label (y)
X = df.drop(columns=["label"])
y = df["label"]

# Check for NaN, inf, or large values
print("Checking for NaN values:", X.isna().sum().sum())
print("Checking for infinite values:", np.isinf(X).sum().sum())
print("Max value in dataset:", X.max().max())

# Replace inf and NaN with 0
# Ensure all values are finite
print("Replacing Inf and NaN values...")
X = X.replace([np.inf, -np.inf], np.nan)  # Convert inf to NaN
X = X.fillna(X.median())  # Fill NaN with median values instead of 0
print("Inf and NaN values replaced.")

print("Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Data split done.")

print("Scaling data...")
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
print("Data scaling done.")

print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("Model training completed.")


# 11. Evaluasi model
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))