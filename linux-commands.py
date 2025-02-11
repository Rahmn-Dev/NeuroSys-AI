from datasets import load_dataset

# Load dataset dari Hugging Face
ds = load_dataset("mrheinen/linux-commands")

# Cek contoh data
print(ds["train"][0])
