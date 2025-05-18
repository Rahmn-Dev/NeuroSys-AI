# run_langflow.py
import os
from dotenv import load_dotenv
import subprocess

# Muat variabel dari .env
load_dotenv()

# Jalankan LangFlow
subprocess.run([
    "langflow",
    "run",
    "--host", "0.0.0.0",
    "--port", "7860"
])
