import google.generativeai as genai
import os

api_key = "AIzaSyDp3px1sCmsABBeUt-GP-hOjOCNmz4k6lg"
genai.configure(api_key=api_key)

try:
    print("Available models:")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print("Error:", e)
