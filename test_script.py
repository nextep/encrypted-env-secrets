import os
import sys

# Add python/ to sys.path so we can import envshield
sys.path.insert(0, os.path.abspath('python'))
import envshield

print("Python Decrypted SECRET_API_KEY:", os.environ.get('SECRET_API_KEY'))
print("Python Decrypted DB_PASSWORD:", os.environ['DB_PASSWORD'])
