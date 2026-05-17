#!/usr/bin/env bash
set -e

echo "=== EnvShield E2E Test ==="

# 1. Create a dummy .env file
echo "Creating dummy .env file..."
cat << 'EOF' > .env
SECRET_API_KEY="sk_live_super_secret_value_12345"
DB_PASSWORD=my_secure_password
EOF

# 2. Run the CLI
echo "Running CLI to encrypt .env..."
python3 cli/envshield-cli.py --file .env

echo ""
echo "Contents of .env.enc:"
cat .env.enc
echo ""

# 3. Create a test Python script
cat << 'EOF' > test_script.py
import os
import sys

# Add python/ to sys.path so we can import envshield
sys.path.insert(0, os.path.abspath('python'))
import envshield

print("Python Decrypted SECRET_API_KEY:", os.environ.get('SECRET_API_KEY'))
print("Python Decrypted DB_PASSWORD:", os.environ['DB_PASSWORD'])
EOF

echo "Running Python test..."
python3 test_script.py

# 4. Create a test Node script
cat << 'EOF' > test_script.js
// require node/envshield.js which automatically intercepts process.env
require('./node/envshield');

console.log("Node Decrypted SECRET_API_KEY:", process.env.SECRET_API_KEY);
console.log("Node Decrypted DB_PASSWORD:", process.env.DB_PASSWORD);
EOF

echo "Running Node test..."
node test_script.js

echo "5. Compiling and running C test..."
gcc -o test_c test.c c/envshield.c -lssl -lcrypto
./test_c

echo "=== All Tests Passed ==="
