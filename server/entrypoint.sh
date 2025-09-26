#!/usr/bin/env bash

# --- Check for required key files ---
echo "Checking key files..."

if [ ! -f "$CLIENT_KEYS_DIR/client_pub.asc" ]; then
  echo "Missing client public key at $CLIENT_KEYS_DIR/client_pub.asc"
  exit 1
fi

if [ ! -f "$SERVER_PUBLIC_KEY_PATH" ]; then
  echo "Missing server public key at $SERVER_PUBLIC_KEY_PATH"
  exit 1
fi

if [ ! -f "$SERVER_PRIVATE_KEY_PATH" ]; then
  echo "Missing server private key at $SERVER_PRIVATE_KEY_PATH"
  exit 1
fi

echo "All key files found."

# --- Check FLAG_2 ---
if [[ -z "${FLAG_2:-}" ]]; then
  echo "WARNING: FLAG_2 is not set"
fi

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
    echo "Replacing placeholder in flag with $FLAG_2"
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag
  fi
else
  echo "WARNING: /app/flag not found, skipping"
fi

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 server:app