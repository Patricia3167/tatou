from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
from pgpy import PGPKey, PGPMessage
import requests
import base64
import json

# --- Config ---
IDENTITY = "GroupTest"
SERVER_URL = "http://localhost:5000"
CLIENT_KEYS_DIR = "C:/Users/Axel/Documents/GitHub/tatou/server/keys"
SERVER_PUB_KEY = "C:/Users/Axel/Documents/tatou-keypair/server_pub.asc"
CLIENT_PRIV_KEY = "C:/Users/Axel/Documents/GitHub/tatou/server/keys/GroupTest_priv.asc"
SERVER_PRIV_KEY = "C:/Users/Axel/Documents/tatou-keypair/server_priv.asc"
CLIENT_PASSPHRASE = "GroupTest"  # Update if needed

# --- Setup ---
identity_manager = IdentityManager(
    client_keys_dir=CLIENT_KEYS_DIR,
    server_public_key_path=SERVER_PUB_KEY,
    server_private_key_path=SERVER_PRIV_KEY
)
rmap_client = RMAP(identity_manager)

# --- Message 1 ---
nonce_client = 12345678
msg1_plain = {"nonceClient": nonce_client, "identity": IDENTITY}
msg1 = {
    "payload": {
        "payload": identity_manager.encrypt_for_server(msg1_plain)
    }
}

res1 = requests.post(f"{SERVER_URL}/rmap-initiate", json=msg1)
assert res1.status_code == 200, f"Message 1 failed: {res1.text}"

resp_json = res1.json()
print("Response from /rmap-initiate:", resp_json)

resp1_payload = resp_json["payload"]
assert isinstance(resp1_payload, str), "Expected base64 string in 'payload'"

# --- Decrypt Message 1 Response ---
armored = base64.b64decode(resp1_payload)
pgp = PGPMessage.from_blob(armored)
client_priv, _ = PGPKey.from_file(CLIENT_PRIV_KEY)

if client_priv.is_protected:
    with client_priv.unlock(CLIENT_PASSPHRASE):
        decrypted = client_priv.decrypt(pgp)
else:
    decrypted = client_priv.decrypt(pgp)

resp1_data = json.loads(decrypted.message)
nonce_server = resp1_data["nonceServer"]

msg2_plain = {"nonceServer": nonce_server}
encrypted_msg2 = identity_manager.encrypt_for_server(msg2_plain)
msg2 = { "payload": { "payload": encrypted_msg2 } }


print("Sending to /rmap-get-link:", msg2)
res2 = requests.post(f"{SERVER_URL}/rmap-get-link", json=msg2)


# Debug output
print("Response from /rmap-get-link:", res2.text)

# Check for error
if res2.status_code != 200:
    raise Exception(f"Message 2 failed: {res2.text}")

resp2_json = res2.json()
link = resp2_json.get("link")
if link:
    print("✅ Watermarked PDF link:", link)
else:
    print("⚠️ No link returned. Full response:", resp2_json)