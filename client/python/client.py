#!/usr/bin/env python3
import argparse
import asyncio
import base64
import json
import time
import getpass
from pathlib import Path

import bcrypt
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from file_transfer import handle_file_frame
from file_transfer import send_file

# -----------------------------
# Paths / DB
# -----------------------------
def user_keys_path() -> Path:
    return Path(__file__).resolve().parent / "../../data/user-keys.json"

def load_user_db():
    db_path = user_keys_path()
    with open(db_path, "r") as f:
        return json.load(f)

def find_user_uuid_by_name(name, user_db):
    for uuid, info in user_db.items():
        if info.get("name") == name:
            return uuid, info
    raise ValueError(f"User '{name}' not found in data/user-keys.json")

def find_user_name_by_uuid(uuid, user_db):
    """Lookup username by UUID."""
    entry = user_db.get(uuid)
    return entry.get("name") if entry else "Unknown"

# -----------------------------
# Base64url helpers
# -----------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_to_bytes(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

# -----------------------------
# Keys loader
# -----------------------------
class UserKeys:
    def __init__(self, username):
        keydir = Path(__file__).resolve().parent / "../../server/src/main/resources/config/keys/users_by_name"
        with open(keydir / f"{username}_sign_private.pem", "rb") as f:
            self.sign_private = serialization.load_pem_private_key(f.read(), password=None)
        with open(keydir / f"{username}_enc_private.pem", "rb") as f:
            self.enc_private = serialization.load_pem_private_key(f.read(), password=None)
        self.sign_public = self.sign_private.public_key()
        self.enc_public = self.enc_private.public_key()

def pubkey_to_b64url(pubkey) -> str:
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64url(der)

def load_pubkey_from_b64url_spki(spki_b64u: str):
    der = b64url_to_bytes(spki_b64u)
    return serialization.load_der_public_key(der)

# -----------------------------
# Crypto ops per SOCP 1.3
# -----------------------------
def rsa_pss_sign_fixed32(privkey, data: bytes) -> str:
    sig = privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return b64url(sig)

def rsa_pss_verify_fixed32(pubkey, data: bytes, sig_b64u: str) -> bool:
    try:
        pubkey.verify(
            b64url_to_bytes(sig_b64u),
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def rsa_oaep_encrypt_b64u(recipient_pub_spki_b64u: str, plaintext: bytes) -> str:
    pubkey = load_pubkey_from_b64url_spki(recipient_pub_spki_b64u)
    ct = pubkey.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return b64url(ct)

def rsa_oaep_decrypt(privkey, ciphertext_b64u: str) -> bytes:
    return privkey.decrypt(
        b64url_to_bytes(ciphertext_b64u),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

# -----------------------------
# Password verification (read-only)
# -----------------------------
def verify_password(user_name: str, user_info: dict) -> bool:
    stored_hash = user_info.get("pwd_hash")
    if not stored_hash or not isinstance(stored_hash, str) or not stored_hash.startswith("$2"):
        print("This user has no valid 'pwd_hash' in data/user-keys.json. "
              "Please set it first (e.g., via your password setup script).")
        return False

    entered = getpass.getpass(f"Enter password for {user_name}: ")
    if not bcrypt.checkpw(entered.encode("utf-8"), stored_hash.encode("utf-8")):
        print("Password incorrect.")
        return False

    print("Password verified locally.")
    return True

# -----------------------------
# Client logic
# -----------------------------
async def interactive_client(uri, user_name, user_uuid, user_info, user_keys, user_db):
    if not verify_password(user_name, user_info):
        return

    async with websockets.connect(uri) as ws:
        print(f"Connected to {uri}")

        hello = {
            "type": "USER_HELLO",
            "from": user_uuid,
            "to": "server",
            "ts": int(time.time() * 1000),
            "payload": {
                "client": "cli-v1",
                "pubkey": pubkey_to_b64url(user_keys.sign_public),
                "enc_pubkey": pubkey_to_b64url(user_keys.enc_public),
            },
        }
        await ws.send(json.dumps(hello))
        print("Sent USER_HELLO (password validated locally).")

        async def recv_loop():
            try:
                async for msg in ws:
                    try:
                        data = json.loads(msg)
                        t = data.get("type")
                        if t == "USER_DELIVER":
                            await handle_user_deliver(data, user_keys, user_db)
                        elif t == "LIST_RESULT":
                            users = data["payload"].get("users", [])
                            print(f"\n[ONLINE USERS] ({len(users)})")
                            for u in users:
                                uid = u["user_id"]
                                server = u["server_id"]
                                user_entry = user_db.get(uid)
                                username = user_entry.get("name") if user_entry else "Unknown"
                                print(f"- {uid} [{username}] @ {server}")
                        elif t == "MSG_PUBLIC_CHANNEL":
                            await handle_public_channel(data, user_db)
                        elif t == "PUBLIC_CHANNEL_KEY_SHARE":
                            await handle_public_key_share(data)
                        elif t == "PUBLIC_CHANNEL_KEY_TO_CLIENT":
                            await handle_public_channel_key_to_client(data)
                        elif t == "USER_WELCOME":
                            await handle_user_welcome(data)
                        elif t in ("FILE_START", "FILE_CHUNK", "FILE_END"):
                            await handle_file_frame(data, user_keys)
                        elif t == "ERROR":
                            await handle_server_error(data)
                        else:
                            print(f"\n[SERVER] {json.dumps(data, indent=2)}")
                    except Exception:
                        print(f"\n[SERVER RAW] {msg}")
            except websockets.ConnectionClosed:
                print("Server closed connection")

        async def send_loop():
            while True:
                try:
                    line = await asyncio.get_event_loop().run_in_executor(None, input, "> ")
                except EOFError:
                    break

                if not line:
                    continue

                if line.startswith("/quit"):
                    await ws.close()
                    break

                elif line.startswith("/list"):
                    frame = {
                        "type": "LIST_USERS",
                        "from": user_uuid,
                        "to": "server",
                        "ts": int(time.time() * 1000),
                        "payload": {}
                    }
                    await ws.send(json.dumps(frame))
                    print("Requested user list")

                elif line.startswith("/tell "):
                    try:
                        _, target_name, text = line.split(" ", 2)
                    except ValueError:
                        print("Usage: /tell <user_name> <text>")
                        continue

                    try:
                        to_uuid, to_info = find_user_uuid_by_name(target_name, user_db)
                    except ValueError as e:
                        print(e)
                        continue

                    ts = int(time.time() * 1000)
                    plaintext = text.encode("utf-8")
                    ciphertext_b64u = rsa_oaep_encrypt_b64u(to_info["enc_pub"], plaintext)
                    to_sign = f"{ciphertext_b64u}|{user_uuid}|{to_uuid}|{ts}".encode("utf-8")
                    content_sig_b64u = rsa_pss_sign_fixed32(user_keys.sign_private, to_sign)
                    frame = {
                        "type": "MSG_DIRECT",
                        "from": user_uuid,
                        "to": to_uuid,
                        "ts": ts,
                        "payload": {
                            "ciphertext": ciphertext_b64u,
                            "sender_pub": user_info["sign_pub"],
                            "content_sig": content_sig_b64u,
                        }
                    }
                    await ws.send(json.dumps(frame))
                    print(f"Sent MSG_DIRECT to {target_name} [{to_uuid}]")

                elif line.startswith("/all "):
                    try:
                        _, text = line.split(" ", 1)
                    except ValueError:
                        print("Usage: /all <text>")
                        continue

                    ts = int(time.time() * 1000)
                    ciphertext = text
                    to_sign = f"{ciphertext}|{user_uuid}|{ts}".encode("utf-8")
                    content_sig_b64u = rsa_pss_sign_fixed32(user_keys.sign_private, to_sign)
                    frame = {
                        "type": "MSG_PUBLIC_CHANNEL",
                        "from": user_uuid,
                        "to": "public",
                        "ts": ts,
                        "payload": {
                            "ciphertext": ciphertext,
                            "sender_pub": user_info["sign_pub"],
                            "content_sig": content_sig_b64u,
                        }
                    }
                    await ws.send(json.dumps(frame))
                    print("Sent to public channel")

                elif line.startswith("/file "):
                    try:
                        _, target_name, path = line.split(" ", 2)
                    except ValueError:
                        print("Usage: /file <user_name> <path>")
                        continue

                    try:
                        to_uuid, to_info = find_user_uuid_by_name(target_name, user_db)
                    except ValueError as e:
                        print(e)
                        continue

                    print(f"Sending file to {target_name} [{to_uuid}] ...")
                    await send_file(ws, user_uuid, to_uuid, to_info["enc_pub"], user_keys, path)

                else:
                    print("Commands: /tell <user_name> <text>, /all <text>, /list, /quit, /file <user> <path>")

        await asyncio.gather(recv_loop(), send_loop())

# -----------------------------
# USER_DELIVER handler
# -----------------------------
async def handle_user_deliver(frame, user_keys, user_db):
    try:
        payload = frame.get("payload", {})
        ciphertext_b64u = payload.get("ciphertext")
        sender_pub_b64u = payload.get("sender_pub")
        content_sig_b64u = payload.get("content_sig")

        from_u = frame.get("from")
        to_u   = frame.get("to")
        ts     = frame.get("ts")

        verify_bytes = f"{ciphertext_b64u}|{from_u}|{to_u}|{ts}".encode("utf-8")
        sender_pub = load_pubkey_from_b64url_spki(sender_pub_b64u)

        ok = rsa_pss_verify_fixed32(sender_pub, verify_bytes, content_sig_b64u)
        if not ok:
            print("\n[DELIVER] ⚠ content_sig verification FAILED — message dropped")
            return

        plaintext = rsa_oaep_decrypt(user_keys.enc_private, ciphertext_b64u).decode("utf-8", errors="replace")
        sender_name = find_user_name_by_uuid(from_u, user_db)
        print("\n[DM] ----------------------------------------")
        print(f"from: {from_u} [{sender_name}]")
        print(f"at  : {ts}")
        print(f"text: {plaintext}")
        print("---------------------------------------------")
    except Exception as e:
        print(f"\n[DELIVER] Error handling USER_DELIVER: {e}")

# -----------------------------
# PUBLIC CHANNEL handlers
# -----------------------------
async def handle_public_channel(frame, user_db):
    try:
        payload = frame.get("payload", {})
        if payload.get("sender") == user_uuid: 
            return
        channel = payload.get("channel", "public")
        sender_uuid = payload.get("sender") or "unknown"
        sender_name = find_user_name_by_uuid(sender_uuid, user_db)
        ts = frame.get("ts")
        text = payload.get("ciphertext") or payload.get("content", "")
        print("\n[PUBLIC] ------------------------------------")
        print(f"channel: {channel}")
        print(f"from   : {sender_uuid} [{sender_name}]")
        print(f"at     : {ts}")
        print(f"text   : {text}")
        print("---------------------------------------------")
    except Exception as e:
        print(f"\n[PUBLIC] Error handling MSG_PUBLIC_CHANNEL: {e}")

async def handle_public_key_share(frame):
    try:
        payload = frame.get("payload", {})
        channel = payload.get("channel_id", "public")
        epoch   = payload.get("epoch")
        alg     = payload.get("alg")
        print(f"\n[PUBLIC] Received key share for channel='{channel}' epoch={epoch} alg={alg}")
    except Exception as e:
        print(f"\n[PUBLIC] Error handling PUBLIC_CHANNEL_KEY_SHARE: {e}")

# -----------------------------
# Additional server message handlers
# -----------------------------
async def handle_public_channel_key_to_client(frame):
    """Handle PUBLIC_CHANNEL_KEY_TO_CLIENT messages from server."""
    # try:
    #     payload = frame.get("payload", {})
    #     channel_id = payload.get("channel_id", "unknown")
    #     epoch = payload.get("epoch", "?")
    #     shares = payload.get("shares", [])
    #     print("\n[CHANNEL KEY UPDATE] -----------------------------")
    #     print(f"Channel : {channel_id}")
    #     print(f"Epoch   : {epoch}")
    #     print(f"Shares  : {len(shares)} share(s)")
    #     if shares:
    #         for i, s in enumerate(shares, 1):
    #             print(f"  - Share {i}: {s}")
    #     print("---------------------------------------------------")
    # except Exception as e:
    #     print(f"[CHANNEL KEY UPDATE] Error: {e}")

async def handle_user_welcome(frame):
    """Handle USER_WELCOME messages from server."""
    try:
        payload = frame.get("payload", {})
        msg = payload.get("msg", "")
        from_server = frame.get("from", "server")
        print("\n[WELCOME] -----------------------------------------")
        print(f"From : {from_server}")
        print(f"Msg  : {msg}")
        print("---------------------------------------------------")
    except Exception as e:
        print(f"[WELCOME] Error: {e}")

async def handle_server_error(frame):
    """Pretty-print structured server errors."""
    try:
        payload = frame.get("payload", {})
        code = payload.get("code", "UNKNOWN")
        detail = payload.get("detail", "No details provided")
        server = frame.get("from", "unknown")
        ts = frame.get("ts")

        print("\n[SERVER ERROR] ------------------------------------")
        print(f"Server : {server}")
        print(f"Code   : {code}")
        print(f"Detail : {detail}")
        print(f"Time   : {ts}")
        print("-----------------------------------------------------")
    except Exception as e:
        print(f"[ERROR HANDLER] Failed to parse error frame: {e}")


# -----------------------------
# Entry
# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="WebSocket server URI (e.g. ws://127.0.0.1:8080/ws)")
    parser.add_argument("--user-id", required=True, help="User name (e.g., alice)")
    args = parser.parse_args()

    db_obj = load_user_db()
    user_uuid, user_info = find_user_uuid_by_name(args.user_id, db_obj["users"])
    keys = UserKeys(args.user_id)

    asyncio.run(interactive_client(args.server, args.user_id, user_uuid, user_info, keys, db_obj["users"]))
