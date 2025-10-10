import os
import sys
import json
import time
import base64
import hashlib
import asyncio
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# --- utils (copy from client or import them) ---
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_to_bytes(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def rsa_oaep_encrypt_b64u(recipient_pub_spki_b64u: str, plaintext: bytes) -> str:
    pubkey = serialization.load_der_public_key(b64url_to_bytes(recipient_pub_spki_b64u))
    ct = pubkey.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return b64url(ct)

def rsa_oaep_decrypt(privkey, ciphertext_b64u: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return privkey.decrypt(
        b64url_to_bytes(ciphertext_b64u),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


# --- file transfer functions ---
CHUNK_SIZE = 446

# ----------------------------
# Sender side
# ----------------------------
async def send_file(ws, sender_uuid, target_uuid, target_pub_enc, user_keys, file_path, mode="dm"):
    """
    Implements:
      FILE_START
      FILE_CHUNK
      FILE_END
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print(f"File '{file_path}' not found")
        return

    file_id = os.urandom(8).hex()
    size = path.stat().st_size
    name = path.name

    # sha256
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    sha256_hex = h.hexdigest()

    ts = int(time.time() * 1000)
    start_frame = {
        "type": "FILE_START",
        "from": sender_uuid,
        "to": target_uuid,
        "ts": ts,
        "payload": {
            "file_id": file_id,
            "name": name,
            "size": size,
            "sha256": sha256_hex,
            "mode": mode
        }
    }
    await ws.send(json.dumps(start_frame))
    print(f"Sent FILE_START for {name} ({size} bytes)")

    # send chunks
    index = 0
    sent_bytes = 0
    total_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
    start_time = time.time()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            ciphertext_b64u = rsa_oaep_encrypt_b64u(target_pub_enc, chunk)
            frame = {
                "type": "FILE_CHUNK",
                "from": sender_uuid,
                "to": target_uuid,
                "ts": int(time.time() * 1000),
                "payload": {
                    "file_id": file_id,
                    "index": index,
                    "ciphertext": ciphertext_b64u
                }
            }
            await ws.send(json.dumps(frame))
            index += 1
            sent_bytes += len(chunk)

            # Progress bar
            elapsed = time.time() - start_time
            speed = sent_bytes / elapsed if elapsed > 0 else 0
            remaining = (size - sent_bytes) / speed if speed > 0 else 0
            progress = sent_bytes / size
            bar_len = 30
            filled = int(bar_len * progress)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(
                f"\rSending {name}: |{bar}| {progress*100:6.2f}% "
                f"({sent_bytes}/{size} bytes) {speed/1024:6.1f} KB/s ETA {remaining:4.1f}s"
            )
            sys.stdout.flush()

    sys.stdout.write("\n")
    end_frame = {
        "type": "FILE_END",
        "from": sender_uuid,
        "to": target_uuid,
        "ts": int(time.time() * 1000),
        "payload": {"file_id": file_id}
    }
    await ws.send(json.dumps(end_frame))
    print(f"Sent FILE_END for {name} ({index} chunks)")


# ----------------------------
# Receiver side
# ----------------------------
active_downloads = {}  # file_id → {"path": Path, "chunks": {}, "size": int, "sha256": str, "name": str, "sender": str}

async def handle_file_frame(frame, user_keys, download_dir="./downloads"):
    t = frame.get("type")
    payload = frame.get("payload", {})
    from_user = frame.get("from")
    ts = frame.get("ts", 0)

    if t == "FILE_START":
        file_id = payload.get("file_id")
        name = payload.get("name", "unknown")
        size = payload.get("size", 0)
        sha256 = payload.get("sha256")
        mode = payload.get("mode", "dm")

        save_dir = Path(download_dir) / from_user
        save_dir.mkdir(parents=True, exist_ok=True)
        temp_path = save_dir / f"{file_id}_{name}"

        active_downloads[file_id] = {
            "path": temp_path,
            "chunks": {},
            "size": size,
            "sha256": sha256,
            "name": name,
            "sender": from_user,
            "mode": mode,
            "start_time": time.time()
        }
        print(f"\n[FILE_START] from={from_user} name={name} size={size} mode={mode}")

    elif t == "FILE_CHUNK":
        file_id = payload.get("file_id")
        idx = payload.get("index")
        ct_b64u = payload.get("ciphertext")

        rec = active_downloads.get(file_id)
        if not rec:
            print(f"[FILE_CHUNK] unknown file_id={file_id}")
            return

        try:
            pt = rsa_oaep_decrypt(user_keys.enc_private, ct_b64u)
        except Exception as e:
            print(f"[FILE_CHUNK] decrypt error for file_id={file_id} index={idx}: {e}")
            return

        rec["chunks"][idx] = pt

        # Progress bar
        received_bytes = sum(len(c) for c in rec["chunks"].values())
        elapsed = time.time() - rec["start_time"]
        speed = received_bytes / elapsed if elapsed > 0 else 0
        remaining = (rec["size"] - received_bytes) / speed if speed > 0 else 0
        progress = received_bytes / rec["size"] if rec["size"] > 0 else 0
        bar_len = 30
        filled = int(bar_len * progress)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(
            f"\rReceiving {rec['name']}: |{bar}| {progress*100:6.2f}% "
            f"({received_bytes}/{rec['size']} bytes) {speed/1024:6.1f} KB/s ETA {remaining:4.1f}s"
        )
        sys.stdout.flush()

    elif t == "FILE_END":
        file_id = payload.get("file_id")
        rec = active_downloads.pop(file_id, None)
        if not rec:
            print(f"[FILE_END] unknown file_id={file_id}")
            return

        sys.stdout.write("\n")  # finish the line

        ordered = [rec["chunks"][i] for i in sorted(rec["chunks"].keys())]
        data = b"".join(ordered)

        # Verify integrity
        sha = hashlib.sha256(data).hexdigest()
        if sha != rec["sha256"]:
            print(f"[FILE_END] SHA256 mismatch! expected={rec['sha256']} got={sha}")
        else:
            with open(rec["path"], "wb") as f:
                f.write(data)
            print(f"[FILE_END] Saved! {rec['path']} ({len(data)} bytes)")

    else:
        print(f"[FILE] unknown type {t}")