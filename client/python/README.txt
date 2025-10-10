# Secure Chat Client (Python)

This is a lightweight interactive client for the SOCP-based secure chat system.  
It connects to the server over WebSockets, loads user keys, and speaks the **User ↔ Server** protocol.

---

## Requirements

- Python **3.10+**
- Dependencies (install with `pip`):

```bash
pip install websockets cryptography

# How to run (temporary format)
python3 client/python/client.py --server ws://127.0.0.1:8080/ws --user-id alice

# change user password

python3 client/python/password_changer.py --user david --password 'david123'

--server → WebSocket server URI

--user-id → Username (e.g., alice, must match key files)

--password → Currently unused (placeholder for later)


