import os
import json
import base64
import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ARGON_MEMORY = 1024 * 64     # 64 MB 
ARGON_TIME = 3               # 3 iterações
ARGON_PARALLELISM = 2
KEY_LEN = 32                 # 256 bits
SALT_LEN = 16
NONCE_LEN = 12


def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva uma chave a partir da senha mestra usando Argon2id (muito seguro)."""
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID
    )

def encrypt(password: str, vault_dict: dict) -> bytes:
    """Cifra o vault (JSON) usando AES-256-GCM."""
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(vault_dict).encode()

    ciphertext = aes.encrypt(nonce, plaintext, None)

    package = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return json.dumps(package).encode()

def decrypt(password: str, blob: bytes) -> dict:
    """Descriptografa o vault usando AES-256-GCM + Argon2id."""
    package = json.loads(blob.decode())

    salt = base64.b64decode(package["salt"])
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])

    key = derive_key(password, salt)
    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Senha mestra incorreta ou arquivo corrompido")

    return json.loads(plaintext.decode())


def init_vault(path: str, password: str):
    if os.path.exists(path):
        raise FileExistsError("Arquivo já existe.")

    empty = {"entries": {}}
    encrypted = encrypt(password, empty)

    with open(path, "wb") as f:
        f.write(encrypted)

    print("Cofre criado com sucesso.")

def load_vault(path: str, password: str):
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt(password, blob)

def save_vault(path: str, password: str, data: dict):
    blob = encrypt(password, data)
    with open(path, "wb") as f:
        f.write(blob)

def add_entry(path: str, password: str, label: str, username: str, pwd: str):
    vault = load_vault(path, password)
    vault["entries"][label] = {"user": username, "password": pwd}
    save_vault(path, password, vault)
    print("Entrada salva.")

def get_entry(path: str, password: str, label: str):
    vault = load_vault(path, password)
    print(json.dumps(vault["entries"].get(label, "Não existe"), indent=2))

def list_entries(path: str, password: str):
    vault = load_vault(path, password)
    print("\n".join(vault["entries"].keys()))

#  CLI

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Vault Seguro - AES-256 + Argon2id")
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("init")
    s.add_argument("file")

    s = sub.add_parser("add")
    s.add_argument("file")
    s.add_argument("label")
    s.add_argument("user")
    s.add_argument("pwd")

    s = sub.add_parser("get")
    s.add_argument("file")
    s.add_argument("label")

    s = sub.add_parser("list")
    s.add_argument("file")

    args = parser.parse_args()

    try:
        if args.cmd == "init":
            pw = getpass.getpass("Senha mestra: ")
            init_vault(args.file, pw)

        elif args.cmd == "add":
            pw = getpass.getpass("Senha mestra: ")
            add_entry(args.file, pw, args.label, args.user, args.pwd)

        elif args.cmd == "get":
            pw = getpass.getpass("Senha mestra: ")
            get_entry(args.file, pw, args.label)

        elif args.cmd == "list":
            pw = getpass.getpass("Senha mestra: ")
            list_entries(args.file, pw)

        else:
            parser.print_help()

    except Exception as e:
        print("Erro:", e)

if __name__ == "__main__":
    main()
