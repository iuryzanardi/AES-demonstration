import secrets
from cryptography.fernet import Fernet
import base64
from typing import Tuple

def generate_key() -> bytes:
    """
    Gera uma chave criptográfica com 32 bytes e codifica como base64.
    """
    key = secrets.token_bytes(32)
    fernet_key = base64.urlsafe_b64encode(key)
    return fernet_key

def encrypt_message(message: str, key: bytes) -> bytes:
    """
    Criptografa uma mensagem com a chave fornecida.
    """
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """
    Descriptografa uma mensagem criptografada com a chave fornecida.
    """
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def run_simulation(message: str) -> None:
    """
    Executa uma simulação de criptografia e descriptografia de mensagem
    com uma chave gerada aleatoriamente.
    """
    key = generate_key()
    encrypted_message = encrypt_message(message, key)
    decrypted_message = decrypt_message(encrypted_message, key)
    print("Mensagem original:", message)
    print("Mensagem criptografada:", encrypted_message)
    print("Mensagem descriptografada:", decrypted_message)

if __name__ == '__main__':
    message = "testando 123"
    run_simulation(message)

