import os

from app.security.crypto_utils import (
    generate_key,
    encrypt_text,
    decrypt_text,
    load_encryption_key,
    encrypt_sensitive_text,
    decrypt_sensitive_text
)

def test_load_encryption_key(monkeypatch):
    """
    Vérifie que la clé peut être chargée
    depuis une variable d'environnement.
    """

    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

    loaded_key = load_encryption_key()

    assert loaded_key == key

def test_environment_encrypt_decrypt(
    monkeypatch
):
    """
    Vérifie le chiffrement avec la clé
    chargée depuis l'environnement.
    """

    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

    original = "192.168.1.25"

    encrypted = encrypt_sensitive_text(
        original
    )

    decrypted = decrypt_sensitive_text(
        encrypted
    )

    assert encrypted != original
    assert decrypted == original

def test_generate_key():
    """
    Vérifie qu'une clé Fernet peut être générée.
    """

    key = generate_key()

    assert isinstance(key, bytes)
    assert len(key) > 0


def test_encrypt_text():
    """
    Vérifie que le texte chiffré est différent
    du texte original.
    """

    key = generate_key()

    original = "192.168.1.25"

    encrypted = encrypt_text(
        original,
        key
    )

    assert isinstance(encrypted, str)
    assert encrypted != original


def test_encrypt_and_decrypt():
    """
    Vérifie qu'un texte peut être chiffré
    puis correctement déchiffré.
    """

    key = generate_key()

    original = (
        "Adresse IP sensible : 192.168.1.25"
    )

    encrypted = encrypt_text(
        original,
        key
    )

    decrypted = decrypt_text(
        encrypted,
        key
    )

    assert decrypted == original


def test_empty_string():
    """
    Vérifie qu'une chaîne vide peut également
    être chiffrée et déchiffrée.
    """

    key = generate_key()

    encrypted = encrypt_text(
        "",
        key
    )

    decrypted = decrypt_text(
        encrypted,
        key
    )

    assert decrypted == ""