"""
Outils de cryptographie du projet.

Ce module permet :
- de générer une clé de chiffrement symétrique ;
- de chiffrer une chaîne de caractères ;
- de déchiffrer une chaîne de caractères.

La librairie cryptography/Fernet est utilisée
afin d'éviter d'implémenter nous-mêmes
des primitives cryptographiques sensibles.
"""

from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """
    Génère une nouvelle clé Fernet.

    Retour
    ------
    bytes
        Clé de chiffrement.
    """

    return Fernet.generate_key()


def encrypt_text(
    text: str,
    key: bytes
) -> str:
    """
    Chiffre une chaîne de caractères.

    Paramètres
    ----------
    text : str
        Texte à chiffrer.

    key : bytes
        Clé Fernet.

    Retour
    ------
    str
        Texte chiffré.
    """

    if text is None:
        raise ValueError(
            "Le texte à chiffrer ne peut pas être None."
        )

    fernet = Fernet(key)

    encrypted = fernet.encrypt(
        text.encode("utf-8")
    )

    return encrypted.decode("utf-8")


def decrypt_text(
    encrypted_text: str,
    key: bytes
) -> str:
    """
    Déchiffre une chaîne chiffrée avec Fernet.

    Paramètres
    ----------
    encrypted_text : str
        Texte chiffré.

    key : bytes
        Clé Fernet utilisée lors du chiffrement.

    Retour
    ------
    str
        Texte original.
    """

    if encrypted_text is None:
        raise ValueError(
            "Le texte chiffré ne peut pas être None."
        )

    fernet = Fernet(key)

    decrypted = fernet.decrypt(
        encrypted_text.encode("utf-8")
    )

    return decrypted.decode("utf-8")