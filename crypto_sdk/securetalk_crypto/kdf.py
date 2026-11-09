"""HKDF-SHA256 (RFC 5869).

Sert a deriver DEUX cles independantes a partir de la SessionKey en mode CMAC :
une cle pour AES-CBC, une autre pour AES-CMAC. Utiliser la meme cle pour deux
usages est une faute classique (guide, section 3.2 point 3).
"""
import hashlib
import hmac


def hkdf_sha256(ikm, info, length, salt=b""):
    if length < 1 or length > 255 * 32:
        raise ValueError("Longueur HKDF invalide")
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()          # extract
    okm = b""
    bloc = b""
    compteur = 1
    while len(okm) < length:                                    # expand
        bloc = hmac.new(prk, bloc + info + bytes([compteur]), hashlib.sha256).digest()
        okm += bloc
        compteur += 1
    return okm[:length]
