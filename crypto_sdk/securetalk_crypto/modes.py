"""Modes de fonctionnement AES : CBC + PKCS#7, AES-CMAC (RFC 4493), AES-GCM.

C'est ton code du cours (sections 6, 7, 7 bis, 7 ter). Ces fonctions levent
des ValueError ; c'est packet.py qui les transforme en AuthTagError.
"""
import hmac
import struct

from .aes import chiffre_bloc, dechiffre_bloc, expansion_cle, xor_octets

# ---------------- Padding PKCS#7 ----------------
def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data):
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError("Padding invalide")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding invalide")
    return data[:-n]


# ---------------- Mode CBC ----------------
def cbc_chiffre(clair, cle, iv):
    if len(iv) != 16:
        raise ValueError("IV CBC : 16 octets")
    cles = expansion_cle(cle)
    clair = pad(clair)
    precedent = iv
    chiffre = b""
    for i in range(0, len(clair), 16):
        avant = xor_octets(clair[i: i + 16], precedent)
        c = chiffre_bloc(avant, cles)
        chiffre += c
        precedent = c
    return chiffre


def cbc_dechiffre(chiffre, cle, iv):
    if len(iv) != 16:
        raise ValueError("IV CBC : 16 octets")
    if len(chiffre) == 0 or len(chiffre) % 16 != 0:
        raise ValueError("Le ciphertext doit etre un multiple de 16 octets")
    cles = expansion_cle(cle)
    precedent = iv
    clair = b""
    for i in range(0, len(chiffre), 16):
        c = chiffre[i: i + 16]
        clair += xor_octets(dechiffre_bloc(c, cles), precedent)
        precedent = c
    return unpad(clair)


# ---------------- AES-CMAC (NIST SP 800-38B / RFC 4493) ----------------
TAILLE_TAG = 16


def _decale_gauche(bloc):
    """Multiplication par x dans GF(2^128)."""
    v = int.from_bytes(bloc, "big") << 1
    msb = v >> 128
    v &= (1 << 128) - 1
    if msb:
        v ^= 0x87
    return v.to_bytes(16, "big")


def sous_cles_cmac(cles):
    L = chiffre_bloc(bytes(16), cles)
    k1 = _decale_gauche(L)
    k2 = _decale_gauche(k1)
    return k1, k2


def cmac(message, cle):
    """Tag AES-CMAC (16 octets) de `message` avec la cle AES `cle`."""
    cles = expansion_cle(cle)
    k1, k2 = sous_cles_cmac(cles)
    n = max(1, (len(message) + 15) // 16)
    complet = len(message) > 0 and len(message) % 16 == 0
    dernier = message[16 * (n - 1):]
    if complet:
        m_last = xor_octets(dernier, k1)
    else:
        dernier = dernier + b"\x80" + b"\x00" * (15 - len(dernier))
        m_last = xor_octets(dernier, k2)
    x = bytes(16)
    for i in range(n - 1):
        x = chiffre_bloc(xor_octets(x, message[16 * i: 16 * i + 16]), cles)
    return chiffre_bloc(xor_octets(x, m_last), cles)


def cmac_verifie(tag, message, cle):
    """Verification en temps constant."""
    return hmac.compare_digest(tag, cmac(message, cle))


# ---------------- AES-GCM (NIST SP 800-38D) ----------------
TAILLE_NONCE = 12
TAILLE_TAG_GCM = 16
R_GCM = 0xe1 << 120


def gf128_mul(x, y):
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R_GCM
        else:
            v >>= 1
    return z


def ghash(h, aad, chiffre):
    def bourrage(d):
        return d + b"\x00" * (-len(d) % 16)
    donnees = bourrage(aad) + bourrage(chiffre) + struct.pack(">QQ", len(aad) * 8, len(chiffre) * 8)
    y = 0
    for i in range(0, len(donnees), 16):
        y = gf128_mul(y ^ int.from_bytes(donnees[i:i + 16], "big"), h)
    return y


def _ctr_gcm(data, cles, j0):
    compteur = int.from_bytes(j0[12:], "big")
    prefixe = j0[:12]
    sortie = b""
    for i in range(0, len(data), 16):
        compteur = (compteur + 1) & 0xFFFFFFFF
        flux = chiffre_bloc(prefixe + compteur.to_bytes(4, "big"), cles)
        sortie += xor_octets(data[i:i + 16], flux)
    return sortie


def _prepare_gcm(cle, nonce):
    if len(nonce) != TAILLE_NONCE:
        raise ValueError("Le nonce GCM doit faire 12 octets")
    cles = expansion_cle(cle)
    h = int.from_bytes(chiffre_bloc(bytes(16), cles), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    return cles, h, j0


def gcm_tag(chiffre, cle, nonce, aad=b""):
    """Calcule le tag GCM attendu (16 octets) pour un texte chiffre."""
    cles, h, j0 = _prepare_gcm(cle, nonce)
    s = ghash(h, aad, chiffre).to_bytes(16, "big")
    return xor_octets(s, chiffre_bloc(j0, cles))


def gcm_ctr(data, cle, nonce):
    """Partie CTR seule (chiffre ou dechiffre, c'est la meme operation)."""
    cles, _h, j0 = _prepare_gcm(cle, nonce)
    return _ctr_gcm(data, cles, j0)


def gcm_chiffre(clair, cle, nonce, aad=b""):
    """Retourne (texte_chiffre, tag)."""
    chiffre = gcm_ctr(clair, cle, nonce)
    return chiffre, gcm_tag(chiffre, cle, nonce, aad)


def gcm_dechiffre(chiffre, tag, cle, nonce, aad=b""):
    """Verifie le tag AVANT de dechiffrer. Leve ValueError si invalide."""
    if not hmac.compare_digest(tag, gcm_tag(chiffre, cle, nonce, aad)):
        raise ValueError("Tag GCM invalide")
    return gcm_ctr(chiffre, cle, nonce)
