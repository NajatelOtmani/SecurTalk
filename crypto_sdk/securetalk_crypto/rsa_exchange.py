"""RSA-OAEP (SHA-256) ecrit a la main : echange de la cle de session.

Les cles sont echangees au format PEM (PKCS#1) pour que le backend puisse
stocker la cle publique dans un champ texte (public_key_pem).
"""
import base64
import hashlib
import os
import secrets

from .aes import xor_octets
from .errors import KeyExchangeError
from .key_manager import SessionKey

H_LEN = 32
E_PUBLIC = 65537


# ---------------- Maths RSA (ton code du cours) ----------------
def pgcd_etendu(a, b):
    """Algorithme d'Euclide etendu (version iterative : pas de limite de recursion)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverse_modulaire(e, phi):
    g, x, _ = pgcd_etendu(e, phi)
    if g != 1:
        raise ValueError("e n'est pas inversible modulo phi")
    return x % phi


def _petits_premiers(limite=1000):
    crible = [True] * limite
    res = []
    for i in range(2, limite):
        if crible[i]:
            res.append(i)
            for j in range(i * i, limite, i):
                crible[j] = False
    return res


PETITS_PREMIERS = _petits_premiers()


def est_premier(n, tours=40):
    """Test de Miller-Rabin."""
    if n < 2:
        return False
    for p in PETITS_PREMIERS:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(tours):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def premier_aleatoire(bits):
    """Premier de `bits` bits ; les 2 bits de poids fort a 1 => n = p*q a la bonne taille."""
    while True:
        n = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if est_premier(n):
            return n


def generer_cles_rsa(bits=2048):
    e = E_PUBLIC
    while True:
        p = premier_aleatoire(bits // 2)
        q = premier_aleatoire(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if pgcd_etendu(e, phi)[0] == 1:
            break
    n = p * q
    d = inverse_modulaire(e, phi)
    privee = {"n": n, "e": e, "d": d, "p": p, "q": q,
              "dp": d % (p - 1), "dq": d % (q - 1),
              "qinv": inverse_modulaire(q, p)}
    return (n, e), privee


# ---------------- OAEP (SHA-256) ----------------
def mgf1(graine, longueur):
    sortie = b""
    compteur = 0
    while len(sortie) < longueur:
        sortie += hashlib.sha256(graine + compteur.to_bytes(4, "big")).digest()
        compteur += 1
    return sortie[:longueur]


def oaep_encode(message, k, label=b""):
    if len(message) > k - 2 * H_LEN - 2:
        raise ValueError("Message trop long pour ce module RSA")
    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * H_LEN - 2)
    db = l_hash + ps + b"\x01" + message
    graine = os.urandom(H_LEN)
    db_masque = xor_octets(db, mgf1(graine, k - H_LEN - 1))
    graine_masquee = xor_octets(graine, mgf1(db_masque, H_LEN))
    return b"\x00" + graine_masquee + db_masque


def oaep_decode(em, k, label=b""):
    """Une seule erreur pour tous les cas (on ne dit pas ce qui a echoue)."""
    l_hash = hashlib.sha256(label).digest()
    erreur = ValueError("Dechiffrement RSA invalide")
    if len(em) != k or k < 2 * H_LEN + 2:
        raise erreur
    y, graine_masquee, db_masque = em[0], em[1:1 + H_LEN], em[1 + H_LEN:]
    graine = xor_octets(graine_masquee, mgf1(db_masque, H_LEN))
    db = xor_octets(db_masque, mgf1(graine, k - H_LEN - 1))
    reste = db[H_LEN:]
    i = 0
    while i < len(reste) and reste[i] == 0:
        i += 1
    ok = (y == 0 and db[:H_LEN] == l_hash and i < len(reste) and reste[i] == 1)
    if not ok:
        raise erreur
    return reste[i + 1:]


def rsa_chiffre(message, publique):
    n, e = publique
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(oaep_encode(message, k), "big")
    return pow(m, e, n).to_bytes(k, "big")


def rsa_dechiffre(chiffre, privee):
    n, p, q = privee["n"], privee["p"], privee["q"]
    k = (n.bit_length() + 7) // 8
    if len(chiffre) != k:
        raise ValueError("Dechiffrement RSA invalide")
    c = int.from_bytes(chiffre, "big")
    if c >= n:
        raise ValueError("Dechiffrement RSA invalide")
    m1 = pow(c, privee["dp"], p)
    m2 = pow(c, privee["dq"], q)
    h = (privee["qinv"] * (m1 - m2)) % p
    m = m2 + h * q
    return oaep_decode(m.to_bytes(k, "big"), k)


# ---------------- Format PEM (PKCS#1, DER minimal) ----------------
def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(v):
    return b"\x02" + _der_len((v.bit_length() + 8) // 8) + v.to_bytes((v.bit_length() + 8) // 8, "big")


def _der_seq(entiers):
    corps = b"".join(_der_int(v) for v in entiers)
    return b"\x30" + _der_len(len(corps)) + corps


def _der_lit(data, pos):
    tag = data[pos]
    longueur = data[pos + 1]
    pos += 2
    if longueur & 0x80:
        nb = longueur & 0x7F
        if nb == 0 or nb > 4:
            raise ValueError("DER invalide")
        longueur = int.from_bytes(data[pos:pos + nb], "big")
        pos += nb
    fin = pos + longueur
    if fin > len(data):
        raise ValueError("DER invalide")
    return tag, data[pos:fin], fin


def _der_entiers(data):
    tag, corps, fin = _der_lit(data, 0)
    if tag != 0x30 or fin != len(data):
        raise ValueError("DER invalide")
    res, pos = [], 0
    while pos < len(corps):
        t, contenu, pos = _der_lit(corps, pos)
        if t != 0x02 or not contenu:
            raise ValueError("DER invalide")
        res.append(int.from_bytes(contenu, "big"))
    return res


def _pem_encode(titre, der):
    b64 = base64.b64encode(der).decode("ascii")
    lignes = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {titre}-----\n" + "\n".join(lignes) + f"\n-----END {titre}-----\n"


def _pem_decode(titre, pem):
    try:
        lignes = [l.strip() for l in pem.strip().splitlines()]
        if lignes[0] != f"-----BEGIN {titre}-----" or lignes[-1] != f"-----END {titre}-----":
            raise ValueError("PEM invalide")
        return base64.b64decode("".join(lignes[1:-1]), validate=True)
    except Exception:
        raise KeyExchangeError("Cle PEM invalide") from None


def _charge_publique(public_pem):
    try:
        n, e = _der_entiers(_pem_decode("RSA PUBLIC KEY", public_pem))
    except KeyExchangeError:
        raise
    except Exception:
        raise KeyExchangeError("Cle publique invalide") from None
    if n.bit_length() < 1024 or e < 3:
        raise KeyExchangeError("Cle publique invalide")
    return n, e


def _charge_privee(private_pem):
    try:
        v = _der_entiers(_pem_decode("RSA PRIVATE KEY", private_pem))
        if len(v) != 9 or v[0] != 0:
            raise ValueError("format")
        return {"n": v[1], "e": v[2], "d": v[3], "p": v[4], "q": v[5],
                "dp": v[6], "dq": v[7], "qinv": v[8]}
    except KeyExchangeError:
        raise
    except Exception:
        raise KeyExchangeError("Cle privee invalide") from None


# ---------------- API publique ----------------
class RSAKeyExchange:
    @staticmethod
    def generate_keypair(bits=2048):
        """Retourne (private_pem, public_pem). Utilise 2048 ou 3072 (1024 = tests seulement)."""
        if bits < 1024 or bits % 2:
            raise ValueError("bits >= 1024 et pair")
        (n, e), pv = generer_cles_rsa(bits)
        private_pem = _pem_encode("RSA PRIVATE KEY", _der_seq(
            [0, pv["n"], pv["e"], pv["d"], pv["p"], pv["q"], pv["dp"], pv["dq"], pv["qinv"]]))
        public_pem = _pem_encode("RSA PUBLIC KEY", _der_seq([n, e]))
        return private_pem, public_pem

    @staticmethod
    def wrap_key(public_pem, session_key):
        """Chiffre la SessionKey (key_id + octets) avec RSA-OAEP -> base64."""
        n, e = _charge_publique(public_pem)
        kid = session_key.key_id.encode("ascii")
        if not 0 < len(kid) < 256:
            raise KeyExchangeError("key_id invalide")
        charge = bytes([len(kid)]) + kid + session_key.key_bytes
        try:
            return base64.b64encode(rsa_chiffre(charge, (n, e))).decode("ascii")
        except ValueError:
            raise KeyExchangeError("Echec du chiffrement RSA") from None

    @staticmethod
    def unwrap_key(private_pem, wrapped_key_b64):
        """Dechiffre la cle recue -> SessionKey. Leve KeyExchangeError si echec."""
        privee = _charge_privee(private_pem)
        try:
            brut = base64.b64decode(wrapped_key_b64.encode("ascii"), validate=True)
            charge = rsa_dechiffre(brut, privee)
            taille_id = charge[0]
            kid = charge[1:1 + taille_id].decode("ascii")
            cle = charge[1 + taille_id:]
            if taille_id == 0 or len(cle) not in (16, 24, 32):
                raise ValueError("charge invalide")
            return SessionKey(kid, len(cle) * 8, cle)
        except Exception:
            raise KeyExchangeError("Echec du dechiffrement de la cle") from None
