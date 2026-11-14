"""Erreurs precises du SDK.

Le client / le backend attrapent ces exceptions pour savoir quel evenement
envoyer au SOC (ex. AuthTagError -> GCM_AUTH_FAIL ou CMAC_AUTH_FAIL).
Aucun message d'erreur ne contient de cle ni de texte clair.
"""


class SecureTalkCryptoError(Exception):
    """Classe mere de toutes les erreurs du SDK."""


class AuthTagError(SecureTalkCryptoError):
    """Tag invalide OU paquet mal forme OU mauvaise cle.

    Volontairement une seule erreur : on ne dit jamais si c'est le tag,
    le padding ou le format qui a echoue (cela aiderait un attaquant).
    """


class ReplayError(SecureTalkCryptoError):
    """Paquet rejoue : le compteur n'est pas plus grand que le dernier vu."""


class KeyExchangeError(SecureTalkCryptoError):
    """Echec RSA : cle PEM invalide, mauvaise cle privee, cle emballee corrompue."""


class UnknownKeyError(SecureTalkCryptoError):
    """Le key_id demande n'existe pas (ou a expire) dans le KeyManager."""
