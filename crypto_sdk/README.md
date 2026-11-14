# securetalk_crypto : SDK cryptographique de SecureTalk AI

Bibliotheque Python **sans dependance externe** (AES, CBC, CMAC, GCM, RSA-OAEP ecrits a la main,
HKDF et HMAC via la bibliotheque standard). Le SDK ne fait ni reseau ni interface :
il prend des donnees et en rend.

> Base pedagogique : a auditer avant tout usage reel.

## Installation (depuis la racine du depot)

    pip install -e crypto_sdk

(ou ajouter le dossier `crypto_sdk` au `PYTHONPATH`).

## Exemple 1 : echange de cle (A -> B, via le backend)

    from securetalk_crypto import KeyManager, RSAKeyExchange

    priv_b, pub_b = RSAKeyExchange.generate_keypair()      # B, une fois, a l'inscription
    key = KeyManager().generate_key(256)                   # A cree la cle de session
    wrapped = RSAKeyExchange.wrap_key(pub_b, key)          # A -> backend -> B (texte base64)
    key_chez_b = RSAKeyExchange.unwrap_key(priv_b, wrapped)  # KeyExchangeError si echec

## Exemple 2 : envoyer / recevoir un message (GCM ou CMAC)

    from securetalk_crypto import encrypt_message, decrypt_message, ReplayGuard

    # A chiffre. mode = "GCM" ou "CMAC" (CMAC = AES-CBC + CMAC)
    packet = encrypt_message("Bonjour", key, "CMAC", "u_1a", "u_2b", "conv_u_1a_u_2b", counter=1)

    # B dechiffre : tag -> anti-rejeu -> dechiffrement
    guard = ReplayGuard()                                  # un seul guard, garde-le en vie
    texte = decrypt_message(packet, key_chez_b, guard)

`packet` est un dictionnaire JSON (guide 2.6) : `message_id, conversation_id, sender_id,
receiver_id, mode, key_id, counter, nonce_b64, ciphertext_b64, tag_b64, timestamp`.

## Exemple 3 : gerer les erreurs (et alerter le SOC)

    from securetalk_crypto import AuthTagError, ReplayError, UnknownKeyError

    try:
        texte = decrypt_message(packet, key_chez_b, guard)
    except AuthTagError:
        ...   # ne PAS afficher le message ; emettre GCM_AUTH_FAIL (ou CMAC_AUTH_FAIL)
    except ReplayError:
        ...   # emettre REPLAY_DETECTED

## Rotation des cles

    km = KeyManager()
    key = km.rotate_key("conv_u_1a_u_2b")      # nouvelle cle, l'ancienne reste valable 5 min
    if km.should_rotate(key):                  # > 500 messages ou > 60 min
        key = km.rotate_key("conv_u_1a_u_2b")
    km.get_key("conv_u_1a_u_2b", packet["key_id"])   # receveur : retrouver la bonne cle (UnknownKeyError)

Sans argument, `rotate_key` suit la rotation du cours : 128 -> 192 -> 256 -> 128.
`km.rotate_key(conv, bits=256)` impose une taille. Le receveur enregistre la cle recue avec
`km.add_key(conversation_id, key)`.

## Regles de securite appliquees

- Nonce GCM (12 octets) et IV CBC (16 octets) aleatoires a chaque message.
- CMAC : Encrypt-then-MAC, deux cles derivees par HKDF (une pour CBC, une pour CMAC).
- Tag lie a `message_id|conversation_id|sender_id|receiver_id|mode|key_id|counter` (AAD).
- Tag verifie AVANT dechiffrement, comparaison en temps constant.
- Une seule erreur `AuthTagError` (on ne dit pas si c'est le tag, le padding ou le format).
- Le compteur anti-rejeu n'avance qu'apres un tag valide.
- `repr(SessionKey)` n'affiche jamais les octets de la cle. `key.wipe()` efface la cle.
- Aucune cle ni texte clair dans les erreurs.

## Tests

    pip install pytest
    cd crypto_sdk
    python -m pytest
