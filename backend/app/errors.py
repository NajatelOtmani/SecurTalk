"""Erreurs HTTP du backend. Format de reponse du guide (2.1) :
{ "error": "CODE_EN_MAJUSCULES", "message": "explication lisible" }"""


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class AuthFailure(ApiError):
    """Echec d'authentification par jeton. `reason` suit le guide (4.3) :
    missing_token | invalid_token | expired_token."""

    def __init__(self, reason, status=401, code=None, message=None, user_id=None):
        code = code or {"missing_token": "MISSING_TOKEN",
                        "invalid_token": "INVALID_TOKEN",
                        "expired_token": "EXPIRED_TOKEN"}[reason]
        super().__init__(status, code, message or "Authentification requise ou invalide")
        self.reason = reason
        self.user_id = user_id
