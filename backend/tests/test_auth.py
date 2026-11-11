import json

from sqlalchemy import text

from conftest import PW, bearer, types

PEM = "-----BEGIN RSA PUBLIC KEY-----\nMAMCAQE=\n-----END RSA PUBLIC KEY-----\n"


def reg(client, name="alice", pw=PW, pem=PEM):
    return client.post("/auth/register", json={"username": name, "password": pw, "public_key_pem": pem})


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_register_ok_et_evenement(client, app):
    r = reg(client)
    assert r.status_code == 201
    uid = r.json()["user_id"]
    assert uid.startswith("u_")
    ev = types(app, "REGISTER_SUCCESS")[0]
    assert ev["source"] == "auth" and ev["target"]["user_id"] == uid and ev["severity"] == "info"


def test_register_doublon_et_validations(client):
    assert reg(client).status_code == 201
    assert reg(client, "ALICE").status_code == 409                    # insensible a la casse
    assert reg(client, "ab").status_code == 400                       # trop court
    assert reg(client, "bad name!").status_code == 400
    r = reg(client, "carol", pw="court")
    assert r.status_code == 400 and r.json()["error"] == "INVALID_PASSWORD"
    assert reg(client, "dave", pem="pas une cle").status_code == 400
    assert client.post("/auth/register", json={"username": "x"}).status_code == 400   # champ manquant


def test_mot_de_passe_jamais_en_clair(client, app):
    reg(client)
    with app.state.engine.connect() as c:
        h = c.execute(text("select password_hash from users")).scalar()
    assert PW not in h and h.startswith("$argon2")


def test_login_ok(client, app):
    uid = reg(client).json()["user_id"]
    r = client.post("/auth/login", json={"username": "alice", "password": PW})
    assert r.status_code == 200
    j = r.json()
    assert j["user_id"] == uid and len(j["token"]) >= 40 and j["expires_at"].endswith("Z")
    assert types(app, "LOGIN_SUCCESS")[0]["actor"]["username"] == "alice"
    with app.state.engine.connect() as c:                              # seul le hash du jeton est stocke
        assert j["token"] not in str(c.execute(text("select * from sessions")).fetchall())


def test_login_echec_meme_reponse_inconnu_ou_mauvais_mdp(client, app):
    uid = reg(client).json()["user_id"]
    a = client.post("/auth/login", json={"username": "alice", "password": "mauvais-mot-de-passe"})
    b = client.post("/auth/login", json={"username": "inconnu", "password": "mauvais-mot-de-passe"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    fails = types(app, "LOGIN_FAIL")
    assert fails[0]["target"]["user_id"] == uid and fails[0]["details"]["reason"] == "bad_password"
    assert fails[1]["target"]["user_id"] is None and fails[1]["details"]["reason"] == "unknown_user"
    assert fails[0]["actor"]["ip"] == "203.0.113.9" and fails[0]["actor"]["username"] == "alice"
    assert fails[0]["severity"] == "low"


def test_attempt_number_augmente(client, app):
    reg(client)
    for _ in range(3):
        client.post("/auth/login", json={"username": "alice", "password": "mauvais-mot-de-passe"})
    assert [e["details"]["attempt_number"] for e in types(app, "LOGIN_FAIL")] == [1, 2, 3]


def test_compte_verrouille_403_meme_avec_bon_mdp(client, app):
    uid = reg(client).json()["user_id"]
    tok = client.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    r = client.post(f"/internal/accounts/{uid}/lock", headers={"X-API-Key": "cle-interne-de-test"})
    assert r.status_code == 200
    r = client.post("/auth/login", json={"username": "alice", "password": PW})
    assert r.status_code == 403 and r.json()["error"] == "ACCOUNT_LOCKED"
    assert client.get("/users/alice/publickey", headers=bearer(tok)).status_code == 401   # sessions supprimees


def test_logout(client, app):
    reg(client)
    tok = client.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    assert client.post("/auth/logout", headers=bearer(tok)).status_code == 204
    assert types(app, "LOGOUT")
    assert client.post("/auth/logout", headers=bearer(tok)).status_code == 401


def test_publickey(client):
    reg(client)
    reg(client, "bob")
    tok = client.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    for url in ("/users/bob/publickey", "/users/bob/public-key"):
        r = client.get(url, headers=bearer(tok))
        assert r.status_code == 200 and r.json()["public_key_pem"].startswith("-----BEGIN")
    assert client.get("/users/inconnu/publickey", headers=bearer(tok)).status_code == 404
    assert client.get("/users/bob/publickey").status_code == 401


def test_jeton_expire(client, app):
    reg(client)
    tok = client.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    with app.state.engine.begin() as c:
        c.execute(text("update sessions set expires_at = '2000-01-01 00:00:00'"))
    r = client.get("/users/alice/publickey", headers=bearer(tok))
    assert r.status_code == 401 and r.json()["error"] == "EXPIRED_TOKEN"
    assert types(app, "SESSION_EXPIRED")


def test_erreurs_au_format_du_guide(client):
    r = client.get("/nimporte-quoi")
    assert r.status_code == 404 and set(r.json()) == {"error", "message"}


def test_aucun_champ_interdit_dans_les_evenements(client, app):
    reg(client)
    client.post("/auth/login", json={"username": "alice", "password": PW})
    texte = json.dumps(app.state.emitter.events)
    assert PW not in texte and '"password"' not in texte and '"token"' not in texte


def test_lecture_env_bom_et_utf16(tmp_path, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "BACKEND_DIR", tmp_path / "backend")
    (tmp_path / "backend").mkdir()
    for nom, enc in (("utf-8-sig", "utf-8-sig"), ("utf-16", "utf-16")):
        (tmp_path / "backend" / ".env").write_text("SOC_KEY_AUTH=abc123\nINTERNAL_KEY_SOC_TO_BACKEND=zzz\n", encoding=enc)
        for k in ("SOC_KEY_AUTH", "INTERNAL_KEY_SOC_TO_BACKEND"):
            monkeypatch.delenv(k, raising=False)
        s = config.Settings.from_env()
        assert s.soc_keys["auth"] == "abc123" and s.internal_key == "zzz", nom
