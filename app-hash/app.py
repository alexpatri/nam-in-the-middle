#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BancoInseguro (CASO 2) - a senha e derivada com PBKDF2 NO NAVEGADOR antes do
POST. O corpo da requisicao continua em HTTP puro (texto claro), mas no lugar da
senha vai um hash forte (PBKDF2-HMAC-SHA256, 210k iteracoes + salt).

OBJETIVO DIDATICO: mostrar que "criptografar a senha no cliente" NAO substitui o
HTTPS. A senha em si nao aparece na captura, MAS:
  - o COOKIE de sessao trafega em claro -> pode ser capturado e reusado
    (sequestro de sessao / pass-the-cookie);
  - o proprio hash vira um "equivalente de senha" -> pode ser reenviado
    (pass-the-hash).
So o TLS (HTTPS) protege o canal inteiro.

ATENCAO: uso exclusivamente educacional, em ambiente controlado.
"""

from flask import Flask, request, redirect, make_response, render_template, url_for
import hashlib
import secrets

app = Flask(__name__)

USERS = {
    "maria": {"senha": "senha123", "saldo": 5000.00},
}
SESSIONS = {}  # token -> usuario

# Parametros do PBKDF2. DEVEM ser identicos aos usados no navegador (login.html).
PBKDF2_ITER = 210000
PBKDF2_HASH = "sha256"


def derivar(usuario: str, senha: str) -> str:
    # salt deterministico por usuario (para o lab). O navegador usa o mesmo.
    salt = ("bancoinseguro:" + usuario).encode()
    return hashlib.pbkdf2_hmac(PBKDF2_HASH, senha.encode(), salt, PBKDF2_ITER).hex()


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", erro=None, iteracoes=PBKDF2_ITER)

    usuario = request.form.get("usuario", "")
    # [PONTO-CHAVE] O servidor recebe o HASH, nao a senha em claro.
    senha_hash = request.form.get("senha_hash", "")
    conta = USERS.get(usuario)
    if conta and secrets.compare_digest(senha_hash, derivar(usuario, conta["senha"])):
        token = secrets.token_hex(8)
        SESSIONS[token] = usuario
        resp = make_response(redirect(url_for("dashboard")))
        # [VULN] Cookie de sessao em claro (sem TLS) -> capturavel e reusavel.
        resp.set_cookie("session", token)
        return resp
    return render_template("login.html", erro="Usuario ou senha invalidos.",
                           iteracoes=PBKDF2_ITER)


def usuario_logado():
    token = request.cookies.get("session")
    return SESSIONS.get(token)


@app.route("/dashboard")
def dashboard():
    usuario = usuario_logado()
    if not usuario:
        return redirect(url_for("login"))
    return render_template("dashboard.html", usuario=usuario,
                           saldo=USERS[usuario]["saldo"])


@app.route("/logout")
def logout():
    token = request.cookies.get("session")
    SESSIONS.pop(token, None)
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
