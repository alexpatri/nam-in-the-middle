#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BancoInseguro - aplicacao PROPOSITALMENTE vulneravel para o lab de
"Cryptographic Failures" (OWASP Top 10 - A02:2021).

FALHA CENTRAL: a aplicacao e servida somente em HTTP (sem TLS). Todo o trafego
- inclusive usuario e senha no POST de login e o cookie de sessao - viaja em
TEXTO CLARO pela rede, podendo ser capturado por um atacante em posicao de
Man-in-the-Middle (ARP spoofing).

ATENCAO: uso exclusivo em ambiente de laboratorio controlado e isolado.
NUNCA exponha esta aplicacao na Internet.
"""

from flask import Flask, request, redirect, make_response, render_template, url_for
import secrets

app = Flask(__name__)

# "banco de dados" em memoria (apenas para o lab)
USERS = {
    "maria": {"senha": "senha123", "saldo": 5000.00},
}
SESSIONS = {}  # token -> usuario


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", erro=None)

    usuario = request.form.get("usuario", "")
    senha = request.form.get("senha", "")
    # [VULN] Credenciais recebidas em HTTP puro -> trafegam em texto claro.
    conta = USERS.get(usuario)
    if not conta or conta["senha"] != senha:
        return render_template("login.html", erro="Usuario ou senha invalidos.")

    token = secrets.token_hex(8)
    SESSIONS[token] = usuario
    resp = make_response(redirect(url_for("dashboard")))
    # [VULN] Cookie de sessao sem Secure/HttpOnly -> tambem visivel na captura.
    resp.set_cookie("session", token)
    return resp


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
    # [VULN] Servido em HTTP (sem TLS) na porta 80.
    app.run(host="0.0.0.0", port=80, debug=False)
