# Lab — Captura de credenciais em HTTP (OWASP A02:2021)

Lab **simples e reprodutível numa única máquina** para demonstrar uma **falha
criptográfica** (Cryptographic Failures): aplicações servidas **somente em HTTP,
sem TLS**. Enquanto **você navega como a vítima**, um atacante que fareja a rede
vê o **tráfego em texto claro**.

Dois casos, para o comparativo do artigo:

| Caso | Descrição | O que o atacante vê |
|------|-----------|---------------------|
| **1** | Senha enviada em **texto claro** | usuário **e senha** + cookie |
| **2** | Senha derivada com **PBKDF2 no navegador** antes do POST | **hash** (senha oculta) + **cookie** |

O **Caso 2** é o argumento central: mesmo "criptografando" a senha no cliente,
o **cookie de sessão trafega em claro** — o atacante o captura e **finge a
sessão** (sequestro). Só o **HTTPS** protege o canal inteiro.

- **Servidor:** containers Docker com as apps vulneráveis.
- **Vítima:** **você**, no navegador do próprio computador.
- **Atacante:** bettercap via Docker, farejando a rede do lab.

> ⚠️ **Uso exclusivamente educacional**, em ambiente que você controla.

---

## 1. Como funciona (e uma nota sobre o ARP spoofing)

No cenário real (Wi-Fi/rede insegura), o atacante se posiciona no meio com
**ARP spoofing** e então lê o tráfego. Nesse lab de **uma máquina só**,
reproduzimos o que interessa ao artigo — **a captura do tráfego em texto claro**
— farejando diretamente a rede (bridge do Docker) por onde o navegador e o
servidor conversam.

> **Por que não o ARP spoofing "de verdade" aqui?** Numa única máquina com
> Docker, o host aplica regras de `iptables`/`bridge-netfilter` que descartam o
> redirecionamento de camada 2 do bettercap. Como o **resultado** (dados em
> claro) é idêntico, capturamos direto na rede. No artigo, descreva o ARP
> spoofing como a **técnica** de posicionamento e use este lab para evidenciar a
> **falha de confidencialidade**. (Apêndice A tem o caminho para tentar o ARP
> spoofing real.)

```
                 rede do lab (bridge Docker "labnet", 172.30.0.0/24)
   ┌────────────────────┐   POST (HTTP claro)   ┌─────────────────────────────┐
   │  VÍTIMA = VOCÊ      │ ─────────────────────►│  Caso 1  server  172.30.0.10 │
   │  navegador do host  │                       │  Caso 2  server-hash .0.11   │
   └────────────────────┘                       └─────────────────────────────┘
                 ▲
                 │ bettercap fareja a bridge
        ┌────────────────────┐
        │  ATACANTE           │ vê usuario/senha (Caso 1) ou hash+cookie (Caso 2)
        │  bettercap/docker   │
        └────────────────────┘
```

Credenciais para os testes: **usuário `maria` / senha `senha123`**.

---

## 2. Pré-requisitos
- Docker + Docker Compose
- **Linux** (o atacante usa `--net=host`; no Docker Desktop de Mac/Windows não
  funciona da mesma forma).

---

## 3. Subir os servidores
```bash
cd lab
docker compose up -d --build
```
Verifique:
```bash
docker compose ps
curl -s -o /dev/null -w "caso1: %{http_code}\n" http://172.30.0.10/login   # -> 200
curl -s -o /dev/null -w "caso2: %{http_code}\n" http://172.30.0.11/login   # -> 200
```

## 4. Ligar o atacante (bettercap)
Em um terminal **dedicado** (deixe rodando durante os testes):
```bash
cd lab/attacker
./run-attacker.sh
```

---

## 5. CASO 1 — senha em texto claro
1. Navegador do host em **<http://172.30.0.10/>** (ou <http://localhost:8000/>).
2. Login com `maria` / `senha123`.
3. No terminal do atacante aparece:
```
[net.sniff.http.request] http ... POST 172.30.0.10/login
usuario=maria&senha=senha123
Set-Cookie: session=<TOKEN>; Path=/
```
A **senha em claro** foi capturada.

---

## 6. CASO 2 — senha com hash PBKDF2 no cliente (o ponto do HTTPS)

> **Acesse SEMPRE por <http://localhost:8001/>** (não pelo IP). A API de
> criptografia do navegador (`crypto.subtle`) só é liberada em "contexto
> seguro", e `localhost` conta como um. O tráfego, mesmo assim, é **HTTP puro** e
> continua capturável.

1. Navegador do host em **<http://localhost:8001/>**.
2. Login com `maria` / `senha123`. A página deriva a senha com
   **PBKDF2-HMAC-SHA256 (210.000 iterações + salt)** e envia só o hash.
3. No terminal do atacante aparece:
```
[net.sniff.http.request] http ... POST localhost:8001/login
usuario=maria&senha_hash=ef291d6f38d1af26cb111555e342ebadc5c456bf6163241aab496d8c7fb1a428
Set-Cookie: session=<TOKEN>; Path=/
```
A **senha em claro NÃO aparece** — mas o **cookie sim**.

### 6.1 Sequestro de sessão (fingir ser a vítima)
Copie o `<TOKEN>` do `Set-Cookie` capturado e prove que o cookie roubado
reautentica **sem senha e sem o hash**:
```bash
curl -s -b "session=<TOKEN>" http://172.30.0.11/dashboard | grep -E "Ola|Saldo|R\$"
# -> Ola, maria / Saldo disponivel   (voce esta dentro da conta)
```
No navegador, o mesmo se faz com a extensão *Cookie Editor*: crie
`session=<TOKEN>` para `localhost:8001` e abra `/dashboard`.

**Conclusão para o artigo:** derivar a senha no cliente oculta a senha, mas
**não protege a sessão** — o cookie (e o próprio hash) trafega em claro e é
reutilizável. A proteção real do canal exige **HTTPS/TLS**.

---

## 7. Ligando ao artigo (A02:2021 — Cryptographic Failures)

| Observação no lab                                   | Falha / Referência                  |
|-----------------------------------------------------|-------------------------------------|
| Caso 1: usuário e senha visíveis                    | Dados sensíveis sem criptografia em trânsito |
| Caso 2: senha oculta, mas **cookie em claro**       | Hash no cliente ≠ canal seguro      |
| Cookie roubado reautentica sem senha                | Sessão sem proteção de transporte (falta TLS) |
| Hash reenviável (pass-the-hash)                     | "Criptografar a senha" não basta    |

**Mitigação:** servir tudo sobre **HTTPS/TLS**, forçar redirecionamento e
**HSTS**, e cookie com `Secure`/`HttpOnly`. Com TLS, tanto a senha quanto o
cookie estariam cifrados no fio.

Fontes oficiais (conforme `detalhes.md`):
- OWASP Top 10 — A02:2021: <https://owasp.org/Top10/>
- OWASP WSTG: <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Cheat Sheets: <https://cheatsheetseries.owasp.org/>

---

## 8. Resetar / desligar
```bash
docker compose restart      # limpa sessões
docker compose down         # desliga tudo
```

---

## 9. Estrutura de arquivos
```
lab/
├── docker-compose.yml            # sobe os dois casos na bridge labnet
├── README.md                     # este roteiro
├── app/                          # CASO 1: senha em texto claro (Flask, HTTP)
│   ├── app.py · requirements.txt · Dockerfile
│   └── templates/{login,dashboard}.html
├── app-hash/                     # CASO 2: PBKDF2 no navegador antes do POST
│   ├── app.py · requirements.txt · Dockerfile
│   └── templates/{login,dashboard}.html   # login.html faz o PBKDF2 no cliente
└── attacker/
    ├── run-attacker.sh           # sobe o bettercap via Docker farejando a bridge
    └── http-sniff.cap            # caplet: net.sniff (captura HTTP em claro)
```

---

## Apêndice A — tentar o ARP spoofing "de verdade" (opcional)
Para o ataque de camada 2 real, é preciso desligar o filtro de bridge do host
(afeta o Docker globalmente enquanto ativo; reversível):
```bash
sudo sysctl net.bridge.bridge-nf-call-iptables=0    # habilita; volte com =1 depois
```
Aí um container atacante na própria `labnet` (com `NET_ADMIN`/`NET_RAW` e
`ip_forward=1`) poderia rodar `arp.spoof` + `net.sniff`. **Recomendação:** para o
artigo, prefira a captura das seções 5–6 (confiável) e descreva o ARP spoofing
conceitualmente.
