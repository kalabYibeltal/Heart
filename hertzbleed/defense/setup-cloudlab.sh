#!/usr/bin/env bash
# setup-cloudlab.sh — bring a FRESH CloudLab node (Ubuntu 20.04) to a ready state.
# Idempotent. Run from anywhere:  bash hertzbleed/defense/setup-cloudlab.sh
set -euo pipefail
HB=$(cd "$(dirname "$0")/.." && pwd)          # .../Heart/hertzbleed
GO_VER=1.21.13

echo "== apt packages"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential stress-ng msr-tools cpufrequtils linux-tools-common \
  "linux-tools-$(uname -r)" python3-venv python3-pip >/dev/null

echo "== Go $GO_VER -> /usr/local/go"
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VER"; then
  curl -sSLo /tmp/go.tgz "https://go.dev/dl/go$GO_VER.linux-amd64.tar.gz"
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
fi
grep -q /usr/local/go/bin ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin

echo "== msr module"
sudo modprobe msr

echo "== python venv ($HB/venv)"
[[ -d $HB/venv ]] || python3 -m venv "$HB/venv"
"$HB/venv/bin/pip" install -q --upgrade pip
"$HB/venv/bin/pip" install -q -r "$HB/defense/requirements.txt"

echo "== build: util objs + local monitor driver"
( cd "$HB/06-circl/local" && make -s )

echo "== build: CIRCL POC binaries"
( cd "$HB/06-circl/circl" && go mod download && cd dh/sidh/POC_ATTACK &&
  for f in sike_local sike_server sike_client; do go build -o $f $f.go; done )

echo "== build: microbenchmarks"
( cd "$HB/defense/microbench" && make -s )

echo "== tests (correctness invariant must stay green)"
( cd "$HB/06-circl/circl" && go test -count=1 ./dh/sidh/internal/p751/ )

echo "== node capability"
"$HB/defense/scripts/hbctl.sh" status || true
"$HB/defense/scripts/hbctl.sh" pstate-check || true
echo "DONE. New shells: PATH includes /usr/local/go/bin. Activate python: source $HB/venv/bin/activate"
