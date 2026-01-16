#!/bin/bash
# 1. Fixer les permissions pour la capture réseau (cap_net_raw)
setcap 'cap_net_raw,cap_net_admin=eip' /usr/bin/mibombo-station
chmod +x /usr/bin/mibombo-station


CONFIG_DIR="/etc/mibombo"
mkdir -p $CONFIG_DIR

if [ ! -f "$CONFIG_DIR/.env" ]; then
    echo "[i] Génération d'une configuration sécurisée dans $CONFIG_DIR/.env"
    cat <<EOF > "$CONFIG_DIR/.env"
# MiBombo - Configuration Automatique
DB_HOST=localhost
DB_NAME=mibombo
DB_USER=mibombo_user
DB_PASSWORD=change_me
SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
ENCRYPTION_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
EOF
    chmod 600 "$CONFIG_DIR/.env"
fi
