#!/bin/bash
# MiBombo - Configuration des permissions sécurisées
# Ce script configure les permissions selon les bonnes pratiques Linux

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="${SUDO_USER:-$USER}"
APP_GROUP="mibombo"

echo "============================================================"
echo "  MiBombo - Configuration des Permissions Sécurisées"
echo "============================================================"
echo ""

# Vérifier qu'on est root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Ce script doit être exécuté avec sudo"
    echo "    Usage: sudo ./setup_permissions.sh"
    exit 1
fi

echo "[1/5] Création du groupe '$APP_GROUP'..."
if ! getent group "$APP_GROUP" > /dev/null 2>&1; then
    groupadd "$APP_GROUP"
    echo "      ✓ Groupe créé"
else
    echo "      ✓ Groupe existe déjà"
fi

echo ""
echo "[2/5] Ajout de l'utilisateur '$APP_USER' au groupe '$APP_GROUP'..."
usermod -a -G "$APP_GROUP" "$APP_USER"
echo "      ✓ Utilisateur ajouté"

echo ""
echo "[3/5] Configuration des permissions des répertoires..."
# Créer les répertoires s'ils n'existent pas
mkdir -p "$SCRIPT_DIR/data/logs"
mkdir -p "$SCRIPT_DIR/data"

# Donner la propriété au groupe mibombo
chown -R "$APP_USER:$APP_GROUP" "$SCRIPT_DIR/data"
chown -R "$APP_USER:$APP_GROUP" "$SCRIPT_DIR/venv" 2>/dev/null || true

# Permissions: propriétaire RWX, groupe RWX, autres R
chmod -R 770 "$SCRIPT_DIR/data"
echo "      ✓ Permissions configurées (770)"

echo ""
echo "[4/5] Configuration des capacités réseau (CAP_NET_RAW)..."
# Donner la capacité de capturer le réseau sans sudo
PYTHON_BIN="$SCRIPT_DIR/venv/bin/python"
if [ -f "$PYTHON_BIN" ]; then
    setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN"
    echo "      ✓ Capacités réseau accordées"
    echo "      → L'application peut capturer sans sudo"
else
    echo "      ⚠ Python venv non trouvé, ignoré"
fi

echo ""
echo "[5/5] Vérification..."
echo "      Groupe: $(getent group $APP_GROUP)"
echo "      Permissions data/: $(stat -c '%a %U:%G' $SCRIPT_DIR/data)"
if [ -f "$PYTHON_BIN" ]; then
    echo "      Capacités Python: $(getcap $PYTHON_BIN)"
fi

echo ""
echo "============================================================"
echo "  ✓ Configuration terminée avec succès!"
echo "============================================================"
echo ""
echo "IMPORTANT:"
echo "  1. Déconnectez-vous et reconnectez-vous pour que le groupe"
echo "     '$APP_GROUP' soit actif (ou tapez: newgrp $APP_GROUP)"
echo ""
echo "  2. Vous pouvez maintenant lancer l'application SANS sudo:"
echo "     python main.py"
echo ""
echo "  3. Les fichiers dans data/ appartiennent au groupe '$APP_GROUP'"
echo "     et sont accessibles en lecture/écriture par tous les membres"
echo ""
echo "============================================================"
