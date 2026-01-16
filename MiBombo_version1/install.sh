#!/bin/bash
#
# MiBombo Remote Installer
# 
# Usage (one-liner):
#   curl -sSL https://raw.githubusercontent.com/IUT-Beziers/sae501-502-ensa_/main/MiBombo_V1/install.sh | sudo bash
#
# Or with wget:
#   wget -qO- https://raw.githubusercontent.com/IUT-Beziers/sae501-502-ensa_/main/MiBombo_V1/install.sh | sudo bash
#

set -e

REPO_URL="https://github.com/IUT-Beziers/sae501-502-ensa_"
RELEASE_URL="$REPO_URL/releases/latest/download/mibombo_1.1.0_all.deb"
INSTALL_DIR="/opt/mibombo"
TMP_DIR="/tmp/mibombo_install"

echo ""
echo "============================================================"
echo "  __  __  _  ____                  _          "
echo " |  \/  |(_)|  _ \                | |         "
echo " | \  / | _ | |_) |  ___   _ __   | |__    ___ "
echo " | |\/| || ||  _ <  / _ \ | '_ \  | '_ \  / _ \ "
echo " | |  | || || |_) || (_) || | | | | |_) || (_) |"
echo " |_|  |_||_||____/  \___/ |_| |_| |_.__/  \___/ "
echo ""
echo "           Remote Installer v1.1.0"
echo "============================================================"
echo ""

# Vérifier root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Ce script doit être exécuté en root (sudo)"
    exit 1
fi

# Vérifier les dépendances
echo "[1/5] Vérification des dépendances..."
apt-get update -qq
apt-get install -y -qq python3 python3-tk python3-venv python3-pip curl

# Télécharger le .deb
echo "[2/5] Téléchargement du package..."
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

if curl -sSL -o mibombo.deb "$RELEASE_URL"; then
    echo "    ✓ Package téléchargé depuis GitHub Releases"
else
    echo "    ⚠ Release non trouvée, clonage du repo..."
    apt-get install -y -qq git
    git clone --depth 1 "$REPO_URL" repo
    cd repo/MiBombo_V1
    ./build_deb.sh
    cp mibombo_*.deb "$TMP_DIR/mibombo.deb"
    cd "$TMP_DIR"
fi

# Installer
echo "[3/5] Installation du package..."
apt-get install -y -qq ./mibombo.deb

# Vérification
echo "[4/5] Vérification de l'installation..."
if [ -f "/opt/mibombo/main.py" ]; then
    echo "    ✓ Fichiers installés"
else
    echo "    ❌ Erreur d'installation"
    exit 1
fi

# Nettoyage
echo "[5/5] Nettoyage..."
rm -rf "$TMP_DIR"

echo ""
echo "============================================================"
echo "✅ MiBombo installé avec succès!"
echo ""
echo "   🚀 Lancer: sudo mibombo"
echo "   📚 Ou depuis le menu Applications"
echo ""
echo "   🌐 API: https://localhost:5000/api/docs"
echo "============================================================"
echo ""
