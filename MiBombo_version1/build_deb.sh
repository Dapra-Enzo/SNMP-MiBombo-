#!/bin/bash
#
# MiBombo .deb Package Builder
# Usage: ./build_deb.sh
#

set -e

VERSION="1.1.0"
PACKAGE_NAME="mibombo_${VERSION}_all"
BUILD_DIR="$(dirname "$0")/build"
DEBIAN_DIR="$(dirname "$0")/debian"

echo "============================================================"
echo "  MiBombo .deb Package Builder v${VERSION}"
echo "============================================================"

# Nettoyer
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME"

echo "[1/6] Copie de la structure Debian..."
cp -r "$DEBIAN_DIR/DEBIAN" "$BUILD_DIR/$PACKAGE_NAME/"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/usr/bin"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/usr/share/applications"
cp "$DEBIAN_DIR/usr/bin/mibombo" "$BUILD_DIR/$PACKAGE_NAME/usr/bin/"
cp "$DEBIAN_DIR/usr/share/applications/mibombo.desktop" "$BUILD_DIR/$PACKAGE_NAME/usr/share/applications/"

echo "[2/6] Copie du code source..."
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/opt/mibombo"

# Copier les fichiers essentiels (exclure venv, __pycache__, .git, build, debian)
rsync -a --exclude='venv' --exclude='__pycache__' --exclude='.git' \
         --exclude='build' --exclude='debian' --exclude='*.pyc' \
         --exclude='*.deb' --exclude='data/*.db' --exclude='data/*.enc' \
         --exclude='.env' --exclude='pcaps/*.pcap' \
         "$(dirname "$0")/" "$BUILD_DIR/$PACKAGE_NAME/opt/mibombo/"

echo "[3/6] Configuration des permissions..."
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/postinst"
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/prerm"
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/usr/bin/mibombo"

echo "[4/6] Nettoyage des fichiers temporaires..."
find "$BUILD_DIR/$PACKAGE_NAME" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$BUILD_DIR/$PACKAGE_NAME" -name "*.pyc" -delete 2>/dev/null || true
find "$BUILD_DIR/$PACKAGE_NAME" -name ".DS_Store" -delete 2>/dev/null || true

echo "[5/6] Construction du package .deb..."
dpkg-deb --build "$BUILD_DIR/$PACKAGE_NAME"

echo "[6/6] Déplacement du package..."
mv "$BUILD_DIR/${PACKAGE_NAME}.deb" "$(dirname "$0")/"

# Nettoyage
rm -rf "$BUILD_DIR"

echo ""
echo "============================================================"
echo "✅ Package créé avec succès!"
echo ""
echo "   📦 Fichier: ${PACKAGE_NAME}.deb"
echo ""
echo "   Installation locale:"
echo "   sudo apt install ./${PACKAGE_NAME}.deb"
echo ""
echo "   Ou upload sur GitHub Releases pour distribution"
echo "============================================================"
