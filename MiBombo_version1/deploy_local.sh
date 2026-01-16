#!/bin/bash
# ============================================================
# MiBombo Station - Script de Déploiement Local (Nginx)
# ============================================================

echo "[+] Installation/Vérification de Nginx..."
sudo apt update && sudo apt install -y nginx

echo "[+] Nettoyage de l'ancien déploiement..."
sudo rm -rf /var/www/html/*

echo "[+] Copie des fichiers MiBombo (Site + Package)..."
if [ -d "website" ]; then
    sudo cp -r website/* /var/www/html/
    echo "✅ Fichiers copiés avec succès."
else
    echo "❌ Erreur : Dossier 'website' non trouvé. Lancez le build d'abord."
    exit 1
fi

echo "[+] Configuration des permissions..."
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Détection intelligente de l'IP locale (on prend la première IP active non-loopback)
IP_LOCALE=$(hostname -I | awk '{print $1}')

echo ""
echo "============================================================"
echo "🚀 DEPLOIEMENT REUSSI !"
echo "============================================================"
echo "Le site MiBombo Station est maintenant hébergé sur ce PC."
echo ""
echo "Vos collègues peuvent y accéder à l'adresse suivante :"
echo "👉 http://$IP_LOCALE"
echo ""
echo "Note : Pour l'installation 'Point & Click', ils n'ont qu'à"
echo "cliquer sur le bouton bleu sur le site."
echo "============================================================"
