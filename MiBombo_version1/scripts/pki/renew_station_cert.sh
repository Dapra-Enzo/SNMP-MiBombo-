#!/bin/bash
# Script de renouvellement du certificat Station (90 jours)
# À exécuter tous les 80 jours (10 jours avant expiration)

PKI_DIR="pki"
INT_DIR="$PKI_DIR/sub_ca"
LEAF_DIR="$PKI_DIR/station"

echo "🔄 Renouvellement du certificat Station"
echo "========================================"

# Vérifier la date d'expiration actuelle
if [ -f "$LEAF_DIR/station.crt" ]; then
    echo "📅 Certificat actuel:"
    openssl x509 -in $LEAF_DIR/station.crt -noout -dates
    echo ""
fi

# Backup de l'ancien certificat
if [ -f "$LEAF_DIR/station.crt" ]; then
    BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
    cp $LEAF_DIR/station.crt $LEAF_DIR/station.crt.backup_$BACKUP_DATE
    echo "✅ Backup: station.crt.backup_$BACKUP_DATE"
fi

# Générer nouvelle clé privée
echo "🔑 Génération nouvelle clé privée..."
openssl genrsa -out $LEAF_DIR/station.key 2048

# Générer CSR
echo "📝 Génération CSR..."
openssl req -new -key $LEAF_DIR/station.key -out $LEAF_DIR/station.csr \
    -subj "/C=FR/ST=France/L=Paris/O=MiBombo Corp/OU=Station/CN=mibombo-station.local"

# Extensions SAN
cat > $LEAF_DIR/station_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = mibombo.local
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# Signature par Sub CA - Validité: 90 jours
echo "✍️  Signature par Sub CA (90 jours)..."
openssl x509 -req -in $LEAF_DIR/station.csr -CA $INT_DIR/subCA.crt -CAkey $INT_DIR/subCA.key -CAcreateserial \
    -out $LEAF_DIR/station.crt -days 90 -sha256 -extfile $LEAF_DIR/station_ext.cnf

# Déploiement
echo "🚀 Déploiement..."
cp $LEAF_DIR/station.key local_key.pem
cat $LEAF_DIR/station.crt $INT_DIR/ca_chain.crt > local_cert.pem

echo ""
echo "✅ Certificat Station renouvelé !"
echo "📅 Nouvelle expiration:"
openssl x509 -in $LEAF_DIR/station.crt -noout -dates

echo ""
echo "⚠️  IMPORTANT: Redémarrer l'application pour charger le nouveau certificat"
echo "   sudo systemctl restart mibombo"
echo "   OU"
echo "   sudo ./venv/bin/python main.py"
