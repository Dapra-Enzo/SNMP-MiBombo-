#!/bin/bash

# Configuration
PKI_DIR="pki"
ROOT_DIR="$PKI_DIR/root_ca"
INT_DIR="$PKI_DIR/sub_ca"
LEAF_DIR="$PKI_DIR/station"

mkdir -p $ROOT_DIR $INT_DIR $LEAF_DIR

echo "[*] Initialisation de la PKI (Mode: Root CA -> Sub CA -> Station)..."

# =============================================================================
# 1. ROOT CA (L'autorité suprême)
# =============================================================================
echo ""
echo "[1/5] Génération du Root CA (Offline)..."

# Clé privée Root
openssl genrsa -out $ROOT_DIR/rootCA.key 4096

# Certificat Root (Auto-signé) - Validité: 5 ans
openssl req -x509 -new -nodes -key $ROOT_DIR/rootCA.key -sha256 -days 1825 \
    -out $ROOT_DIR/rootCA.crt \
    -subj "/C=FR/ST=France/L=Paris/O=MiBombo Corp/OU=Security Board/CN=MiBombo Root CA"

echo "    -> Root CA créé: $ROOT_DIR/rootCA.crt"

# =============================================================================
# 2. SUB CA (Autorité Intermédiaire opérationnelle)
# =============================================================================
echo ""
echo "[2/5] Génération du Sub CA (Intermediate)..."

# Clé privée Intermédiaire
openssl genrsa -out $INT_DIR/subCA.key 4096

# CSR pour l'intermédiaire
openssl req -new -key $INT_DIR/subCA.key -out $INT_DIR/subCA.csr \
    -subj "/C=FR/ST=France/L=Paris/O=MiBombo Corp/OU=Operational IT/CN=MiBombo Network SubCA"

# Extension pour dire que c'est un CA
cat > $INT_DIR/subca_ext.cnf << EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF

# Signature du SubCA par le Root CA - Validité: 1 an
openssl x509 -req -in $INT_DIR/subCA.csr -CA $ROOT_DIR/rootCA.crt -CAkey $ROOT_DIR/rootCA.key -CAcreateserial \
    -out $INT_DIR/subCA.crt -days 365 -sha256 -extfile $INT_DIR/subca_ext.cnf

# Création de la chaîne complète (Chain of Trust)
cat $INT_DIR/subCA.crt $ROOT_DIR/rootCA.crt > $INT_DIR/ca_chain.crt

echo "    -> Sub CA créé et validé: $INT_DIR/subCA.crt"
echo "    -> Chaîne de confiance: $INT_DIR/ca_chain.crt"

# =============================================================================
# 3. STATION CERT (Certificat final pour l'API)
# =============================================================================
echo ""
echo "[3/5] Génération du certificat Station (API)..."

# Clé privée Serveur
openssl genrsa -out $LEAF_DIR/station.key 2048

# CSR Serveur
openssl req -new -key $LEAF_DIR/station.key -out $LEAF_DIR/station.csr \
    -subj "/C=FR/ST=France/L=Paris/O=MiBombo Corp/OU=Station/CN=mibombo-station.local"

# Extensions SAN (Subject Alt Name)
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

# Signature par le SUB CA (Pas le root !) - Validité: 90 jours
openssl x509 -req -in $LEAF_DIR/station.csr -CA $INT_DIR/subCA.crt -CAkey $INT_DIR/subCA.key -CAcreateserial \
    -out $LEAF_DIR/station.crt -days 90 -sha256 -extfile $LEAF_DIR/station_ext.cnf

echo "    -> Certificat Station créé: $LEAF_DIR/station.crt"

# =============================================================================
# 4. DEPLOIEMENT
# =============================================================================
echo ""
echo "[4/5] Déploiement des certificats..."

# Copie vers la racine pour que l'API les trouve
cp $LEAF_DIR/station.key local_key.pem
# Le certificat serveur DOIT inclure la chaîne intermédiaire pour que les clients valident
cat $LEAF_DIR/station.crt $INT_DIR/subCA.crt > local_cert.pem

echo "    -> Clé installée : local_key.pem"
echo "    -> Certificat (+Chain) installé : local_cert.pem"

# =============================================================================
# 5. INSTRUCTIONS
# =============================================================================
echo ""
echo "[5/5] Terminé !"
echo "----------------------------------------------------------------"
echo "Pour sécuriser votre navigateur :"
echo "Importez ce fichier dans vos 'Autorités de Certification Racines de Confiance' :"
echo "   >>> $ROOT_DIR/rootCA.crt <<<"
echo ""
echo "Ensuite, votre Sub-CA et votre Station seront automatiquement validés."
echo "----------------------------------------------------------------"
