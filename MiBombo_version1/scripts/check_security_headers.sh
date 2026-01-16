#!/bin/bash
# Script de vérification des headers de sécurité HTTP

echo "🔍 Vérification des Headers de Sécurité HTTP"
echo "=============================================="
echo ""

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction de test
check_header() {
    local header_name="$1"
    local expected_value="$2"
    
    # Extraire le header de la réponse
    actual_value=$(echo "$RESPONSE" | grep -i "^$header_name:" | cut -d' ' -f2- | tr -d '\r')
    
    if [ -n "$actual_value" ]; then
        echo -e "${GREEN}✓${NC} $header_name: $actual_value"
        return 0
    else
        echo -e "${RED}✗${NC} $header_name: MANQUANT"
        return 1
    fi
}

# Lancer l'API en arrière-plan (si pas déjà lancée)
echo "Démarrage de l'API..."
if ! pgrep -f "python.*api/api.py" > /dev/null; then
    ./venv/bin/python -c "from api.api import create_app; app = create_app(); app.run(host='0.0.0.0', port=5001)" &
    API_PID=$!
    sleep 3
    echo "API démarrée (PID: $API_PID)"
else
    echo "API déjà en cours d'exécution"
fi

# Faire une requête HTTP
echo ""
echo "Requête HTTP vers http://localhost:5001/api/stats..."
RESPONSE=$(curl -s -i http://localhost:5001/api/stats 2>/dev/null)

if [ -z "$RESPONSE" ]; then
    echo -e "${RED}Erreur: Impossible de contacter l'API${NC}"
    exit 1
fi

echo ""
echo "Headers de Sécurité Détectés:"
echo "-----------------------------"

# Vérifier chaque header
TOTAL=0
PASSED=0

check_header "X-Content-Type-Options" "nosniff" && ((PASSED++))
((TOTAL++))

check_header "X-Frame-Options" "DENY" && ((PASSED++))
((TOTAL++))

check_header "X-XSS-Protection" "1; mode=block" && ((PASSED++))
((TOTAL++))

check_header "Strict-Transport-Security" && ((PASSED++))
((TOTAL++))

check_header "Content-Security-Policy" && ((PASSED++))
((TOTAL++))

check_header "Referrer-Policy" && ((PASSED++))
((TOTAL++))

check_header "Permissions-Policy" && ((PASSED++))
((TOTAL++))

check_header "X-Download-Options" "noopen" && ((PASSED++))
((TOTAL++))

check_header "X-DNS-Prefetch-Control" "off" && ((PASSED++))
((TOTAL++))

# Résumé
echo ""
echo "=============================================="
echo "Résultat: $PASSED/$TOTAL headers présents"

if [ $PASSED -eq $TOTAL ]; then
    echo -e "${GREEN}✓ Tous les headers de sécurité sont configurés !${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Certains headers manquent${NC}"
    exit 1
fi
