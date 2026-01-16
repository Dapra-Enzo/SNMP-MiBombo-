#!/bin/bash
# Script pour lancer tous les tests unitaires
echo "--- Lancement des tests MiBombo ---"
./venv/bin/python -m pytest tests/ -v
