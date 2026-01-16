# SAE501/2 - Projet Logiciel : MiBombo Suite

*Introduction : La SAE501/2 consiste à réaliser en binôme un outil logiciel de gestion de trames SNMP. Ce dépôt contient la solution "MiBombo Suite" développée dans ce cadre.*

---

## 👥 Équipe / Collaborateurs
- **Techniciens/Développeurs** : M. Boudina Salah, M. Dapra Enzo
- **Client/Tuteurs** : M. Druon Sebastien, M. Borelly Cristophe, M. Comby Frederic

## 📝 Contexte et Enjeux
Les clients expriment le besoin d’un logiciel permettant de gérer différentes requêtes SNMP (**GET, SET, TRAP, …**) sur un réseau local.
Le projet intègre plusieurs dimensions :
- **Technique** : développement réseau, sécurité, analyse de trames, base de données, API REST et interface graphique.
- **Organisationnelle** : travail en binôme avec une répartition claire des rôles, gestion de projet et suivi régulier avec le client.
- **Professionnelle** : tenue de réunions, rédaction de comptes rendus, documentation et déploiement.

---

# 📖 Documentation Technique - MiBombo Suite

**Version**: 1.1.0-secure  
**Date**: 2026-01-13

## 🎯 Démarrage Rapide

```bash
# 1. Générer la PKI
./MiBombo_version1/scripts/pki/generate_pki.sh

# 2. Configurer les secrets
cp MiBombo_version1/.env.example MiBombo_version1/.env
# Éditer .env avec vos vraies clés

# 3. Installer les dépendances
pip install -r MiBombo_version1/requirements.txt

# 4. Lancer l'application
cd MiBombo_version1
sudo ./venv/bin/python main.py
```

## 📁 Structure du Projet

```
sae501-502-ensa_/
├── 📂 MiBombo_version1/    # Code source principal
│   ├── 📂 docs/            # Documentation détaillée
│   ├── 📂 scripts/         # Scripts utilitaires
│   ├── 📂 pki/             # Certificats
│   ├── 📂 core/            # Modules principaux
│   ├── 📂 gui/             # Interface graphique
│   └── 🐍 main.py          # Point d'entrée
└── 📜 README.md            # Ce fichier
```

## 🔐 Sécurité & Configuration

### Checklist Sécurité
Voir [MiBombo_version1/docs/security/TODO_SECURITY.md](MiBombo_version1/docs/security/TODO_SECURITY.md)

### PKI (Certificats)
Voir [MiBombo_version1/docs/pki/PKI_MANAGEMENT.md](MiBombo_version1/docs/pki/PKI_MANAGEMENT.md)
Les commandes de gestion se trouvent dans `MiBombo_version1/scripts/pki/`.

## 🛠️ Scripts Utilitaires

| Script | Description | Localisation |
|--------|-------------|--------------|
| `generate_pki.sh` | Génération PKI complète | `MiBombo_version1/scripts/pki/` |
| `renew_station_cert.sh` | Renouvellement Station | `MiBombo_version1/scripts/pki/` |
| `check_security_headers.sh` | Vérification headers HTTP | `MiBombo_version1/scripts/` |

## 🚀 Utilisation

### Lancer l'Application
```bash
cd MiBombo_version1
sudo ./venv/bin/python main.py
```

### Interface
- **API REST**: `https://localhost:5000` (Docs: `/api/docs`)
- **GUI**: Login `admin` / `admin` (à changer)

## 🧪 Tests

```bash
cd MiBombo_version1
# Tests unitaires
pytest tests/

# Tests de sécurité
./scripts/check_security_headers.sh
```

---
**Licence**: MiBombo Suite - Propriétaire | © 2026 MiBombo Corp