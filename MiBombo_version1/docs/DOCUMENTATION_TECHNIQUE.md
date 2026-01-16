<![CDATA[<div align="center">

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# **DOCUMENTATION TECHNIQUE**

# **MiBombo Suite**

## Analyseur de Trames SNMP Sécurisé

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Version 1.1.0**

**Janvier 2026**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Équipe de Développement

| Rôle | Nom |
|------|-----|
| **Développeur Principal** | M. Dapra Enzo |
| **Développeur Principal** | M. Boudina Salah |

### Encadrement Client / Tuteurs

| Rôle | Nom |
|------|-----|
| **Client** | M. Druon Sebastien |
| **Client** | M. Borelly Cristophe |
| **Client** | M. Comby Frederic |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**IUT de Béziers – BUT Réseaux & Télécommunications**

**SAE 501/502 – Projet Logiciel ENSA**

</div>

---

<div style="page-break-after: always;"></div>

# Table des Matières

1. [Introduction](#1-introduction)
   - 1.1 [Présentation du Projet](#11-présentation-du-projet)
   - 1.2 [Objectifs](#12-objectifs)
   - 1.3 [Public Cible](#13-public-cible)
   - 1.4 [Conventions Documentaires](#14-conventions-documentaires)
2. [Architecture du Système](#2-architecture-du-système)
   - 2.1 [Vue d'Ensemble](#21-vue-densemble)
   - 2.2 [Composants Principaux](#22-composants-principaux)
   - 2.3 [Technologies Utilisées](#23-technologies-utilisées)
   - 2.4 [Flux de Données](#24-flux-de-données)
3. [Prérequis et Environnement](#3-prérequis-et-environnement)
   - 3.1 [Configuration Matérielle](#31-configuration-matérielle)
   - 3.2 [Configuration Logicielle](#32-configuration-logicielle)
   - 3.3 [Dépendances Python](#33-dépendances-python)
   - 3.4 [Ports Réseau Utilisés](#34-ports-réseau-utilisés)
4. [Installation et Déploiement](#4-installation-et-déploiement)
   - 4.1 [Récupération depuis GitHub](#41-récupération-depuis-github)
   - 4.2 [Installation Manuelle (Développeur)](#42-installation-manuelle-développeur)
   - 4.3 [Installation via Paquet Debian](#43-installation-via-paquet-debian)
   - 4.4 [Déploiement Docker](#44-déploiement-docker)
   - 4.5 [Vérification de l'Installation](#45-vérification-de-linstallation)
5. [Configuration](#5-configuration)
   - 5.1 [Variables d'Environnement (.env)](#51-variables-denvironnement-env)
   - 5.2 [Infrastructure PKI](#52-infrastructure-pki)
   - 5.3 [Configuration Base de Données](#53-configuration-base-de-données)
   - 5.4 [Configuration Réseau](#54-configuration-réseau)
6. [Guide d'Utilisation](#6-guide-dutilisation)
   - 6.1 [Lancement de l'Application](#61-lancement-de-lapplication)
   - 6.2 [Authentification](#62-authentification)
   - 6.3 [Interface Principale (GUI)](#63-interface-principale-gui)
   - 6.4 [API REST](#64-api-rest)
   - 6.5 [Mode Ligne de Commande (CLI)](#65-mode-ligne-de-commande-cli)
7. [Fonctionnalités Détaillées](#7-fonctionnalités-détaillées)
   - 7.1 [Capture de Paquets SNMP](#71-capture-de-paquets-snmp)
   - 7.2 [Analyse et Déchiffrement SNMPv3](#72-analyse-et-déchiffrement-snmpv3)
   - 7.3 [Détection d'Anomalies](#73-détection-danomalies)
   - 7.4 [Gestion des Utilisateurs](#74-gestion-des-utilisateurs)
   - 7.5 [Topologie Réseau](#75-topologie-réseau)
   - 7.6 [Export et Rapports](#76-export-et-rapports)
8. [Sécurité](#8-sécurité)
   - 8.1 [Authentification Sécurisée](#81-authentification-sécurisée)
   - 8.2 [Gestion des Certificats](#82-gestion-des-certificats)
   - 8.3 [Chiffrement des Données](#83-chiffrement-des-données)
   - 8.4 [Bonnes Pratiques](#84-bonnes-pratiques)
9. [Maintenance et Dépannage](#9-maintenance-et-dépannage)
   - 9.1 [Logs et Diagnostics](#91-logs-et-diagnostics)
   - 9.2 [Problèmes Courants](#92-problèmes-courants)
   - 9.3 [Sauvegarde et Restauration](#93-sauvegarde-et-restauration)
   - 9.4 [Mises à Jour](#94-mises-à-jour)
10. [Annexes](#10-annexes)
    - 10.1 [Liste des Figures](#101-liste-des-figures)
    - 10.2 [Arborescence du Projet](#102-arborescence-du-projet)
    - 10.3 [Glossaire](#103-glossaire)
    - 10.4 [Références](#104-références)
11. [Perspectives d'Évolution](#11-perspectives-dévolution)
    - 11.1 [Roadmap Technique](#111-roadmap-technique)
    - 11.2 [Améliorations Planifiées](#112-améliorations-planifiées)
    - 11.3 [Contributions et Retours](#113-contributions-et-retours)

---

<div style="page-break-after: always;"></div>

# 1. Introduction

## 1.1 Présentation du Projet

**MiBombo Suite** est une solution logicielle complète de gestion et d'analyse de trames SNMP (Simple Network Management Protocol). Développée dans le cadre de la SAE 501/502 du BUT Réseaux & Télécommunications de l'IUT de Béziers, cette application répond aux besoins des administrateurs réseau en matière de supervision et de sécurité.

Le protocole SNMP est omniprésent dans les infrastructures réseau modernes. Il permet de surveiller et de gérer les équipements (routeurs, switches, serveurs, imprimantes, etc.) de manière centralisée. Cependant, l'analyse du trafic SNMP peut s'avérer complexe, notamment avec l'introduction de SNMPv3 et ses mécanismes de chiffrement.

MiBombo Suite offre une interface unifiée pour :
- **Capturer** les trames SNMP en temps réel sur le réseau
- **Analyser** le contenu des paquets (v1, v2c et v3)
- **Déchiffrer** les messages SNMPv3 avec authentification et confidentialité
- **Détecter** les anomalies comportementales sur le réseau
- **Alerter** les opérateurs en cas de comportement suspect

*cf. Figure 1 : Interface principale de MiBombo Suite*

## 1.2 Objectifs

Les objectifs principaux du projet sont :

| Objectif | Description |
|----------|-------------|
| **Technique** | Développement d'un outil capable de capturer, analyser et stocker les trames SNMP v1/v2c/v3 |
| **Sécurité** | Implémentation d'un système d'authentification robuste avec 2FA et gestion des rôles |
| **Ergonomie** | Interface graphique intuitive de type "tableau de bord" pour les équipes SOC/NOC |
| **Extensibilité** | API REST documentée permettant l'intégration avec d'autres outils |
| **Autonomie** | Déploiement simplifié via paquet Debian ou conteneur Docker |

## 1.3 Public Cible

Cette documentation s'adresse aux profils suivants :

- **Administrateurs Système** : Installation, configuration et maintenance
- **Ingénieurs Réseau** : Utilisation quotidienne pour la supervision
- **Analystes Sécurité (SOC)** : Détection d'anomalies et investigation
- **Développeurs** : Intégration API et contribution au code

## 1.4 Conventions Documentaires

Ce document utilise les conventions suivantes pour faciliter la lecture :

| Convention | Signification |
|------------|---------------|
| `commande` | Commande à exécuter dans un terminal |
| **Terme** | Terme important ou nom de menu |
| *cf. Figure X* | Référence à une capture d'écran à insérer |
| ⚠️ | Avertissement important |
| 💡 | Conseil ou astuce |
| 📁 | Chemin de fichier ou répertoire |

### Codes Couleur des Alertes

Dans l'interface MiBombo, les alertes utilisent un système de couleurs standardisé :

| Couleur | Niveau | Signification |
|---------|--------|---------------|
| 🟢 Vert | OK / Info | Fonctionnement normal, information |
| 🟡 Jaune | Warning | Attention requise, anomalie mineure |
| 🟠 Orange | Critical | Situation critique nécessitant une action |
| 🔴 Rouge | Emergency | Urgence, intervention immédiate requise |

---

<div style="page-break-after: always;"></div>

# 2. Architecture du Système

## 2.1 Vue d'Ensemble

MiBombo Suite adopte une architecture modulaire composée de plusieurs couches distinctes :

```
┌─────────────────────────────────────────────────────────────────┐
│                      COUCHE PRÉSENTATION                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Interface     │  │    API REST     │  │      CLI        │  │
│  │   Graphique     │  │   (Flask)       │  │   (argparse)    │  │
│  │   (CustomTk)    │  │   Port 5000     │  │                 │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
└───────────┼────────────────────┼────────────────────┼───────────┘
            │                    │                    │
┌───────────┴────────────────────┴────────────────────┴───────────┐
│                      COUCHE MÉTIER (CORE)                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐  │
│  │   Sniffer   │ │  Analyzer   │ │  Anomaly    │ │   Auth    │  │
│  │  (Scapy)    │ │  (Parser)   │ │  Detector   │ │  Manager  │  │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └─────┬─────┘  │
└─────────┼───────────────┼───────────────┼──────────────┼────────┘
          │               │               │              │
┌─────────┴───────────────┴───────────────┴──────────────┴────────┐
│                      COUCHE DONNÉES                             │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐   │
│  │   PostgreSQL/SQLite │  │   Fichiers (PCAP, Config, Logs) │   │
│  └─────────────────────┘  └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

*cf. Figure 2 : Schéma d'architecture de MiBombo Suite*

## 2.2 Composants Principaux

### 2.2.1 Module Sniffer (`core/sniffer.py`)

Responsable de la capture des paquets réseau en temps réel grâce à la bibliothèque **Scapy**. Il écoute sur l'interface réseau spécifiée et filtre les trames SNMP (ports UDP 161 et 162).

**Caractéristiques :**
- Capture en mode promiscuous
- Filtre BPF configurable
- File d'attente thread-safe pour le traitement asynchrone

### 2.2.2 Module Analyzer (`core/analyzer.py`)

Parse et interprète les paquets SNMP capturés. Supporte les trois versions du protocole :

| Version | Fonctionnalités |
|---------|-----------------|
| **v1** | Parsing complet, extraction des OID et valeurs |
| **v2c** | Idem v1 + support des types étendus |
| **v3** | Authentification (MD5, SHA), Chiffrement (DES, AES), USM |

### 2.2.3 Module Anomaly Detector (`core/anomaly_detector.py`)

Système de détection comportementale basé sur des règles et des seuils statistiques :

- Détection de scan de communautés
- Alerte sur trafic anormal (pics d'activité)
- Identification de sources suspectes
- Classification par sévérité (Info, Warning, Critical, Emergency)

### 2.2.4 Module Authentication (`core/secure_authentication.py`)

Gestion de l'authentification et des autorisations :

- Hashage des mots de passe (Argon2/bcrypt)
- Authentification à deux facteurs (2FA) par e-mail
- Gestion des rôles (admin, operator, viewer)
- Sessions sécurisées avec tokens JWT

## 2.3 Technologies Utilisées

| Catégorie | Technologie | Version |
|-----------|-------------|---------|
| **Langage** | Python | 3.11+ |
| **GUI** | CustomTkinter | 5.x |
| **Capture Réseau** | Scapy | 2.5+ |
| **API Web** | Flask + Flask-CORS | 3.x |
| **Base de Données** | PostgreSQL / SQLite | 16 / 3 |
| **Chiffrement** | Cryptography | 41+ |
| **Graphiques** | Matplotlib | 3.8+ |
| **Conteneurisation** | Docker + Compose | 24+ |

---

<div style="page-break-after: always;"></div>

# 3. Prérequis et Environnement

## 3.1 Configuration Matérielle

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| **Processeur** | Dual-core 2 GHz | Quad-core 3 GHz |
| **Mémoire RAM** | 2 Go | 4 Go ou plus |
| **Stockage** | 500 Mo | 2 Go (pour les captures) |
| **Réseau** | 1 interface Ethernet | Interface dédiée au mirroring |

> **Note :** La capture de paquets nécessite des privilèges élevés (root/sudo) ou des capabilities réseau appropriées.

## 3.2 Configuration Logicielle

### Système d'Exploitation

MiBombo Suite est conçu pour fonctionner sur les systèmes Linux :

| Distribution | Version Testée | Statut |
|--------------|----------------|--------|
| **Debian** | 12 (Bookworm), 13 (Trixie) | ✅ Supporté |
| **Ubuntu** | 22.04 LTS, 24.04 LTS | ✅ Supporté |
| **Rocky Linux** | 9.x | ⚠️ Partiel |
| **Windows** | 10/11 (WSL2) | ⚠️ Expérimental |

### Paquets Système Requis

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    libpq-dev postgresql-client \
    tcpdump wireshark-common \
    openssl git curl
```

*cf. Figure 3 : Installation des dépendances système sur Debian*

## 3.3 Dépendances Python

Les dépendances Python sont listées dans le fichier `requirements.txt` :

```
# Framework Web
Flask>=3.0.0
Flask-CORS>=4.0.0
flask-socketio>=5.3.0

# Capture Réseau
scapy>=2.5.0

# Interface Graphique
customtkinter>=5.2.0
Pillow>=10.0.0
matplotlib>=3.8.0

# Base de Données
psycopg2-binary>=2.9.0
influxdb-client>=1.36.0

# Sécurité
cryptography>=41.0.0
pyotp>=2.9.0
argon2-cffi>=23.1.0

# Utilitaires
python-dotenv>=1.0.0
requests>=2.31.0
psutil>=5.9.0
```

---

<div style="page-break-after: always;"></div>

# 4. Installation et Déploiement

## 4.1 Récupération depuis GitHub

### Étape 1 : Cloner le Dépôt

```bash
# Clonage du dépôt (accès public)
git clone https://github.com/IUT-Beziers/sae501-502-ensa_.git

# OU avec un token d'accès personnel (accès privé)
git clone https://<VOTRE_TOKEN>@github.com/IUT-Beziers/sae501-502-ensa_.git
```

*cf. Figure 4 : Clonage du dépôt GitHub*

### Étape 2 : Naviguer vers le Répertoire

```bash
cd sae501-502-ensa_/MiBombo_version1
```

### Étape 3 : Vérifier la Structure

```bash
ls -la
```

Vous devriez voir la structure suivante :

```
MiBombo_version1/
├── api/                 # API REST Flask
├── assets/              # Ressources graphiques (logo, icônes)
├── config/              # Fichiers de configuration (générés)
├── core/                # Modules métier principaux
├── data/                # Données et logs (générés)
├── debian/              # Scripts de packaging Debian
├── docs/                # Documentation additionnelle
├── gui/                 # Interface graphique
├── pki/                 # Certificats PKI (générés)
├── scripts/             # Scripts utilitaires
├── tests/               # Tests unitaires et d'intégration
├── utils/               # Utilitaires divers
├── .env.example         # Template des variables d'environnement
├── main.py              # Point d'entrée principal
├── requirements.txt     # Dépendances Python
└── run.sh               # Script de lancement
```

*cf. Figure 5 : Arborescence du projet MiBombo*

## 4.2 Installation Manuelle (Développeur)

Cette méthode est recommandée pour les développeurs ou pour un déploiement de test.

### Étape 1 : Créer un Environnement Virtuel

```bash
python3 -m venv venv
source venv/bin/activate
```

*cf. Figure 6 : Création et activation du virtual environment*

### Étape 2 : Installer les Dépendances

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

*cf. Figure 7 : Installation des dépendances Python*

### Étape 3 : Configurer les Variables d'Environnement

```bash
cp .env.example .env
nano .env
```

Modifiez les valeurs par défaut, notamment les clés de sécurité :

```bash
# Génération d'une clé sécurisée
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

*cf. Figure 8 : Configuration du fichier .env*

### Étape 4 : Générer l'Infrastructure PKI

```bash
chmod +x scripts/pki/generate_pki.sh
./scripts/pki/generate_pki.sh
```

Cette commande génère :
- Autorité de certification racine (Root CA)
- Autorité de certification subordonnée (Sub CA)
- Certificat de la station MiBombo

*cf. Figure 9 : Génération des certificats PKI*

### Étape 5 : Lancer l'Application

```bash
sudo ./run.sh
```

Ou directement :

```bash
sudo ./venv/bin/python main.py
```

*cf. Figure 10 : Démarrage de MiBombo Suite*

## 4.3 Installation via Paquet Debian

Cette méthode est recommandée pour un déploiement en production.

### Étape 1 : Construire le Paquet

```bash
chmod +x build_deb.sh
./build_deb.sh
```

*cf. Figure 11 : Construction du paquet .deb*

### Étape 2 : Installer le Paquet

```bash
sudo dpkg -i mibombo_1.1.0_all.deb

# Résoudre les dépendances manquantes si nécessaire
sudo apt-get install -f
```

*cf. Figure 12 : Installation du paquet Debian*

### Étape 3 : Lancer l'Application

```bash
sudo mibombo
```

L'application est également accessible depuis le menu des applications du bureau.

*cf. Figure 13 : Lancement via le menu Applications*

## 4.4 Déploiement Docker

### Étape 1 : Construire l'Image

```bash
docker-compose build
```

### Étape 2 : Démarrer les Conteneurs

```bash
docker-compose up -d
```

Cette commande démarre :
- Le conteneur MiBombo (application principale)
- Le conteneur InfluxDB (métriques temps réel)

*cf. Figure 14 : Déploiement Docker avec docker-compose*

### Étape 3 : Vérifier l'État

```bash
docker-compose ps
docker-compose logs -f mibombo-app
```

### Étape 4 : Accéder à l'Application

- **API REST** : `https://localhost:5000`
- **Documentation API** : `https://localhost:5000/api/docs`
- **InfluxDB UI** : `http://localhost:8086`

---

<div style="page-break-after: always;"></div>

# 5. Configuration

## 5.1 Variables d'Environnement (.env)

Le fichier `.env` centralise toutes les configurations sensibles. Il ne doit **jamais** être commité sur Git.

| Variable | Description | Exemple |
|----------|-------------|---------|
| `FLASK_SECRET_KEY` | Clé secrète Flask pour les sessions | `votre_cle_aleatoire_32_chars` |
| `SNIFFER_KEY` | Clé de chiffrement des captures | `Fernet.generate_key()` |
| `AUTH_KEY` | Clé de chiffrement des tokens auth | `Fernet.generate_key()` |
| `ENCRYPTION_KEY` | Clé générale de chiffrement | `Fernet.generate_key()` |
| `DATABASE_URL` | URL de connexion PostgreSQL | `postgresql://user:pass@host/db` |
| `INFLUXDB_TOKEN` | Token d'accès InfluxDB | `my-super-secret-token` |
| `INFLUXDB_ORG` | Organisation InfluxDB | `mibombo-org` |
| `INFLUXDB_BUCKET` | Bucket InfluxDB | `mibombo-bucket` |

*cf. Figure 15 : Exemple de fichier .env configuré*

### Génération Automatique des Clés

Le script `postinst` du paquet Debian génère automatiquement ces clés lors de l'installation. Pour une installation manuelle :

```bash
python3 -c "
from cryptography.fernet import Fernet
print('SNIFFER_KEY=' + Fernet.generate_key().decode())
print('AUTH_KEY=' + Fernet.generate_key().decode())
print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())
"
```

## 5.2 Infrastructure PKI

MiBombo utilise une infrastructure à clé publique (PKI) hiérarchique pour sécuriser les communications HTTPS.

### Structure de la PKI

```
pki/
├── root_ca/
│   ├── rootCA.key          # Clé privée Root CA (protéger absolument)
│   ├── rootCA.pem          # Certificat Root CA
│   └── rootCA.srl          # Numéro de série
├── sub_ca/
│   ├── subCA.key           # Clé privée Sub CA
│   ├── subCA.pem           # Certificat Sub CA
│   └── subCA.csr           # Requête de signature
└── station/
    ├── station.key         # Clé privée Station
    ├── station.pem         # Certificat Station
    └── station.csr         # Requête de signature
```

### Durées de Validité

| Certificat | Durée | Commande de Renouvellement |
|------------|-------|----------------------------|
| Root CA | 5 ans | Regénération complète |
| Sub CA | 1 an | `./scripts/pki/generate_pki.sh` |
| Station | 90 jours | `./scripts/pki/renew_station_cert.sh` |

*cf. Figure 16 : Hiérarchie des certificats PKI*

## 5.3 Configuration Base de Données

### SQLite (Par défaut)

MiBombo utilise SQLite par défaut pour une installation simplifiée. Le fichier `mibombo.db` est créé automatiquement au premier lancement.

### PostgreSQL (Production)

Pour un environnement de production, PostgreSQL est recommandé :

```bash
# Création de la base de données
sudo -u postgres psql
CREATE DATABASE mibombo;
CREATE USER mibombo WITH ENCRYPTED PASSWORD 'votre_mot_de_passe';
GRANT ALL PRIVILEGES ON DATABASE mibombo TO mibombo;
```

Configurez ensuite `DATABASE_URL` dans `.env` :

```
DATABASE_URL=postgresql://mibombo:votre_mot_de_passe@localhost/mibombo
```

---

<div style="page-break-after: always;"></div>

# 6. Guide d'Utilisation

## 6.1 Lancement de l'Application

### Mode Graphique (Défaut)

```bash
sudo ./run.sh
# ou
sudo mibombo
```

Au démarrage, l'application affiche :
1. Le logo ASCII MiBombo
2. Les modules chargés
3. L'URL de l'API REST
4. La fenêtre de connexion

*cf. Figure 17 : Écran de démarrage de l'application*

### Mode CLI (Ligne de Commande)

```bash
sudo python main.py --cli -i eth0
```

Options disponibles :

| Option | Description | Défaut |
|--------|-------------|--------|
| `-i, --interface` | Interface réseau à écouter | `eth0` |
| `-f, --filter` | Filtre BPF personnalisé | `udp port 161 or 162` |
| `-d, --database` | Chemin vers la base SQLite | `mibombo.db` |
| `--with-api` | Active l'API REST en arrière-plan | Désactivé |

*cf. Figure 18 : Utilisation en mode CLI*

### Mode API Seule

```bash
sudo python main.py --api-only --api-port 5000
```

Ce mode lance uniquement le serveur API REST, sans interface graphique.

## 6.2 Authentification

### Première Connexion

Lors du premier lancement, un compte administrateur par défaut est créé :

| Champ | Valeur |
|-------|--------|
| **Identifiant** | `admin` |
| **Mot de passe** | `admin` |

> ⚠️ **ATTENTION** : Changez immédiatement ce mot de passe après la première connexion !

*cf. Figure 19 : Écran de connexion*

### Authentification à Deux Facteurs (2FA)

Si activée, l'utilisateur recevra un code à 6 chiffres par e-mail après avoir entré son mot de passe.

*cf. Figure 20 : Saisie du code 2FA*

### Création de Compte

Les nouveaux utilisateurs peuvent demander la création d'un compte :
1. Cliquer sur "Créer un compte"
2. Remplir le formulaire (identifiant, e-mail, mot de passe)
3. La demande est envoyée à l'administrateur pour validation

*cf. Figure 21 : Formulaire d'inscription*

## 6.3 Interface Principale (GUI)

### Vue d'Ensemble

L'interface principale est organisée en plusieurs onglets :

| Onglet | Description |
|--------|-------------|
| **SOC (Security)** | Tableau de bord sécurité avec alertes et anomalies |
| **NOC (Network)** | Statistiques réseau et performances |
| **Synthèse** | Vue consolidée des captures SNMP |
| **Historique** | Recherche et filtrage des paquets passés |
| **Topologie** | Cartographie du réseau découvert |
| **API** | Documentation interactive de l'API |
| **Paramètres** | Configuration de l'application |

*cf. Figure 22 : Interface principale avec onglets*

### Onglet SOC

Cet onglet présente :
- **Jauges temps réel** : CPU, RAM, débit réseau
- **Graphique temporel** : Évolution du nombre de paquets/seconde
- **Panneau d'alertes** : Liste des anomalies détectées avec sévérité
- **Top IP** : Classement des hôtes les plus actifs

*cf. Figure 23 : Vue détaillée de l'onglet SOC*

### Onglet Historique

Permet de :
- Rechercher des paquets par IP, OID, version SNMP
- Filtrer par plage de dates
- Exporter les résultats en CSV ou PCAP
- Voir les détails complets d'un paquet

*cf. Figure 24 : Recherche et filtrage de l'historique*

### Onglet Topologie

Affiche une carte interactive des équipements détectés sur le réseau, construite automatiquement à partir des adresses IP observées.

*cf. Figure 25 : Vue de la topologie réseau*

## 6.4 API REST

### Points d'Accès Principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/api/status` | État de l'application |
| `POST` | `/api/capture/start` | Démarrer une capture |
| `POST` | `/api/capture/stop` | Arrêter la capture |
| `GET` | `/api/packets` | Liste des paquets capturés |
| `GET` | `/api/stats` | Statistiques globales |
| `GET` | `/api/alerts` | Alertes d'anomalies |

### Authentification API

L'API utilise des tokens Bearer :

```bash
# Obtenir un token
curl -X POST https://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}' \
  --insecure

# Utiliser le token
curl https://localhost:5000/api/status \
  -H "Authorization: Bearer <TOKEN>" \
  --insecure
```

*cf. Figure 26 : Documentation interactive de l'API (Swagger UI)*

## 6.5 Mode Ligne de Commande (CLI)

Le mode CLI est utile pour :
- Les serveurs sans interface graphique
- L'intégration dans des scripts
- Le déploiement headless (Docker, VM)

### Exemple de Session CLI

```bash
$ sudo python main.py --cli -i eth0 --with-api

============================================================
     MiBombo Suite V1.1.0 - Mode CLI
============================================================
  Interface: eth0
  Filtre: udp port 161 or udp port 162
  Database: mibombo.db
============================================================
[+] API REST: http://0.0.0.0:5000

[*] Capture en cours... (Ctrl+C pour arreter)

[LIVE] Paquets:    142 | Alertes:    3
```

*cf. Figure 27 : Session CLI en cours*

---

<div style="page-break-after: always;"></div>

# 7. Fonctionnalités Détaillées

## 7.1 Capture de Paquets SNMP

### Démarrage de la Capture

Depuis l'interface graphique :
1. Sélectionner l'interface réseau dans les paramètres
2. Cliquer sur le bouton "Démarrer la capture"
3. Observer les paquets apparaître en temps réel

*cf. Figure 28 : Bouton de démarrage de capture*

### Filtre BPF

Le filtre par défaut est :
```
udp port 161 or udp port 162
```

Personnalisable pour cibler des hôtes spécifiques :
```
host 192.168.1.100 and (udp port 161 or udp port 162)
```

## 7.2 Analyse et Déchiffrement SNMPv3

MiBombo supporte le déchiffrement des paquets SNMPv3 sécurisés.

### Prérequis

Pour déchiffrer les messages SNMPv3, vous devez enregistrer les credentials des agents :
1. Aller dans Paramètres > Credentials SNMPv3
2. Ajouter un utilisateur : Username, Auth Protocol (MD5/SHA), Auth Key, Priv Protocol (DES/AES), Priv Key

*cf. Figure 29 : Configuration des credentials SNMPv3*

### Niveaux de Sécurité

| Niveau | Auth | Priv | Description |
|--------|------|------|-------------|
| `noAuthNoPriv` | ❌ | ❌ | Aucune sécurité |
| `authNoPriv` | ✅ | ❌ | Authentification uniquement |
| `authPriv` | ✅ | ✅ | Authentification + Chiffrement |

## 7.3 Détection d'Anomalies

Le module de détection analyse en permanence le trafic et génère des alertes.

### Types d'Anomalies Détectées

| Type | Description | Sévérité |
|------|-------------|----------|
| **Community Scan** | Tentatives multiples avec différentes communautés | Warning |
| **Traffic Spike** | Augmentation soudaine du nombre de requêtes | Info |
| **Unknown Source** | Nouvelle IP non répertoriée | Info |
| **Suspicious OID** | Accès à des OID sensibles | Critical |
| **Flood Attack** | Volume anormal depuis une même source | Emergency |

*cf. Figure 30 : Panneau des alertes d'anomalies*

## 7.4 Gestion des Utilisateurs

### Rôles et Permissions

| Rôle | Permissions |
|------|-------------|
| **admin** | Toutes les permissions (gestion utilisateurs, configuration) |
| **operator** | Capture, analyse, export des données |
| **viewer** | Consultation seule (lecture des statistiques) |

### Administration des Comptes

Accessible via Paramètres > Gestion des Utilisateurs :
- Valider les demandes d'inscription
- Activer/Désactiver des comptes
- Modifier les rôles
- Réinitialiser les mots de passe

*cf. Figure 31 : Interface de gestion des utilisateurs*

## 7.5 Topologie Réseau

La vue topologique affiche les équipements découverts :
- Position automatique en fonction des sous-réseaux
- Indicateur de statut (actif, inactif, alerté)
- Clic pour afficher les détails d'un hôte

*cf. Figure 32 : Exemple de topologie réseau*

---

<div style="page-break-after: always;"></div>

# 8. Sécurité

## 8.1 Authentification Sécurisée

### Stockage des Mots de Passe

Les mots de passe sont hashés avec **Argon2id**, l'algorithme recommandé par OWASP :
- Résistant aux attaques GPU
- Protection contre les attaques par canal auxiliaire
- Salage automatique

### Protection Contre les Attaques

| Attaque | Protection |
|---------|------------|
| **Brute Force** | Limitation du nombre de tentatives (rate limiting) |
| **Session Hijacking** | Tokens JWT avec expiration courte |
| **CSRF** | Tokens CSRF sur les formulaires |
| **XSS** | Échappement des entrées utilisateur |

## 8.2 Gestion des Certificats

### Renouvellement Automatique

Configurer un cron pour le renouvellement automatique :

```bash
# Renouveler le certificat Station tous les 80 jours
0 2 */80 * * /opt/mibombo/scripts/pki/renew_station_cert.sh && systemctl restart mibombo
```

### Vérification des Certificats

```bash
# Vérifier l'expiration
openssl x509 -in pki/station/station.pem -noout -dates
```

*cf. Figure 33 : Vérification de la validité des certificats*

## 8.3 Bonnes Pratiques

1. **Ne jamais utiliser les identifiants par défaut** en production
2. **Activer le 2FA** pour tous les comptes administrateurs
3. **Sauvegarder régulièrement** la base de données et les configurations
4. **Mettre à jour** les dépendances Python régulièrement
5. **Isoler** le serveur MiBombo dans un VLAN dédié si possible

---

<div style="page-break-after: always;"></div>

# 9. Maintenance et Dépannage

## 9.1 Logs et Diagnostics

### Emplacement des Logs

```
data/logs/
├── mibombo.log         # Log principal de l'application
├── api.log             # Log des requêtes API
├── security.log        # Événements de sécurité (connexions, alertes)
└── sniffer.log         # Log du module de capture
```

### Niveaux de Log

| Niveau | Description |
|--------|-------------|
| `DEBUG` | Informations de débogage détaillées |
| `INFO` | Événements normaux |
| `WARNING` | Situations inhabituelles non bloquantes |
| `ERROR` | Erreurs nécessitant une attention |
| `CRITICAL` | Erreurs graves empêchant le fonctionnement |

*cf. Figure 34 : Exemple de fichier de log*

## 9.2 Problèmes Courants

### Erreur : "SNIFFER_KEY manquante"

**Cause** : Le fichier `.env` n'est pas configuré ou la clé est invalide.

**Solution** :
```bash
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print('SNIFFER_KEY=' + Fernet.generate_key().decode())" >> .env
```

### Erreur : "Permission denied" lors de la capture

**Cause** : L'application n'a pas les droits root.

**Solution** :
```bash
sudo ./run.sh
```

### Erreur : "No module named 'xyz'"

**Cause** : Dépendance Python manquante.

**Solution** :
```bash
pip install -r requirements.txt
```

### L'interface ne s'affiche pas (environnement headless)

**Cause** : Aucun display X11 disponible.

**Solution** : Utiliser le mode CLI ou configurer X11 forwarding :
```bash
ssh -X user@serveur
sudo python main.py
```

*cf. Figure 35 : Résolution d'erreurs courantes*

## 9.3 Sauvegarde et Restauration

### Sauvegarde Complète

```bash
# Sauvegarde des données et configurations
tar -czf mibombo_backup_$(date +%Y%m%d).tar.gz \
    --exclude=venv --exclude=__pycache__ \
    mibombo.db config/ data/ .env
```

### Restauration

```bash
tar -xzf mibombo_backup_20260116.tar.gz -C /opt/mibombo/
```

*cf. Figure 36 : Processus de sauvegarde et restauration*

---

<div style="page-break-after: always;"></div>

# 10. Annexes

## 10.1 Liste des Figures

| Figure | Description | Page |
|--------|-------------|------|
| Figure 1 | Interface principale de MiBombo Suite | Introduction |
| Figure 2 | Schéma d'architecture de MiBombo Suite | Architecture |
| Figure 3 | Installation des dépendances système sur Debian | Prérequis |
| Figure 4 | Clonage du dépôt GitHub | Installation |
| Figure 5 | Arborescence du projet MiBombo | Installation |
| Figure 6 | Création et activation du virtual environment | Installation |
| Figure 7 | Installation des dépendances Python | Installation |
| Figure 8 | Configuration du fichier .env | Installation |
| Figure 9 | Génération des certificats PKI | Installation |
| Figure 10 | Démarrage de MiBombo Suite | Installation |
| Figure 11 | Construction du paquet .deb | Installation |
| Figure 12 | Installation du paquet Debian | Installation |
| Figure 13 | Lancement via le menu Applications | Installation |
| Figure 14 | Déploiement Docker avec docker-compose | Installation |
| Figure 15 | Exemple de fichier .env configuré | Configuration |
| Figure 16 | Hiérarchie des certificats PKI | Configuration |
| Figure 17 | Écran de démarrage de l'application | Utilisation |
| Figure 18 | Utilisation en mode CLI | Utilisation |
| Figure 19 | Écran de connexion | Utilisation |
| Figure 20 | Saisie du code 2FA | Utilisation |
| Figure 21 | Formulaire d'inscription | Utilisation |
| Figure 22 | Interface principale avec onglets | Utilisation |
| Figure 23 | Vue détaillée de l'onglet SOC | Utilisation |
| Figure 24 | Recherche et filtrage de l'historique | Utilisation |
| Figure 25 | Vue de la topologie réseau | Utilisation |
| Figure 26 | Documentation interactive de l'API (Swagger UI) | Utilisation |
| Figure 27 | Session CLI en cours | Utilisation |
| Figure 28 | Bouton de démarrage de capture | Fonctionnalités |
| Figure 29 | Configuration des credentials SNMPv3 | Fonctionnalités |
| Figure 30 | Panneau des alertes d'anomalies | Fonctionnalités |
| Figure 31 | Interface de gestion des utilisateurs | Fonctionnalités |
| Figure 32 | Exemple de topologie réseau | Fonctionnalités |
| Figure 33 | Vérification de la validité des certificats | Sécurité |
| Figure 34 | Exemple de fichier de log | Maintenance |
| Figure 35 | Résolution d'erreurs courantes | Maintenance |
| Figure 36 | Processus de sauvegarde et restauration | Maintenance |
| Figure 37 | Roadmap des versions MiBombo Suite | Perspectives |
| Figure 38 | Comparaison avant/après résolution DNS | Perspectives |

## 10.2 Arborescence du Projet

```
MiBombo_version1/
├── api/
│   ├── __init__.py
│   └── api.py                 # Définition de l'API REST Flask
├── assets/
│   └── logo.png               # Logo de l'application
├── core/
│   ├── __init__.py
│   ├── analyzer.py            # Analyse des paquets SNMP
│   ├── anomaly_detector.py    # Détection d'anomalies
│   ├── app_config.py          # Configuration applicative
│   ├── authentication.py      # Authentification legacy
│   ├── logger.py              # Système de logging
│   ├── mailer.py              # Envoi d'e-mails (2FA)
│   ├── PostgresDB.py          # Couche d'accès base de données
│   ├── secure_authentication.py # Auth sécurisée (nouveau)
│   ├── sniffer.py             # Capture de paquets
│   ├── snmp_credentials.py    # Gestion des credentials SNMPv3
│   └── ssl_config.py          # Configuration SSL/TLS
├── gui/
│   ├── __init__.py
│   ├── auth_panel.py          # Widgets d'authentification
│   ├── documentation_tab.py   # Onglet documentation
│   ├── extensions.py          # Extensions GUI
│   ├── legacy_auth_widgets.py # Widgets auth legacy
│   ├── main_gui.py            # Interface principale
│   └── sem_topology.py        # Widget topologie
├── scripts/
│   └── pki/
│       ├── generate_pki.sh    # Génération PKI complète
│       └── renew_station_cert.sh # Renouvellement certificat
├── tests/
│   ├── test_api.py
│   ├── test_auth.py
│   └── test_components.py
├── utils/
│   ├── __init__.py
│   └── db_viewer.py           # Visualiseur base de données
├── .env.example               # Template variables d'environnement
├── docker-compose.yml         # Configuration Docker
├── Dockerfile                 # Image Docker
├── main.py                    # Point d'entrée
├── requirements.txt           # Dépendances Python
└── run.sh                     # Script de lancement
```

## 10.3 Glossaire

| Terme | Définition |
|-------|------------|
| **2FA** | Two-Factor Authentication – Authentification à deux facteurs |
| **API** | Application Programming Interface – Interface de programmation |
| **ASN.1** | Abstract Syntax Notation One – Notation de syntaxe abstraite utilisée par SNMP |
| **BER** | Basic Encoding Rules – Règles d'encodage de base pour ASN.1 |
| **BPF** | Berkeley Packet Filter – Filtre de paquets utilisé pour la capture réseau |
| **CA** | Certificate Authority – Autorité de certification |
| **CLI** | Command Line Interface – Interface en ligne de commande |
| **CSRF** | Cross-Site Request Forgery – Falsification de requête inter-sites |
| **DES** | Data Encryption Standard – Algorithme de chiffrement symétrique |
| **FQDN** | Fully Qualified Domain Name – Nom de domaine pleinement qualifié |
| **GUI** | Graphical User Interface – Interface graphique utilisateur |
| **JWT** | JSON Web Token – Jeton d'authentification au format JSON |
| **MIB** | Management Information Base – Base d'informations de gestion SNMP |
| **NOC** | Network Operations Center – Centre d'opérations réseau |
| **OID** | Object Identifier – Identifiant d'objet dans l'arborescence SNMP |
| **PCAP** | Packet Capture – Format de fichier de capture réseau |
| **PDU** | Protocol Data Unit – Unité de données du protocole SNMP |
| **PKI** | Public Key Infrastructure – Infrastructure à clé publique |
| **REST** | Representational State Transfer – Architecture de services web |
| **SNMP** | Simple Network Management Protocol – Protocole de gestion réseau |
| **SOC** | Security Operations Center – Centre d'opérations de sécurité |
| **SSL/TLS** | Secure Sockets Layer / Transport Layer Security – Protocoles de sécurisation |
| **USM** | User-based Security Model – Modèle de sécurité utilisateur de SNMPv3 |
| **XSS** | Cross-Site Scripting – Injection de scripts inter-sites |

## 10.4 Références

### Standards et RFCs

| Document | Titre | Lien |
|----------|-------|------|
| RFC 3411 | Architecture for SNMP | https://datatracker.ietf.org/doc/html/rfc3411 |
| RFC 3412 | Message Processing and Dispatching | https://datatracker.ietf.org/doc/html/rfc3412 |
| RFC 3414 | User-based Security Model (USM) | https://datatracker.ietf.org/doc/html/rfc3414 |
| RFC 3416 | Protocol Operations for SNMPv2 | https://datatracker.ietf.org/doc/html/rfc3416 |
| RFC 3418 | MIB for SNMP | https://datatracker.ietf.org/doc/html/rfc3418 |

### Documentation des Technologies

| Technologie | Documentation |
|-------------|---------------|
| **Python 3.11** | https://docs.python.org/3.11/ |
| **Scapy** | https://scapy.readthedocs.io/ |
| **CustomTkinter** | https://customtkinter.tomschimansky.com/ |
| **Flask** | https://flask.palletsprojects.com/ |
| **PostgreSQL** | https://www.postgresql.org/docs/ |
| **Docker** | https://docs.docker.com/ |
| **Cryptography** | https://cryptography.io/en/latest/ |

### Ressources de Sécurité

| Ressource | Lien |
|-----------|------|
| OWASP Authentication Cheat Sheet | https://cheatsheetseries.owasp.org/ |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks |
| ANSSI Guides | https://www.ssi.gouv.fr/guide/ |

---

<div style="page-break-after: always;"></div>

# 11. Perspectives d'Évolution

Ce chapitre présente la feuille de route technique et les améliorations planifiées pour les futures versions de MiBombo Suite.

## 11.1 Roadmap Technique

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ROADMAP MiBombo Suite                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Q1 2026 (Actuel)           Q2 2026              Q3-Q4 2026                │
│  ─────────────────          ─────────            ─────────────              │
│                                                                             │
│  ✅ v1.1.0                  🔄 v1.2.0            📋 v2.0.0                  │
│  • SNMPv3 complet           • Résolution DNS     • Interface web           │
│  • Détection anomalies      • Dashboard avancé   • Multi-instances         │
│  • API REST                 • Alertes email      • Machine Learning        │
│  • Auth 2FA                 • Export PDF         • Clustering HA           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

*cf. Figure 37 : Roadmap des versions MiBombo Suite*

## 11.2 Améliorations Planifiées

### 🔄 En Cours de Développement

#### Résolution DNS (IP → Nom de Domaine)

> **Statut** : 🟡 En développement actif

Nous travaillons actuellement sur un **patch de résolution DNS** qui permettra d'afficher automatiquement les noms de domaine (FQDN) à la place des adresses IP brutes dans l'interface.

**Fonctionnalités prévues :**

| Fonctionnalité | Description |
|----------------|-------------|
| **Résolution automatique** | Conversion IP → hostname en temps réel |
| **Cache DNS** | Mise en cache des résolutions pour optimiser les performances |
| **Résolution inversée** | Support du reverse DNS (PTR records) |
| **Mode hybride** | Affichage "hostname (IP)" pour une meilleure lisibilité |
| **Configuration** | Choix du serveur DNS, timeout, politique de cache |

**Exemple d'affichage attendu :**

```
Avant (actuel) :
┌──────────────────────────────────────────────────────────────┐
│ Source         │ Destination    │ Version │ Type    │ Status │
├────────────────┼────────────────┼─────────┼─────────┼────────┤
│ 192.168.1.100  │ 192.168.1.1    │ v2c     │ GetReq  │ OK     │
│ 10.0.0.50      │ 192.168.1.254  │ v3      │ GetResp │ OK     │
└──────────────────────────────────────────────────────────────┘

Après (avec patch DNS) :
┌──────────────────────────────────────────────────────────────┐
│ Source              │ Destination        │ Version │ Type    │
├─────────────────────┼────────────────────┼─────────┼─────────┤
│ srv-web.local       │ router.local       │ v2c     │ GetReq  │
│ switch-core.lan     │ fw-ext.local       │ v3      │ GetResp │
└──────────────────────────────────────────────────────────────┘
```

*cf. Figure 38 : Comparaison avant/après résolution DNS*

**Impact technique :**

- Nouveau module `core/dns_resolver.py`
- Cache LRU (Least Recently Used) avec TTL configurable
- Option dans les paramètres utilisateur
- Tolérance aux pannes DNS (fallback sur IP)

### 📋 Planifié pour les Versions Futures

#### Version 1.2.0 (Q2 2026)

| Fonctionnalité | Priorité | Description |
|----------------|----------|-------------|
| **Dashboard enrichi** | Haute | Widgets personnalisables, graphiques interactifs |
| **Alertes par email** | Haute | Notifications automatiques en cas d'anomalie critique |
| **Export PDF** | Moyenne | Génération de rapports formatés au format PDF |
| **Filtres avancés** | Moyenne | Filtrage multi-critères dans l'historique |
| **Thèmes personnalisés** | Basse | Mode sombre/clair, personnalisation des couleurs |

#### Version 1.3.0 (Q3 2026)

| Fonctionnalité | Priorité | Description |
|----------------|----------|-------------|
| **Plugin système** | Haute | Architecture extensible via plugins Python |
| **Intégration Syslog** | Haute | Export des alertes vers serveurs Syslog |
| **Support SNMP Traps** | Haute | Traitement amélioré des traps SNMPv2c/v3 |
| **Base InfluxDB native** | Moyenne | Métriques temps réel dans InfluxDB |
| **Webhooks** | Moyenne | Notifications vers services tiers (Slack, Teams) |

#### Version 2.0.0 (Q4 2026 - 2027)

| Fonctionnalité | Priorité | Description |
|----------------|----------|-------------|
| **Interface Web** | Haute | Accès via navigateur (React/Vue.js) |
| **Multi-instances** | Haute | Déploiement distribué sur plusieurs nœuds |
| **Machine Learning** | Moyenne | Détection d'anomalies par apprentissage automatique |
| **Haute Disponibilité** | Moyenne | Clustering actif/passif, failover automatique |
| **API GraphQL** | Basse | Complément à l'API REST existante |

### 🔧 Améliorations Techniques Continues

| Domaine | Amélioration |
|---------|--------------|
| **Performance** | Optimisation du parsing SNMP, réduction de l'empreinte mémoire |
| **Sécurité** | Audit régulier des dépendances, tests de pénétration |
| **Tests** | Couverture de test > 80%, tests d'intégration automatisés |
| **Documentation** | Tutoriels vidéo, exemples d'intégration API |
| **Accessibilité** | Conformité WCAG 2.1 pour l'interface graphique |

## 11.3 Contributions et Retours

### Comment Contribuer

MiBombo Suite est un projet développé dans un cadre académique. Les contributions et retours sont les bienvenus :

1. **Signaler un bug** : Ouvrir une issue sur le dépôt GitHub
2. **Proposer une fonctionnalité** : Décrire le besoin dans une issue dédiée
3. **Contribuer au code** : Fork, développement, Pull Request
4. **Documentation** : Améliorer ou traduire la documentation existante

### Contact

| Canal | Utilisation |
|-------|-------------|
| **GitHub Issues** | Bugs, demandes de fonctionnalités |
| **Email projet** | Contact direct avec l'équipe de développement |
| **IUT de Béziers** | Encadrement académique |

### Remerciements

L'équipe de développement remercie :

- **M. Druon Sébastien**, **M. Borelly Christophe** et **M. Comby Frédéric** pour leur encadrement et leurs conseils
- L'ensemble des enseignants du département **R&T de l'IUT de Béziers**
- La communauté open source pour les bibliothèques utilisées

---

<div align="center">

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Document généré le 16 Janvier 2026**

**MiBombo Suite v1.1.0**

**© 2026 - IUT de Béziers - BUT R&T**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

</div>
]]>
