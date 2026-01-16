
def _build_documentation_tab(self, parent):
    """Construit l'onglet Documentation."""
    doc_frame = ctk.CTkFrame(parent, fg_color="transparent")
    doc_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Zone de texte défilante pour le markdown
    textbox = ctk.CTkTextbox(doc_frame, font=ctk.CTkFont(family="Consolas", size=14),
                               text_color=THEME["text_primary"],
                               fg_color=THEME["bg_input"])
    textbox.pack(fill="both", expand=True)
        
    documentation_text = """
# MiBombo Station - Documentation

## Introduction
MiBombo Station est un outil de surveillance et d'analyse de trafic SNMP.

## Fonctionnalités
- **Capture**: Intercepte les paquets SNMP v1, v2c et v3.
- **Analyse**: Détecte les anomalies et les tentatives d'intrusion.
- **API REST**: Permet d'interagir avec la station via HTTP/HTTPS.

## Utilisation de l'API
Toutes les requêtes doivent être authentifiées.
URL de base: https://<ip>:5000/api

### Endpoints
- `GET /api/status`: Statut du serveur
- `GET /api/packets`: Liste des paquets capturés
- `POST /api/auth/login`: Connexion

## Support
Pour toute assistance, contactez l'administrateur.
"""
    textbox.insert("0.0", documentation_text)
    textbox.configure(state="disabled") # Lecture seule

#TODO: Ajouter la documentation de l'API 
