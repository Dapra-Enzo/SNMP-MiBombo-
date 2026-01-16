#!/usr/bin/env python3
"""
MiBombo - Interface GUI Sniffer SNMP
version 1.0.0
Fontionnalité des classes :
- Sniffer : Permet de capturer les paquets SNMP
- Analyser : Permet d'analyser les paquets SNMP
- DataBase : Permet de stocker les paquets SNMP
- ConfAPP : Permet de configurer l'application
- get_detector : Permet de detecter les anomalies
- AuthManager : Permet de gérer l'authentification
- get_auth_manager : Permet de gérer l'authentification
- logger : Permet de logger les actions de l'utilisateur
"""

# Liste des imports a avoir
import customtkinter as ctk
from tkinter import filedialog, ttk, messagebox
import tkinter as tk
from threading import Thread, Event, Lock
from queue import Queue, Empty
import json, os, sys, time, traceback, psutil
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import deque

# Importation de l"API avec un try except
try:
    from api.api import CaptureManager
    API_AVAILABLE = True
    from core.mib import translate_oid
except ImportError:
    API_AVAILABLE = False
    def translate_oid(oid): return oid



# Tout les imports des graphs du soft avec mtaplotlib 
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from PIL import Image as PILImage


# Définit la racine du projet et l’ajoute au chemin Python pour les imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

# Import des modules core
CORE_AVAILABLE = False
Sniffer = None
Analyser = None
DataBase = None
ConfAPP = None
get_detector = None
AuthManager = None
get_auth_manager = None
logger = None

# Importe et initialise les modules core de l’application avec gestion d’erreur

try:
    from core.sniffer import Sniffer as _Sniffer
    from core.analyzer import PacketAnalyzer as _Analyser
    from core.PostgresDB import DataBase as _DataBase
    from core.app_config import ConfAPP as _ConfAPP
    from core.anomaly_detector import get_detector as _get_detector
    from core.authentication import AuthenticationManager as _AuthManager, get_auth_manager as _get_auth_manager
    from core.logger import get_logger
    
    Sniffer = _Sniffer
    Analyser = _Analyser
    DataBase = _DataBase
    ConfAPP = _ConfAPP
    get_detector = _get_detector
    AuthManager = _AuthManager
    get_auth_manager = _get_auth_manager
    logger = get_logger("GUI")
    
    CORE_AVAILABLE = True
    print("[+] Les modules cores sont bien chrager ")
except ImportError as e:
    print(f"[!] Erreur des modules cores: {e}")

# Import des widgets d'authentification (ancien système - fallback)
try:
    from gui.legacy_auth_widgets import LoginWindow, ProfilePanel, UserManagementPanel
    AUTH_WIDGETS_AVAILABLE = True
except ImportError:
    try:
        from legacy_auth_widgets import LoginWindow, ProfilePanel, UserManagementPanel
        AUTH_WIDGETS_AVAILABLE = True
    except ImportError:
        AUTH_WIDGETS_AVAILABLE = False
        print("[!] Auth widgets not available")

# Import du nouveau système d'authentification sécurisé
SECURE_AUTH_AVAILABLE = False
SecureLoginWindow = None
run_secure_login = None
get_secure_auth_manager = None
TicketManagementPanel = None
SecureUserManagementPanel = None
UserListPanel = None

# Charge le système d’authentification sécurisé et ses dépendances avec chemins alternatifs et vérifications

try:
    from core.secure_authentication import get_secure_auth_manager as _get_secure_auth_manager
    get_secure_auth_manager = _get_secure_auth_manager
    print("[+] Les modules de l'authentification sécurisé sont bien chargés")
    
    from gui.auth_panel import (
        SecureLoginWindow as _SecureLoginWindow, 
        run_secure_login as _run_secure_login,
        TicketManagementPanel as _TicketManagementPanel,
        SecureUserManagementPanel as _SecureUserManagementPanel,
        UserListPanel as _UserListPanel
    )
    SecureLoginWindow = _SecureLoginWindow
    run_secure_login = _run_secure_login
    TicketManagementPanel = _TicketManagementPanel
    SecureUserManagementPanel = _SecureUserManagementPanel
    UserListPanel = _UserListPanel
    SECURE_AUTH_AVAILABLE = True
    print("[+] Le système d'authentification sécurisé est bien chargé")
except ImportError as e:
    print(f"[!] Erreur lors du chargement du système d'authentification sécurisé: {e}")
    try:
        from secure_auth import get_secure_auth_manager as _get_secure_auth_manager
        get_secure_auth_manager = _get_secure_auth_manager
        
        from auth_panel import (
            SecureLoginWindow as _SecureLoginWindow, 
            run_secure_login as _run_secure_login,
            TicketManagementPanel as _TicketManagementPanel,
            SecureUserManagementPanel as _SecureUserManagementPanel,
            UserListPanel as _UserListPanel
        )
        SecureLoginWindow = _SecureLoginWindow
        run_secure_login = _run_secure_login
        TicketManagementPanel = _TicketManagementPanel
        SecureUserManagementPanel = _SecureUserManagementPanel
        UserListPanel = _UserListPanel
        SECURE_AUTH_AVAILABLE = True
        print("[+] Le système d'authentification sécurisé est bien chargé (alt path)")
    except ImportError as e2:
        print(f"[!] Erreur lors du chargement du système d'authentification sécurisé (alt path): {e2}")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Import du widget de topologie
TOPOLOGY_WIDGET_AVAILABLE = False
TopologyPanel = None
get_topology = None
try:
    from gui.sem_topology import TopologyPanel as _TopologyPanel, get_topology as _get_topology
    TopologyPanel = _TopologyPanel
    get_topology = _get_topology
    TOPOLOGY_WIDGET_AVAILABLE = True
    print("[+] Le widget de topologie est bien chargé")
except ImportError:
    try:
        from sem_topology import TopologyPanel as _TopologyPanel, get_topology as _get_topology
        TopologyPanel = _TopologyPanel
        get_topology = _get_topology
        TOPOLOGY_WIDGET_AVAILABLE = True
        print("[+] Le widget de topologie est bien chargé")
    except ImportError as e:
        print(f"[!] Erreur lors du chargement du widget de topologie: {e}")

try:
    from core.snmp_credentials import snmp_cred_mgr
except ImportError:
    snmp_cred_mgr = None
    print("[!] SNMP Credential Manager not available")

# ───────────────────── THEME Clair Bleu et Blanc (un peu de gris) ─────────────────────


THEME = {
    # Arriere plan
    "bg_main": "#F0F2F5",       
    "bg_panel": "#FFFFFF",     
    "bg_card": "#FFFFFF",       
    "bg_input": "#F1F5F9",      
    "bg_hover": "#E2E8F0",      

    # Bordures
    "border": "#CBD5E1",        # Subtle border
    "border_light": "#E2E8F0",
    
    # TTexte
    "text_primary": "#1E293B",  
    "text_secondary": "#475569",
    "text_muted": "#64748B",    
    
    # Couleur accentuation bleu
    "accent": "#3B82F6",        
    "accent_light": "#60A5FA",
    "accent_dark": "#2563EB",
    "accent_hover": "#2563EB",
    
    # COueleurs des states
    "success": "#10B981",       
    "warning": "#F59E0B",       
    "error": "#EF4444",         
    "info": "#3B82F6",         
    
    # Couleurs des graphiques
    "chart_green": "#10B981",
    "chart_blue": "#3B82F6",
    "chart_orange": "#F59E0B",
    "chart_purple": "#8B5CF6",
    "chart_cyan": "#06B6D4",
    "chart_yellow": "#FBBF24",
    "chart_red": "#EF4444",
    "chart_pink": "#EC4899",
    
    # Grille
    "grid": "#E2E8F0",
}

# style pour matplotlib
plt.rcParams.update({
    'figure.facecolor': THEME["bg_card"],
    'axes.facecolor': THEME["bg_card"],
    'axes.edgecolor': THEME["border"],
    'axes.labelcolor': THEME["text_secondary"],
    'axes.grid': True,
    'grid.color': THEME["grid"],
    'grid.alpha': 0.5,
    'text.color': THEME["text_primary"],
    'xtick.color': THEME["text_secondary"],
    'ytick.color': THEME["text_secondary"],
    'legend.facecolor': THEME["bg_panel"],
    'legend.edgecolor': THEME["border"],
    'font.size': 11,
})

# ───────────────────── POLICE DE TEXTE ─────────────────────



FONTS = {
    "title_xl": ("Segoe UI", 24, "bold"),
    "title_lg": ("Segoe UI", 18, "bold"),
    "title_md": ("Segoe UI", 15, "bold"),
    "title_sm": ("Segoe UI", 13, "bold"),
    "body_lg": ("Segoe UI", 14, "normal"),
    "body_md": ("Segoe UI", 13, "normal"),
    "body_sm": ("Segoe UI", 12, "normal"),
    "mono_lg": ("Consolas", 13, "normal"),
    "mono_md": ("Consolas", 12, "normal"),
    "mono_sm": ("Consolas", 11, "normal"),
    "stat_value": ("Segoe UI", 36, "bold"),
    "gauge_value": ("Segoe UI", 28, "bold"),
}

ctk.set_appearance_mode("light")




class GraphiqueTemps(tk.Frame):
    """
    Widget affichant un graphique linéaire (courbe) évoluant en temps réel.
    
    Utilité :
    - Suivre l'évolution temporelle d'une métrique (ex: débit réseau, latence).
    - Visualiser l'historique récent (les N derniers points).
    - Mettre en évidence les pics et les creux d'activité.

    Fonctions associées :
    - _build() : Initialise la figure Matplotlib et le canevas Tkinter.
    - add_series(name, color) : Crée une nouvelle courbe (série de données) vide.
    - add_point(series_name, value) : Ajoute un point de donnée à une série à l'instant T.
    - update_chart() : Redessine le graphique avec les nouvelles données et ajuste l'axe X (temps).
    - clear_data() : Efface toutes les courbes et réinitialise le graphique.
    """
    
    def __init__(self, parent, title="", ylabel="", max_points=60, **kwargs):
        """Initialisation du graphique"""
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._ylabel = ylabel
        self._max_points = max_points
        self._series = {}
        self._lock = Lock()
        
        self._build()
    
    def _build(self):
        """Construction du graphique post initialisation"""
        header = tk.Frame(self, bg=THEME["bg_card"], height=40)
        header.pack(fill="x", padx=15, pady=(12, 0))
        
        
        title_frame = tk.Frame(header, bg=THEME["bg_card"])
        title_frame.pack(side="left")
        
        tk.Label(title_frame, text=self._title,
                font=("Segoe UI", 14, "bold"),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"]).pack(side="left")
        
        
        self._value_label = tk.Label(header, text="0",
                                    font=("Segoe UI", 20, "bold"),
                                    fg=THEME["accent"],
                                    bg=THEME["bg_card"])
        self._value_label.pack(side="right", padx=10)
        self._fig = Figure(figsize=(5, 2.5), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)        
        self._setup_axes()
    
    def _setup_axes(self):
        """Configuration des axes du graphique et de la grille et des labels"""
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        self._ax.spines['top'].set_visible(False)
        self._ax.spines['right'].set_visible(False)
        self._ax.spines['bottom'].set_color(THEME["grid"])
        self._ax.spines['left'].set_color(THEME["grid"])
        self._ax.spines['bottom'].set_linewidth(0.5)
        self._ax.spines['left'].set_linewidth(0.5)
        self._ax.grid(True, alpha=0.15, color=THEME["text_muted"], linestyle='-', linewidth=0.5)
        self._ax.set_axisbelow(True)
        self._ax.tick_params(axis='both', labelsize=9, colors=THEME["text_muted"], length=0)
        self._ax.set_ylabel(self._ylabel, fontsize=10, color=THEME["text_secondary"], labelpad=10)
        self._fig.tight_layout(pad=2)
    
    def add_series(self, name: str, color: str):
        """Ajout d'une série de données"""
        with self._lock:
            self._series[name] = {
                "data": deque(maxlen=self._max_points),
                "color": color
            }
    
    def add_point(self, series_name: str, value: float, timestamp: datetime = None):
        """Ajout d'un point de données"""
        if timestamp is None:
            timestamp = datetime.now()
        with self._lock:
            if series_name in self._series:
                self._series[series_name]["data"].append((timestamp, value))
    
    def update_chart(self):
        """MAJ du graphique avec les nouvelles données"""
        with self._lock:
            self._ax.clear()
            self._setup_axes()
            
            last_value = None
            for name, series in self._series.items():
                if series["data"] and len(series["data"]) > 1:
                    times = [d[0] for d in series["data"]]
                    values = [d[1] for d in series["data"]]
                    
                    color = series["color"]
                    self._ax.plot(times, values, color=color, linewidth=3.5, 
                                 solid_capstyle='round', zorder=3)
                    self._ax.fill_between(times, 0, values, alpha=0.45, color=color, zorder=2)
                    self._ax.fill_between(times, 0, values, alpha=0.15, color=color, zorder=1)

                    if len(values) > 0:
                        self._ax.scatter([times[-1]], [values[-1]], color=color, s=80, zorder=4, edgecolors='white', linewidth=2)
                    
                    last_value = values[-1] if values else None
            
           
            self._ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            self._ax.xaxis.set_major_locator(plt.MaxNLocator(5))
            self._fig.autofmt_xdate()
            
            
            if last_value is not None:
                self._value_label.configure(text=f"{last_value:.1f}")
            
            try:
                self._canvas.draw_idle()
            except:
                pass
    
    def clear_data(self):
        """Fonction de nettoyage des données"""
        with self._lock:
            for name in self._series:
                self._series[name]["data"].clear()
            self._ax.clear()
            self._setup_axes()
            self._value_label.configure(text="0.0")
            try:
                self._canvas.draw_idle()
            except:
                pass


class GraphiqueBarre(tk.Frame):
    """
    Widget affichant un graphique en barres horizontales pour les classements (Top N).
    
    Utilité :
    - Comparer des valeurs entre différentes entités (ex: Top IP talkers, Protocoles).
    - Identifier rapidement les éléments les plus actifs ou consommateurs.
    - Offrir une vue synthétique et ordonnée.

    Fonctions associées :
    - _build() : Prépare la structure graphique (titre, figure, axes).
    - set_data(data, colors) : Reçoit un dictionnaire {label: valeur}, trie les données, garde le Top N et met à jour les barres.
    """
    
    def __init__(self, parent, title="", **kwargs):
        """Initialisation du graphique en barres"""
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._data = {}
        self._build()
    
    def _build(self):
        """Construction du graphique en barres"""        
        header = tk.Frame(self, bg=THEME["bg_card"], height=40)
        header.pack(fill="x", padx=15, pady=(12, 0))
        
        tk.Label(header, text=self._title,
                font=("Segoe UI", 14, "bold"),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"]).pack(side="left")
        
       
        self._fig = Figure(figsize=(4, 2.8), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)   
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
    
    def set_data(self, data: Dict[str, float], colors: List[str] = None):
        """Mise à jour des données du graphique en triant et limitant les données"""
        self._data = data
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        
        if not data:
            try:
                self._canvas.draw_idle()
            except:
                pass
            return
        
        
        sorted_data = dict(sorted(data.items(), key=lambda x: x[1], reverse=True)[:6])
        labels = list(sorted_data.keys())
        values = list(sorted_data.values())
        
        
        grafana_colors = [
            "#7eb26d", "#eab839", "#6ed0e0", "#ef843c", 
            "#e24d42", "#1f78c1", "#ba43a9", "#705da0"
        ]
        
        if colors is None:
            colors = grafana_colors
        
       
        y_pos = range(len(labels))
        bars = self._ax.barh(y_pos, values, color=colors[:len(labels)], 
                            height=0.6, edgecolor='none', alpha=0.9)
        
        
        self._ax.set_yticks(y_pos)
        self._ax.set_yticklabels(labels, fontsize=10, color=THEME["text_primary"])
        self._ax.invert_yaxis()
        
       
        for i, (bar, val) in enumerate(zip(bars, values)):
            self._ax.text(bar.get_width() + max(values)*0.02, bar.get_y() + bar.get_height()/2,
                         f'{int(val)}', va='center', fontsize=10, 
                         color=THEME["text_secondary"], fontweight='bold')
        
        
        self._ax.spines['top'].set_visible(False)
        self._ax.spines['right'].set_visible(False)
        self._ax.spines['bottom'].set_visible(False)
        self._ax.spines['left'].set_visible(False)
        self._ax.tick_params(axis='x', which='both', bottom=False, labelbottom=False)
        self._ax.tick_params(axis='y', which='both', left=False)
        self._ax.set_axisbelow(True)
        self._ax.xaxis.grid(True, alpha=0.1, color=THEME["text_muted"])
        self._fig.tight_layout(pad=2)
        try:
            self._canvas.draw_idle()
        except:
            pass


class JaugeCirculaire(tk.Frame):
    """
    Widget graphique affichant une jauge semi-circulaire (style indicateur de vitesse).
    
    Utilité :
    - Visualiser une métrique en temps réel (CPU, RAM, Débit).
    - Afficher des zones de couleur selon des seuils (Vert/Orange/Rouge).
    - Fournir un retour visuel immédiat sur l'état du système.
    
    Fonctions associées :
    - _build() : Construction initiale du widget et du canevas matplotlib.
    - _draw_gauge() : Dessin de l'arc de cercle (numpy + plot) et gestion des couleurs.
    - set_value(val) : Mise à jour de la valeur affichée et redessin de la jauge.
    """
    
    def __init__(self, parent, title="", max_val=100, unit="", 
                 thresholds=None, **kwargs):
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._max_val = max_val
        self._unit = unit
        self._value = 0
        self._thresholds = thresholds or {"warning": 60, "critical": 80}
        
        self._build()
    
    def _build(self):
        """Construction de cette dites jauge circulaire"""
        tk.Label(self, text=self._title,
                font=("Segoe UI", 12),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"]).pack(pady=(15, 8))
        
        self._fig = Figure(figsize=(2.2, 1.4), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111, projection='polar')        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack()       
        self._value_label = tk.Label(self, text="0",
                                    font=("Segoe UI", 36, "bold"),
                                    fg=THEME["success"],
                                    bg=THEME["bg_card"])
        self._value_label.pack(pady=(0, 2))
        
        tk.Label(self, text=self._unit,
                font=("Segoe UI", 11),
                fg=THEME["text_muted"],
                bg=THEME["bg_card"]).pack(pady=(0, 15))
        
        self._draw_gauge()
    
    def _draw_gauge(self):
        """Dessin de la jauge circulaire et import de numpy 
        de Plus couleurs en fonction des seuils
        Valeurs avec des pourcentage
        Le fait de masquer les axes et de les remplacer par des lignes permet de créer un effet de jauge"""
        import numpy as np
        
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        self._ax.set_theta_offset(np.pi)
        self._ax.set_theta_direction(-1)
        self._ax.set_thetamin(0)
        self._ax.set_thetamax(180)
        theta_bg = np.linspace(0, np.pi, 100)
        self._ax.plot(theta_bg, [1]*100, color=THEME["border"], linewidth=20, 
                     solid_capstyle='round', alpha=0.5)
        

        pct = min(self._value / self._max_val, 1.0) if self._max_val > 0 else 0
        theta_val = np.linspace(0, np.pi * pct, 100)
        
        
        pct_100 = pct * 100
        if pct_100 >= self._thresholds["critical"]:
            color = THEME["error"]
        elif pct_100 >= self._thresholds["warning"]:
            color = THEME["warning"]
        else:
            color = THEME["success"]
        
        if pct > 0.01:
            self._ax.plot(theta_val, [1]*len(theta_val), color=color, linewidth=24, 
                         solid_capstyle='round', alpha=0.3)
            self._ax.plot(theta_val, [1]*len(theta_val), color=color, linewidth=18, 
                         solid_capstyle='round')
        
        self._ax.set_yticks([])
        self._ax.set_xticks([])
        self._ax.spines['polar'].set_visible(False)
        
        self._fig.tight_layout(pad=0)
        
        try:
            self._canvas.draw_idle()
        except:
            pass
        
        self._value_label.configure(text=f"{int(self._value)}", fg=color)
    
    def set_value(self, val):
        """Mise à jour de la valeur"""
        self._value = val
        self._draw_gauge()






class CarteStatistique(ctk.CTkFrame):
    """
    Widget affichant une carte statique compacte avec une icône et une valeur.
    
    Utilité :
    - Afficher une métrique clé (KPI) de manière isolée (ex: Nombre d'alertes, Taille cache).
    - Fournir un indicateur visuel rapide grâce à l'icône et à la couleur.
    - S'intégrer dans une grille de tableau de bord (Dashboard).

    Fonctions associées :
    - set_value(val, color) : Met à jour la valeur affichée et optionnellement sa couleur.
    """
    
    def __init__(self, parent, title="", icon="", color=None, **kwargs):
        """Initialisation du widget"""
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._color = color or THEME["text_primary"]
        
        
        ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=24)).pack(anchor="w", padx=18, pady=(15, 0))
        
        
        self._value_label = ctk.CTkLabel(self, text="0",
                                        font=ctk.CTkFont(size=42, weight="bold"),
                                        text_color=self._color)
        self._value_label.pack(anchor="w", padx=18, pady=(8, 0))
        
        
        ctk.CTkLabel(self, text=title,
                    font=ctk.CTkFont(size=13),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=18, pady=(2, 15))
    
    def set_value(self, val, color=None):
        self._value_label.configure(text=str(val))
        if color:
            self._value_label.configure(text_color=color)

class TableauBordAPI(ctk.CTkFrame):
    """Dashboard API - Stats, Docs & Testeur"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_main"], **kwargs)
        
      
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = "127.0.0.1"
            
        self._base_url = f"https://{ip}:5000"
        self._stats_queue = Queue()
        self._build()
        self._start_refresh_loop()
        self.after(1000, self._poll_stats_queue)
    
    def _build(self):
        
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True, padx=5, pady=5)
        
       
        self._build_dashboard(self._scroll)
        
        
        sep = ctk.CTkFrame(self._scroll, fg_color=THEME["grid"], height=2)
        sep.pack(fill="x", padx=20, pady=20)
        
       
        self._build_tester(self._scroll)

    def _build_dashboard(self, parent):
        
        header = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=10, height=80)
        header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(header, text="📡 API Gateway", 
                    font=ctk.CTkFont(size=22, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left", padx=20, pady=15)
                    
        
        self._status_badge = ctk.CTkLabel(header, text="● EN LIGNE", 
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        text_color=THEME["success"])
        self._status_badge.pack(side="left", padx=10)
        
        
        link_frame = ctk.CTkFrame(header, fg_color="transparent")
        link_frame.pack(side="right", padx=20)
        ctk.CTkLabel(link_frame, text="Endpoint:", text_color=THEME["text_muted"]).pack(side="left", padx=5)
        url_entry = ctk.CTkEntry(link_frame, width=200, fg_color=THEME["bg_input"])
        url_entry.insert(0, self._base_url)
        url_entry.configure(state="readonly")
        url_entry.pack(side="left")
        
        # 2. KPI Cards Row
        stats_frame = ctk.CTkFrame(parent, fg_color="transparent")
        stats_frame.pack(fill="x", padx=5, pady=5)
        stats_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        self._cards = {}
        kp_config = [
            ("total_requests", "📊 Total Requêtes", "0", THEME["accent"]),
            ("error_rate", "⚠️ Taux d'Erreur", "0%", THEME["error"]),
            ("avg_latency", "⏱️ Latence Moyenne", "0 ms", THEME["warning"]),
            ("active_sessions", "👥 Sessions Actives", "0", THEME["success"])
        ]
        
        for idx, (key, title, val, color) in enumerate(kp_config):
            card = ctk.CTkFrame(stats_frame, fg_color=THEME["bg_card"], corner_radius=10)
            card.grid(row=0, column=idx, padx=8, pady=8, sticky="ew")
            
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color=THEME["text_secondary"]).pack(pady=(12,5))
            val_lbl = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(size=26, weight="bold"), text_color=color)
            val_lbl.pack(pady=(0,12))
            self._cards[key] = val_lbl

        
        row_frame = ctk.CTkFrame(parent, fg_color="transparent")
        row_frame.pack(fill="x", padx=5, pady=5)
        row_frame.grid_columnconfigure((0,1), weight=1)
        
        
        sec_frame = ctk.CTkFrame(row_frame, fg_color=THEME["bg_card"], corner_radius=10)
        sec_frame.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        
        ctk.CTkLabel(sec_frame, text="🛡️ Sécurité & Conformité", 
                    font=ctk.CTkFont(size=14, weight="bold"), text_color=THEME["text_primary"]).pack(padx=15, pady=15, anchor="w")
        
        self._sec_labels = {}
        for feat in ["🔒 HTTPS / TLS (SSL)", "🔑 Bearer Token Auth", "🛑 Rate Limiting"]:
            l = ctk.CTkLabel(sec_frame, text=f"✓ {feat}", text_color=THEME["success"], anchor="w")
            l.pack(padx=20, pady=4, fill="x")
            self._sec_labels[feat] = l

        
        doc_frame = ctk.CTkFrame(row_frame, fg_color=THEME["bg_card"], corner_radius=10)
        doc_frame.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        
        ctk.CTkLabel(doc_frame, text="📚 Documentation", 
                    font=ctk.CTkFont(size=14, weight="bold"), text_color=THEME["text_primary"]).pack(padx=15, pady=15, anchor="w")
        
        ctk.CTkLabel(doc_frame, text="Documentation interactive des endpoints\navec exemples et codes d'erreur.",
                    text_color=THEME["text_secondary"], justify="left").pack(padx=20, pady=5, anchor="w")
        
        ctk.CTkButton(doc_frame, text="📄 Ouvrir la Doc Web", 
                     command=self._open_docs,
                     fg_color=THEME["accent"], hover_color=THEME["accent_hover"]).pack(pady=15)

    def _open_docs(self):
        url = f"{self._base_url}/api/docs"
        import webbrowser, subprocess
        
        if os.geteuid() == 0:
            user = os.environ.get('SUDO_USER')
            if user:
                try:
                    
                    cmd = ["sudo", "-u", user, "xdg-open", url]
                    subprocess.Popen(cmd)
                    return
                except Exception as e:
                    print(f"Failed to launch browser as {user}: {e}")
        
        webbrowser.open(url)

    def _build_tester(self, parent):
        if not REQUESTS_AVAILABLE:
            ctk.CTkLabel(parent, text="Module 'requests' requis\npip install requests",
                        font=ctk.CTkFont(size=14),
                        text_color=THEME["error"]).pack(pady=50)
            return
        
      
        title_frame = ctk.CTkFrame(parent, fg_color="transparent")
        title_frame.pack(fill="x", padx=10, pady=(5, 10))
        ctk.CTkLabel(title_frame, text="🔧 Testeur d'API REST", 
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        ctk.CTkLabel(title_frame, text="Testez vos endpoints directement", 
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_muted"]).pack(side="left", padx=15)
        
       
        header = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=10)
        header.pack(fill="x", padx=10, pady=5)
        
       
        url_frame = ctk.CTkFrame(header, fg_color="transparent")
        url_frame.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(url_frame, text="🌐 URL:", font=ctk.CTkFont(size=12, weight="bold"), text_color=THEME["text_secondary"]).pack(side="left", padx=5)
        self._url_entry = ctk.CTkEntry(url_frame, width=300, height=36, fg_color=THEME["bg_input"], corner_radius=8)
        self._url_entry.insert(0, self._base_url)
        self._url_entry.pack(side="left", padx=5, fill="x", expand=True)
        
       
        req_frame = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=8)
        req_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        row = ctk.CTkFrame(req_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=12)
        
        self._method_var = ctk.StringVar(value="GET")
        ctk.CTkOptionMenu(row, values=["GET", "POST", "PUT", "DELETE"],
                         variable=self._method_var, width=90, height=32,
                         fg_color=THEME["bg_input"]).pack(side="left", padx=5)
        
        self._endpoint_entry = ctk.CTkEntry(row, width=280, height=32, placeholder_text="/api/status", fg_color=THEME["bg_input"])
        self._endpoint_entry.insert(0, "/api/status")
        self._endpoint_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        ctk.CTkButton(row, text="Envoyer", command=self._send_request,
                     fg_color=THEME["accent"], hover_color=THEME["accent_hover"],
                     width=100, height=32).pack(side="left", padx=5)
        
       
        resp_frame = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=8)
        resp_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._status_label = ctk.CTkLabel(resp_frame, text="", font=ctk.CTkFont(size=11), text_color=THEME["text_muted"])
        self._status_label.pack(side="top", anchor="e", padx=10, pady=5)
        
        self._response_text = ctk.CTkTextbox(resp_frame, fg_color=THEME["bg_panel"], font=ctk.CTkFont(family="Courier", size=11))
        self._response_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _start_refresh_loop(self):
        """Poll stats from API periodically"""
        if not self.winfo_exists(): return
        
       
        from core.ssl_config import SSL_VERIFY
        
        def fetch():
            try:
                
                r = requests.get(f"{self._base_url}/api/stats", verify=SSL_VERIFY, timeout=2)
                if r.status_code == 200:
                    data = r.json().get("api_usage", {})
                    self._stats_queue.put(data)
            except:
                pass
            
        Thread(target=fetch, daemon=True).start()
       
        self.after(5000, self._start_refresh_loop)

    def _poll_stats_queue(self):
        """Check for stats updates from background thread"""
        try:
            while True:
                data = self._stats_queue.get_nowait()
                self._update_stats(data)
        except Empty:
            pass
        
        if self.winfo_exists():
            self.after(1000, self._poll_stats_queue)

    def _update_stats(self, data: Dict):
        if not data: return
        self._cards["total_requests"].configure(text=str(data.get("requests", 0)))
        
        errs = data.get("errors", 0)
        reqs = data.get("requests", 0)
        rate = (errs / reqs * 100) if reqs > 0 else 0
        self._cards["error_rate"].configure(text=f"{rate:.1f}%")
        
        lat = data.get("avg_latency_ms", 0)
        self._cards["avg_latency"].configure(text=f"{lat}ms")
    
    
    def _set_endpoint(self, ep):
        self._endpoint_entry.delete(0, "end")
        self._endpoint_entry.insert(0, ep)
    
    def _send_request(self):
        base = self._url_entry.get().strip().rstrip("/")
        endpoint = self._endpoint_entry.get().strip()
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = base + endpoint
        method = self._method_var.get()
        
        self._response_text.delete("1.0", "end")
        self._status_label.configure(text="Envoi...", text_color=THEME["warning"])
        
        def do_request():
            try:
                start = time.time()
                kw = {"timeout": 10, "verify": False}
                if method == "GET": r = requests.get(url, **kw)
                elif method == "POST": r = requests.post(url, json={}, **kw)
                elif method == "PUT": r = requests.put(url, json={}, **kw)
                else: r = requests.delete(url, **kw)
                elapsed = (time.time() - start) * 1000
                
                self.after(0, lambda: self._show_response(r, elapsed))
            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda: self._show_error(err_msg))
        
        Thread(target=do_request, daemon=True).start()
    
    def _show_response(self, r, elapsed):
        color = THEME["success"] if r.status_code < 400 else THEME["error"]
        self._status_label.configure(text=f"{r.status_code} - {elapsed:.0f}ms", text_color=color)
        try:
            txt = json.dumps(r.json(), indent=2)
        except:
            txt = r.text
        self._response_text.insert("1.0", txt)
        
    def _show_error(self, msg):
        self._status_label.configure(text="Erreur", text_color=THEME["error"])
        self._response_text.insert("1.0", f"Exception: {msg}")
    


class PanneauAlertes(ctk.CTkFrame):
    """
    Widget affichant un panneau latéral défilant listant les alertes de sécurité détectées.
    
    Utilité :
    - Centraliser les notifications de sécurité (Anomalies, Intrusions).
    - Afficher les détails critiques (Type, Gravité, Timestamp, IP).
    - Utiliser un code couleur pour hiérarchiser l'urgence (Rouge=Critique, Orange=Warning).

    Fonctions associées :
    - _build() : Construit l'en-tête (compteur) et la zone de liste défilante.
    - add_alert(alert) : Reçoit un objet alerte, crée une "carte" d'alerte visuelle et l'ajoute à la liste.
    """
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._alerts = []
        self._build()
    
    def _build(self):
        """Fonctionnement :
        - Création d'un frame pour le header
        - Création d'un label pour le titre
        - Création d'un label pour le compteur"""
   
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=14)
        
        ctk.CTkLabel(header, text="🚨 Alertes Comportementales",
                    font=ctk.CTkFont(size=15, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._count_label = ctk.CTkLabel(header, text="0",
                                        font=ctk.CTkFont(size=13, weight="bold"),
                                        text_color=THEME["error"],
                                        fg_color=THEME["bg_input"],
                                        corner_radius=10, width=35)
        self._count_label.pack(side="right")
        
        
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=6, height=200)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def add_alert(self, alert):
        """Ajoute une alerte au panneau"""
        self._alerts.append(alert)
        self._count_label.configure(text=str(len(self._alerts)))
        
        # par theme choisi
        colors = {
            "critical": THEME["error"],
            "warning": THEME["warning"],
            "info": THEME["info"],
            "emergency": THEME["chart_pink"]
        }
        color = colors.get(alert.severity, THEME["warning"])
        
       
        card = ctk.CTkFrame(self._list_frame, fg_color=THEME["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=4)
        
     
        indicator = ctk.CTkFrame(card, fg_color=color, width=5, corner_radius=2)
        indicator.pack(side="left", fill="y", padx=(0, 12))
        
    
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", expand=True, pady=10, padx=(0, 12))
        
       
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text=alert.anomaly_type,
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=color).pack(side="left")
        
        ctk.CTkLabel(header, text=alert.timestamp[-8:] if len(alert.timestamp) > 8 else alert.timestamp,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(side="right")
        
       
        ctk.CTkLabel(content, text=f"Source: {alert.source_ip}",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"]).pack(anchor="w", pady=(3, 0))
        
       
        msg = alert.message[:70] + "..." if len(alert.message) > 70 else alert.message
        ctk.CTkLabel(content, text=msg,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(anchor="w")
    
    def clear(self):
        """Efface toutes les alertes"""
        self._alerts.clear()
        self._count_label.configure(text="0")
        for widget in self._list_frame.winfo_children():
            widget.destroy()

class GraphiqueDonut(tk.Frame):
    """
    Widget affichant un diagramme en beignet pour les proportions.
    
    Utilité :
    - Montrer la répartition en pourcentage d'un tout (ex: Versions SNMP v1/v2c/v3).
    - Visualiser les parts relatives de chaque catégorie.
    - Esthétique moderne et compacte comparée à un camembert classique.

    Fonctions associées :
    - _build() : Initialise le graphique circulaire.
    - update(data, colors) : Met à jour les sections du beignet avec les nouvelles proportions et couleurs.
    """
    
    def __init__(self, parent, title="", **kwargs):
        """Initialisation du graphique"""
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._fig = None
        self._ax = None
        self._canvas = None
        self._build()
    
    def _build(self):
        """Fonctionnement : 
        - Création d'une figure avec matplotlib
        - Création d'un graphique en forme de donut avec matplotlib
        - Création d'un canvas avec tkinter
        - Ajout du graphique dans le canvas
        - Mise à jour du graphique"""
        tk.Label(self, text=self._title, font=("Segoe UI", 12, "bold"),
                 fg=THEME["text_secondary"], bg=THEME["bg_card"]).pack(pady=(10, 5))
        
        
        self._fig = Figure(figsize=(3, 2.5), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)
        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True)
        
        
        self.update({"No Data": 1}, ["#444444"])

    def update(self, data: dict, colors: list = None):
        """Fonctionnement :
        - Mise à jour des données
        - Mise à jour des couleurs
        - Mise à jour du graphique"""
        if not self._ax: return
        
        self._ax.clear()
        
        labels = list(data.keys())
        sizes = list(data.values())
        
        if not sizes or sum(sizes) == 0:
            sizes = [1]
            labels = ["No Data"]
            chart_colors = ["#333333"]
            text_color = "#555555"
        else:
            chart_colors = colors if colors else [THEME["chart_blue"], THEME["chart_green"], THEME["chart_orange"], THEME["error"]]
            text_color = THEME["text_primary"]

       
        wedges, texts, autotexts = self._ax.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=90,
            colors=chart_colors, pctdistance=0.85, 
            textprops=dict(color=text_color, fontsize=9)
        )
     
        centre_circle = plt.Circle((0,0), 0.70, fc=THEME["bg_card"])
        self._ax.add_artist(centre_circle)
        
     
        for t in texts:
            t.set_color(THEME["text_secondary"])
            t.set_fontsize(8)
            
        self._ax.axis('equal')  
        self._fig.tight_layout()
        
        try:
            self._canvas.draw_idle()
        except:
            pass

class TableauProfilsIP(ctk.CTkFrame):
    """
    Widget affichant un tableau des profils IP avec leur réputation et statistiques.
    
    Utilité :
    - Surveiller les entités communiquant sur le réseau (IP, Paquets, Erreurs).
    - Identifier les acteurs malveillants via le score de réputation (0-100%).
    - Trier et filtrer les IP les plus actives.

    Fonctions associées :
    - _build() : Construit la structure du tableau (en-têtes et zone de liste).
    - update_profiles(profiles) : Trie les profils par réputation et met à jour les lignes (création/mise à jour).
    - _add_profile_row(profile) : Crée une nouvelle ligne de tableau pour une IP.
    - _update_profile_row(ip, profile) : Met à jour les valeurs d'une ligne existante à chaud.
    """
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._profiles = []
        self._profile_rows = {}  
        self._build()
    
    def _build(self):
        """Fonctionnement de la fonction build ! 
        Header puis En-têtes de colonnes puis Liste des profils et liste"""
        
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=15)
        
        ctk.CTkLabel(header, text="👤 Profils IP - Analyse Comportementale",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        cols_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=0)
        cols_frame.pack(fill="x", padx=12)
        
        columns = [
            ("IP", 140), ("Réputation", 90), ("Paquets", 80), 
            ("Erreurs", 70), ("PPS", 60), ("Status", 100)
        ]
        
        for col_name, width in columns:
            ctk.CTkLabel(cols_frame, text=col_name, width=width,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=THEME["text_secondary"]).pack(side="left", padx=6, pady=10)
        
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=0, height=200)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def update_profiles(self, profiles: List[Dict]):
        """Met à jour la liste des profilsé"""
        sorted_profiles = sorted(profiles, key=lambda x: x.get("reputation_score", 100))[:15]
        
        new_ips = [p.get("ip") for p in sorted_profiles]
        old_ips = [p.get("ip") for p in self._profiles]
        
        if new_ips != old_ips:
            for widget in self._list_frame.winfo_children():
                widget.destroy()
            self._profile_rows.clear()
            
            for profile in sorted_profiles:
                self._add_profile_row(profile)
        else:
            for profile in sorted_profiles:
                ip = profile.get("ip")
                if ip in self._profile_rows:
                    self._update_profile_row(ip, profile)
        
        self._profiles = sorted_profiles
    
    def _add_profile_row(self, profile: Dict):
        ip = profile.get("ip", "?")
        
        row = ctk.CTkFrame(self._list_frame, fg_color="transparent", height=38)
        row.pack(fill="x", pady=2)
        row.pack_propagate(False)
        
        ip_label = ctk.CTkLabel(row, text=ip[:18], width=140,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_primary"], anchor="w")
        ip_label.pack(side="left", padx=6)
        
        rep = profile.get("reputation_score", 100)
        rep_color = self._get_rep_color(rep)
        
        rep_label = ctk.CTkLabel(row, text=f"{rep:.0f}%", width=90,
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=rep_color)
        rep_label.pack(side="left", padx=6)
        
        pkt_label = ctk.CTkLabel(row, text=str(profile.get("packet_count", 0)), width=80,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"])
        pkt_label.pack(side="left", padx=6)
        
        errors = profile.get("error_count", 0)
        err_color = THEME["error"] if errors > 5 else THEME["text_secondary"]
        err_label = ctk.CTkLabel(row, text=str(errors), width=70,
                    font=ctk.CTkFont(size=12),
                    text_color=err_color)
        err_label.pack(side="left", padx=6)
        
        
        pps = profile.get("packets_per_second", 0)
        pps_label = ctk.CTkLabel(row, text=f"{pps:.1f}", width=60,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"])
        pps_label.pack(side="left", padx=6)
        
        
        status_text, status_color = self._get_status(profile)
        status_label = ctk.CTkLabel(row, text=status_text, width=100,
                    font=ctk.CTkFont(size=12),
                    text_color=status_color)
        status_label.pack(side="left", padx=6)
        
        
        self._profile_rows[ip] = {
            "row": row,
            "rep_label": rep_label,
            "pkt_label": pkt_label,
            "err_label": err_label,
            "pps_label": pps_label,
            "status_label": status_label
        }
    
    def _update_profile_row(self, ip: str, profile: Dict):
        """Met à jour une ligne existante sans la recréer"""
        widgets = self._profile_rows.get(ip)
        if not widgets:
            return
        
        rep = profile.get("reputation_score", 100)
        rep_color = self._get_rep_color(rep)
        widgets["rep_label"].configure(text=f"{rep:.0f}%", text_color=rep_color)
        
        widgets["pkt_label"].configure(text=str(profile.get("packet_count", 0)))
        
        errors = profile.get("error_count", 0)
        err_color = THEME["error"] if errors > 5 else THEME["text_secondary"]
        widgets["err_label"].configure(text=str(errors), text_color=err_color)
        
        pps = profile.get("packets_per_second", 0)
        widgets["pps_label"].configure(text=f"{pps:.1f}")
        
        status_text, status_color = self._get_status(profile)
        widgets["status_label"].configure(text=status_text, text_color=status_color)
    
    def _get_rep_color(self, rep: float) -> str:
        if rep < 30:
            return THEME["error"]
        elif rep < 60:
            return THEME["warning"]
        return THEME["success"]
    
    def _get_status(self, profile: Dict) -> tuple:
        rep = profile.get("reputation_score", 100)
        if profile.get("is_blacklisted"):
            return "🚫 Bloqué", THEME["error"]
        elif rep < 30:
            return "⚠️ Suspect", THEME["warning"]
        return "✓ Normal", THEME["success"]




class AnalyseurBaseline:
    """
    Analyseur de baseline pour détection d'anomalies par dépassement de seuil.
    
    Calcule une moyenne mobile du trafic et génère des alertes quand le trafic
    dépasse un certain pourcentage au-dessus de cette baseline.
    
    Supporte 3 baselines distinctes:
    - JOUR: 8h-18h en semaine (Lundi-Vendredi)
    - NUIT: 18h-8h tous les jours
    - WEEKEND: Samedi-Dimanche (toute la journée)
    """
    
    # Constantes pour les périodes
    PERIOD_DAY = "JOUR"      # 8h-18h semaine
    PERIOD_NIGHT = "NUIT"    # 18h-8h
    PERIOD_WEEKEND = "WEEKEND"  # Samedi-Dimanche
    
    def __init__(self, window_size: int = 60, threshold_pct: float = 50.0,
                 min_samples: int = 10):
        """
        Args:
            window_size: Taille de la fenêtre pour le calcul de la moyenne (en secondes)
            threshold_pct: Pourcentage de dépassement pour déclencher une alerte
            min_samples: Nombre minimum d'échantillons avant de commencer l'analyse
        """
        self.window_size = window_size
        self.threshold_pct = threshold_pct
        self.min_samples = min_samples
        
        # === BASELINES PAR PÉRIODE ===
        # Historiques séparés pour chaque période
        self._histories = {
            self.PERIOD_DAY: {"pps": deque(maxlen=window_size * 10), "errors": deque(maxlen=window_size * 10)},
            self.PERIOD_NIGHT: {"pps": deque(maxlen=window_size * 10), "errors": deque(maxlen=window_size * 10)},
            self.PERIOD_WEEKEND: {"pps": deque(maxlen=window_size * 10), "errors": deque(maxlen=window_size * 10)},
        }
        
        
        self._baselines = {
            self.PERIOD_DAY: {"pps": 0.0, "errors": 0.0, "std_pps": 0.0, "std_errors": 0.0, "samples": 0},
            self.PERIOD_NIGHT: {"pps": 0.0, "errors": 0.0, "std_pps": 0.0, "std_errors": 0.0, "samples": 0},
            self.PERIOD_WEEKEND: {"pps": 0.0, "errors": 0.0, "std_pps": 0.0, "std_errors": 0.0, "samples": 0},
        }
        
        
        self._thresholds = {
            self.PERIOD_DAY: {"pps": 0.0, "errors": 0.0},
            self.PERIOD_NIGHT: {"pps": 0.0, "errors": 0.0},
            self.PERIOD_WEEKEND: {"pps": 0.0, "errors": 0.0},
        }
        
        
        self._current_period = self._get_period()
        
        
        self._pps_history = deque(maxlen=window_size * 2)
        self._error_history = deque(maxlen=window_size * 2)
        
        
        self._baseline_pps = 0.0
        self._baseline_errors = 0.0
        self._std_pps = 0.0
        self._std_errors = 0.0
        
        
        self._threshold_pps = 0.0
        self._threshold_errors = 0.0
        
        
        self._total_samples = 0
        self._alerts_generated = 0
        self._last_alert_time = 0
        self._alert_cooldown = 5  
        
        
        self.alerts = []
        
        
        self._learning_status = {
            self.PERIOD_DAY: {"is_learning": True, "complete": False},
            self.PERIOD_NIGHT: {"is_learning": True, "complete": False},
            self.PERIOD_WEEKEND: {"is_learning": True, "complete": False},
        }
        
        
        self._is_learning = True
        self._learning_complete = False
        
        self._lock = Lock()
    
    def _get_period(self, timestamp: float = None) -> str:
        """Détermine la période (JOUR, NUIT, WEEKEND) pour un timestamp donné"""
        if timestamp is None:
            now = datetime.now()
        else:
            now = datetime.fromtimestamp(timestamp)
        
        weekday = now.weekday()  # 0=Lundi, 6=Dimanche
        hour = now.hour
        
        # Weekend (Samedi=5, Dimanche=6)
        if weekday >= 5:
            return self.PERIOD_WEEKEND
        
        # Jour ouvré: 8h-18h
        if 8 <= hour < 18:
            return self.PERIOD_DAY
        
        # Nuit
        return self.PERIOD_NIGHT
    
    def get_period_name(self) -> str:
        """Retourne le nom de la période courante en français"""
        period = self._get_period()
        names = {
            self.PERIOD_DAY: "📅 Jour (8h-18h)",
            self.PERIOD_NIGHT: "🌙 Nuit (18h-8h)", 
            self.PERIOD_WEEKEND: "🏖️ Weekend"
        }
        return names.get(period, "Inconnu")
    
    def add_sample(self, pps: float, errors: int, timestamp: float = None):
        """Ajoute un échantillon et recalcule les baselines"""
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            
            self._pps_history.append((timestamp, pps))
            self._error_history.append((timestamp, errors))
            self._total_samples += 1
            
            
            period = self._get_period(timestamp)
            self._current_period = period
            
            self._histories[period]["pps"].append((timestamp, pps))
            self._histories[period]["errors"].append((timestamp, errors))
            self._baselines[period]["samples"] += 1
            
            
            self._compute_baselines()
            self._compute_period_baselines(period)
    
    def _compute_baselines(self):
        """Calcule les baselines (moyenne et écart-type)
        avec une technique de moyenne mobile et écart-type"""
        now = time.time()
        
        
        recent_pps = [v for t, v in self._pps_history if now - t <= self.window_size]
        recent_errors = [v for t, v in self._error_history if now - t <= self.window_size]
        
        if len(recent_pps) >= self.min_samples:
            self._is_learning = False
            self._learning_complete = True
            
            
            self._baseline_pps = sum(recent_pps) / len(recent_pps)
            self._baseline_errors = sum(recent_errors) / len(recent_errors) if recent_errors else 0
            
            
            if len(recent_pps) > 1:
                variance_pps = sum((x - self._baseline_pps) ** 2 for x in recent_pps) / len(recent_pps)
                self._std_pps = variance_pps ** 0.5
            
            if len(recent_errors) > 1 and self._baseline_errors > 0:
                variance_errors = sum((x - self._baseline_errors) ** 2 for x in recent_errors) / len(recent_errors)
                self._std_errors = variance_errors ** 0.5
            
            
            self._threshold_pps = max(
                self._baseline_pps * (1 + self.threshold_pct / 100),
                self._baseline_pps + 2 * self._std_pps
            )
            self._threshold_errors = max(
                self._baseline_errors * (1 + self.threshold_pct / 100) if self._baseline_errors > 0 else 5,
                self._baseline_errors + 2 * self._std_errors if self._baseline_errors > 0 else 5
            )
    
    def _compute_period_baselines(self, period: str):
        """Calcule les baselines pour une période spécifique (JOUR/NUIT/WEEKEND)"""
        now = time.time()
        history = self._histories[period]
        
        
        recent_pps = [v for t, v in history["pps"] if now - t <= self.window_size * 5]
        recent_errors = [v for t, v in history["errors"] if now - t <= self.window_size * 5]
        
        if len(recent_pps) >= self.min_samples:
            self._learning_status[period]["is_learning"] = False
            self._learning_status[period]["complete"] = True
            
            baseline_pps = sum(recent_pps) / len(recent_pps)
            baseline_errors = sum(recent_errors) / len(recent_errors) if recent_errors else 0
            
            std_pps = 0.0
            std_errors = 0.0
            
            if len(recent_pps) > 1:
                variance_pps = sum((x - baseline_pps) ** 2 for x in recent_pps) / len(recent_pps)
                std_pps = variance_pps ** 0.5
            
            if len(recent_errors) > 1 and baseline_errors > 0:
                variance_errors = sum((x - baseline_errors) ** 2 for x in recent_errors) / len(recent_errors)
                std_errors = variance_errors ** 0.5
            
            self._baselines[period]["pps"] = baseline_pps
            self._baselines[period]["errors"] = baseline_errors
            self._baselines[period]["std_pps"] = std_pps
            self._baselines[period]["std_errors"] = std_errors
            
            self._thresholds[period]["pps"] = max(
                baseline_pps * (1 + self.threshold_pct / 100),
                baseline_pps + 2 * std_pps
            )
            self._thresholds[period]["errors"] = max(
                baseline_errors * (1 + self.threshold_pct / 100) if baseline_errors > 0 else 5,
                baseline_errors + 2 * std_errors if baseline_errors > 0 else 5
            )
    
    def get_period_stats(self) -> Dict:
        """Retourne les statistiques de toutes les périodes"""
        return {
            "current_period": self._get_period(),
            "period_name": self.get_period_name(),
            "baselines": {
                period: {
                    "pps": round(data["pps"], 2),
                    "errors": round(data["errors"], 2),
                    "samples": data["samples"],
                    "learning": self._learning_status[period]["is_learning"]
                }
                for period, data in self._baselines.items()
            },
            "thresholds": {
                period: {
                    "pps": round(data["pps"], 2),
                    "errors": round(data["errors"], 2)
                }
                for period, data in self._thresholds.items()
            }
        }
    
    def check_anomaly(self, pps: float, errors: int) -> List[Dict]:
        """
        Vérifie si les valeurs actuelles dépassent les seuils.
        Retourne une liste d'alertes.
        """
        alerts = []
        now = time.time()
        
        with self._lock:
            if self._is_learning:
                return alerts
            
            if pps > self._threshold_pps and self._threshold_pps > 0:
                if now - self._last_alert_time >= self._alert_cooldown:
                    deviation_pct = ((pps - self._baseline_pps) / self._baseline_pps * 100) if self._baseline_pps > 0 else 0
                    
                    alert = {
                        "type": "PPS_THRESHOLD_EXCEEDED",
                        "severity": "warning" if deviation_pct < 100 else "critical",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Débit anormal: {pps:.1f} PPS (baseline: {self._baseline_pps:.1f}, seuil: {self._threshold_pps:.1f})",
                        "details": {
                            "current_pps": pps,
                            "baseline_pps": round(self._baseline_pps, 2),
                            "threshold_pps": round(self._threshold_pps, 2),
                            "deviation_pct": round(deviation_pct, 1),
                            "std_pps": round(self._std_pps, 2)
                        }
                    }
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self._alerts_generated += 1
                    self._last_alert_time = now
            
            if errors > self._threshold_errors and self._threshold_errors > 0:
                if now - self._last_alert_time >= self._alert_cooldown:
                    deviation_pct = ((errors - self._baseline_errors) / self._baseline_errors * 100) if self._baseline_errors > 0 else 100
                    
                    alert = {
                        "type": "ERROR_RATE_EXCEEDED",
                        "severity": "warning" if deviation_pct < 100 else "critical",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Taux d'erreur anormal: {errors} (baseline: {self._baseline_errors:.1f}, seuil: {self._threshold_errors:.1f})",
                        "details": {
                            "current_errors": errors,
                            "baseline_errors": round(self._baseline_errors, 2),
                            "threshold_errors": round(self._threshold_errors, 2),
                            "deviation_pct": round(deviation_pct, 1)
                        }
                    }
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self._alerts_generated += 1
                    self._last_alert_time = now
        
        return alerts
    
    def get_status(self) -> Dict:
        """Retourne l'état actuel de l'analyseur"""
        with self._lock:
            return {
                "is_learning": self._is_learning,
                "learning_progress": min(100, (self._total_samples / self.min_samples) * 100),
                "total_samples": self._total_samples,
                "baseline_pps": round(self._baseline_pps, 2),
                "baseline_errors": round(self._baseline_errors, 2),
                "std_pps": round(self._std_pps, 2),
                "threshold_pps": round(self._threshold_pps, 2),
                "threshold_errors": round(self._threshold_errors, 2),
                "threshold_pct": self.threshold_pct,
                "alerts_generated": self._alerts_generated,
                "window_size": self.window_size
            }
    
    def update_threshold(self, new_threshold_pct: float):
        """Met à jour le pourcentage de seuil"""
        with self._lock:
            self.threshold_pct = new_threshold_pct
            self._compute_baselines()
    
    def reset(self):
        """Réinitialise l'analyseur"""
        with self._lock:
            self._pps_history.clear()
            self._error_history.clear()
            self._baseline_pps = 0.0
            self._baseline_errors = 0.0
            self._std_pps = 0.0
            self._std_errors = 0.0
            self._threshold_pps = 0.0
            self._threshold_errors = 0.0
            self._total_samples = 0
            self._alerts_generated = 0
            self._is_learning = True
            self._learning_complete = False
            self.alerts.clear()




class PanneauBaseline(ctk.CTkFrame):
    """Panneau d'affichage et contrôle de l'analyse baseline"""
    
    def __init__(self, parent, analyzer: AnalyseurBaseline, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._analyzer = analyzer
        self._build()
    
    def _build(self):
        
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=15)
        
        ctk.CTkLabel(header, text="📊 Analyse de Baseline Dynamique",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left")
        
        # Statusdu deep learning 
        self._learning_label = ctk.CTkLabel(header, text="🔄 Apprentissage...",
                                           font=ctk.CTkFont(size=12),
                                           text_color=THEME["warning"])
        self._learning_label.pack(side="right")
        
        
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        content.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Colonne 1: Baseline des paquets emis par secondes
        col1 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col1.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col1, text="📈 Baseline PPS",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 5))
        
        self._baseline_pps_label = ctk.CTkLabel(col1, text="--",
                                               font=ctk.CTkFont(size=28, weight="bold"),
                                               text_color=THEME["chart_green"])
        self._baseline_pps_label.pack()
        
        ctk.CTkLabel(col1, text="paquets/sec",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack()
        
        self._threshold_pps_label = ctk.CTkLabel(col1, text="Seuil: --",
                                                font=ctk.CTkFont(size=12),
                                                text_color=THEME["text_secondary"])
        self._threshold_pps_label.pack(pady=(8, 12))
        
        # Baseline Erreurs
        col2 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col2.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col2, text="⚠️ Baseline Erreurs",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 5))
        
        self._baseline_errors_label = ctk.CTkLabel(col2, text="--",
                                                  font=ctk.CTkFont(size=28, weight="bold"),
                                                  text_color=THEME["chart_orange"])
        self._baseline_errors_label.pack()
        
        ctk.CTkLabel(col2, text="erreurs/sec",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack()
        
        self._threshold_errors_label = ctk.CTkLabel(col2, text="Seuil: --",
                                                   font=ctk.CTkFont(size=12),
                                                   text_color=THEME["text_secondary"])
        self._threshold_errors_label.pack(pady=(8, 12))
        
        # 
        col3 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col3.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col3, text="⚙️ Configuration",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 10))
        
        # 
        ctk.CTkLabel(col3, text="Seuil de dépassement:",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack()
        
        slider_frame = ctk.CTkFrame(col3, fg_color="transparent")
        slider_frame.pack(fill="x", padx=15, pady=5)
        
        self._threshold_slider = ctk.CTkSlider(slider_frame, from_=10, to=200,
                                              number_of_steps=19,
                                              command=self._on_threshold_change,
                                              fg_color=THEME["bg_input"],
                                              progress_color=THEME["accent"])
        self._threshold_slider.set(self._analyzer.threshold_pct)
        self._threshold_slider.pack(side="left", fill="x", expand=True)
        
        self._threshold_value_label = ctk.CTkLabel(slider_frame, 
                                                  text=f"{int(self._analyzer.threshold_pct)}%",
                                                  font=ctk.CTkFont(size=13, weight="bold"),
                                                  text_color=THEME["accent"], width=50)
        self._threshold_value_label.pack(side="right", padx=(10, 0))
        
        # Bouton qui permet de reset
        ctk.CTkButton(col3, text="🔄 Réinitialiser", 
                     command=self._reset_baseline,
                     fg_color=THEME["bg_input"],
                     hover_color=THEME["error"],
                     font=ctk.CTkFont(size=11),
                     height=30).pack(pady=(10, 12))
        
        # Statistiques
        stats_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6)
        stats_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self._stats_label = ctk.CTkLabel(stats_frame, 
                                        text="Échantillons: 0 | Alertes: 0 | Fenêtre: 60s",
                                        font=ctk.CTkFont(size=11),
                                        text_color=THEME["text_muted"])
        self._stats_label.pack(pady=8)
    
    def _on_threshold_change(self, value):
        self._analyzer.update_threshold(value)
        self._threshold_value_label.configure(text=f"{int(value)}%")
    
    def _reset_baseline(self):
        self._analyzer.reset()
        self.update_display()
    
    def update_display(self):
        """Met à jour l'affichage avec les données actuelles"""
        status = self._analyzer.get_status()
        
        
        if status["is_learning"]:
            progress = status["learning_progress"]
            self._learning_label.configure(
                text=f"🔄 Apprentissage: {progress:.0f}%",
                text_color=THEME["warning"]
            )
        else:
            self._learning_label.configure(
                text="✓ Baseline établie",
                text_color=THEME["success"]
            )
        
        
        self._baseline_pps_label.configure(text=f"{status['baseline_pps']:.1f}")
        self._baseline_errors_label.configure(text=f"{status['baseline_errors']:.1f}")
        
        
        self._threshold_pps_label.configure(
            text=f"Seuil: {status['threshold_pps']:.1f} (±{status['std_pps']:.1f})"
        )
        self._threshold_errors_label.configure(
            text=f"Seuil: {status['threshold_errors']:.1f}"
        )
        
        period_name = self._analyzer.get_period_name()
        self._stats_label.configure(
            text=f"{period_name} | "
                 f"Échantillons: {status['total_samples']} | "
                 f"Alertes: {status['alerts_generated']} | "
                 f"Fenêtre: {status['window_size']}s"
        )




class EquipementSNMP:
    """Représente un appareil SNMP découvert sur le réseau"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.mac = None
        self.hostname = None
        self.sys_descr = None
        self.sys_name = None
        self.sys_location = None
        self.sys_contact = None
        self.sys_object_id = None
        self.snmp_versions = set()  # {"v1", "v2c", "v3"}
        self.communities = set()
        self.usm_users = set()  # Pour SNMPv3
        self.ports = set()  # Ports utilisés
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.packet_count = 0
        self.request_count = 0  # GET, SET, etc.
        self.response_count = 0
        self.trap_count = 0
        self.error_count = 0
        self.oids_accessed = set()  # OIDs interrogés
        self.vendor = None  # Déduit du MAC ou sysObjectID
        self.device_type = "unknown"  # router, switch, server, printer, etc.
        self.is_manager = False  # Envoie des requêtes
        self.is_agent = False    # Répond aux requêtes
        self.status = "active"   # active, inactive, suspicious
        # Nouveaux champs pour la gestion
        self.is_trusted = False   # Appareil de confiance (vert)
        self.is_ignored = False   # Appareil ignoré (masqué)
        self.is_blocked = False   # Appareil bloqué (rouge)
        self.custom_name = None   # Nom personnalisé
        self.notes = None         # Notes utilisateur
        
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.custom_name or self.hostname or self.sys_name or "Inconnu",
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "vendor": self.vendor or "Inconnu",
            "device_type": self.device_type,
            "snmp_versions": list(self.snmp_versions),
            "communities": list(self.communities)[:5],  # Limiter
            "usm_users": list(self.usm_users)[:5],
            "ports": list(self.ports),
            "first_seen": self.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "packet_count": self.packet_count,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "trap_count": self.trap_count,
            "error_count": self.error_count,
            "is_manager": self.is_manager,
            "is_agent": self.is_agent,
            "status": self.status,
            "oids_count": len(self.oids_accessed),
            # Nouveaux champs possible a intégrer notamment le bail de Cisco avec FA0/1 #TODO 
            "is_trusted": self.is_trusted,
            "is_ignored": self.is_ignored,
            "is_blocked": getattr(self, "is_blocked", False),
            "custom_name": self.custom_name,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: Dict):
        """Reconstruit un objet SNMPDevice depuis un dictionnaire"""
        device = cls(data["ip"])
        device.mac = data.get("mac")
        device.hostname = data.get("hostname")
        device.sys_descr = data.get("sys_descr")
        device.sys_name = data.get("sys_name")
        device.sys_location = data.get("sys_location")
        device.vendor = data.get("vendor")
        device.device_type = data.get("device_type", "unknown")
        
        device.snmp_versions = set(data.get("snmp_versions", []))
        device.communities = set(data.get("communities", []))
        device.usm_users = set(data.get("usm_users", []))
        device.ports = set(data.get("ports", []))
        
        if "first_seen" in data:
            try: device.first_seen = datetime.strptime(data["first_seen"], "%Y-%m-%d %H:%M:%S")
            except: pass
            
        if "last_seen" in data:
            try: device.last_seen = datetime.strptime(data["last_seen"], "%Y-%m-%d %H:%M:%S")
            except: pass
            
        device.packet_count = data.get("packet_count", 0)
        device.request_count = data.get("request_count", 0)
        device.response_count = data.get("response_count", 0)
        device.trap_count = data.get("trap_count", 0)
        device.error_count = data.get("error_count", 0)
        
        device.is_manager = data.get("is_manager", False)
        device.is_agent = data.get("is_agent", False)
        device.status = data.get("status", "active")
        
        device.is_trusted = data.get("is_trusted", False)
        device.is_ignored = data.get("is_ignored", False)
        device.is_blocked = data.get("is_blocked", False)
        device.custom_name = data.get("custom_name")
        device.notes = data.get("notes")
        
        return device


class GestionnaireEquipements:
    """Gestionnaire de découverte et suivi des appareils SNMP"""
    
    # OIDs système standard
    OID_SYS_DESCR = "1.3.6.1.2.1.1.1"
    OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2"
    OID_SYS_NAME = "1.3.6.1.2.1.1.5"
    OID_SYS_LOCATION = "1.3.6.1.2.1.1.6"
    OID_SYS_CONTACT = "1.3.6.1.2.1.1.4"
    
    # Préfixes OID constructeurs connus
    VENDOR_OIDS = {
        "1.3.6.1.4.1.9": "Cisco",
        "1.3.6.1.4.1.2636": "Juniper",
        "1.3.6.1.4.1.11": "HP",
        "1.3.6.1.4.1.2011": "Huawei",
        "1.3.6.1.4.1.6527": "Nokia",
        "1.3.6.1.4.1.3076": "Alteon/Nortel",
        "1.3.6.1.4.1.1991": "Foundry/Brocade",
        "1.3.6.1.4.1.1916": "Extreme Networks",
        "1.3.6.1.4.1.25506": "H3C",
        "1.3.6.1.4.1.8072": "Net-SNMP",
        "1.3.6.1.4.1.311": "Microsoft",
        "1.3.6.1.4.1.2021": "Linux UCD-SNMP",
    }
    
    # Préfixes MAC constructeurs connu via les ressouce web 
    MAC_VENDORS = {
        "00:00:0c": "Cisco",
        "00:1a:a1": "Cisco",
        "00:1b:54": "Cisco",
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "00:15:5d": "Microsoft Hyper-V",
        "08:00:27": "VirtualBox",
        "00:1c:42": "Parallels",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:1e:67": "Intel",
        "3c:fd:fe": "Intel",
        "00:25:90": "SuperMicro",
        "00:30:48": "SuperMicro",
        "00:e0:4c": "Realtek",
        "00:1a:2b": "Ayecom",
        "70:b3:d5": "IEEE Registration",
    }
    
    # Types de PDU qui indiquent un vrai appareil SNMP (agent)
    AGENT_PDU_TYPES = {"response", "snmpresponse", "trap", "snmptrap", "trapv2", 
                       "inform", "snmpinform", "report"}
    
    # Types de PDU qui indiquent un manager SNMP
    MANAGER_PDU_TYPES = {"get", "getnext", "getrequest", "getnextrequest", 
                         "set", "setrequest", "bulk", "getbulk", "snmpbulk"}
    
    def __init__(self):
        self._devices: Dict[str, SNMPDevice] = {}  
        self._pending_devices: Dict[str, SNMPDevice] = {}  
        self._lock = Lock()
        self._lock = Lock()
        self._inactive_timeout = 300 # Delai de temps avant inactivité reglable donc 
        self._data_file = os.path.join(ROOT_DIR, "data", "devices.json")
        
       
        os.makedirs(os.path.dirname(self._data_file), exist_ok=True)
        
    def save_devices(self):
        """Sauvegarde les appareils sur le disque"""
        try:
            with self._lock:
                data = {ip: dev.to_dict() for ip, dev in self._devices.items()}
            
            with open(self._data_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            pass 

    def load_devices(self):
        """Charge les appareils depuis le disque"""
        if not os.path.exists(self._data_file):
            return
            
        try:
            with open(self._data_file, 'r') as f:
                data = json.load(f)
                
            with self._lock:
                self._devices = {}
                for ip, dev_data in data.items():
                    try:
                        self._devices[ip] = SNMPDevice.from_dict(dev_data)
                    except:
                        pass
            print(f"[+] La il y a{len(self._devices)} appareils chargés a partir de {self._data_file}")
        except Exception as e:
            print(f"[!] Les devices sont pas bien chargés: {e}")
        
    def process_packet(self, pkt_data: Dict):
        """
        Traite un paquet SNMP et met à jour les appareils.
        
        Logique de découverte :
        - Un appareil est confirmé comme "vrai" s'il ENVOIE une Response, Trap ou Inform
        - Les managers (qui envoient des requêtes) sont aussi des vrais appareils
        - Les IPs qui ne font que recevoir des requêtes ne sont PAS des appareils confirmés
        """
        with self._lock:
            ip_src = pkt_data.get("ip_src")
            pdu_type = str(pkt_data.get("snmp_pdu_type", "")).lower()
            
            if not ip_src:
                return
            
            
            is_agent_response = any(t in pdu_type for t in self.AGENT_PDU_TYPES)
            is_manager_request = any(t in pdu_type for t in self.MANAGER_PDU_TYPES)
          
            if is_agent_response or is_manager_request:
               
                if ip_src in self._pending_devices and ip_src not in self._devices:
                    self._devices[ip_src] = self._pending_devices.pop(ip_src)
                
              
                if ip_src not in self._devices:
                    self._devices[ip_src] = EquipementSNMP(ip_src)
                
                self._update_device(ip_src, pkt_data, is_agent=is_agent_response, 
                                   is_manager=is_manager_request)
            else:
               
                if ip_src not in self._devices:
                    if ip_src not in self._pending_devices:
                        self._pending_devices[ip_src] = EquipementSNMP(ip_src)
                    self._update_device_basic(self._pending_devices[ip_src], pkt_data)

    def set_sys_name(self, ip: str, name: str):
        """Met à jour le nom système d'un appareil (Appellé par SNMP Sender)"""
        with self._lock:
            if ip not in self._devices:
               
                 self._devices[ip] = EquipementSNMP(ip)
            
            device = self._devices[ip]
            device.sys_name = str(name)[:100]
            device.last_seen = datetime.now()
            print(f"[GestionnaireEquipements] Updated sysName for {ip}: {device.sys_name}")

    
    def _update_device(self, ip: str, pkt_data: Dict, is_agent: bool = False, 
                       is_manager: bool = False):
        """Met à jour un appareil confirmé"""
        device = self._devices[ip]
        device.last_seen = datetime.now()
        device.packet_count += 1
        
        if is_agent:
            device.is_agent = True
            pdu_type = str(pkt_data.get("snmp_pdu_type", "")).lower()
            if "response" in pdu_type:
                device.response_count += 1
            elif "trap" in pdu_type or "inform" in pdu_type:
                device.trap_count += 1
        
        if is_manager:
            device.is_manager = True
            device.request_count += 1
        
       
        self._update_device_basic(device, pkt_data)
    
    def _update_device_basic(self, device: EquipementSNMP, pkt_data: Dict):
        """Met à jour les infos de base d'un appareil"""
        
        if pkt_data.get("mac_src"):
            device.mac = pkt_data["mac_src"]
            self._detect_vendor_from_mac(device)
        
        
        if pkt_data.get("port_src"):
            device.ports.add(pkt_data["port_src"])
        
       
        version = str(pkt_data.get("snmp_version", ""))
        if version == "0":
            device.snmp_versions.add("v1")
        elif version == "1":
            device.snmp_versions.add("v2c")
        elif version == "3":
            device.snmp_versions.add("v3")
        
        # Community (v1/v2c)
        community = pkt_data.get("snmp_community")
        if community and community not in ["", "None", None]:
            device.communities.add(str(community))
        
        # USM User (v3)
        usm_user = pkt_data.get("snmp_usm_user_name")
        if usm_user and usm_user not in ["", "None", None]:
            device.usm_users.add(str(usm_user))
        
      
        error_status = pkt_data.get("snmp_error_status")
        if error_status and str(error_status) not in ["0", "None", ""]:
            device.error_count += 1
        
        # OIDs et infos système
        oids = pkt_data.get("snmp_oidsValues", [])
        if isinstance(oids, str):
            try:
                oids = json.loads(oids).get("oidsValues", [])
            except:
                oids = []
        
        for oid_entry in oids:
            oid = oid_entry.get("oid", "")
            value = oid_entry.get("value", "")
            device.oids_accessed.add(oid)
            
            
            if value and value not in ["None", "", "b''"]:
                if self.OID_SYS_DESCR in oid:
                    device.sys_descr = str(value)[:200]
                    self._detect_device_type(device)
                elif self.OID_SYS_NAME in oid:
                    device.sys_name = str(value)[:100]
                elif self.OID_SYS_LOCATION in oid:
                    device.sys_location = str(value)[:100]
                elif self.OID_SYS_CONTACT in oid:
                    device.sys_contact = str(value)[:100]
                elif self.OID_SYS_OBJECT_ID in oid:
                    device.sys_object_id = str(value)
                    self._detect_vendor_from_oid(device)
        
        
        self._determine_device_status(device)
    
    def _detect_vendor_from_mac(self, device: EquipementSNMP):
        """Détecte le constructeur à partir du préfixe MAC"""
        if not device.mac:
            return
        mac_prefix = device.mac.lower()[:8]
        for prefix, vendor in self.MAC_VENDORS.items():
            if mac_prefix.startswith(prefix.lower()):
                device.vendor = vendor
                return
    
    def _detect_vendor_from_oid(self, device: EquipementSNMP):
        """Détecte le constructeur à partir du sysObjectID"""
        if not device.sys_object_id:
            return
        for oid_prefix, vendor in self.VENDOR_OIDS.items():
            if device.sys_object_id.startswith(oid_prefix):
                device.vendor = vendor
                return
    
    def _detect_device_type(self, device: EquipementSNMP):
        """Détecte le type d'appareil à partir de sysDescr"""
        if not device.sys_descr:
            return
        
        descr_lower = device.sys_descr.lower()
        
        if any(x in descr_lower for x in ["router", "routeur", "ios", "junos"]):
            device.device_type = "router"
        elif any(x in descr_lower for x in ["switch", "catalyst", "nexus"]):
            device.device_type = "switch"
        elif any(x in descr_lower for x in ["firewall", "asa", "fortigate", "palo"]):
            device.device_type = "firewall"
        elif any(x in descr_lower for x in ["access point", "wireless", "wifi", "ap"]):
            device.device_type = "access_point"
        elif any(x in descr_lower for x in ["printer", "imprimante", "laserjet", "print"]):
            device.device_type = "printer"
        elif any(x in descr_lower for x in ["linux", "ubuntu", "debian", "centos", "rhel"]):
            device.device_type = "server_linux"
        elif any(x in descr_lower for x in ["windows", "microsoft"]):
            device.device_type = "server_windows"
        elif any(x in descr_lower for x in ["ups", "apc", "eaton"]):
            device.device_type = "ups"
        elif any(x in descr_lower for x in ["storage", "nas", "san", "netapp", "synology"]):
            device.device_type = "storage"
        elif any(x in descr_lower for x in ["camera", "ipcam", "video"]):
            device.device_type = "camera"
        else:
            device.device_type = "unknown"
    
    def _determine_device_status(self, device: EquipementSNMP):
        """Détermine le status de l'appareil"""
        
        elapsed = (datetime.now() - device.last_seen).total_seconds()
        if elapsed > self._inactive_timeout:
            device.status = "inactive"
        elif device.error_count > device.packet_count * 0.5:
            device.status = "suspicious"
        else:
            device.status = "active"
    
    def get_all_devices(self) -> List[Dict]:
        """Retourne la liste de tous les appareils confirmés"""
        with self._lock:
           
            for device in self._devices.values():
                self._determine_device_status(device)
            
            return [d.to_dict() for d in sorted(
                self._devices.values(), 
                key=lambda x: x.last_seen, 
                reverse=True
            )]
    
    def get_device(self, ip: str) -> Optional[Dict]:
        """Retourne un appareil spécifique"""
        with self._lock:
            if ip in self._devices:
                return self._devices[ip].to_dict()
            return None
    
    def get_statistics(self) -> Dict:
        """Retourne des statistiques globales"""
        with self._lock:
            total = len(self._devices)
            active = sum(1 for d in self._devices.values() if d.status == "active")
            managers = sum(1 for d in self._devices.values() if d.is_manager)
            agents = sum(1 for d in self._devices.values() if d.is_agent)
            
          
            by_type = {}
            for d in self._devices.values():
                by_type[d.device_type] = by_type.get(d.device_type, 0) + 1
            
           
            by_version = {"v1": 0, "v2c": 0, "v3": 0}
            for d in self._devices.values():
                for v in d.snmp_versions:
                    by_version[v] = by_version.get(v, 0) + 1
            
            return {
                "total_devices": total,
                "active_devices": active,
                "inactive_devices": total - active,
                "managers": managers,
                "agents": agents,
                "by_type": by_type,
                "by_snmp_version": by_version,
                "trusted": sum(1 for d in self._devices.values() if d.is_trusted),
                "ignored": sum(1 for d in self._devices.values() if d.is_ignored),
                "blocked": sum(1 for d in self._devices.values() if getattr(d, "is_blocked", False))
            }
    
    def set_trusted(self, ip: str, trusted: bool = True):
        """Marque un appareil comme de confiance"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].is_trusted = trusted
                if trusted:
                    self._devices[ip].is_ignored = False 
                    self._devices[ip].is_blocked = False 
                return True
        return False
    
    def set_ignored(self, ip: str, ignored: bool = True):
        """Marque un appareil comme ignoré"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].is_ignored = ignored
                if ignored:
                    self._devices[ip].is_trusted = False 
                    self._devices[ip].is_blocked = False 
                return True
        return False

    def set_blocked(self, ip: str, blocked: bool = True):
        """Marque un appareil comme bloqué"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].is_blocked = blocked
                if blocked:
                    self._devices[ip].is_trusted = False
                    self._devices[ip].is_ignored = False
                return True
        return False
    
    def set_custom_name(self, ip: str, name: str):
        """Définit un nom personnalisé pour un appareil"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].custom_name = name if name else None
                return True
        return False
    
    def set_notes(self, ip: str, notes: str):
        """Définit des notes pour un appareil"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].notes = notes if notes else None
                return True
        return False
    
    def get_trusted_devices(self) -> List[Dict]:
        """Retourne la liste des appareils de confiance"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values() if d.is_trusted]
    
    def get_blocked_devices(self) -> List[Dict]:
        """Retourne la liste des appareils bloqués"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values() if getattr(d, "is_blocked", False)]

    def get_ignored_devices(self) -> List[Dict]:
        """Retourne la liste des appareils ignorés"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values() if d.is_ignored]
    
    def get_filtered_devices(self, show_ignored: bool = False, show_inactive: bool = True,
                            device_type: str = None) -> List[Dict]:
        """Retourne la liste filtrée des appareils"""
        with self._lock:
            # Mettre à jour les status
            for device in self._devices.values():
                self._determine_device_status(device)
            
            result = []
            for d in self._devices.values():
                if d.is_ignored and not show_ignored:
                    continue
                
                if d.status == "inactive" and not show_inactive:
                    continue
                
                if device_type and d.device_type != device_type:
                    continue
                result.append(d.to_dict())
            
            return sorted(result, key=lambda x: x['last_seen'], reverse=True)
    
    def export_devices(self) -> List[Dict]:
        """Exporte tous les appareils pour sauvegarde"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]
    
    def delete_device(self, ip: str) -> bool:
        """Supprime un appareil de la liste"""
        with self._lock:
            if ip in self._devices:
                del self._devices[ip]
                return True
        return False
    
    def clear(self):
        """Efface tous les appareils"""
        with self._lock:
            self._devices.clear()
            self._pending_devices.clear()




class ListeEquipements(ctk.CTkFrame):
    """Widget affichant la liste des appareils SNMP avec design TABLEAU & STATS"""
    
    DEVICE_ICONS = {
        "router": "🌐", "switch": "🔀", "firewall": "🛡️", "access_point": "📶",
        "printer": "🖨️", "server_linux": "🐧", "server_windows": "🪟",
        "ups": "🔋", "storage": "💾", "camera": "📷", "unknown": "❓"
    }
    
    def __init__(self, parent, device_manager=None, on_select=None, on_trust=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._device_manager = device_manager
        self._on_select = on_select
        self._on_trust = on_trust
        self._devices = []
        self._whitelist_ips = []
        self._rows = []
        self._lock = Lock()
        
        self._build()
        
    def _build(self):
        
        stats_container = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=10)
        stats_container.pack(fill="x", padx=15, pady=(0, 15))
        
        self._create_stats_header(stats_container)
        
   
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(action_frame, text="Inventaire Réseau", font=ctk.CTkFont(size=18, weight="bold"), text_color="black").pack(side="left")
        
        ctk.CTkButton(action_frame, text="📥 Exporter (CSV)", width=120, height=32,
                     fg_color=THEME["bg_panel"], hover_color=THEME["accent"],
                     font=ctk.CTkFont(size=12, weight="bold"),
                     command=self._export_devices).pack(side="right")
                     
        
        cols_container = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6, height=45)
        cols_container.pack(fill="x", padx=15)
        
        self.cols_cfg = [(0, 45), (1, 140), (2, 180), (3, 110), (4, 110), (5, 110), (6, 0)]
        
        headers = ["Type", "Adresse IP", "Nom Système", "Rôle", "Confiance", "État", "Actions"]
        
        for idx, (col_idx, w) in enumerate(self.cols_cfg):
            cols_container.grid_columnconfigure(col_idx, weight=1 if col_idx in [2,6] else 0)
            ctk.CTkLabel(cols_container, text=headers[idx], width=w if w>0 else 0,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=THEME["text_secondary"], anchor="w").grid(row=0, column=col_idx, padx=10, pady=10, sticky="ew")
                        
        
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._list_frame.pack(fill="both", expand=True, padx=5, pady=(5, 10))
        
        
        for idx, (col_idx, w) in enumerate(self.cols_cfg):
            self._list_frame.grid_columnconfigure(col_idx, weight=1 if col_idx in [2,6] else 0)

    def _create_stats_header(self, parent):
        
        self._stat_labels = {}
        metrics = [
            ("Total", "total", "#3b82f6"),
            ("Actifs", "active", "#10b981"), 
            ("Inactifs", "inactive", "#6b7280"),
            ("Trusted", "trusted", "#8b5cf6"),
            ("Bloqués", "blocked", "#ef4444"),
            ("Agents", "agent", "#f59e0b"),
            ("Managers", "manager", "#ec4899")
        ]
        
        parent.grid_columnconfigure(tuple(range(len(metrics))), weight=1)
        
        for i, (label, key, color) in enumerate(metrics):
            frame = ctk.CTkFrame(parent, fg_color="transparent")
            frame.grid(row=0, column=i, pady=15, padx=10)
            
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=12), text_color=THEME["text_secondary"]).pack()
            self._stat_labels[key] = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color=color)
            self._stat_labels[key].pack()

    def update_devices(self, devices: List[Dict], whitelist: List[str]):
        """Met à jour la liste et les stats"""
        with self._lock:
            
            for widgets in self._rows:
                for w in widgets: w.destroy()
            self._rows.clear()
            
            self._whitelist_ips = whitelist
            self._devices = devices
            
           
            stats = {k: 0 for k in ["total", "active", "inactive", "trusted", "blocked", "agent", "manager"]}
            stats["total"] = len(devices)
            
            for idx, dev in enumerate(devices):
                ip = dev.get("ip")
                is_active = dev.get("status") == "active" 
                is_trusted = dev.get("is_trusted", False) 
                is_blocked = dev.get("is_blocked", False)
                
                role = ""
                if dev.get("is_manager") and dev.get("is_agent"):
                    role = "Manager/Agent"
                elif dev.get("is_manager"):
                    role = "Manager"
                elif dev.get("is_agent"):
                    role = "Agent"
                else:
                    role = "Inconnu"
                
               
                stats["active"] += 1 if is_active else 0
                stats["inactive"] += 1 if not is_active else 0
                stats["trusted"] += 1 if is_trusted else 0
                stats["blocked"] += 1 if is_blocked else 0
                stats["manager"] += 1 if dev.get("is_manager") else 0
                stats["agent"] += 1 if dev.get("is_agent") else 0
                
                bg_color = THEME["bg_card"] if idx % 2 == 0 else THEME["bg_input"]
                
                
                row_widgets = []
                
                
                icon = self.DEVICE_ICONS.get(dev.get("device_type", "unknown"), "❓")
                l0 = ctk.CTkLabel(self._list_frame, text=icon, width=45, fg_color=bg_color, font=ctk.CTkFont(size=16))
                l0.grid(row=idx, column=0, sticky="nsew", pady=1, padx=(5,1))
                row_widgets.append(l0)
                
                
                l1 = ctk.CTkLabel(self._list_frame, text=ip, width=140, fg_color=bg_color, anchor="w", font=ctk.CTkFont(family="monospace"))
                l1.grid(row=idx, column=1, sticky="nsew", pady=1, padx=1)
                row_widgets.append(l1)
                
                name = dev.get("custom_name") or dev.get("hostname") or dev.get("sys_name") or "Inconnu"
                l2 = ctk.CTkLabel(self._list_frame, text=name[:25], fg_color=bg_color, anchor="w")
                l2.grid(row=idx, column=2, sticky="nsew", pady=1, padx=1)
                row_widgets.append(l2)
                
                
                l3 = ctk.CTkLabel(self._list_frame, text=role, width=110, fg_color=bg_color, anchor="center", text_color=THEME["text_secondary"])
                l3.grid(row=idx, column=3, sticky="nsew", pady=1, padx=1)
                row_widgets.append(l3)
                
                
                if is_blocked:
                    trust_txt = "⛔ BOQUÉ"
                    trust_col = "#ef4444"
                else:
                    trust_txt = "✅ Sûr" if is_trusted else "⚠️ Inconnu"
                    trust_col = "#10b981" if is_trusted else "#f59e0b"
                l4 = ctk.CTkLabel(self._list_frame, text=trust_txt, width=110, fg_color=bg_color, text_color=trust_col, font=ctk.CTkFont(weight="bold"))
                l4.grid(row=idx, column=4, sticky="nsew", pady=1, padx=1)
                row_widgets.append(l4)
                
                
                status_txt = "Actif" if is_active else "Inactif"
                status_col = THEME["success"] if is_active else THEME["text_muted"]
                l5 = ctk.CTkLabel(self._list_frame, text=status_txt, width=110, fg_color=bg_color, text_color=status_col)
                l5.grid(row=idx, column=5, sticky="nsew", pady=1, padx=1)
                row_widgets.append(l5)
                
                
                act_frame = ctk.CTkFrame(self._list_frame, fg_color=bg_color, corner_radius=0)
                act_frame.grid(row=idx, column=6, sticky="nsew", pady=1, padx=(1,5))
                row_widgets.append(act_frame)
                
                
                btn_det = ctk.CTkButton(act_frame, text="🔍 Détails", width=70, height=24,
                                      fg_color=THEME["chart_blue"], font=ctk.CTkFont(size=11),
                                      command=lambda d=dev: self._on_select(d) if self._on_select else None)
                btn_det.pack(side="left", padx=5)
                
                if not is_trusted:
                    btn_trust = ctk.CTkButton(act_frame, text="✅ Trust", width=70, height=24,
                                            fg_color=THEME["bg_panel"], border_width=1, border_color=THEME["success"],
                                            text_color=THEME["success"], hover_color="#ECFDF5", font=ctk.CTkFont(size=11),
                                            command=lambda i=ip: self._on_trust(i) if self._on_trust else None)
                    btn_trust.pack(side="left", padx=2)
                
                
                if not is_blocked:
                    btn_block = ctk.CTkButton(act_frame, text="⛔ Block", width=70, height=24,
                                            fg_color=THEME["bg_panel"], border_width=1, border_color=THEME["error"],
                                            text_color=THEME["error"], hover_color="#FEF2F2", font=ctk.CTkFont(size=11),
                                    
                                            
                                            command=lambda d=dev: self._on_select(d) if self._on_select else None)
                    btn_block.pack(side="left", padx=2)
                
                
                self._rows.append(row_widgets)

            
            for key, count in stats.items():
                if key in self._stat_labels:
                    self._stat_labels[key].configure(text=str(count))

    def _export_devices(self):
        pass
        

class ListePaquets(ctk.CTkFrame):
    """Liste des paquets avec coloration selon l'analyse - Design Pro"""
    
    def __init__(self, parent, on_select=None, device_manager=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._on_select = on_select
        self._device_manager = device_manager
        self.packets = []
        self._rows = []
        self._lock = Lock()
        self._build()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(header, text="📦 Flux SNMP (Temps Réel)",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._count_label = ctk.CTkLabel(header, text="0 paquets capturés",
                                        font=ctk.CTkFont(size=12),
                                        text_color=THEME["text_secondary"])
        self._count_label.pack(side="right")
        
        # En-têtes colonnes (Grid Layout pour alignement parfait)
        # Structure de grille: 7 colonnes
        cols_config = [
            (0, 50),   # #
            (1, 90),   # Heure
            (2, 140),  # Source
            (3, 140),  # Dest
            (4, 110),  # PDU
            (5, 120),  # Community
            (6, 90)    # Tag/Status
        ]
        
        cols = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6, height=35)
        cols.pack(fill="x", padx=10, pady=(0, 5))
        
        headers = ["#", "Heure", "Source", "Destination", "PDU Type", "Community", "Statut"]
        
        for idx, (col_idx, width) in enumerate(cols_config):
            cols.grid_columnconfigure(col_idx, weight=1 if idx in [2,3,5] else 0)
            ctk.CTkLabel(cols, text=headers[idx], width=width,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=THEME["text_secondary"], anchor="w").grid(row=0, column=col_idx, padx=5, pady=8, sticky="w")
        
        # Liste scrollable
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self._list_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Configurer la grille interne de la liste pour qu'elle corresponde aux headers
        for idx, (col_idx, width) in enumerate(cols_config):
            self._list_frame.grid_columnconfigure(col_idx, weight=1 if idx in [2,3,5] else 0)

    def add_packet(self, pkt: Dict, raw_data: bytes = None):
        """Ajoute un paquet à la liste de manière thread-safe"""
        with self._lock:
            # If raw_data provided, attach it to the dict
            if raw_data:
                pkt["_raw"] = raw_data
                
            self.packets.append(pkt)
            idx = len(self.packets) - 1
            
            # Limit display to 100 latest lines for performance
            if len(self._rows) >= 100:
                old = self._rows.pop(0)
                for widget in old:
                    widget.destroy()
            
            self._create_row(pkt, idx)
            self._count_label.configure(text=f"{len(self.packets)} paquets capturés")
            
            # Auto-scroll (only if not manually scrolling, ideally)
            try:
                self._list_frame._parent_canvas.yview_moveto(1.0)
            except:
                pass
    
    def _create_row(self, pkt: Dict, idx: int):
        tag = pkt.get('tag', 0)
        error_status = pkt.get('snmp_error_status', 0)
        # Conversion en entier pour vérification
        try:
            err_code = int(error_status)
        except:
            err_code = 0
            
        pdu_type = str(pkt.get('snmp_pdu_type', 'N/A'))
        
        # Logique de couleur
        status_text = "✅ Succès"
        status_color = "#10b981" # Vert
        # Fond géré par les cellules individuelles (pilules)
        cell_bg_color = THEME["bg_input"] # Fond gris
        
        if err_code != 0:
            status_text = f"❌ Erreur {err_code}"
            status_color = "#ef4444" # Rouge vif
        else:
            ip = str(pkt.get('ip_src', '')).strip()
            device_info = self._device_manager.get_device(ip) if hasattr(self, '_device_manager') else None
            is_trusted = device_info.get("is_trusted", False) if device_info else False
            
            # LOG DE DEBUG
            if is_trusted:
                print(f"[DEBUG UI] Paquet depuis appareil DE CONFIANCE {ip} -> Force VERT")

            if is_trusted:
                # OVERRIDE DE CONFIANCE: Si l'appareil est de confiance, on ignore le WARN (tag=1)
                status_text = "✅ Succès"
                status_color = "#10b981" # Vert
            elif tag == 1:
                status_text = "WARN"
                status_color = "#F97316" # Orange

        # Création des labels directement dans la grille
        row_widgets = []
        
        # Style partagé
        common_font = ctk.CTkFont(family="monospace", size=11)
        pill_radius = 6 # Coins arrondis
        
        # 1. Numéro
        l1 = ctk.CTkLabel(self._list_frame, text=str(idx + 1), width=50, font=common_font, text_color=THEME["text_muted"], anchor="center", fg_color=cell_bg_color, corner_radius=pill_radius)
        l1.grid(row=idx, column=0, sticky="ew", padx=2, pady=2)
        row_widgets.append(l1)
        
        # 2. Heure (HH:MM:SS) - Parse robuste du timestamp original
        ts_raw = pkt.get('time_stamp', '')
        ts = "N/A"
        if ts_raw:
            try:
                # Format attendu: "YYYY-MM-DD HH:MM:SS.ffffff" ou "YYYY-MM-DD HH:MM:SS"
                ts_str = str(ts_raw)
                if " " in ts_str:
                    # Extraire la partie heure après l'espace
                    time_part = ts_str.split(" ")[1]
                    # Garder seulement HH:MM:SS (sans microsecondes)
                    ts = time_part.split(".")[0] if "." in time_part else time_part[:8]
                else:
                    # Repli: 8 derniers caractères
                    ts = ts_str[-8:] if len(ts_str) >= 8 else ts_str
            except:
                ts = str(ts_raw)[-8:] if len(str(ts_raw)) >= 8 else str(ts_raw)
        l2 = ctk.CTkLabel(self._list_frame, text=ts, width=90, font=common_font, text_color=THEME["text_primary"], anchor="center", fg_color=cell_bg_color, corner_radius=pill_radius)
        l2.grid(row=idx, column=1, sticky="ew", padx=2, pady=2)
        row_widgets.append(l2)
        
        # 3. IP Source
        l3 = ctk.CTkLabel(self._list_frame, text=str(pkt.get('ip_src', 'N/A')), font=common_font, text_color=THEME["accent"], anchor="w", fg_color=cell_bg_color, corner_radius=pill_radius)
        l3.grid(row=idx, column=2, sticky="ew", padx=2, pady=2)
        row_widgets.append(l3)
        
        # 4. IP Dest
        l4 = ctk.CTkLabel(self._list_frame, text=str(pkt.get('ip_dst', 'N/A')), font=common_font, text_color=THEME["text_secondary"], anchor="w", fg_color=cell_bg_color, corner_radius=pill_radius)
        l4.grid(row=idx, column=3, sticky="ew", padx=2, pady=2)
        row_widgets.append(l4)
        
        # 5. Type PDU
        pdu_color = THEME["text_primary"]
        if "set" in pdu_type.lower(): pdu_color = "#eab308" # Jaune pour SET
        elif "trap" in pdu_type.lower(): pdu_color = "#f97316" # Orange pour TRAP
        elif "get" in pdu_type.lower(): pdu_color = "#3b82f6" # Bleu pour GET
        
        l5 = ctk.CTkLabel(self._list_frame, text=pdu_type, width=110, font=ctk.CTkFont(size=11, weight="bold"), text_color=pdu_color, anchor="center", fg_color=cell_bg_color, corner_radius=pill_radius)
        l5.grid(row=idx, column=4, sticky="ew", padx=2, pady=2)
        row_widgets.append(l5)
        
        # 6. Communauté
        comm = str(pkt.get('snmp_community', 'desc_inconnue'))
        if len(comm) > 15: comm = comm[:12] + "..."
        l6 = ctk.CTkLabel(self._list_frame, text=comm, width=120, font=common_font, text_color=THEME["text_muted"], anchor="w", fg_color=cell_bg_color, corner_radius=pill_radius)
        l6.grid(row=idx, column=5, sticky="ew", padx=2, pady=2)
        row_widgets.append(l6)
        
        # 7. Statut (Tag) - Badge coloré
        # On utilise un Frame pour simuler un badge arrondi si désiré, ou juste du texte coloré
        l7 = ctk.CTkLabel(self._list_frame, text=status_text, width=90, font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color, anchor="center", fg_color=cell_bg_color, corner_radius=pill_radius)
        l7.grid(row=idx, column=6, sticky="ew", padx=2, pady=2)
        row_widgets.append(l7)
        
        # Click for details
        if self._on_select:
            for w in row_widgets:
                w.bind("<Button-1>", lambda e, p=pkt: self._on_select(p))
                w.configure(cursor="hand2")
        
        self._rows.append(row_widgets)
    def clear(self):
        with self._lock:
            self.packets.clear()
            for row_widgets in self._rows:
                for w in row_widgets:
                    try:
                        w.destroy()
                    except:
                        pass
            self._rows.clear()
            self._count_label.configure(text="0 paquets capturés")
    
    def get_stats(self):
        with self._lock:
            total = len(self.packets)
            suspects = sum(1 for p in self.packets if p.get('tag') == 1)
            errors = sum(1 for p in self.packets if p.get('snmp_error_status', 0) != 0)
        return {"total": total, "suspects": suspects, "errors": errors}




class PanneauDetailPaquet(ctk.CTkFrame):
    """Panneau de détails d'un paquet - Support SNMPv1/v2c/v3"""
    
    def __init__(self, parent, on_trust=None, capture_mgr=None, device_manager=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._on_trust = on_trust
        self._capture_mgr = capture_mgr
        self._device_manager = device_manager
        self._current_ip = None
        self._current_packet = None
        self._build()
    
    def _build(self):
        # Header Container
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=18, pady=(15, 10))
        
        # Titre
        ctk.CTkLabel(header_frame, text="📋 Détails du paquet",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        # Bouton Trust
        self._trust_btn = ctk.CTkButton(header_frame, text="✅ Trust Equip.", 
                                       command=self._handle_trust,
                                       width=100, height=24,
                                       font=ctk.CTkFont(size=11, weight="bold"),
                                       fg_color=THEME["success"], hover_color="#059669")
        self._trust_btn.pack(side="right", padx=5)
        self._trust_btn.configure(state="disabled") # Disabled by default

        # Bouton Export PCAP
        self._export_btn = ctk.CTkButton(header_frame, text="💾 PCAP", width=80,
                                       command=self._export_pcap,
                                       height=24, font=ctk.CTkFont(size=11),
                                       fg_color=THEME["bg_panel"], border_width=1,
                                       border_color=THEME["accent"], text_color=THEME["accent"],
                                       hover_color=THEME["accent_hover"])
        self._export_btn.pack(side="right", padx=5)
        self._export_btn.configure(state="disabled")
        
        # Zone de texte - POLICE PLUS GRANDE
        self._text = ctk.CTkTextbox(self, fg_color=THEME["bg_panel"],
                                   font=ctk.CTkFont(family="monospace", size=13),
                                   text_color=THEME["text_primary"])
        self._text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text.insert("1.0", "Sélectionnez un paquet pour voir les détails...")
        self._text.configure(state="disabled")
        
    def _handle_trust(self):
        if self._on_trust and self._current_ip:
            self._on_trust(self._current_ip)
            # Rafraichir l'affichage pour montrer le changement de statut
            if self._current_packet:
                self.show_packet(self._current_packet)

    def _export_pcap(self):
        """Exporte le paquet courant en PCAP"""
        if not self._current_packet or not self._capture_mgr or not self._capture_mgr.analyser: return
        
        raw = self._current_packet.get("_raw")
        if not raw: return
        
        # Dialog save
        filename = ctk.filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Exporter le paquet en PCAP"
        )
        
        if filename:
            success = self._capture_mgr.analyser.export_packet_bytes(raw, filename)
            if success:
                tk.messagebox.showinfo("Export réussi", f"Fichier sauvegardé :\n{filename}")
            else:
                tk.messagebox.showerror("Erreur", "Echec de l'export du paquet.")

    def show_packet(self, pkt: Dict):
        """Affiche les détails d'un paquet (v1/v2c/v3)"""
        self._current_ip = pkt.get('ip_src')
        
        # Activer le bouton si IP présente
        if self._current_ip:
            self._trust_btn.configure(state="normal")
        else:
            self._trust_btn.configure(state="disabled")

        # Memoriser packet
        self._current_packet = pkt

        # Activer Export si raw bytes disponibles
        if pkt.get("_raw"):
            self._export_btn.configure(state="normal")
        else:
            self._export_btn.configure(state="disabled")

        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        
        # Parser les OIDs
        oids = pkt.get('snmp_oidsValues', [])
        if isinstance(oids, str):
            try:
                oids = json.loads(oids).get('oidsValues', [])
            except:
                oids = []
        
        # Déterminer la version
        version_raw = str(pkt.get('snmp_version', '1'))
        if version_raw == '0':
            version = "SNMPv1"
        elif version_raw == '3':
            version = "SNMPv3"
        else:
            version = "SNMPv2c"
        
        is_trusted = False
        if self._device_manager:
             dev = self._device_manager.get_device(pkt.get('ip_src'))
             if dev and dev.get('is_trusted'):
                  is_trusted = True

        tag_str = "⚠️ SUSPECT (Warn)" if pkt.get('tag') == 1 else "✓ OK"
        if is_trusted:
            tag_str = "✓ OK (Trusted)"

        
        text = f"""
═══════════════════════════════════════════════════════════
  TIMESTAMP:  {pkt.get('time_stamp', 'N/A')}
  VERSION:    {version}
═══════════════════════════════════════════════════════════

  ▸ RÉSEAU
  ─────────────────────────────────────────────────────────
    MAC Source:      {str(pkt.get('mac_src', 'N/A'))}
    MAC Destination: {str(pkt.get('mac_dst', 'N/A'))}
    IP Source:       {str(pkt.get('ip_src', 'N/A'))}
    IP Destination:  {str(pkt.get('ip_dst', 'N/A'))}
    Ports:           {pkt.get('port_src', '?')} → {pkt.get('port_dst', '?')}

  ▸ STATUS:          {tag_str}
"""
        
        # Section spécifique SNMPv3
        if version_raw == '3':
            is_auth = "✓" if pkt.get('is_authenticated') else "✗"
            is_priv = "✓" if pkt.get('is_encrypted') else "✗"
            text += f"""
  ▸ SNMPv3 SECURITY
  ─────────────────────────────────────────────────────────
    Security Level:  {pkt.get('security_level', 'N/A')}
    User Name:       {pkt.get('snmp_usm_user_name', 'N/A')}
    Engine ID:       {pkt.get('snmp_usm_engine_id', 'N/A')[:32] if pkt.get('snmp_usm_engine_id') else 'N/A'}...
    Auth Protocol:   {pkt.get('snmp_usm_auth_protocol', 'N/A')} [{is_auth}]
    Priv Protocol:   {pkt.get('snmp_usm_priv_protocol', 'N/A')} [{is_priv}]
    Engine Boots:    {pkt.get('snmp_usm_engine_boots', 'N/A')}
    Engine Time:     {pkt.get('snmp_usm_engine_time', 'N/A')}

  ▸ SNMPv3 PDU
  ─────────────────────────────────────────────────────────
    Message ID:      {pkt.get('snmp_msg_id', 'N/A')}
    PDU Type:        {pkt.get('snmp_pdu_type', 'N/A')}
    Request ID:      {pkt.get('snmp_request_id', 'N/A')}
    Error Status:    {pkt.get('snmp_error_status', 0)}
    Decrypt Status:  {pkt.get('decryption_status', 'N/A')}
"""
        else:
            # SNMPv1/v2c
            text += f"""
  ▸ SNMP
  ─────────────────────────────────────────────────────────
    Community:       {str(pkt.get('snmp_community', 'N/A'))}
    Type PDU:        {str(pkt.get('snmp_pdu_type', 'N/A'))}
    Request ID:      {str(pkt.get('snmp_request_id', 'N/A'))}
    Error Status:    {str(pkt.get('snmp_error_status', 0))}
    Error Index:     {str(pkt.get('snmp_error_index', 0))}
"""
        
        text += f"""
  ▸ STATUS:          {tag_str}

  ▸ OIDs ({len(oids)} variable{'s' if len(oids) > 1 else ''})
  ─────────────────────────────────────────────────────────
"""
        for i, oid in enumerate(oids[:10], 1):
            oid_str = str(oid.get('oid', 'N/A'))
            # TRADUCTION OID
            translated = translate_oid(oid_str)
            
            val_str = str(oid.get('value', 'N/A'))[:60]
            
            if translated != oid_str:
                text += f"    [{i}] {translated}\n        OID: {oid_str}\n"
            else:
                text += f"    [{i}] {oid_str}\n"
                
            text += f"        Valeur: {val_str}\n\n"
        
        if len(oids) > 10:
            text += f"    ... et {len(oids) - 10} autres OIDs\n"
        
        text += "\n═══════════════════════════════════════════════════════════"
        
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")







class ApplicationMiBombo(ctk.CTk):
    """Application principale MiBombo  - Style Thème RobotBoy"""
    
    def __init__(self):
        super().__init__()
        self.title("MiBombo v1.0.0 - Outils SNMP ")
        self.geometry("1500x900")
        self.configure(fg_color=THEME["bg_main"])
        
        
        self._queue = None 
        self._stats_queue = Queue()
        self._db = None
        self._config_mgr = None
        
        
        self._capture_mgr = None
        if API_AVAILABLE:
            self._capture_mgr = CaptureManager()
            
        self._detector = None
        
        self._is_capturing = False
        self._stop_event = Event()
        
        self._interface = "eth0"
        self._snmp_filter = "udp port 161 or udp port 162 or udp port 10161"
        self._db_file = "mibombo.db"
        self._db_file = "mibombo.db"
        self._config_file = os.path.join(ROOT_DIR, "config", "conf.json")
        self._pcap_dir = os.path.join(ROOT_DIR, "captures")
        self._assets_dir = os.path.join(ROOT_DIR, "assets")
        
       
        try:
            icon_path = os.path.join(self._assets_dir, "logo.png")
            if os.path.exists(icon_path):
                icon_img = PILImage.open(icon_path)
                photo_img = tk.PhotoImage(file=icon_path)
                self.iconphoto(False, photo_img)
        except Exception as e:
            print(f"[!] Icone soft mal chargé: {e}")
        
        
        self._last_pkt_count = 0
        self._pps = 0.0
        self._errors_per_sec = 0
        self._last_error_count = 0
        
        # Données pour les graphiques
        self._pps_history = deque(maxlen=60)
        self._threat_history = deque(maxlen=60)
        
        
        self._current_threat_level = 0.0  
        self._last_alert_time = time.time() 
        self._last_alert_count_for_decay = 0 
        self._threat_decay_rate = 5.0 
        
        
        self._baseline_analyzer = AnalyseurBaseline(
            window_size=60,      
            threshold_pct=50.0,  
            min_samples=10       
        )
        
        
        self._device_manager = GestionnaireEquipements()
        
        # === AUTHENTIFICATION ===
        self._is_authenticated = False
        self._current_user = None
        self._auth_manager = None
        
        if get_auth_manager:
            self._auth_manager = get_auth_manager()
        
        self._setup_ui()
        self._init_core()
        self.after(1000, self._update_loop)
    
    def _init_core(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Modules core non disponibles", 
                                        text_color=THEME["error"])
            return
        
        try:
            os.makedirs(self._pcap_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
            
            self._db = DataBase(require_encryption=True)
            self._db.initDB()
            
            self._config_mgr = ConfAPP(confFile=self._config_file)
            if self._config_mgr.config is None:
                self._config_mgr.creatConf()
            
            self._detector = get_detector()
            
            # self._status_label.configure(text="✓ Système prêt", text_color=THEME["success"])
        except Exception as e:
            print(f"[!] Initialisation de core mal exécuter: {e}")
            traceback.print_exc()
            # self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=THEME["error"])


        
        try:
            self._device_manager.load_devices()
        except:
            pass
            
        # Charger l'historique des paquets
        self.after(500, self._load_history)

    def _load_history(self):
        """Charge l'historique des paquets depuis la DB au démarrage"""
        if not self._db: return
        
        try:
            all_pkts = []
            
            for table in ["snmp_v3", "snmp_v2", "snmp_v1"]:
                if not self._db.table_exists(table): continue
                
                cols_info = self._db.getChamps(table)
                if not cols_info: continue
                
                # Compatibilité : Postgres (list[str]) vs SQLite (list[tuple])
                if isinstance(cols_info[0], str):
                    col_names = cols_info
                else:
                    col_names = [c[1] for c in cols_info]
                
                rows = self._db.getLatest(table, col_names, limit=50)
                
                for row in rows:
                    pkt = dict(zip(col_names, row))
                    all_pkts.append(pkt)
            
            
            all_pkts.sort(key=lambda x: x.get('time_stamp') or "", reverse=False)
            
            
            if len(all_pkts) > 500:
                all_pkts = all_pkts[-500:]
                
            print(f"[Core] Historique restauré: {len(all_pkts)} paquets chargés.")
            
            for pkt in all_pkts:
                if hasattr(self, '_packet_list') and self._packet_list:
                    self._packet_list.add_packet(pkt)
                    
        except Exception as e:
            print(f"[!] Erreur Historique non chargé : {e}")

    def logout(self):
        """Déconnecte l'utilisateur et retourne au login"""
        if messagebox.askyesno("Déconnexion", "Voulez-vous vraiment vous déconnecter ?"):
            try:
                # Log de sécurité
                if self._current_user:
                     print(f"[AUTH] Déconnexion demandée par {self._current_user.get('username')}")
                
                if self._auth_manager:
                    self._auth_manager.logout()
            except:
                pass
            
            self._is_authenticated = False
            self.destroy()
    
    def on_closing(self):
        """Appelé lors de la fermeture de l'application"""
        if messagebox.askokcancel("Quitter", "Voulez-vous vraiment quitter ?"):
            try:
                self._stop_event.set()
                self._is_capturing = False
                
                # Sauvegarder
                self._device_manager.save_devices()
                if self._detector:
                    self._detector.save_stats()
                
                if self._sniffer:
                    self._sniffer.stop()
            except:
                pass
            self.destroy()
            sys.exit(0)

    def _setup_ui(self):
        self.grid_columnconfigure(1, weight=1)  
        self.grid_rowconfigure(0, weight=0) 
        self.grid_rowconfigure(1, weight=1) 
        
        
        header = ctk.CTkFrame(self, height=50, fg_color=THEME["bg_panel"], corner_radius=0)
        header.grid(row=0, column=1, sticky="ew")
        header.grid_propagate(False)
        
        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.pack(side="left", padx=15)
        
        ctk.CTkLabel(logo_frame, text="MiBombo",
                    font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=THEME["accent"]).pack()
        
        
        capture_control_frame = ctk.CTkFrame(header, fg_color="transparent")
        capture_control_frame.pack(side="left", padx=20)
        
        
        interface_frame = ctk.CTkFrame(capture_control_frame, fg_color=THEME["bg_card"],
                                      corner_radius=8, height=36)
        interface_frame.pack(side="left", padx=(0, 8))
        
        ctk.CTkLabel(interface_frame, text="🌐",
                    font=ctk.CTkFont(size=14)).pack(side="left", padx=(8, 4))
        
        
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
            interfaces.sort(key=lambda x: (x != "eth0", x))
        except:
            interfaces = ["eth0", "wlan0", "lo"]
        
        self._header_if_selector = ctk.CTkComboBox(
            interface_frame,
            values=interfaces,
            width=120,
            height=28,
            corner_radius=6,
            fg_color=THEME["bg_input"],
            button_color=THEME["accent"],
            button_hover_color=THEME["accent_hover"],
            border_width=0
        )
        if interfaces:
            self._header_if_selector.set(interfaces[0])
        self._header_if_selector.pack(side="left", padx=(0, 8), pady=4)
        
        
        self._start_btn = ctk.CTkButton(
            capture_control_frame,
            text="▶ Démarrer Capture",
            command=self.start_capture,
            fg_color=THEME["success"],
            hover_color="#2ea043",
            height=36,
            width=160,
            corner_radius=8,
            font=ctk.CTkFont(size=13, weight="bold")
        )
        self._start_btn.pack(side="left", padx=2)
        
        self._stop_btn = ctk.CTkButton(
            capture_control_frame,
            text="⏹ Arrêter",
            command=self.stop_capture,
            fg_color=THEME["error"],
            hover_color="#da3633",
            height=36,
            width=100,
            corner_radius=8,
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled"
        )
        self._stop_btn.pack(side="left", padx=2)
        
        # Capture indicator
        self._capture_indicator = ctk.CTkLabel(header, text="● ARRÊTÉ",
                                              font=ctk.CTkFont(size=11, weight="bold"),
                                              text_color=THEME["text_muted"])
        self._capture_indicator.pack(side="left", padx=15)
        
        
        self._time_label = ctk.CTkLabel(header, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color=THEME["text_muted"])
        self._time_label.pack(side="right", padx=20)
        
        # ===== SIDEBAR GAUCHE =====
        self._sidebar = ctk.CTkFrame(self, width=200, fg_color=THEME["bg_panel"], corner_radius=0)
        self._sidebar.grid(row=0, column=0, rowspan=2, sticky="ns")
        self._sidebar.grid_propagate(False)
        
        # Logo dans la sidebar
        logo_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=(20, 30))
        
        try:
            logo_path = os.path.join(self._assets_dir, "logo.png")
            if os.path.exists(logo_path):
                pil_image = PILImage.open(logo_path)
                
                logo_image = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(110, 110))
                
                ctk.CTkLabel(logo_frame, text="", image=logo_image).pack(anchor="w", pady=(0, 5))
            else:
                ctk.CTkLabel(logo_frame, text="MiBombo",
                            font=ctk.CTkFont(size=20, weight="bold"),
                            text_color=THEME["accent"]).pack(anchor="w")
        except:
             ctk.CTkLabel(logo_frame, text="MiBombo",
                        font=ctk.CTkFont(size=20, weight="bold"),
                        text_color=THEME["accent"]).pack(anchor="w")

        ctk.CTkLabel(logo_frame, text="Software by ENSA",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w")

        
        self._top_user_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        self._top_user_frame.pack(fill="x", padx=15, pady=(0, 20))
        
        
        ctk.CTkLabel(self._top_user_frame, text="👤", font=ctk.CTkFont(size=24)).pack(side="left", padx=(0, 10))
        
        # Infos
        info_subframe = ctk.CTkFrame(self._top_user_frame, fg_color="transparent")
        info_subframe.pack(side="left", fill="x", expand=True)
        
        self._user_indicator = ctk.CTkLabel(info_subframe, text="...",
                                           font=ctk.CTkFont(size=13, weight="bold"),
                                           text_color=THEME["text_primary"])
        self._user_indicator.pack(anchor="w")
        
        self._user_role_label = ctk.CTkLabel(info_subframe, text="...",
                                            font=ctk.CTkFont(size=11),
                                            text_color=THEME["text_muted"])
        self._user_role_label.pack(anchor="w")
        
        # Bouton Déconnexion (Petit bouton rouge à droite)
        ctk.CTkButton(
            self._top_user_frame,
            text="🚪",
            width=30,
            height=30,
            fg_color="#EF4444",
            hover_color="#DC2626",
            font=ctk.CTkFont(size=14),
            command=self.logout
        ).pack(side="right", padx=(5, 0))
        # ---------------------------------------------
        
        # Menu de navigation
        self._nav_buttons = {}
        self._current_tab = "dashboard"
        
        nav_items = [
            ("dashboard", "📊  Vue Globale"),
            ("capture", "📡  Sniffer"),
            ("snmp_sender", "📤  Émetteur SNMP"),  # NEW: Émetteur SNMP
            ("devices", "🖥️  Équipements"),
            ("behavior", "🔍 Enquête"),
            ("api", "🔌  Interface API"),
            ("snmpv3_users", "🔐 Gestion SNMPv3"),
            ("profile", "👤  Gestion Utilisateur"),
            ("documentation", "📚  Documentation"),
        ]
        
        for tab_id, tab_name in nav_items:
            btn_container = ctk.CTkFrame(self._sidebar, fg_color="transparent")
            btn_container.pack(fill="x", padx=12, pady=4)
            
            if tab_id == "snmpv3_users":
                btn = ctk.CTkButton(
                    btn_container,
                    text=tab_name,
                    font=ctk.CTkFont(size=14, weight="bold"),
                    fg_color="transparent",
                    text_color=THEME["text_secondary"],
                    hover_color=THEME["bg_hover"],
                    anchor="w",
                    height=42,
                    corner_radius=8,
                    border_width=0,
                    border_spacing=12,
                    command=self.open_snmp_users # Direct call
                )
            else:
                btn = ctk.CTkButton(
                    btn_container,
                    text=tab_name,
                    font=ctk.CTkFont(size=14, weight="bold"),
                    fg_color="transparent",
                    text_color=THEME["text_secondary"],
                    hover_color=THEME["bg_hover"],
                    anchor="w",
                    height=42,
                    corner_radius=8,
                    border_width=0,
                    border_spacing=12,  # Plus d'espace pour le texte
                    command=lambda t=tab_id: self._switch_tab(t)
                )
            btn.pack(fill="x")
            self._nav_buttons[tab_id] = btn
        
        self._admin_btn_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        
        # Bouton Admin (sera affiché seulement si admin)
        self._admin_btn = ctk.CTkButton(
            self._admin_btn_frame,
            text="⚙️ Parametres",
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            text_color=THEME["warning"],
            hover_color=THEME["bg_hover"],
            anchor="w",
            height=40,
            corner_radius=6,
            command=lambda: self._switch_tab("admin")
        )
        self._nav_buttons["admin"] = self._admin_btn
        # Ne pas afficher par défaut, sera affiché si admin
        
        # Sélectionner le premier onglet
        self._nav_buttons["dashboard"].configure(
            fg_color=THEME["accent"],
            text_color=THEME["text_primary"]
        )
        
        # Séparateur
        ctk.CTkFrame(self._sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=20)
        
        
        # Spacer
        ctk.CTkFrame(self._sidebar, fg_color="transparent").pack(fill="both", expand=True)
        
        
        self._admin_btn_frame.pack(side="bottom", fill="x", padx=12, pady=(0, 5))
        
        # ===== CONTAINER PRINCIPAL =====
        main_container = ctk.CTkFrame(self, fg_color=THEME["bg_main"])
        main_container.grid(row=1, column=1, sticky="nsew")
        
        
        
        # Titre du main header
        self._page_title = ctk.CTkLabel(header, text="Dashboard",
                                       font=ctk.CTkFont(size=18, weight="bold"),
                                       text_color=THEME["text_primary"])
        self._page_title.pack(side="left", padx=20, pady=10)
        
        
        ctk.CTkButton(header, text="Vider la liste", width=100, height=30,
                     fg_color=THEME["bg_input"],
                     hover_color=THEME["error"],
                     font=ctk.CTkFont(size=11),
                     command=self.clear_all).pack(side="right", padx=5)
        
        statusbar = ctk.CTkFrame(main_container, height=28, fg_color=THEME["bg_panel"], corner_radius=0)
        statusbar.pack(fill="x", side="bottom")
        
        self._status_label = ctk.CTkLabel(statusbar, text="",
                                         font=ctk.CTkFont(size=10),
                                         text_color=THEME["text_muted"])
        self._status_label.pack(side="left", padx=15, pady=5)
        
        # self._user_status supprimé pour éviter les doublons
        
        
        # Core status - affichage désactivé (visible uniquement dans les logs)
        # core_txt = "Core OK" if CORE_AVAILABLE else "Core ERR"
        # core_col = THEME["success"] if CORE_AVAILABLE else THEME["error"]
        # ctk.CTkLabel(statusbar, text=core_txt, font=ctk.CTkFont(size=10),
        #             text_color=core_col).pack(side="right", padx=15)
        
        # Container pour les pages
        self._pages_container = ctk.CTkFrame(main_container, fg_color=THEME["bg_main"])
        self._pages_container.pack(fill="both", expand=True, padx=10, pady=10)
        self._pages_container.grid_columnconfigure(0, weight=1)
        self._pages_container.grid_rowconfigure(0, weight=1)
        
        # Créer toutes les pages
        self._pages = {}
        
        self._pages["dashboard"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["capture"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["snmp_sender"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")  # NEW
        self._pages["devices"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["topology"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["behavior"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["api"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["profile"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["documentation"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["admin"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        
        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        
        # Construire le contenu de chaque page
        self._build_dashboard_tab(self._pages["dashboard"])
        self._build_capture_tab(self._pages["capture"])
        self._build_snmp_sender_tab(self._pages["snmp_sender"])  # NEW
        self._build_devices_tab(self._pages["devices"])
        self._build_topology_tab(self._pages["topology"])
        self._build_behavior_tab(self._pages["behavior"])
        self._build_api_tab(self._pages["api"])
        self._build_profile_tab(self._pages["profile"])
        self._build_admin_tab(self._pages["admin"])
        self._build_documentation_tab(self._pages["documentation"])
        
        # Afficher la page dashboard par default
        self._pages["dashboard"].tkraise()
        
    def open_snmp_users(self):
        """Ouvre la gestion des utilisateurs SNMPv3"""
        if not snmp_cred_mgr:
            messagebox.showerror("Erreur", "Gestionnaire de credentials non disponible (Clé manquante ?)")
            return
            
        dialog = DialogueUtilisateursSNMP(self)
        self.wait_window(dialog)
    
    def _switch_tab(self, tab_id: str):
        """Change l'onglet actif."""
        for btn_id, btn in self._nav_buttons.items():
            btn.configure(
                fg_color="transparent",
                text_color=THEME["text_secondary"]
            )
        
        # Activer le bouton sélectionné
        self._nav_buttons[tab_id].configure(
            fg_color=THEME["accent"],
            text_color=THEME["text_primary"]
        )
        
        # Ctitre
        titles = {
            "dashboard": "Dashboard",
            "capture": "Capture",
            "snmp_sender": "Émetteur SNMP",  
            "devices": "Appareils",
            "topology": "Topology Map",
            "behavior": "Analyse Comportementale",
            "api": "API REST",
            "snmpv3_users": "Gestion SNMPv3",
            "profile": "Profil",
            "admin": "Parametres"
        }
        self._page_title.configure(text=titles.get(tab_id, tab_id))
        
        # Afficher la page correspondante
        self._pages[tab_id].tkraise()
        self._current_tab = tab_id
        
        # 
        if tab_id == "profile":
            self._update_profile_visibility()
    
    def _build_dashboard_tab(self, tab):
        """Construit l'onglet Dashboard avec 3 vues métiers (SOC, NOC, Exec)"""
        # --- Custom Navigation Bar ---
        nav_frame = ctk.CTkFrame(tab, fg_color="transparent")
        nav_frame.pack(fill="x", padx=5, pady=5)
        nav_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        self._dash_btns = {}
        
        # Bouton SOC
        self._dash_btns["soc"] = ctk.CTkButton(
            nav_frame, 
            text="🛡️ SOC (Sécurité)", 
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            fg_color=THEME["bg_card"],
            text_color=THEME["text_secondary"],
            command=lambda: self._switch_dash_view("soc")
        )
        self._dash_btns["soc"].grid(row=0, column=0, sticky="ew", padx=2)
        
        # Bouton NOC
        self._dash_btns["noc"] = ctk.CTkButton(
            nav_frame, 
            text="📡 NOC (Réseau)", 
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            fg_color=THEME["bg_card"],
            text_color=THEME["text_secondary"],
            command=lambda: self._switch_dash_view("noc")
        )
        self._dash_btns["noc"].grid(row=0, column=1, sticky="ew", padx=2)
        
        # Bouton Synthèse
        self._dash_btns["exec"] = ctk.CTkButton(
            nav_frame, 
            text="📊 Synthèse", 
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            fg_color=THEME["bg_card"],
            text_color=THEME["text_secondary"],
            command=lambda: self._switch_dash_view("exec")
        )
        self._dash_btns["exec"].grid(row=0, column=2, sticky="ew", padx=2)
        
        # --- Content Container ---
        self._dash_container = ctk.CTkFrame(tab, fg_color="transparent")
        self._dash_container.pack(fill="both", expand=True, padx=5, pady=5)
        self._dash_container.grid_rowconfigure(0, weight=1)
        self._dash_container.grid_columnconfigure(0, weight=1)
        
        # Création des vues (empilées via grid)
        self._dash_views = {}
        
        # View SOC
        self._dash_views["soc"] = ctk.CTkFrame(self._dash_container, fg_color="transparent")
        self._dash_views["soc"].grid(row=0, column=0, sticky="nsew")
        self._build_soc_view(self._dash_views["soc"])
        
        # View NOC
        self._dash_views["noc"] = ctk.CTkFrame(self._dash_container, fg_color="transparent")
        self._dash_views["noc"].grid(row=0, column=0, sticky="nsew")
        self._build_noc_view(self._dash_views["noc"])
        
        # View Exec
        self._dash_views["exec"] = ctk.CTkFrame(self._dash_container, fg_color="transparent")
        self._dash_views["exec"].grid(row=0, column=0, sticky="nsew")
        self._build_exec_view(self._dash_views["exec"])
        
        # Activer SOC par défaut
        self._switch_dash_view("soc")

    def _switch_dash_view(self, view_name):
        """Change la vue active du dashboard"""
        # Raise la vue demandée
        self._dash_views[view_name].tkraise()
        
        # Mettre à jour le style des boutons
        for name, btn in self._dash_btns.items():
            if name == view_name:
                btn.configure(fg_color=THEME["accent"], text_color="#ffffff")
            else:
                btn.configure(fg_color=THEME["bg_card"], text_color=THEME["text_secondary"])
    
    def _build_soc_view(self, parent):
        """Vue Sécurité (SOC) - Menaces et Intrusions"""
        parent.grid_columnconfigure((0, 1, 2, 3), weight=1)
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_rowconfigure(2, weight=1)
        
        # ROW 0: Stats Sécurité
        self._stat_suspects = CarteStatistique(parent, title="Src Warning", icon="⚠️", color=THEME["warning"])
        self._stat_suspects.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self._stat_alerts = CarteStatistique(parent, title="Alertes en cours", icon="🚨", color=THEME["error"])
        self._stat_alerts.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # KPI: Tentatives d'écriture (Set)
        self._stat_sets = CarteStatistique(parent, title="Tentatives SET (Blocked)", icon="🛡️", color=THEME["accent"])
        self._stat_sets.set_value(0) # Sera mis à jour
        self._stat_sets.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        # KPI: Auth Failures
        self._stat_auth_fail = CarteStatistique(parent, title="Auth failed", icon="🔒", color=THEME["chart_orange"])
        self._stat_auth_fail.set_value(0)
        self._stat_auth_fail.grid(row=0, column=3, sticky="nsew", padx=5, pady=5)
        
        # ROW 1: Graphique Menace
        self._chart_threat = GraphiqueTemps(parent, title="🔴 Pourcentage de Menace en cours (%)", ylabel="%")
        self._chart_threat.add_series("Threat", THEME["chart_red"])
        self._chart_threat.grid(row=1, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
            
        # ROW 2: Liste Alertes + Donut Sécurité
        # Alertes (Gauche)
        self._alert_list = PanneauAlertes(parent)
        self._alert_list._list_frame.configure(height=180)
        self._alert_list.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # Donut Sécurité (Droite)
        self._chart_security = GraphiqueDonut(parent, title="🛡️ Sécurité Protocoles (v3 vs v1/v2)")
        self._chart_security.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)

    def _build_noc_view(self, parent):
        """Vue Réseau (NOC) - Performance et Disponibilité"""
        parent.grid_columnconfigure((0, 1, 2, 3), weight=1)
        parent.grid_rowconfigure(1, weight=1)
        
        # ROW 0: Stats Réseau
        self._stat_packets = CarteStatistique(parent, title="Nmb de Paquets", icon="📦", color=THEME["chart_blue"])
        self._stat_packets.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self._stat_pps = CarteStatistique(parent, title="Paquets/sec", icon="📈", color=THEME["chart_green"])
        self._stat_pps.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        self._stat_devices_up = CarteStatistique(parent, title="Nmb d'appareil actifs", icon="🟢", color=THEME["success"])
        self._stat_devices_up.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        self._stat_latency = CarteStatistique(parent, title="Latence Moy (est.)", icon="⏱️", color=THEME["text_primary"])
        self._stat_latency.set_value("2ms") # Mock pour l'instant
        self._stat_latency.grid(row=0, column=3, sticky="nsew", padx=5, pady=5)
        
        # ROW 1: Graphique PPS
        self._chart_pps = GraphiqueTemps(parent, title="Graphique du traffic SNMP", ylabel="PPS")
        self._chart_pps.add_series("PPS", THEME["chart_green"])
        self._chart_pps.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # ROW 1 (Droite): Top Talkers (Tableau simple)
        talker_frame = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=8)
        talker_frame.grid(row=1, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(talker_frame, text="🏆 Top Talkers (IPs)", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        self._top_talkers_list = ctk.CTkTextbox(talker_frame, fg_color=THEME["bg_panel"])
        self._top_talkers_list.pack(fill="both", expand=True, padx=10, pady=10)
        self._top_talkers_list.insert("1.0", "En attente de données...")

    def _build_exec_view(self, parent):
        """Vue Synthèse (Exec) - Scores et Conformité"""
        parent.grid_columnconfigure((0, 1), weight=1)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        
        # Score de Sécurité Global (Zone Gauche)
        score_frame = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=8)
        score_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=20)
        
        ctk.CTkLabel(score_frame, text="Global Security Score", font=ctk.CTkFont(size=16)).pack(pady=(15, 5))
        self._security_score_label = ctk.CTkLabel(score_frame, text="A+", font=ctk.CTkFont(size=64, weight="bold"), text_color=THEME["success"])
        self._security_score_label.pack(pady=(0, 15))
        
        # Zone Basse : Conformité (Gauche) vs Résumé (Droite)
        # Conformité
        self._compliance_chart = GraphiqueDonut(parent, title="Conformité du Parc (Appareils Monitorés)")
        self._compliance_chart.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        # Mock data (sera mis à jour)
        self._compliance_chart.update({"Conforme": 12, "Non-Conforme": 3}, [THEME["success"], THEME["warning"]])
        
        # Résumé Texte et Actions
        summary_frame = ctk.CTkFrame(parent, fg_color=THEME["bg_card"], corner_radius=8)
        summary_frame.grid(row=1, column=1, sticky="nsew", padx=20, pady=20)
        ctk.CTkLabel(summary_frame, text="📝 Synthèse Hebdomadaire", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        summary_text = """
        • Tendance: Stable
        • Incidents majeurs: 0
        • Nouveaux appareils: 2
        """
        self._summary_label = ctk.CTkLabel(summary_frame, text=summary_text, justify="left", font=ctk.CTkFont(family="Courier", size=12))
        self._summary_label.pack(pady=5)

        # Bouton Rapport PDF
        btn_report = ctk.CTkButton(summary_frame, text="📄 Générer Rapport Audit (PDF)", 
                                 command=self._generate_pdf_report,
                                 fg_color=THEME["accent"], hover_color=THEME["accent_hover"])
        btn_report.pack(pady=20, padx=20, fill="x")

    def _trust_device_handler(self, ip_address):
        """Callback pour faire confiance à une IP"""
        if not ip_address: return
        
        # Confirmation
        if not tk.messagebox.askyesno("Confiance", f"Voulez-vous ajouter l'IP {ip_address} à la liste blanche (Whitelist) ?\n\nLes futurs paquets de cette source ne seront plus marqués 'SUSPECT'."):
            return
            
        try:
            # Update config via AppConfig
            if self._config_mgr and self._config_mgr.config:
                if "whitelist" not in self._config_mgr.config:
                    self._config_mgr.config["whitelist"] = {}
                
                whitelist = self._config_mgr.config["whitelist"]
                
                if "IPs" not in whitelist:
                    whitelist["IPs"] = []
                    
                if ip_address not in whitelist["IPs"]:
                    whitelist["IPs"].append(ip_address)
                    try:
                        self._config_mgr._save()
                    except AttributeError:
                        # Fallback si _save est inaccessible ou renommé
                        pass
                    
                    # Notifier la mise à jour dynamique de l'analyseur
                    if self._analyser:
                        self._analyser.config = self._config_mgr.config
                        
                    tk.messagebox.showinfo("Succès", f"L'équipement {ip_address} est maintenant de confiance !")
                else:
                    tk.messagebox.showinfo("Info", f"L'équipement {ip_address} est déjà dans la liste blanche.")
        except Exception as e:
            tk.messagebox.showerror("Erreur", f"Impossible de mettre à jour la configuration : {e}")

    def _generate_pdf_report(self):
        """Génère un rapport d'audit PDF avec ReportLab"""
        try:
            import time
            from datetime import datetime
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib import colors as pdf_colors
            
            # Dossier de destination
            report_dir = os.path.join(os.getcwd(), "Rapport")
            os.makedirs(report_dir, exist_ok=True)
            
            # Nom de fichier formaté
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = os.path.join(report_dir, f"Audit_MiBombo_{timestamp}.pdf")
            
            c = canvas.Canvas(filename, pagesize=letter)
            width, height = letter
            
            # Header
            c.setFont("Helvetica-Bold", 24)
            c.drawString(50, height - 50, "MiBombo - Rapport d'Audit")
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 70, f"Généré le: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            c.line(50, height - 80, width - 50, height - 80)
            
            # Section 1: Synthèse
            y = height - 120
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "1. Synthèse de Sécurité")
            y -= 30
            c.setFont("Helvetica", 12)
            c.drawString(70, y, f"Score Global: {self._security_score_label.cget('text')}")
            y -= 20
            
            # Section 2: Nouveaux Appareils (La logique Top Talkers pourrait être réutilisée ici)
            y -= 40
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "2. Nouveaux Appareils & Problèmes")
            y -= 30
            c.setFont("Helvetica", 12)
            
            # Get devices
            if hasattr(self, '_device_manager') and self._device_manager:
                devices = self._device_manager.get_all_devices()
                new_devs = [d for d in devices if d.get('status') == 'active'] # Changed from 'online' to 'active'
                c.drawString(70, y, f"Appareils en ligne: {len(new_devs)}")
                y -= 20
                for d in new_devs[:5]:
                    c.drawString(90, y, f"- {d.get('ip')} ({d.get('sys_descr', 'N/A')[:30]}...)") # Changed sysDescr
                    y -= 15
            else:
                c.drawString(70, y, "Aucune donnée d'appareil disponible.")
            
            # Section 3: Alertes
            y -= 40
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "3. Dernières Alertes Critiques")
            y -= 30
            c.setFont("Helvetica", 12)
            
            if hasattr(self, '_detector') and self._detector:
                 for alert in self._detector.alerts[-5:]:
                     c.setFillColor(pdf_colors.red)
                     c.drawString(70, y, f"[!] {alert.message[:60]}")
                     c.setFillColor(pdf_colors.black)
                     y -= 15
            else:
                 c.drawString(70, y, "Aucune alerte critique récente.")

            c.save()
            tk.messagebox.showinfo("Succès", f"Rapport PDF généré : {filename}")
            
        except Exception as e:
            print(f"Erreur PDF: {e}")
            tk.messagebox.showerror("Erreur", f"Impossible de générer le PDF.\n{e}")
    
    def _build_capture_tab(self, tab):
        """Construit l'onglet Capture (Layout: 70% Liste, 30% Détails)"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=7) # Liste (70%)
        tab.grid_rowconfigure(1, weight=3) # Détails (30%)
        
        # 1. Liste des paquets (Haut)
        self._packet_list = ListePaquets(tab, on_select=self._on_packet_select, device_manager=self._device_manager)
        self._packet_list.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # 2. Détails du paquet (Bas)
        # Plus d'alertes ici, juste les détails sur toute la largeur
        # 2. Détails du paquet (Bas)
        # Plus d'alertes ici, juste les détails sur toute la largeur
        self._packet_detail = PanneauDetailPaquet(tab, on_trust=self._trust_device_handler, capture_mgr=self._capture_mgr, device_manager=self._device_manager)
        self._packet_detail.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
    
   
    
    def _build_snmp_sender_tab(self, tab):
        """Construit l'onglet Émetteur SNMP pour SNMPv2c et SNMPv3"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=0)  # Header
        tab.grid_rowconfigure(1, weight=1)  # Contenu
        
       
        header = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12, height=80)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))
        header.grid_propagate(False)
        
        ctk.CTkLabel(header, text="📤 Émetteur de Requêtes SNMP",
                    font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left", padx=20, pady=20)
        
        ctk.CTkLabel(header, text="Envoyer des requêtes GET, SET, WALK vers des équipements SNMP",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_muted"]).pack(side="left", padx=10)
        
       
        left_panel = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=5)
        
        # Titre
        ctk.CTkLabel(left_panel, text="⚙️ Configuration",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        # --- Version SNMP ---
        version_frame = ctk.CTkFrame(left_panel, fg_color=THEME["bg_panel"], corner_radius=8)
        version_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(version_frame, text="Version SNMP",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self._snmp_version_var = ctk.StringVar(value="v2c")
        version_selector = ctk.CTkSegmentedButton(version_frame, 
                                                  values=["v2c", "v3"],
                                                  variable=self._snmp_version_var,
                                                  command=self._on_snmp_version_change,
                                                  fg_color=THEME["bg_input"],
                                                  selected_color=THEME["accent"])
        version_selector.pack(fill="x", padx=10, pady=(0, 10))
        
        # --- Cible ---
        target_frame = ctk.CTkFrame(left_panel, fg_color=THEME["bg_panel"], corner_radius=8)
        target_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(target_frame, text="Cible",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        ip_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        ip_frame.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(ip_frame, text="IP:", width=60).pack(side="left")
        self._snmp_target_ip = ctk.CTkEntry(ip_frame, placeholder_text="192.168.1.1",
                                           fg_color=THEME["bg_input"])
        self._snmp_target_ip.pack(side="left", fill="x", expand=True, padx=5)
        
        port_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        port_frame.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(port_frame, text="Port:", width=60).pack(side="left")
        self._snmp_target_port = ctk.CTkEntry(port_frame, placeholder_text="161", width=80,
                                             fg_color=THEME["bg_input"])
        self._snmp_target_port.insert(0, "161")
        self._snmp_target_port.pack(side="left", padx=5)
        
        # OID Prédéfinis (Quick Select)
        oid_presets_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        oid_presets_frame.pack(fill="x", padx=10, pady=(5, 2))
        ctk.CTkLabel(oid_presets_frame, text="🎯 Raccourcis:", width=80).pack(side="left")
        
        # Dictionnaire des OIDs communs avec traduction
        self._oid_presets = {
            "📋 Description Système": "1.3.6.1.2.1.1.1.0",
            "🏷️ Nom Système": "1.3.6.1.2.1.1.5.0",
            "📍 Emplacement": "1.3.6.1.2.1.1.6.0",
            "👤 Contact Admin": "1.3.6.1.2.1.1.4.0",
            "⏱️ Uptime": "1.3.6.1.2.1.1.3.0",
            "🆔 Object ID": "1.3.6.1.2.1.1.2.0",
            "🔢 Nb Interfaces": "1.3.6.1.2.1.2.1.0",
            "📡 Table Interfaces": "1.3.6.1.2.1.2.2",
            "🌐 Table IP": "1.3.6.1.2.1.4.20",
            "📊 Table TCP": "1.3.6.1.2.1.6.13",
            "📈 Table UDP": "1.3.6.1.2.1.7.5",
            "🔌 Table ARP": "1.3.6.1.2.1.4.22",
            "📦 In Octets (if1)": "1.3.6.1.2.1.2.2.1.10.1",
            "📤 Out Octets (if1)": "1.3.6.1.2.1.2.2.1.16.1",
        }
        
        self._oid_selector = ctk.CTkOptionMenu(
            oid_presets_frame,
            values=list(self._oid_presets.keys()),
            command=self._on_oid_preset_select,
            fg_color=THEME["bg_input"],
            button_color=THEME["accent"],
            width=200
        )
        self._oid_selector.set("📋 Description Système")
        self._oid_selector.pack(side="left", fill="x", expand=True, padx=5)
        
        # OID manuel (pour personnalisation)
        oid_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        oid_frame.pack(fill="x", padx=10, pady=(2, 10))
        ctk.CTkLabel(oid_frame, text="OID:", width=80).pack(side="left")
        self._snmp_oid = ctk.CTkEntry(oid_frame, placeholder_text="1.3.6.1.2.1.1.1.0",
                                     fg_color=THEME["bg_input"])
        self._snmp_oid.insert(0, "1.3.6.1.2.1.1.1.0")
        self._snmp_oid.pack(side="left", fill="x", expand=True, padx=5)
        
        # --- Paramètres v2c ---
        self._v2c_frame = ctk.CTkFrame(left_panel, fg_color=THEME["bg_panel"], corner_radius=8)
        self._v2c_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(self._v2c_frame, text="Paramètres SNMPv2c",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        comm_frame = ctk.CTkFrame(self._v2c_frame, fg_color="transparent")
        comm_frame.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(comm_frame, text="Community:", width=80).pack(side="left")
        self._snmp_community = ctk.CTkEntry(comm_frame, placeholder_text="public",
                                           fg_color=THEME["bg_input"])
        self._snmp_community.insert(0, "public")
        self._snmp_community.pack(side="left", fill="x", expand=True, padx=5)
        
        # --- Paramètres v3 (initialement caché) ---
        self._v3_frame = ctk.CTkFrame(left_panel, fg_color=THEME["bg_panel"], corner_radius=8)
        
        ctk.CTkLabel(self._v3_frame, text="Paramètres SNMPv3",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Username
        user_frame = ctk.CTkFrame(self._v3_frame, fg_color="transparent")
        user_frame.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(user_frame, text="Username:", width=100).pack(side="left")
        self._snmp_v3_user = ctk.CTkEntry(user_frame, placeholder_text="snmpuser",
                                         fg_color=THEME["bg_input"])
        self._snmp_v3_user.pack(side="left", fill="x", expand=True, padx=5)
        
        # Security Level
        sec_frame = ctk.CTkFrame(self._v3_frame, fg_color="transparent")
        sec_frame.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(sec_frame, text="Sec Level:", width=100).pack(side="left")
        self._snmp_v3_sec_level = ctk.CTkOptionMenu(sec_frame, 
                                                    values=["noAuthNoPriv", "authNoPriv", "authPriv"],
                                                    fg_color=THEME["bg_input"])
        self._snmp_v3_sec_level.set("authPriv")
        self._snmp_v3_sec_level.pack(side="left", fill="x", expand=True, padx=5)
        
        # Auth Protocol
        auth_frame = ctk.CTkFrame(self._v3_frame, fg_color="transparent")
        auth_frame.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(auth_frame, text="Auth Proto:", width=100).pack(side="left")
        self._snmp_v3_auth_proto = ctk.CTkOptionMenu(auth_frame, 
                                                     values=["MD5", "SHA", "SHA256", "SHA512"],
                                                     fg_color=THEME["bg_input"])
        self._snmp_v3_auth_proto.set("SHA")
        self._snmp_v3_auth_proto.pack(side="left", padx=5)
        
        self._snmp_v3_auth_key = ctk.CTkEntry(auth_frame, placeholder_text="Auth Key",
                                             show="•", fg_color=THEME["bg_input"])
        self._snmp_v3_auth_key.pack(side="left", fill="x", expand=True, padx=5)
        
        # Priv Protocol
        priv_frame = ctk.CTkFrame(self._v3_frame, fg_color="transparent")
        priv_frame.pack(fill="x", padx=10, pady=(2, 10))
        ctk.CTkLabel(priv_frame, text="Priv Proto:", width=100).pack(side="left")
        self._snmp_v3_priv_proto = ctk.CTkOptionMenu(priv_frame, 
                                                     values=["DES", "AES", "AES192", "AES256"],
                                                     fg_color=THEME["bg_input"])
        self._snmp_v3_priv_proto.set("AES")
        self._snmp_v3_priv_proto.pack(side="left", padx=5)
        
        self._snmp_v3_priv_key = ctk.CTkEntry(priv_frame, placeholder_text="Priv Key",
                                             show="•", fg_color=THEME["bg_input"])
        self._snmp_v3_priv_key.pack(side="left", fill="x", expand=True, padx=5)
        
        # --- Opération ---
        op_frame = ctk.CTkFrame(left_panel, fg_color=THEME["bg_panel"], corner_radius=8)
        op_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(op_frame, text="Opération",
                    font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self._snmp_operation = ctk.CTkSegmentedButton(op_frame, 
                                                      values=["GET", "SET", "WALK", "GETNEXT"],
                                                      command=self._on_snmp_operation_change,
                                                      fg_color=THEME["bg_input"],
                                                      selected_color=THEME["accent"])
        self._snmp_operation.set("GET")
        self._snmp_operation.pack(fill="x", padx=10, pady=5)
        
        # Valeur pour SET (initialement caché)
        self._set_value_frame = ctk.CTkFrame(op_frame, fg_color="transparent")
        
        val_frame = ctk.CTkFrame(self._set_value_frame, fg_color="transparent")
        val_frame.pack(fill="x", pady=2)
        ctk.CTkLabel(val_frame, text="Valeur:", width=60).pack(side="left")
        self._snmp_set_value = ctk.CTkEntry(val_frame, placeholder_text="Nouvelle valeur",
                                           fg_color=THEME["bg_input"])
        self._snmp_set_value.pack(side="left", fill="x", expand=True, padx=5)
        
        type_frame = ctk.CTkFrame(self._set_value_frame, fg_color="transparent")
        type_frame.pack(fill="x", pady=(2, 10))
        ctk.CTkLabel(type_frame, text="Type:", width=60).pack(side="left")
        self._snmp_set_type = ctk.CTkOptionMenu(type_frame, 
                                                values=["String", "Integer", "OID", "IP"],
                                                fg_color=THEME["bg_input"])
        self._snmp_set_type.set("String")
        self._snmp_set_type.pack(side="left", padx=5)
        
        # Bouton Envoyer
        btn_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=15)
        
        self._snmp_send_btn = ctk.CTkButton(btn_frame, text="🚀 Envoyer la Requête",
                                           font=ctk.CTkFont(size=14, weight="bold"),
                                           fg_color=THEME["accent"],
                                           hover_color=THEME["accent_hover"],
                                           height=45,
                                           command=self._send_snmp_request)
        self._snmp_send_btn.pack(fill="x")
        
        
        right_panel = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        right_panel.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=5)
        
        
        result_header = ctk.CTkFrame(right_panel, fg_color="transparent")
        result_header.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(result_header, text="📋 Résultats",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        ctk.CTkButton(result_header, text="🗑️ Effacer", width=80,
                     fg_color=THEME["bg_panel"], hover_color=THEME["bg_hover"],
                     command=self._clear_snmp_results).pack(side="right")
        
        
        self._snmp_results = ctk.CTkTextbox(right_panel, 
                                           fg_color=THEME["bg_panel"],
                                           font=ctk.CTkFont(family="Courier", size=11),
                                           wrap="word")
        self._snmp_results.pack(fill="both", expand=True, padx=15, pady=(5, 15))
        self._snmp_results.insert("1.0", "En attente de requête...\n\n" + 
                                  "💡 Instructions:\n" +
                                  "1. Sélectionnez la version SNMP (v2c ou v3)\n" +
                                  "2. Entrez l'IP et le port de la cible\n" +
                                  "3. Spécifiez l'OID à interroger\n" +
                                  "4. Choisissez l'opération (GET, SET, WALK...)\n" +
                                  "5. Cliquez sur 'Envoyer la Requête'\n")
    
    def _on_snmp_version_change(self, version):
        """Change l'affichage selon la version SNMP sélectionnée"""
        if version == "v2c":
            self._v2c_frame.pack(fill="x", padx=15, pady=5)
            self._v3_frame.pack_forget()
        else:
            self._v2c_frame.pack_forget()
            self._v3_frame.pack(fill="x", padx=15, pady=5)
    
    def _on_oid_preset_select(self, selection):
        """Remplit l'OID quand un raccourci est sélectionné"""
        oid = self._oid_presets.get(selection, "")
        if oid:
            self._snmp_oid.delete(0, "end")
            self._snmp_oid.insert(0, oid)
    
    def _on_snmp_operation_change(self, operation):
        """Affiche/cache le champ valeur pour SET"""
        if operation == "SET":
            self._set_value_frame.pack(fill="x", padx=10, pady=5)
        else:
            self._set_value_frame.pack_forget()
    
    def _clear_snmp_results(self):
        """Efface les résultats SNMP"""
        self._snmp_results.delete("1.0", "end")
        self._snmp_results.insert("1.0", "Résultats effacés.\n")
    
    def _send_snmp_request(self):
        """Envoie une requête SNMP"""
        import threading
        
        # Récupérer les paramètres
        version = self._snmp_version_var.get()
        target_ip = self._snmp_target_ip.get().strip()
        target_port = int(self._snmp_target_port.get() or "161")
        oid = self._snmp_oid.get().strip()
        operation = self._snmp_operation.get()
        
        if not target_ip or not oid:
            self._snmp_results.insert("end", "\n❌ Erreur: IP et OID requis\n")
            return
        
        self._snmp_results.insert("end", f"\n{'='*50}\n")
        self._snmp_results.insert("end", f"📤 Envoi {operation} vers {target_ip}:{target_port}\n")
        self._snmp_results.insert("end", f"   OID: {oid}\n")
        self._snmp_results.insert("end", f"   Version: SNMP{version}\n")
        self._snmp_results.see("end")
        
        # Lancer dans un thread
        def do_request():
            try:
                from pysnmp.hlapi import (
                    getCmd, setCmd, nextCmd, bulkCmd,
                    SnmpEngine, CommunityData, UdpTransportTarget,
                    ContextData, ObjectType, ObjectIdentity,
                    UsmUserData
                )
                
                engine = SnmpEngine()
                target = UdpTransportTarget((target_ip, target_port), timeout=5, retries=1)
                context = ContextData()
                
                # Auth data selon version
                if version == "v2c":
                    community = self._snmp_community.get() or "public"
                    auth = CommunityData(community)
                else:
                    from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol
                    user = self._snmp_v3_user.get() or "snmpuser"
                    auth_key = self._snmp_v3_auth_key.get()
                    priv_key = self._snmp_v3_priv_key.get()
                    auth = UsmUserData(user, auth_key, priv_key,
                                      authProtocol=usmHMACSHAAuthProtocol,
                                      privProtocol=usmAesCfb128Protocol)
                
                obj = ObjectType(ObjectIdentity(oid))
                
                # Exécuter l'opération
                if operation == "GET":
                    iterator = getCmd(engine, auth, target, context, obj)
                elif operation == "GETNEXT":
                    iterator = nextCmd(engine, auth, target, context, obj)
                elif operation == "WALK":
                    results = []
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        engine, auth, target, context, obj, lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            results.append(f"{varBind[0]} = {varBind[1]}")
                    
                    self.after(0, lambda: self._display_snmp_result(
                        f"✅ WALK - {len(results)} résultats:\n" + "\n".join(results[:50])
                    ))
                    return
                elif operation == "SET":
                    from pysnmp.proto.rfc1902 import OctetString, Integer32
                    val = self._snmp_set_value.get()
                    val_type = self._snmp_set_type.get()
                    if val_type == "Integer":
                        typed_val = Integer32(int(val))
                    else:
                        typed_val = OctetString(val)
                    obj = ObjectType(ObjectIdentity(oid), typed_val)
                    iterator = setCmd(engine, auth, target, context, obj)
                
                # Récupérer le résultat
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                
                if errorIndication:
                    result = f"❌ Erreur: {errorIndication}"
                elif errorStatus:
                    result = f"❌ Erreur SNMP: {errorStatus.prettyPrint()}"
                else:
                    result = f"✅ Succès:\n"
                    for varBind in varBinds:
                        result += f"   {varBind[0]} = {varBind[1]}\n"
                        
                        # MAJ AUTO: Si on reçoit le sysName, mettre à jour l'équipement
                        oid_str = str(varBind[0])
                        val_str = str(varBind[1])
                        if "1.3.6.1.2.1.1.5" in oid_str:
                             self.after(0, lambda i=target_ip, n=val_str: self._device_manager.set_sys_name(i, n))

                
                self.after(0, lambda: self._display_snmp_result(result))
                
            except Exception as e:
                err_msg = str(e) # Capturer en dehors de la lambda
                self.after(0, lambda m=err_msg: self._display_snmp_result(f"❌ Exception: {m}"))
        
        threading.Thread(target=do_request, daemon=True).start()
    
    def _display_snmp_result(self, result):
        """Affiche un résultat SNMP"""
        self._snmp_results.insert("end", f"\n{result}\n")
        self._snmp_results.see("end")
    
    def _build_devices_tab(self, tab):
        """Construit l'onglet Appareils (Nouveau Design)"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=6) # 60% Liste
        tab.grid_rowconfigure(1, weight=4) # 40% Détails
        
        # 1. LISTE (Nouveau Widget)
        self._device_list = ListeEquipements(tab, 
                                           device_manager=self._device_manager,
                                           on_select=self._on_device_select,
                                           on_trust=self._trust_device_handler)
        self._device_list.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # 2. DÉTAILS
        self._device_detail = PanneauDetailEquipement(tab, device_manager=self._device_manager, on_action=self._refresh_device_list)
        self._device_detail.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
    
    def _on_device_select(self, device: Dict):
        """Callback sélection d'un appareil"""
        self._device_detail.show_device(device)
    
    def _refresh_device_list(self):
        """Rafraîchit la liste des appareils après une action"""
        if hasattr(self, '_device_list'):
            devices = self._device_manager.get_all_devices()
            whitelist = []
            if self._config_mgr and self._config_mgr.config:
                whitelist = self._config_mgr.config.get("whitelist", {}).get("IPs", [])
            self._device_list.update_devices(devices, whitelist)
    
    def _build_topology_tab(self, tab):
        """Construit l'onglet Topology Map"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        if not TOPOLOGY_WIDGET_AVAILABLE:
            
            error_frame = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
            error_frame.place(relx=0.5, rely=0.5, anchor="center")
            
            ctk.CTkLabel(
                error_frame,
                text="🗺️",
                font=ctk.CTkFont(size=48)
            ).pack(pady=(30, 10))
            
            ctk.CTkLabel(
                error_frame,
                text="Module Topology non disponible",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=THEME["error"]
            ).pack(pady=5)
            
            ctk.CTkLabel(
                error_frame,
                text="Vérifiez que les fichiers topology.py et topology_widget.py\nsont présents dans les dossiers core/ et gui/",
                font=ctk.CTkFont(size=12),
                text_color=THEME["text_secondary"]
            ).pack(pady=(5, 30), padx=30)
            return
        
        # Panel de topologie complet
        self._topology_panel = TopologyPanel(tab)
        self._topology_panel.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Référence pour ajouter les paquets
        self._topology = get_topology() if get_topology else None
    
    def _build_behavior_tab(self, tab):
        """Construit l'onglet Analyse Comportementale - Design SOC Professionnel"""
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(0, weight=0)  # Header
        tab.grid_rowconfigure(1, weight=1)  # Main content
        tab.grid_rowconfigure(2, weight=0)  # Footer/Alerts
        
       
        header = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))
        header.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        
        # Titre
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        ctk.CTkLabel(title_frame, text="🛡️ Centre de Sécurité SNMP",
                    font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left")
        
        score_frame = ctk.CTkFrame(header, fg_color=THEME["bg_panel"], corner_radius=8)
        score_frame.grid(row=0, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(score_frame, text="SCORE", font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(pady=(8, 0))
        self._security_score_value = ctk.CTkLabel(score_frame, text="A+", 
                    font=ctk.CTkFont(size=32, weight="bold"),
                    text_color=THEME["success"])
        self._security_score_value.pack()
        ctk.CTkLabel(score_frame, text="Excellente", font=ctk.CTkFont(size=10),
                    text_color=THEME["success"]).pack(pady=(0, 8))
        
        stats_data = [
            ("🔴 Critiques", "0", "critical_count"),
            ("🟠 Warnings", "0", "warning_count"),
            ("🔵 Info", "0", "info_count"),
            ("📦 Total Paquets", "0", "total_packets"),
        ]
        
        for idx, (label, value, attr_name) in enumerate(stats_data):
            stat_frame = ctk.CTkFrame(header, fg_color="transparent")
            stat_frame.grid(row=0, column=idx + 2, padx=15, pady=10)
            
            val_label = ctk.CTkLabel(stat_frame, text=value, 
                        font=ctk.CTkFont(size=24, weight="bold"),
                        text_color=THEME["text_primary"])
            val_label.pack()
            setattr(self, f"_investigation_{attr_name}", val_label)
            
            ctk.CTkLabel(stat_frame, text=label, font=ctk.CTkFont(size=11),
                        text_color=THEME["text_secondary"]).pack()
        
        
        left_panel = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=5)
        
        
        timeline_header = ctk.CTkFrame(left_panel, fg_color="transparent")
        timeline_header.pack(fill="x", padx=15, pady=(15, 10))
        
        ctk.CTkLabel(timeline_header, text="📜 Timeline des Événements",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        ctk.CTkButton(timeline_header, text="⟳", width=30, height=30,
                     fg_color=THEME["bg_panel"], hover_color=THEME["bg_hover"],
                     command=self._refresh_investigation).pack(side="right")
        
        
        self._timeline_frame = ctk.CTkScrollableFrame(left_panel, 
                                                      fg_color=THEME["bg_panel"],
                                                      corner_radius=8)
        self._timeline_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        self._timeline_placeholder = ctk.CTkLabel(self._timeline_frame, 
                    text="En attente d'événements...",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_muted"])
        self._timeline_placeholder.pack(pady=50)
        
        
        right_panel = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        right_panel.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=5)
        
        
        ctk.CTkLabel(right_panel, text="🏆 Top Talkers",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=15, pady=(15, 5))
        
        self._top_talkers_frame = ctk.CTkFrame(right_panel, fg_color=THEME["bg_panel"], 
                                               corner_radius=8, height=120)
        self._top_talkers_frame.pack(fill="x", padx=10, pady=5)
        self._top_talkers_frame.pack_propagate(False)
        
        self._top_talkers_list = ctk.CTkLabel(self._top_talkers_frame, 
                    text="📊 Aucune donnée\n\nLancez une capture pour\nvoir les statistiques.",
                    font=ctk.CTkFont(family="Courier", size=11),
                    text_color=THEME["text_muted"], justify="left")
        self._top_talkers_list.pack(pady=20, padx=10, anchor="w")
        
        
        ctk.CTkLabel(right_panel, text="📊 Distribution par Version",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=15, pady=(15, 5))
        
        proto_frame = ctk.CTkFrame(right_panel, fg_color=THEME["bg_panel"], 
                                   corner_radius=8)
        proto_frame.pack(fill="x", padx=10, pady=5)
        
        
        versions = [("SNMPv1", THEME["error"], "_proto_v1"), 
                   ("SNMPv2c", THEME["warning"], "_proto_v2"),
                   ("SNMPv3", THEME["success"], "_proto_v3")]
        
        for name, color, attr in versions:
            row = ctk.CTkFrame(proto_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(row, text=name, width=60, font=ctk.CTkFont(size=11),
                        text_color=THEME["text_secondary"]).pack(side="left")
            
            bar = ctk.CTkProgressBar(row, height=12, corner_radius=6,
                                    fg_color=THEME["bg_main"], progress_color=color)
            bar.pack(side="left", fill="x", expand=True, padx=5)
            bar.set(0)
            setattr(self, attr, bar)
            
            pct_label = ctk.CTkLabel(row, text="0%", width=40, 
                                    font=ctk.CTkFont(size=11),
                                    text_color=THEME["text_muted"])
            pct_label.pack(side="right")
            setattr(self, f"{attr}_pct", pct_label)
        
        # Actions Rapides
        ctk.CTkLabel(right_panel, text="⚡ Actions Rapides",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=15, pady=(15, 5))
        
        actions_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        actions_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkButton(actions_frame, text="📄 Exporter Rapport",
                     fg_color=THEME["accent"], hover_color=THEME["accent_hover"],
                     command=self._export_investigation_report).pack(fill="x", pady=3)
        
        ctk.CTkButton(actions_frame, text="🧹 Réinitialiser Stats",
                     fg_color=THEME["bg_panel"], hover_color=THEME["bg_hover"],
                     text_color=THEME["text_primary"],
                     command=self._reset_investigation_stats).pack(fill="x", pady=3)
        
        
        alerts_frame = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=12)
        alerts_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))
        
        alerts_header = ctk.CTkFrame(alerts_frame, fg_color="transparent")
        alerts_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(alerts_header, text="🚨 Alertes de Sécurité Récentes",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["warning"]).pack(side="left")
        
        self._alerts_count_label = ctk.CTkLabel(alerts_header, text="0 alertes",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_muted"])
        self._alerts_count_label.pack(side="right")
        
        self._alerts_list_frame = ctk.CTkScrollableFrame(alerts_frame, 
                                                        fg_color=THEME["bg_panel"],
                                                        corner_radius=8, height=100)
        self._alerts_list_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self._investigation_events = []
        self._investigation_stats = {"critical": 0, "warning": 0, "info": 0, "v1": 0, "v2": 0, "v3": 0}
    
    def _refresh_investigation(self):
        """Rafraîchit les données d'investigation"""
        if hasattr(self, '_detector') and self._detector:
            alerts = self._detector.alerts
            self._investigation_stats["critical"] = len([a for a in alerts if a.severity == "critical"])
            self._investigation_stats["warning"] = len([a for a in alerts if a.severity in ("warning", "medium")])
            self._investigation_stats["info"] = len([a for a in alerts if a.severity in ("info", "low")])
        
        if hasattr(self, '_investigation_critical_count'):
            self._investigation_critical_count.configure(text=str(self._investigation_stats["critical"]))
            self._investigation_warning_count.configure(text=str(self._investigation_stats["warning"]))
            self._investigation_info_count.configure(text=str(self._investigation_stats["info"]))
            
           
            critical = self._investigation_stats["critical"]
            warning = self._investigation_stats["warning"]
            info = self._investigation_stats["info"]
            
           
            risk_score = min(100, (critical * 30) + (warning * 10) + (info * 3))
            
            
            if hasattr(self, '_last_alert_time'):
                temps_depuis_alerte = time.time() - self._last_alert_time
                if temps_depuis_alerte < 5:  
                    risk_score = min(100, risk_score * 1.5) 
            
            
            current_threat = getattr(self, '_current_threat_level', 0)
            
            final_score = (risk_score * 0.6) + (current_threat * 0.4)
            
            
            if final_score < 5:
                score, color = "A+", THEME["success"]
            elif final_score < 15:
                score, color = "A", THEME["success"]
            elif final_score < 30:
                score, color = "B+", "#22c55e" 
            elif final_score < 45:
                score, color = "B", THEME["warning"]
            elif final_score < 60:
                score, color = "C", "#f97316" 
            elif final_score < 75:
                score, color = "D", THEME["error"]
            else:
                score, color = "F", "#dc2626" 
            
            self._security_score_value.configure(text=score, text_color=color)
            
            
            if hasattr(self, '_security_score_label'):
                self._security_score_label.configure(text=score, text_color=color)
    
    def _add_timeline_event(self, event_type: str, message: str, time_str: str = None):
        """Ajoute un événement à la timeline"""
        import datetime
        if not time_str:
            time_str = datetime.datetime.now().strftime("%H:%M:%S")
        
        
        if hasattr(self, '_timeline_placeholder') and self._timeline_placeholder.winfo_exists():
            self._timeline_placeholder.destroy()
        
        
        colors = {"critical": THEME["error"], "warning": THEME["warning"], 
                 "info": THEME["accent"], "success": THEME["success"]}
        
        event_frame = ctk.CTkFrame(self._timeline_frame, fg_color="transparent")
        event_frame.pack(fill="x", pady=2)
        
        
        ctk.CTkLabel(event_frame, text=time_str, width=60,
                    font=ctk.CTkFont(family="Courier", size=10),
                    text_color=THEME["text_muted"]).pack(side="left", padx=5)
        
        
        dot_color = colors.get(event_type, THEME["text_secondary"])
        dot = ctk.CTkFrame(event_frame, width=10, height=10, corner_radius=5, 
                          fg_color=dot_color)
        dot.pack(side="left", padx=5)
        
        
        ctk.CTkLabel(event_frame, text=message,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_primary"], anchor="w").pack(side="left", fill="x", expand=True)
        
        
        self._investigation_events.append((event_type, message, time_str))
        if len(self._investigation_events) > 50:
            self._investigation_events = self._investigation_events[-50:]
    
    def _export_investigation_report(self):
        """Exporte un rapport d'investigation"""
        tk.messagebox.showinfo("Export", "Fonctionnalité en cours de développement.\nLe rapport sera exporté en PDF.")
    
    def _reset_investigation_stats(self):
        """Réinitialise les statistiques d'investigation"""
        if tk.messagebox.askyesno("Réinitialiser", "Voulez-vous vraiment réinitialiser toutes les statistiques ?"):
            self._investigation_stats = {"critical": 0, "warning": 0, "info": 0, "v1": 0, "v2": 0, "v3": 0}
            self._refresh_investigation()
            tk.messagebox.showinfo("Succès", "Statistiques réinitialisées.")
    
    def _build_api_tab(self, tab):
        """Construit l'onglet API"""
        self._api_client = TableauBordAPI(tab)
        self._api_client.pack(fill="both", expand=True)
    
    def _build_profile_tab(self, tab):
        """Construit l'onglet Profil (Layout: Admin Haut)"""
        tab.grid_columnconfigure(0, weight=7) 
        tab.grid_columnconfigure(1, weight=3) 
        tab.grid_rowconfigure(0, weight=1)    
        
        if SECURE_AUTH_AVAILABLE and UserListPanel:
            
            self._user_list_frame = ctk.CTkFrame(tab, fg_color="transparent")
            self._user_list_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
            
            self._user_list_panel = UserListPanel(self._user_list_frame, auth_manager=get_secure_auth_manager())
            self._user_list_panel.pack(fill="both", expand=True)

            
            self._ticket_frame = ctk.CTkFrame(tab, fg_color="transparent")
            self._ticket_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
            
            self._ticket_panel = TicketManagementPanel(self._ticket_frame, auth_manager=get_secure_auth_manager())
            self._ticket_panel.pack(fill="both", expand=True)
            
            # (Section Mon Profil supprimée sur demande)
            
            
            self._update_secure_profile_visibility()
            return
        
        
        if not AUTH_WIDGETS_AVAILABLE:
            ctk.CTkLabel(tab, text="Module d'authentification non disponible",
                        font=ctk.CTkFont(size=14),
                        text_color=THEME["error"]).pack(pady=50)
            return
        
        
        self._profile_panel = ProfilePanel(tab, 
                                          auth_manager=self._auth_manager,
                                          on_logout=self._on_logout)
        self._profile_panel.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)
        
        
        self._user_mgmt_panel = UserManagementPanel(tab, auth_manager=self._auth_manager)
        self._user_mgmt_panel.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)
        
        # Masquer le panneau de gestion si pas admin
        self._update_profile_visibility()
    
    def _build_simple_profile(self, frame):
        """Construit un profil simple pour le nouveau système (AVEC 2FA)"""
        ctk.CTkLabel(
            frame,
            text="👤 Mon Profil",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(pady=(20, 15), padx=20, anchor="w")
        
        # Info utilisateur
        info_frame = ctk.CTkFrame(frame, fg_color=THEME["bg_input"], corner_radius=8)
        info_frame.pack(fill="x", padx=15, pady=5)
        
        self._profile_name_label = ctk.CTkLabel(
            info_frame,
            text="Chargement...",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=THEME["text_primary"]
        )
        self._profile_name_label.pack(pady=(15, 5), padx=15, anchor="w")
        
        self._profile_username_label = ctk.CTkLabel(
            info_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=THEME["accent"]
        )
        self._profile_username_label.pack(pady=(0, 5), padx=15, anchor="w")
        
        self._profile_role_label = ctk.CTkLabel(
            info_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        )
        self._profile_role_label.pack(pady=(0, 15), padx=15, anchor="w")

        # Bouton déconnexion
        ctk.CTkButton(
            frame,
            text="🚪 Déconnexion",
            fg_color=THEME["error"],
            hover_color="#da3633",
            height=38,
            font=ctk.CTkFont(size=12),
            command=self._on_logout
        ).pack(fill="x", padx=15, pady=(5, 15))


    
    def _update_secure_profile_visibility(self):
        """Met à jour la visibilité pour le nouveau système"""
        if not hasattr(self, '_profile_name_label'):
            return
        
        user = self._current_user
        if user:
            self._profile_name_label.configure(text=user.get('full_name', 'Utilisateur'))
            self._profile_username_label.configure(text=f"@{user.get('username', 'N/A')}")
            role = user.get('role', 'user')
            self._profile_role_label.configure(text=f"Rôle: {role.capitalize()}")
            
            
            if hasattr(self, '_user_list_frame') and hasattr(self, '_ticket_frame'):
                if role == "admin" or "all" in user.get("permissions", []):
                    self._user_list_frame.grid()
                    self._ticket_frame.grid()
                    
                    if hasattr(self, '_user_list_panel'): self._user_list_panel.refresh()
                    if hasattr(self, '_ticket_panel'): self._ticket_panel.refresh()
                else:
                    self._user_list_frame.grid_remove()
                    self._ticket_frame.grid_remove()
    
    def _update_profile_visibility(self):
        """Met à jour la visibilité des panneaux selon le rôle."""
        if not hasattr(self, '_profile_panel'):
            return
        
        if self._auth_manager and self._auth_manager.current_user:
            user = self._auth_manager.current_user
            self._profile_panel.update_profile()
            
            # Afficher la gestion des users seulement pour admin
            if user.get("role") == "admin" or "all" in user.get("permissions", []):
                self._user_mgmt_panel.grid()
                self._user_mgmt_panel.refresh()
            else:
                self._user_mgmt_panel.grid_remove()
    
    def _on_logout(self):
        """Callback de déconnexion."""
        self._is_authenticated = False
        self._current_user = None
        
        
        if self._is_capturing:
            self.stop_capture()
        
        
        self.destroy()
    

    
    def _build_admin_tab(self, tab):
        """Construit l'onglet Parametres (Vide pour l'instant)"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        ctk.CTkLabel(tab, text="Page Parametres (Vide)", 
                     font=ctk.CTkFont(size=20),
                     text_color=THEME["text_secondary"]).pack(expand=True)
    
    def _refresh_admin_panel(self):
        """Rafraîchit tout le panneau admin (Vide maintenant)"""
        pass
    
    def _refresh_tickets(self):
        """Rafraîchit la liste des tickets"""
        if not hasattr(self, '_tickets_scroll'):
            return
            
        
        for widget in self._tickets_scroll.winfo_children():
            widget.destroy()
        
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            ctk.CTkLabel(
                self._tickets_scroll,
                text="Module d'authentification non disponible",
                text_color=THEME["text_muted"]
            ).pack(pady=20)
            return
        
        auth = get_secure_auth_manager()
        tickets = auth.get_pending_tickets()
        
        if not tickets:
            ctk.CTkLabel(
                self._tickets_scroll,
                text="Aucun ticket en attente",
                text_color=THEME["text_muted"],
                font=ctk.CTkFont(size=12)
            ).pack(pady=30)
            return
        
        for ticket in tickets:
            self._create_ticket_card(ticket)
    
    def _create_ticket_card(self, ticket: Dict):
        """Crée une carte pour un ticket"""
        card = ctk.CTkFrame(self._tickets_scroll, fg_color=THEME["bg_input"], corner_radius=8)
        card.pack(fill="x", pady=5, padx=5)
        
        # Info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(fill="x", padx=12, pady=10)
        
        ctk.CTkLabel(
            info_frame,
            text=f"👤 {ticket['username']}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            info_frame,
            text=f"📧 {ticket['email']}",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", pady=(2, 0))
        
        ctk.CTkLabel(
            info_frame,
            text=f"📅 {ticket['created_at'][:16]}",
            font=ctk.CTkFont(size=10),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", pady=(2, 0))
        
        # 
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 10))
        
        ctk.CTkButton(
            btn_frame,
            text="✓ Approuver",
            width=100,
            height=30,
            fg_color=THEME["success"],
            hover_color="#2ea043",
            font=ctk.CTkFont(size=11),
            command=lambda t=ticket: self._approve_ticket(t)
        ).pack(side="left", padx=(0, 5))
        
        ctk.CTkButton(
            btn_frame,
            text="✗ Refuser",
            width=100,
            height=30,
            fg_color=THEME["error"],
            hover_color="#da3633",
            font=ctk.CTkFont(size=11),
            command=lambda t=ticket: self._reject_ticket(t)
        ).pack(side="left")
    
    def _approve_ticket(self, ticket: Dict):
        """Approuve un ticket"""
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            return
        
        auth = get_secure_auth_manager()
        admin_id = self._current_user.get("id", "") if self._current_user else ""
        
        success, msg = auth.approve_ticket(ticket['id'], admin_id)
        
        if success:
            self._status_label.configure(text=f"✓ {msg}", text_color=THEME["success"])
        else:
            self._status_label.configure(text=f"✗ {msg}", text_color=THEME["error"])
        
        self._refresh_tickets()
    
    def _reject_ticket(self, ticket: Dict):
        """Refuse un ticket"""
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            return
        
        auth = get_secure_auth_manager()
        admin_id = self._current_user.get("id", "") if self._current_user else ""
        
        success, msg = auth.reject_ticket(ticket['id'], admin_id, "Demande refusée par l'administrateur")
        
        if success:
            self._status_label.configure(text=f"✓ {msg}", text_color=THEME["warning"])
        else:
            self._status_label.configure(text=f"✗ {msg}", text_color=THEME["error"])
        
        self._refresh_tickets()
    
    def _refresh_users(self):
        """Rafraîchit la liste des utilisateurs"""
        
        for widget in self._users_scroll.winfo_children():
            widget.destroy()
        
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            ctk.CTkLabel(
                self._users_scroll,
                text="Module d'authentification non disponible",
                text_color=THEME["text_muted"]
            ).pack(pady=20)
            return
        
        auth = get_secure_auth_manager()
        users = auth.get_all_users()
        
        if not users:
            ctk.CTkLabel(
                self._users_scroll,
                text="Aucun utilisateur",
                text_color=THEME["text_muted"]
            ).pack(pady=30)
            return
        
        for user in users:
            self._create_user_card(user)
    
    def _create_user_card(self, user: Dict):
        """Crée une carte pour un utilisateur"""
        card = ctk.CTkFrame(self._users_scroll, fg_color=THEME["bg_input"], corner_radius=8)
        card.pack(fill="x", pady=5, padx=5)
        
        
        role_color = THEME["warning"] if user['role'] == 'admin' else THEME["info"]
        status_color = THEME["success"] if user['status'] == 'active' else THEME["error"]
        
        
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(fill="x", padx=12, pady=10)
        
        
        line1 = ctk.CTkFrame(info_frame, fg_color="transparent")
        line1.pack(fill="x")
        
        ctk.CTkLabel(
            line1,
            text=f"👤 {user['username']}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(side="left")
        
        ctk.CTkLabel(
            line1,
            text=user['role'].upper(),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=role_color
        ).pack(side="right")
        
        
        line2 = ctk.CTkFrame(info_frame, fg_color="transparent")
        line2.pack(fill="x", pady=(3, 0))

    def _build_documentation_tab(self, parent):
        """Construit l'onglet Documentation."""
        
        pass
        
        

    
    def _change_user_role(self, user: Dict, new_role: str):
        """Change le rôle d'un utilisateur"""
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            return
        
        auth = get_secure_auth_manager()
        success, msg = auth.update_user(user['id'], role=new_role)
        
        if success:
            self._status_label.configure(text=f"✓ Rôle modifié: {user['username']} → {new_role}", 
                                        text_color=THEME["success"])
        else:
            self._status_label.configure(text=f"✗ {msg}", text_color=THEME["error"])
        
        self._refresh_users()
    
    def _toggle_user_status(self, user: Dict, new_status: str):
        """Active/désactive un utilisateur"""
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            return
        
        auth = get_secure_auth_manager()
        success, msg = auth.update_user(user['id'], status=new_status)
        
        if success:
            action = "activé" if new_status == 'active' else "désactivé"
            self._status_label.configure(text=f"✓ Compte {user['username']} {action}", 
                                        text_color=THEME["success"])
        else:
            self._status_label.configure(text=f"✗ {msg}", text_color=THEME["error"])
        
        self._refresh_users()
    
    def _delete_user(self, user: Dict):
        """Supprime un utilisateur"""
        if not SECURE_AUTH_AVAILABLE or not get_secure_auth_manager:
            return
        
        auth = get_secure_auth_manager()
        success, msg = auth.delete_user(user['id'])
        
        if success:
            self._status_label.configure(text=f"✓ Utilisateur {user['username']} supprimé", 
                                        text_color=THEME["warning"])
        else:
            self._status_label.configure(text=f"✗ {msg}", text_color=THEME["error"])
        
        self._refresh_users()
    
    def _on_packet_select(self, pkt):
        """Callback sélection d'un paquet"""
        self._packet_detail.show_packet(pkt)
    

    

    
    def _on_packet_received(self, data: Dict, raw_bytes: bytes = None):
        """Callback appelé par le CaptureManager quand un paquet arrive"""
        # print(f"[GUI DEBUG] Packet received: {data.get('ip_src')} -> {data.get('ip_dst')}")
       
        self.after(0, lambda: self._process_packet_ui(data, raw_bytes))

    def _on_alert_received(self, alerts):
        """Callback appelé par le CaptureManager quand une alerte survient"""
      
        alert_list = alerts if isinstance(alerts, list) else [alerts]
        for alert in alert_list:
            self.after(0, lambda a=alert: self._process_alert_ui(a))

    def _process_packet_ui(self, data: Dict, raw_bytes: bytes = None):
        """Mise à jour UI pour un nouveau paquet"""
        try:
            
            if hasattr(self, '_packet_list'):
                self._packet_list.add_packet(data, raw_bytes)
                
            
            if hasattr(self, '_topology') and self._topology:
                self._topology.add_packet(data)
                
            
            if hasattr(self, '_investigation_stats'):
                version = str(data.get('snmp_version', ''))
                if '1' in version and '0' not in version:
                    self._investigation_stats['v1'] = self._investigation_stats.get('v1', 0) + 1
                elif '2' in version:
                    self._investigation_stats['v2'] = self._investigation_stats.get('v2', 0) + 1
                elif '3' in version:
                    self._investigation_stats['v3'] = self._investigation_stats.get('v3', 0) + 1
                
                
                if hasattr(self, '_investigation_total_packets'):
                    total = sum(self._investigation_stats.values())
                    self._investigation_total_packets.configure(text=str(total))
            
            
            
            if hasattr(self, '_device_manager') and self._device_manager:
                self._device_manager.process_packet(data)
        except Exception:
            traceback.print_exc()

    def _process_alert_ui(self, alert: Dict):
        """Mise à jour UI pour une nouvelle alerte"""
        if hasattr(self, '_alert_list') and self._alert_list:
            self._alert_list.add_alert(alert)

    def start_capture(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Modules core non disponibles!", 
                                        text_color=THEME["error"])
            return
        
        if self._is_capturing:
            return
        
        
        self._interface = self._header_if_selector.get().strip() or "eth0"
        
        try:
            
            result = self._capture_mgr.start(iface=self._interface, filt=self._snmp_filter)
            
            if not result.get("success"):
                raise Exception(result.get("error"))
            
            # Enregistrement des callbacks
            self._capture_mgr.add_packet_callback(self._on_packet_received)
            self._capture_mgr.add_alert_callback(self._on_alert_received)
            
            self._is_capturing = True
            
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_indicator.configure(text="● CAPTURE (API)", text_color=THEME["success"])
            self._status_label.configure(text=f"Capture API sur {self._interface}...", 
                                        text_color=THEME["success"])
            
        except Exception as e:
            print(f"[!] Errer de démarrage r: {e}")
            traceback.print_exc()
            self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=THEME["error"])
    
    def _capture_loop(self):
        
        pass
            
    def _prepare_db_data(self, data):
        
        pass
    
    def stop_capture(self):
        self._is_capturing = False
        
        if self._capture_mgr:
            self._capture_mgr.stop()
            self._capture_mgr.remove_packet_callback(self._on_packet_received)
            self._capture_mgr.remove_alert_callback(self._on_alert_received)
            
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._capture_indicator.configure(text="● STOP", text_color=THEME["text_secondary"])
        self._status_label.configure(text="Capture arrêtée", text_color=THEME["text_secondary"])

    def clear_all(self):
        # 1. API Clear
        if self._capture_mgr:
            self._capture_mgr.clear_data()
            
        
        self._packet_list.clear()
        self._alert_list.clear() 
        
        
        self._last_pkt_count = 0
        self._last_error_count = 0
        self._pps = 0
        self._errors_per_sec = 0  
        
        if hasattr(self, '_chart_pps'):
            self._chart_pps.clear_data()
            
        if hasattr(self, '_chart_threat'):
            self._chart_threat.clear_data()
            
        if hasattr(self, '_investigation_stats'):
             self._investigation_stats = {'v1': 0, 'v2': 0, 'v3': 0}
             
        if hasattr(self, '_investigation_total_packets'):
             self._investigation_total_packets.configure(text="0")

        self._status_label.configure(text="Données effacées", text_color=THEME["text_primary"])
    
    def _update_loop(self):
        """Boucle de mise à jour UI"""
        now = datetime.now()
        self._time_label.configure(text=now.strftime("%H:%M:%S"))
        
        current_count = len(self._packet_list.packets)
        self._pps = current_count - self._last_pkt_count
        self._last_pkt_count = current_count
        
        # Stats
        stats = self._packet_list.get_stats()
        total = stats["total"]
        suspects = stats["suspects"]
        errors = stats["errors"]
        
        # Calcul erreurs/sec
        errors_this_sec = errors - self._last_error_count
        self._last_error_count = errors
        
        
        self._baseline_analyzer.add_sample(self._pps, errors_this_sec)
        
        
        baseline_alerts = self._baseline_analyzer.check_anomaly(self._pps, errors_this_sec)
        
        for alert in baseline_alerts:
            self._add_baseline_alert(alert)
        
        
        if hasattr(self, '_baseline_panel'):
            self._baseline_panel.update_display()
        
        
        
        self._stat_packets.set_value(total)
        self._stat_pps.set_value(int(self._pps))
        self._stat_suspects.set_value(suspects, THEME["error"] if suspects > 0 else THEME["warning"])
        
        # Alertes
        alert_count = 0
        if self._detector:
            alert_count = len(self._detector.alerts) if hasattr(self._detector, 'alerts') else 0
        alert_count += self._baseline_analyzer._alerts_generated
        self._stat_alerts.set_value(alert_count, THEME["error"] if alert_count > 0 else THEME["text_muted"])
        
        
        self._chart_pps.add_point("PPS", self._pps, now)
        
        
        current_alert_count = alert_count
        
        if current_alert_count > self._last_alert_count_for_decay:
            nouvelles_alertes = current_alert_count - self._last_alert_count_for_decay
            self._current_threat_level = min(100, self._current_threat_level + (nouvelles_alertes * 15))
            self._last_alert_time = time.time()
            self._last_alert_count_for_decay = current_alert_count
            
            
            if self._detector and hasattr(self._detector, 'alerts'):
                for alert in self._detector.alerts[-nouvelles_alertes:]:
                    self._add_timeline_event(
                        alert.severity,
                        f"[{alert.anomaly_type}] {alert.message[:50]}...",
                        alert.timestamp[-8:] if len(alert.timestamp) >= 8 else alert.timestamp
                    )
        else:
            
            temps_depuis_alerte = time.time() - self._last_alert_time
            if temps_depuis_alerte > 2.0:  
                decroissance = (temps_depuis_alerte - 2.0) * self._threat_decay_rate
                self._current_threat_level = max(0, self._current_threat_level - decroissance * 0.1)
        
        threat = self._current_threat_level
        self._chart_threat.add_point("Threat", threat, now)
        
        
        if now.second % 2 == 0:
            self._chart_pps.update_chart()
            self._chart_threat.update_chart()
        
        
        if hasattr(self, '_top_talkers_list') and now.second % 5 == 0:
            
            ip_counts = {}
            for p in self._packet_list.packets[-500:]:
                src = p.get('ip_src', 'Unknown')
                ip_counts[src] = ip_counts.get(src, 0) + 1
            
            
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            
            txt = "Top Talkers (last 500 pkts):\n\n"
            if not sorted_ips:
                txt += "En attente de trafic..."
            else:
                for i, (ip, count) in enumerate(sorted_ips, 1):
                    txt += f"{i}. {ip} : {count} pkts\n"
            
            try:
                self._top_talkers_list.delete("1.0", "end")
                self._top_talkers_list.insert("1.0", txt)
            except: pass
        
        
        
        if hasattr(self, '_alert_list') and now.second % 2 == 0:
            
            recent_alerts = []
            if self._detector and hasattr(self._detector, 'alerts'):
                recent_alerts.extend(self._detector.alerts[-20:])
            
            
            current_count = int(self._alert_list._count_label.cget("text"))
            if len(recent_alerts) != current_count:
                self._alert_list.clear() 
                for alert in reversed(recent_alerts): 
                    self._alert_list.add_alert(alert)

        if hasattr(self, '_alerts_list_frame') and now.second % 3 == 0:
            
            recent_alerts = []
            if self._detector and hasattr(self._detector, 'alerts'):
                recent_alerts = list(self._detector.alerts[-10:])
            
            
            if hasattr(self, '_alerts_count_label'):
                self._alerts_count_label.configure(text=f"{len(recent_alerts)} alertes")
            
            
            for widget in self._alerts_list_frame.winfo_children():
                widget.destroy()
            
            if not recent_alerts:
                ctk.CTkLabel(self._alerts_list_frame, 
                            text="Aucune alerte récente",
                            font=ctk.CTkFont(size=11),
                            text_color=THEME["text_muted"]).pack(pady=20)
            else:
                for alert in reversed(recent_alerts): 
                    alert_row = ctk.CTkFrame(self._alerts_list_frame, fg_color="transparent")
                    alert_row.pack(fill="x", pady=2)
                    
                    
                    color = THEME["error"] if alert.severity == "critical" else THEME["warning"]
                    ctk.CTkFrame(alert_row, width=4, height=20, fg_color=color, 
                                corner_radius=2).pack(side="left", padx=(0, 8))
                    
                    ctk.CTkLabel(alert_row, text=f"[{alert.anomaly_type}] {alert.message[:40]}...",
                                font=ctk.CTkFont(size=10),
                                text_color=THEME["text_primary"]).pack(side="left")
                    
                    ctk.CTkLabel(alert_row, text=alert.timestamp[-8:],
                                font=ctk.CTkFont(size=9),
                                text_color=THEME["text_muted"]).pack(side="right")

        
        if hasattr(self, '_chart_security') and now.second % 4 == 0:
            sec_stats = {"Secured (v3)": 0, "Unsecured (v1/v2)": 0}
            
            
            if self._device_manager:
                d_stats = self._device_manager.get_statistics()
                v_stats = d_stats.get("by_snmp_version", {})
                sec_stats["Secured (v3)"] += v_stats.get("v3", 0)
                sec_stats["Unsecured (v1/v2)"] += v_stats.get("v1", 0) + v_stats.get("v2c", 0)
            
            if hasattr(self, '_packet_list') and sum(sec_stats.values()) == 0:
                for p in self._packet_list.packets[-200:]:
                    ver = p.get('version', '')
                    if '3' in ver:
                        sec_stats["Secured (v3)"] += 1
                    else:
                        sec_stats["Unsecured (v1/v2)"] += 1
            
            self._chart_security.update(sec_stats, [THEME["success"], THEME["error"]])
        
        if now.second % 3 == 0 and self._detector:
            profiles = self._detector.get_all_profiles()
            
            if hasattr(self, '_ip_table') and self._ip_table:
                try:
                    self._ip_table.update_profiles(profiles)
                except:
                    pass
            
            if hasattr(self, '_top_talkers_list') and profiles:
                try:
                    sorted_ips = sorted(profiles.items(), key=lambda x: x[1].get('request_count', 0), reverse=True)[:5]
                    lines = []
                    for ip, data in sorted_ips:
                        count = data.get('request_count', 0)
                        lines.append(f"{ip:15} | {count:5} reqs")
                    
                    if lines:
                        self._top_talkers_list.configure(text="\n".join(lines))
                except:
                    pass
            
            # Update version distribution bars
            if hasattr(self, '_proto_v1'):
                try:
                    v1 = self._investigation_stats.get("v1", 0)
                    v2 = self._investigation_stats.get("v2", 0)
                    v3 = self._investigation_stats.get("v3", 0)
                    total = v1 + v2 + v3 or 1
                    
                    self._proto_v1.set(v1 / total)
                    self._proto_v2.set(v2 / total)
                    self._proto_v3.set(v3 / total)
                    
                    self._proto_v1_pct.configure(text=f"{int(v1/total*100)}%")
                    self._proto_v2_pct.configure(text=f"{int(v2/total*100)}%")
                    self._proto_v3_pct.configure(text=f"{int(v3/total*100)}%")
                except:
                    pass
        
        # Updates LISTE DES APPAREILS (Toutes les 2 sec)
        if now.second % 15 == 0:
            if hasattr(self, '_device_list') and self._device_manager:
                devices = self._device_manager.get_all_devices()
                whitelist = []
                if self._config_mgr and self._config_mgr.config:
                    whitelist = self._config_mgr.config.get("whitelist", {}).get("IPs", [])
                
                self._device_list.update_devices(devices, whitelist)
            
            # Stats détecteur
            try:
                det_stats = self._detector.get_statistics()
                if hasattr(self, '_detector_stats_label'):
                    self._detector_stats_label.configure(
                        text=f"Paquets analysés: {det_stats['total_packets_analyzed']} | "
                             f"Alertes comportement: {det_stats['total_alerts_generated']} | "
                             f"IPs bloquées: {det_stats['blocked_ips_count']}"
                    )
                
                # Stats appareils
                dev_stats = self._device_manager.get_statistics()
                # Check if _device_stats_label exists before configuring
                if hasattr(self, '_device_stats_label'):
                    self._device_stats_label.configure(
                        text=f"{dev_stats['total_devices']} appareils découverts | "
                             f"{dev_stats['active_devices']} actifs | "
                             f"{dev_stats.get('trusted', 0)} connus"
                    )
                
                # Mettre à jour les mini cards
                if hasattr(self, '_device_stats_cards'):
                    if 'total' in self._device_stats_cards:
                        self._device_stats_cards['total'].configure(text=str(dev_stats['total_devices']))
                    if 'active' in self._device_stats_cards:
                        self._device_stats_cards['active'].configure(text=str(dev_stats['active_devices']))
                    if 'managers' in self._device_stats_cards:
                        self._device_stats_cards['managers'].configure(text=str(dev_stats['managers']))
                    if 'agents' in self._device_stats_cards:
                        self._device_stats_cards['agents'].configure(text=str(dev_stats['agents']))
                    if 'trusted' in self._device_stats_cards:
                        self._device_stats_cards['trusted'].configure(text=str(dev_stats.get('trusted', 0)))
                    if 'ignored' in self._device_stats_cards:
                        self._device_stats_cards['ignored'].configure(text=str(dev_stats.get('ignored', 0)))
            except Exception as e:
                pass
        
        if now.second % 30 == 0 and hasattr(self, '_device_manager'):
            try:
                self._device_manager.save_devices()
            except:
                pass
        
        self.after(1000, self._update_loop)
    
    def _add_baseline_alert(self, alert: Dict):
        """Ajoute une alerte baseline à l'interface"""
        if not hasattr(self, '_baseline_alerts_frame'):
            return
        
        color = THEME["error"] if alert["severity"] == "critical" else THEME["warning"]
        
        card = ctk.CTkFrame(self._baseline_alerts_frame, fg_color=THEME["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=3, padx=5)
        
        indicator = ctk.CTkFrame(card, fg_color=color, width=4, corner_radius=2)
        indicator.pack(side="left", fill="y")
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", expand=True, pady=8, padx=10)
        
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text=alert["type"],
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=color).pack(side="left")
        
        ctk.CTkLabel(header, text=alert["timestamp"][-8:],
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(side="right")
        
        # Message
        ctk.CTkLabel(content, text=alert["message"],
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", pady=(3, 0))
        
        # Détails
        details = alert.get("details", {})
        if "deviation_pct" in details:
            ctk.CTkLabel(content, 
                        text=f"Déviation: +{details['deviation_pct']:.1f}% par rapport à la baseline",
                        font=ctk.CTkFont(size=10),
                        text_color=THEME["text_muted"]).pack(anchor="w")
        
        # Limiter le nombre d'alertes affichées
        children = self._baseline_alerts_frame.winfo_children()
        if len(children) > 20:
            children[0].destroy()
        
        self._add_timeline_event(alert["severity"], alert["message"], alert["timestamp"][-8:])
    
    def set_authenticated_user(self, user_data: Dict):
        """Configure l'utilisateur authentifié."""
        self._is_authenticated = True
        self._current_user = user_data
        
        username = user_data.get("username", "?")
        role = user_data.get("role", "?").upper()
        
        self._user_indicator.configure(text=username)
        self._user_role_label.configure(text=role)
        
        
        # Afficher le bouton Admin si l'utilisateur est admin
        if role == "ADMIN" and hasattr(self, '_admin_btn'):
            self._admin_btn.pack(fill="x", padx=0, pady=2)
            # Rafraîchir les tickets
            if hasattr(self, '_refresh_admin_panel'):
                self._refresh_admin_panel()
        
        # Mettre à jour le panneau profil (nouveau système)
        if SECURE_AUTH_AVAILABLE and hasattr(self, '_secure_mgmt_panel'):
            self._update_secure_profile_visibility()
        else:
            # Ancien système
            self._update_profile_visibility()

class PanneauDetailEquipement(ctk.CTkFrame):
    """Panneau de détails d'un appareil SNMP avec boutons d'action"""
    
    def __init__(self, parent, device_manager=None, on_action=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._device_manager = device_manager
        self._on_action = on_action  
        self._current_device = None
        self._build()
    
    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(12, 8))
        
        ctk.CTkLabel(header, text="📋 Détails de l'appareil",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        
        self._btn_trust = ctk.CTkButton(btn_frame, text="⭐ Confiance",
                                       width=90, height=28,
                                       font=ctk.CTkFont(size=11),
                                       fg_color=THEME["success"],
                                       hover_color="#2ea043",
                                       command=self._toggle_trusted)
        self._btn_trust.pack(side="left", padx=3)
        
        self._btn_ignore = ctk.CTkButton(btn_frame, text="🚫 Ignorer",
                                        width=80, height=28,
                                        font=ctk.CTkFont(size=11),
                                        fg_color=THEME["bg_panel"],
                                        hover_color=THEME["error"],
                                        command=self._toggle_ignored)
        self._btn_ignore.pack(side="left", padx=3)
        
        self._btn_block = ctk.CTkButton(btn_frame, text="⛔ Bloquer",
                                        width=80, height=28,
                                        font=ctk.CTkFont(size=11),
                                        fg_color=THEME["error"],
                                        hover_color="#b91c1c",
                                        command=self._toggle_blocked)
        self._btn_block.pack(side="left", padx=3)
        
        ctk.CTkButton(btn_frame, text="📋",
                     width=32, height=28,
                     font=ctk.CTkFont(size=12),
                     fg_color=THEME["bg_panel"],
                     hover_color=THEME["accent"],
                     command=self._copy_ip).pack(side="left", padx=3)
        
        # Zone de texte
        self._text = ctk.CTkTextbox(self, fg_color=THEME["bg_panel"],
                                   font=ctk.CTkFont(family="Courier", size=12),
                                   text_color=THEME["text_primary"])
        self._text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text.insert("1.0", "Sélectionnez un appareil pour voir les détails...")
        self._text.configure(state="disabled")
    
    def show_device(self, device: Dict):
        """Affiche les détails d'un appareil"""
        self._current_device = device
        
        self._update_buttons()
        
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        
        roles = []
        if device.get("is_manager"):
            roles.append("Manager (envoie des requêtes)")
        if device.get("is_agent"):
            roles.append("Agent (répond aux requêtes)")
        role_str = " & ".join(roles) if roles else "Non déterminé"
        
        versions = device.get("snmp_versions", [])
        versions_str = ", ".join(versions) if versions else "Non détecté"
        
        communities = device.get("communities", [])
        communities_str = ", ".join(communities) if communities else "N/A"
        
        usm_users = device.get("usm_users", [])
        usm_str = ", ".join(usm_users) if usm_users else "N/A"
        
        ports = device.get("ports", [])
        ports_str = ", ".join(str(p) for p in sorted(ports)) if ports else "N/A"
        
        is_trusted = device.get("is_trusted", False)
        is_ignored = device.get("is_ignored", False)
        is_blocked = device.get("is_blocked", False)
        if is_blocked:
            status_display = "⛔ BLOQUÉ"
        elif is_trusted:
            status_display = "⭐ CONFIANCE"
        elif is_ignored:
            status_display = "🚫 IGNORÉ"
        else:
            status_display = device.get('status', 'N/A').upper()
        
        # Nom personnalisé
        custom_name = device.get("custom_name")
        name_display = f"{custom_name} (personnalisé)" if custom_name else device.get('hostname', 'Inconnu')
        
        text = f"""
═══════════════════════════════════════════════════════════════
  APPAREIL SNMP  {status_display}
═══════════════════════════════════════════════════════════════

  ▸ IDENTIFICATION
  ─────────────────────────────────────────────────────────────
    Adresse IP:      {device.get('ip', 'N/A')}
    Adresse MAC:     {device.get('mac', 'N/A')}
    Hostname:        {name_display}
    Vendor:          {device.get('vendor', 'Inconnu')}
    Type:            {device.get('device_type', 'unknown').replace('_', ' ').title()}

  ▸ INFORMATIONS SYSTÈME (MIB-2)
  ─────────────────────────────────────────────────────────────
    sysName:         {device.get('sys_name', 'N/A')}
    sysDescr:        {(device.get('sys_descr') or 'N/A')[:60]}
    sysLocation:     {device.get('sys_location', 'N/A')}

  ▸ SNMP
  ─────────────────────────────────────────────────────────────
    Versions:        {versions_str}
    Communities:     {communities_str}
    USM Users (v3):  {usm_str}
    Ports utilisés:  {ports_str}
    Rôle:            {role_str}

  ▸ STATISTIQUES
  ─────────────────────────────────────────────────────────────
    Total paquets:   {device.get('packet_count', 0)}
    Requêtes:        {device.get('request_count', 0)}
    Réponses:        {device.get('response_count', 0)}
    Traps:           {device.get('trap_count', 0)}
    Erreurs:         {device.get('error_count', 0)}
    OIDs accédés:    {device.get('oids_count', 0)}

  ▸ ACTIVITÉ
  ─────────────────────────────────────────────────────────────
    Première vue:    {device.get('first_seen', 'N/A')}
    Dernière vue:    {device.get('last_seen', 'N/A')}

═══════════════════════════════════════════════════════════════

  
"""
        
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")
    
    def _update_buttons(self):
        """Met à jour l'apparence des boutons selon l'état"""
        if not self._current_device:
            return
        
        is_trusted = self._current_device.get("is_trusted", False)
        is_ignored = self._current_device.get("is_ignored", False)
        is_blocked = self._current_device.get("is_blocked", False)
        
        if is_trusted:
            self._btn_trust.configure(text="⭐ Retiré", fg_color=THEME["warning"])
        else:
            self._btn_trust.configure(text="⭐ Confiance", fg_color=THEME["success"])
        
        if is_ignored:
            self._btn_ignore.configure(text="👁️ Afficher", fg_color=THEME["accent"])
        else:
            self._btn_ignore.configure(text="🚫 Ignorer", fg_color=THEME["bg_panel"])
            
        if is_blocked:
            self._btn_block.configure(text="🟢 Débloquer", fg_color=THEME["success"])
        else:
            self._btn_block.configure(text="⛔ Bloquer", fg_color=THEME["error"])
    
    def _toggle_trusted(self):
        """Toggle l'état trusted"""
        if self._current_device and self._device_manager:
            ip = self._current_device.get("ip")
            current = self._current_device.get("is_trusted", False)
            self._device_manager.set_trusted(ip, not current)
            self._current_device["is_trusted"] = not current
            self._current_device["is_ignored"] = False
            self._update_buttons()
            self.show_device(self._current_device)
            if self._on_action:
                self._on_action()
    
    def _toggle_ignored(self):
        """Toggle l'état ignored"""
        if self._current_device and self._device_manager:
            ip = self._current_device.get("ip")
            current = self._current_device.get("is_ignored", False)
            self._device_manager.set_ignored(ip, not current)
            self._current_device["is_ignored"] = not current
            self._current_device["is_trusted"] = False
            self._update_buttons()
            self.show_device(self._current_device)
            if self._on_action:
                self._on_action()
    
    def _toggle_blocked(self):
        """Toggle l'état blocked"""
        if self._current_device and self._device_manager:
            ip = self._current_device.get("ip")
            current = self._current_device.get("is_blocked", False)
            self._device_manager.set_blocked(ip, not current)
            self._current_device["is_blocked"] = not current
            if not current:
                self._current_device["is_trusted"] = False
                self._current_device["is_ignored"] = False
            self._update_buttons()
            self.show_device(self._current_device)
            if self._on_action:
                self._on_action()

    def _copy_ip(self):
        """Copie l'IP dans le presse-papiers"""
        if self._current_device:
            ip = self._current_device.get("ip", "")
            self.clipboard_clear()
            self.clipboard_append(ip)



class DialogueUtilisateursSNMP(ctk.CTkToplevel):
    """Dialogue de gestion des utilisateurs SNMPv3"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Gestion des Utilisateurs SNMPv3")
        self.geometry("700x500")
        self.configure(fg_color=THEME["bg_main"])
        
        # Centre la fenetre
        self.transient(parent)
        self.after(100, lambda: self._safe_grab())
        
        self._build_ui()
        self._load_users()

    def _safe_grab(self):
        try:
            self.wait_visibility()
            self.grab_set()
        except:
            pass
        
    def _build_ui(self):
        # Header pour le titre
        header = ctk.CTkFrame(self, height=60, fg_color=THEME["bg_panel"])
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text="🔐 Utilisateurs SNMPv3 (USM)", 
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left", padx=20, pady=15)
        
        
        list_container = ctk.CTkFrame(self, fg_color=THEME["bg_card"])
        list_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Liste scrollable
        self.scroll_list = ctk.CTkScrollableFrame(list_container, fg_color="transparent")
        self.scroll_list.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Actions
        actions = ctk.CTkFrame(self, height=60, fg_color=THEME["bg_panel"])
        actions.pack(fill="x", side="bottom")
        
        ctk.CTkButton(actions, text="➕ Ajouter un utilisateur", 
                     command=self._add_user_dialog, 
                     fg_color=THEME["success"], hover_color="#2ea043").pack(side="right", padx=20, pady=15)
        
        ctk.CTkButton(actions, text="Fermer", 
                     command=self.destroy,
                     fg_color=THEME["border"], hover_color=THEME["border_light"]).pack(side="right", padx=10)

    def _load_users(self):
        # Clear de la liste
        for widget in self.scroll_list.winfo_children():
            widget.destroy()
            
        users = snmp_cred_mgr.get_all_users()
        
        if not users:
            ctk.CTkLabel(self.scroll_list, text="Aucun utilisateur configuré", 
                        text_color=THEME["text_muted"]).pack(pady=20)
            return

        # Headers
        headers = ctk.CTkFrame(self.scroll_list, fg_color=THEME["bg_input"], height=35)
        headers.pack(fill="x", pady=(0, 5))
        
        ctk.CTkLabel(headers, text="Utilisateur", width=120, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=10)
        ctk.CTkLabel(headers, text="Auth", width=80, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        ctk.CTkLabel(headers, text="Priv", width=80, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        
        for user in users:
            row = ctk.CTkFrame(self.scroll_list, fg_color=THEME["bg_panel"])
            row.pack(fill="x", pady=2)
            
            ctk.CTkLabel(row, text=user["username"], width=120, anchor="w", text_color=THEME["accent"]).pack(side="left", padx=10)
            ctk.CTkLabel(row, text=user["auth_proto"], width=80, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=user["priv_proto"], width=80, anchor="w").pack(side="left")
            
            # Bouton supprimer
            ctk.CTkButton(row, text="🗑", width=30, fg_color="transparent", text_color=THEME["error"],
                         hover_color=THEME["bg_input"],
                         command=lambda u=user["username"]: self._delete_user(u)).pack(side="right", padx=10)
            
            # Bouton modifier
            ctk.CTkButton(row, text="✏", width=30, fg_color="transparent", text_color=THEME["info"],
                         hover_color=THEME["bg_input"],
                         command=lambda u=user: self._edit_user(u)).pack(side="right", padx=0)

    def _delete_user(self, username):
        if messagebox.askyesno("Confirmation", f"Supprimer l'utilisateur {username} ?"):
            snmp_cred_mgr.delete_user(username)
            self._load_users()

    def _edit_user(self, user):
        self._add_user_dialog(user)

    def _add_user_dialog(self, edit_user=None):
        dialog = ctk.CTkToplevel(self)
        title = "Modifier Utilisateur" if edit_user else "Nouvel Utilisateur"
        dialog.title(title)
        dialog.geometry("400x550")
        dialog.transient(self)
        
        def safe_grab():
            try:
                dialog.wait_visibility()
                dialog.grab_set()
            except:
                pass
        
        dialog.after(100, safe_grab)
        
        # Formulaire ajout/modification
        ctk.CTkLabel(dialog, text=title, font=ctk.CTkFont(size=16, weight="bold")).pack(pady=20)
        
        # Username  (SecurityName)
        ctk.CTkLabel(dialog, text="Nom d'utilisateur (SecurityName)").pack(anchor="w", padx=20)
        entry_user = ctk.CTkEntry(dialog)
        entry_user.pack(fill="x", padx=20, pady=(0, 10))
        if edit_user:
            entry_user.insert(0, edit_user["username"])
            entry_user.configure(state="disabled") 
        
        # Auth Protocol (SHA, MD5, Aucun)
        ctk.CTkLabel(dialog, text="Protocole Authentification").pack(anchor="w", padx=20)
        combo_auth = ctk.CTkComboBox(dialog, values=["SHA", "MD5", "Aucun"])
        combo_auth.pack(fill="x", padx=20, pady=(0, 10))
        if edit_user: combo_auth.set(edit_user["auth_proto"])
        
        # Auth Key (Password)
        ctk.CTkLabel(dialog, text="Clé d'Authentification (Password)").pack(anchor="w", padx=20)
        entry_auth_key = ctk.CTkEntry(dialog, show="*")
        entry_auth_key.pack(fill="x", padx=20, pady=(0, 10))
        if edit_user and edit_user["auth_key"]: entry_auth_key.insert(0, edit_user["auth_key"])
        
        # Priv Protocol (AES, DES, Aucun)
        ctk.CTkLabel(dialog, text="Protocole Chiffrement (Privacy)").pack(anchor="w", padx=20)
        combo_priv = ctk.CTkComboBox(dialog, values=["AES", "DES", "Aucun"])
        combo_priv.pack(fill="x", padx=20, pady=(0, 10))
        if edit_user: combo_priv.set(edit_user["priv_proto"])
        
        # Priv Key (Privacy Key)
        ctk.CTkLabel(dialog, text="Clé de Chiffrement (Privacy Key)").pack(anchor="w", padx=20)
        entry_priv_key = ctk.CTkEntry(dialog, show="*")
        entry_priv_key.pack(fill="x", padx=20, pady=(0, 20))
        if edit_user and edit_user["priv_key"]: entry_priv_key.insert(0, edit_user["priv_key"])
        
        def save():
            user = entry_user.get().strip()
            if not user: return
            
            auth_p = combo_auth.get()
            auth_k = entry_auth_key.get()
            priv_p = combo_priv.get()
            priv_k = entry_priv_key.get()
            
            
            if auth_p != "Aucun" and not auth_k:
                messagebox.showerror("Erreur", "Clé d'authentification requise")
                return
            if priv_p != "Aucun" and not priv_k:
                messagebox.showerror("Erreur", "Clé de chiffrement requise")
                return

            snmp_cred_mgr.add_user(user, auth_p, auth_k, priv_p, priv_k)
            self._load_users()
            dialog.destroy()
        
        ctk.CTkButton(dialog, text="Enregistrer", command=save, fg_color=THEME["success"]).pack(pady=20)

def run_with_auth():
    """Lance l'application avec authentification obligatoire."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    
    
    user_data_result = [None]
    app_closed_by_logout = [False]
    
    def show_login():
        """Affiche la fenêtre de login et retourne True si succès."""
        login_root = ctk.CTk()
        login_root.title("MiBombo - Connexion")
        login_root.geometry("400x520")
        login_root.resizable(False, False)
        login_root.configure(fg_color=THEME["bg_main"])
        
        # Centrer la fenêtre
        login_root.update_idletasks()
        x = (login_root.winfo_screenwidth() - 400) // 2
        y = (login_root.winfo_screenheight() - 520) // 2
        login_root.geometry(f"400x520+{x}+{y}")
        
        auth = get_auth_manager()
        login_success = [False]
        
        # Interface de login pour les users
        # Logo
        ctk.CTkLabel(login_root, text="MiBombo",
                    font=ctk.CTkFont(size=28, weight="bold"),
                    text_color=THEME["accent"]).pack(pady=(40, 5))
        
        ctk.CTkLabel(login_root, text="Pro",
                    font=ctk.CTkFont(size=14),
                    text_color=THEME["text_secondary"]).pack()
        
        ctk.CTkLabel(login_root, text="Connexion requise",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(pady=(10, 25))
        
        # Formulaire de connexion
        form_frame = ctk.CTkFrame(login_root, fg_color=THEME["bg_card"], corner_radius=12)
        form_frame.pack(padx=40, fill="x")
        
        ctk.CTkLabel(form_frame, text="Identifiant",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        username_entry = ctk.CTkEntry(form_frame, height=38, fg_color=THEME["bg_input"])
        username_entry.pack(fill="x", padx=20)
        
        ctk.CTkLabel(form_frame, text="Mot de passe",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        password_entry = ctk.CTkEntry(form_frame, height=38, show="*", fg_color=THEME["bg_input"])
        password_entry.pack(fill="x", padx=20)
        
        error_label = ctk.CTkLabel(form_frame, text="",
                                  font=ctk.CTkFont(size=11),
                                  text_color=THEME["error"])
        error_label.pack(pady=8)
        
        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get()
            
            if not username or not password:
                error_label.configure(text="Remplissez tous les champs")
                return
            
            success, msg, user = auth.login(username, password)
            
            if success:
                login_success[0] = True
                user_data_result[0] = user
                login_root.quit()
                login_root.destroy()
            else:
                error_label.configure(text=msg)
                password_entry.delete(0, "end")
        
        login_btn = ctk.CTkButton(form_frame, text="Se connecter",
                                 command=do_login,
                                 height=40,
                                 fg_color=THEME["accent"],
                                 font=ctk.CTkFont(size=13, weight="bold"))
        login_btn.pack(fill="x", padx=20, pady=(5, 20))
        
        # Bind Enter qui veut dire que quand on appuie sur la touche Enter, on appelle la fonction do_login
        login_root.bind("<Return>", lambda e: do_login())
        
        # Lien mot de passe oublié pour changer le mdp plus implémenter
        def show_password_request():
            """Affiche le formulaire de demande de réinitialisation."""
            # Créer une nouvelle fenêtre
            request_window = ctk.CTkToplevel(login_root)
            request_window.title("Demande de reinitialisation")
            request_window.geometry("420x380")
            request_window.minsize(420, 380)
            request_window.configure(fg_color=THEME["bg_main"])
            
            # Centrer
            request_window.update_idletasks()
            rx = (request_window.winfo_screenwidth() - 420) // 2
            ry = (request_window.winfo_screenheight() - 380) // 2
            request_window.geometry(f"420x380+{rx}+{ry}")
            
            request_window.transient(login_root)
            request_window.grab_set()
            
            # Contenu principal de la fenetre de demande de reinitialisation
            main_frame = ctk.CTkFrame(request_window, fg_color="transparent")
            main_frame.pack(fill="both", expand=True, padx=25, pady=20)
            
            ctk.CTkLabel(main_frame, text="Mot de passe oublie",
                        font=ctk.CTkFont(size=18, weight="bold"),
                        text_color=THEME["text_primary"]).pack(pady=(0, 5))
            
            ctk.CTkLabel(main_frame, text="Envoyez une demande a l'administrateur",
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_muted"]).pack(pady=(0, 15))
            
            # Formulaire de demande de reinitialisation
            ctk.CTkLabel(main_frame, text="Votre identifiant",
                        font=ctk.CTkFont(size=12),
                        text_color=THEME["text_secondary"]).pack(anchor="w")
            
            req_username = ctk.CTkEntry(main_frame, height=38, fg_color=THEME["bg_input"],
                                       font=ctk.CTkFont(size=12))
            req_username.pack(fill="x", pady=(3, 12))
            
       
            current_username = username_entry.get().strip()
            if current_username:
                req_username.insert(0, current_username)
            
            ctk.CTkLabel(main_frame, text="Raison (optionnel)",
                        font=ctk.CTkFont(size=12),
                        text_color=THEME["text_secondary"]).pack(anchor="w")
            
            req_reason = ctk.CTkTextbox(main_frame, height=70, fg_color=THEME["bg_input"],
                                       font=ctk.CTkFont(size=11))
            req_reason.pack(fill="x", pady=(3, 10))
            
            status_label = ctk.CTkLabel(main_frame, text="",
                                       font=ctk.CTkFont(size=11))
            status_label.pack(pady=5)
            
            def submit_request():
                uname = req_username.get().strip()
                reason = req_reason.get("1.0", "end").strip()
                
                if not uname:
                    status_label.configure(text="Identifiant requis", text_color=THEME["error"])
                    return
                
                # Créer le ticket pas encore 100 pourcent au point 
                success, msg, ticket_id = auth.create_ticket(
                    username=uname,
                    ticket_type="password_reset",
                    subject=f"Demande de reinitialisation de mot de passe",
                    message=reason if reason else "Aucune raison specifiee"
                )
                
                if success:
                    status_label.configure(
                        text=f"Demande envoyee (Ticket #{ticket_id})",
                        text_color=THEME["success"]
                    )
                    request_window.after(2000, request_window.destroy)
                else:
                    status_label.configure(text=msg, text_color=THEME["error"])
            
            # Boutons
            btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
            btn_frame.pack(fill="x", pady=(5, 0))
            
            ctk.CTkButton(btn_frame, text="Annuler", width=100, height=36,
                         fg_color=THEME["bg_input"],
                         font=ctk.CTkFont(size=12),
                         command=request_window.destroy).pack(side="left")
            
            ctk.CTkButton(btn_frame, text="Envoyer", width=100, height=36,
                         fg_color=THEME["success"],
                         font=ctk.CTkFont(size=12),
                         command=submit_request).pack(side="right")
        
        # Bouton mot de passe oublié pareil
        forgot_btn = ctk.CTkButton(login_root, text="Mot de passe oublie ?",
                                  command=show_password_request,
                                  fg_color="transparent",
                                  hover_color=THEME["bg_hover"],
                                  text_color=THEME["info"],
                                  font=ctk.CTkFont(size=11),
                                  height=30)
        forgot_btn.pack(pady=(10, 5))
        
        # Informations sur les identifiants par defaut
        ctk.CTkLabel(login_root, text="Identifiants par defaut: admin / admin",
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(pady=10)
        
        # Focus sur le champ username_entry
        username_entry.focus()
        

        def on_close():
            login_root.quit()
            login_root.destroy()
        
        login_root.protocol("WM_DELETE_WINDOW", on_close)
        
        login_root.mainloop()
        
        return login_success[0]
    
    # Boucle principale de l'application
    while True:
        if not show_login():
            break
        
        if user_data_result[0] is None:
            break
        
        try:
            app = ApplicationMiBombo()
            app.set_authenticated_user(user_data_result[0])
            app.mainloop()
            
            if hasattr(app, '_is_authenticated') and not app._is_authenticated:
                user_data_result[0] = None
                continue
            else:
                break
        except Exception as e:
            print(f"Erreur application: {e}")
            import traceback
            traceback.print_exc()
            break


def main():
    """Point d'entrée principal - authentification obligatoire."""
    print("[*] Demarrage MiBombo")
    print(f"[*] SECURE_AUTH_AVAILABLE = {SECURE_AUTH_AVAILABLE}")
    print(f"[*] get_auth_manager = {get_auth_manager is not None}")
    
    # Utiliser le nouveau système d'auth sécurisé si disponible
    if SECURE_AUTH_AVAILABLE and run_secure_login is not None:
        print("[+] Authentification sécurisée")
        
        user_data = [None]
        
        def on_login_success(user):
            user_data[0] = user
        
        while True:
            user = run_secure_login(on_success=on_login_success)
            
            if not user:
                print("[*] Connexion annulée")
                break
            
            try:
                print(f"[+] Utilisateur {user} maintenant connecté")
                app = ApplicationMiBombo()
                
                # Adapter les données utilisateur
                adapted_user = {
                    "id": user.get("id"),
                    "username": user.get("username", "user"),
                    "email": user.get("email", ""),
                    "full_name": user.get("username", "Utilisateur"),
                    "role": user.get("role", "user"),
                    "permissions": user.get("permissions", []),
                }
                
                print(f"[+] Launch du software avec l'user': {adapted_user['username']}")
                app.set_authenticated_user(adapted_user)
                app.mainloop()
                
                if hasattr(app, '_is_authenticated') and not app._is_authenticated:
                    user_data[0] = None
                    continue
                else:
                    break
            except Exception as e:
                print(f"[!] Software erreur : {e}")
                import traceback
                traceback.print_exc()
                break
    
    # Fallback vers l'ancien système afinb de debug le nouveau système sécurisé 
    elif get_auth_manager:
        print("[!] UUtilisaation de l'ancien auth pour debug")
        print("[!] Créer compter indispo")
        try:
            run_with_auth()
        except Exception as e:
            print(f"[!] Erreur: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("=" * 50)
        print("  ERREUR: Module d'authentification requis")
        print("=" * 50)
        print("\nEst ce quee ces fichhiers existent ?:")
        print("  - core/secure_auth.py (nouveau)")
        print("  - gui/secure_auth_widgets.py (nouveau)")
        print("  - OU core/auth.py (ancien)")
        print("  - OU gui/auth_widgets.py (ancien)")


if __name__ == "__main__":
    main()


