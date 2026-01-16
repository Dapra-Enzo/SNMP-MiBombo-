#!/usr/bin/env python3
"""
MiBombo Suite - Network Topology v4 (Optimisée)
=================================================
Version optimisée pour gérer beaucoup de noeuds sans crash.
- Throttling du redraw
- Limite de noeuds affichés
- Batch updates
- Pas de redraw pendant le drag
"""

import math
from typing import Optional, Dict, List, Tuple
from datetime import datetime
from collections import defaultdict
import time

try:
    import customtkinter as ctk
    import tkinter as tk
except ImportError:
    print("[!] CustomTkinter not available")

# Thème
THEME = {
    "bg_dark": "#0d1117",
    "bg_panel": "#161b22",
    "bg_card": "#21262d",
    "bg_node": "#30363d",
    "border": "#30363d",
    "text": "#e6edf3",
    "text_dim": "#8b949e",
    "text_muted": "#484f58",
    "accent": "#58a6ff",
    "success": "#3fb950",
    "warning": "#d29922",
    "error": "#f85149",
}

# Configuration
MAX_NODES_DISPLAY = 100  # Limite d'affichage pour éviter les lags
REDRAW_COOLDOWN = 0.5    # Minimum 500ms entre les redraws
UPDATE_INTERVAL = 3000   # Stats update toutes les 3s


class NetworkTopology:
    """
    Gestionnaire central de la topologie réseau (Version optimisée).
    
    Utilité :
    - Maintenir l'état du graphe réseau (noeuds et liens) en mémoire.
    - Gérer les statistiques de trafic par noeud (paquets, volume).
    - Calculer le layout (disposition spatiale) des noeuds pour l'affichage.
    - Limiter le nombre de noeuds actifs pour éviter les surcharges.

    Fonctions associées :
    - add_packet(packet) : Traite un packet pour mettre à jour ou créer des noeuds/liens.
    - calculate_layout(w, h) : Algorithme (Spring/Force-directed) pour positionner les noeuds.
    - get_top_nodes(limit) : Récupère les X noeuds les plus actifs pour l'affichage.
    - clear() : Réinitialise complètement la topologie.
    """
    
    def __init__(self):
        self.nodes: Dict[str, dict] = {}
        self.links: Dict[str, dict] = {}
        self.total_packets = 0
        self._layout_done = False
        self._dirty = False  # Flag pour savoir si on doit recalculer
    
    def add_packet(self, packet: dict):
        """Ajoute un paquet (optimisé)"""
        try:
            src = packet.get("ip_src", "")
            dst = packet.get("ip_dst", "")
            if not src or not dst:
                return
            
            self.total_packets += 1
            
            # Créer les noeuds seulement s'ils n'existent pas
            for ip, is_src in [(src, True), (dst, False)]:
                if ip not in self.nodes:
                    self.nodes[ip] = {
                        "ip": ip,
                        "type": self._guess_type(ip),
                        "x": 0, "y": 0,
                        "pkts_in": 0, "pkts_out": 0,
                        "suspect": False,
                        "communities": set(),
                        "first_seen": datetime.now(),
                        "last_seen": datetime.now(),
                    }
                    self._dirty = True
                    self._layout_done = False
                
                n = self.nodes[ip]
                n["last_seen"] = datetime.now()
                n["pkts_out" if is_src else "pkts_in"] += 1
                
                if packet.get("snmp_community"):
                    n["communities"].add(packet["snmp_community"])
                if packet.get("authorized") == False:
                    n["suspect"] = True
            
            # Lien
            key = f"{src}|{dst}"
            if key not in self.links:
                self.links[key] = {"src": src, "dst": dst, "pkts": 0}
                self._dirty = True
            self.links[key]["pkts"] += 1
            
        except Exception:
            pass
    
    def _guess_type(self, ip: str) -> str:
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                last = int(parts[3])
                if last == 1:
                    return "router"
                elif last == 254:
                    return "gateway"
        except:
            pass
        return "host"
    
    def calculate_layout(self, width: int, height: int):
        """Layout simple et rapide"""
        if not self.nodes or self._layout_done:
            return
        
        # Trier les IPs pour avoir un ordre cohérent
        ips = sorted(self.nodes.keys(), 
                    key=lambda x: [int(p) if p.isdigit() else 0 for p in x.split(".")])
        
        # Séparer gateways/routers des autres
        gateways = [ip for ip in ips if self.nodes[ip]["type"] in ("router", "gateway")]
        others = [ip for ip in ips if self.nodes[ip]["type"] not in ("router", "gateway")]
        
        margin = 100
        usable_w = width - margin * 2
        usable_h = height - margin * 2
        
        # Positionner les gateways en haut
        if gateways:
            spacing = usable_w // (len(gateways) + 1)
            for i, ip in enumerate(gateways):
                self.nodes[ip]["x"] = margin + spacing * (i + 1)
                self.nodes[ip]["y"] = margin + 50
        
        # Positionner les autres en grille
        if others:
            # Limiter pour éviter les problèmes
            display_others = others[:MAX_NODES_DISPLAY]
            
            cols = max(1, int(math.sqrt(len(display_others) * 1.5)))
            rows = (len(display_others) + cols - 1) // cols
            
            cell_w = usable_w // max(1, cols)
            cell_h = (usable_h - 150) // max(1, rows)
            
            start_y = margin + 150
            
            for i, ip in enumerate(display_others):
                col = i % cols
                row = i // cols
                self.nodes[ip]["x"] = margin + col * cell_w + cell_w // 2
                self.nodes[ip]["y"] = start_y + row * cell_h
        
        self._layout_done = True
        self._dirty = False
    
    def get_stats(self) -> dict:
        types = defaultdict(int)
        for n in self.nodes.values():
            types[n["type"]] += 1
        
        return {
            "nodes": len(self.nodes),
            "links": len(self.links),
            "packets": self.total_packets,
            "types": dict(types),
        }
    
    def clear(self):
        self.nodes.clear()
        self.links.clear()
        self.total_packets = 0
        self._layout_done = False
        self._dirty = True
    
    def get_top_nodes(self, limit: int = MAX_NODES_DISPLAY) -> List[str]:
        """Retourne les noeuds les plus actifs"""
        sorted_nodes = sorted(
            self.nodes.keys(),
            key=lambda ip: self.nodes[ip]["pkts_in"] + self.nodes[ip]["pkts_out"],
            reverse=True
        )
        return sorted_nodes[:limit]


# Singleton
_topo = None
def get_topology() -> NetworkTopology:
    global _topo
    if _topo is None:
        _topo = NetworkTopology()
    return _topo


class TopologyCanvas(tk.Canvas):
    """
    Zone de dessin interactive (Tkinter Canvas) pour la visualisation du réseau.
    
    Utilité :
    - Dessiner graphiquement les noeuds (icônes) et les liens (lignes).
    - Gérer les interactions utilisateur (Zoom, Pan, Sélection, Drag & Drop).
    - Optimiser le rendu via throttling (limitation du taux de rafraîchissement).

    Fonctions associées :
    - redraw() : Déclenche le redessin complet du graphe (optimisé).
    - _draw_nodes() : Affiche les icônes et labels des équipements.
    - _draw_links() : Trace les connexions entre les équipements.
    - fit/center() : Ajuste la vue pour englober tout le réseau.
    """
    
    ICONS = {
        "router":  ("R", "#3b82f6", "Routeur"),
        "gateway": ("G", "#8b5cf6", "Gateway"),
        "switch":  ("S", "#10b981", "Switch"),
        "server":  ("H", "#f59e0b", "Serveur"),
        "host":    ("PC", "#6b7280", "Hôte"),
    }
    
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=THEME["bg_dark"], highlightthickness=0, **kw)
        
        self.topo = get_topology()
        
        # Vue
        self._scale = 1.0
        self._pan_x = 0
        self._pan_y = 0
        self._dragging = False
        self._drag_start = None
        
        # Sélection
        self._selected = None
        self._on_select = None
        
        # Throttling
        self._last_redraw = 0
        self._redraw_scheduled = False
        
        # Bindings
        self.bind("<MouseWheel>", self._wheel)
        self.bind("<Button-4>", self._wheel)
        self.bind("<Button-5>", self._wheel)
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._drag)
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Configure>", self._on_resize)
    
    def set_callback(self, cb):
        self._on_select = cb
    
    def _on_resize(self, event):
        """Redraw après resize avec délai"""
        self._schedule_redraw()
    
    def _schedule_redraw(self):
        """Planifie un redraw avec throttling"""
        if self._redraw_scheduled:
            return
        
        now = time.time()
        elapsed = now - self._last_redraw
        
        if elapsed >= REDRAW_COOLDOWN:
            self._do_redraw()
        else:
            self._redraw_scheduled = True
            delay = int((REDRAW_COOLDOWN - elapsed) * 1000)
            self.after(delay, self._do_redraw)
    
    def _do_redraw(self):
        """Effectue le redraw"""
        self._redraw_scheduled = False
        self._last_redraw = time.time()
        
        try:
            self.delete("all")
            
            w = self.winfo_width() or 800
            h = self.winfo_height() or 600
            
            self._draw_grid(w, h)
            
            if not self.topo.nodes:
                self._draw_empty(w, h)
                return
            
            if not self.topo._layout_done:
                self.topo.calculate_layout(w, h)
            
            # Dessiner seulement les top noeuds
            top_nodes = self.topo.get_top_nodes(MAX_NODES_DISPLAY)
            
            self._draw_links(top_nodes)
            self._draw_nodes(top_nodes)
            self._draw_legend(len(self.topo.nodes), len(top_nodes))
            
        except Exception as e:
            print(f"[!] Redraw error: {e}")
    
    def redraw(self):
        """Public method - avec throttling"""
        self._schedule_redraw()
    
    def _draw_grid(self, w: int, h: int):
        step = 50
        color = "#161b22"
        for x in range(0, w + step, step):
            self.create_line(x, 0, x, h, fill=color)
        for y in range(0, h + step, step):
            self.create_line(0, y, w, y, fill=color)
    
    def _draw_empty(self, w: int, h: int):
        self.create_text(w//2, h//2 - 20, text="Topology Map",
                        font=("Segoe UI", 24, "bold"), fill="#30363d")
        self.create_text(w//2, h//2 + 20, text="Démarrez une capture SNMP",
                        font=("Segoe UI", 12), fill="#484f58")
    
    def _tx(self, x: float, y: float) -> Tuple[float, float]:
        return (x * self._scale + self._pan_x, y * self._scale + self._pan_y)
    
    def _draw_links(self, nodes_to_draw: List[str]):
        """Dessine les liens (seulement entre noeuds affichés)"""
        nodes_set = set(nodes_to_draw)
        
        for link in self.topo.links.values():
            if link["src"] not in nodes_set or link["dst"] not in nodes_set:
                continue
            
            src = self.topo.nodes.get(link["src"])
            dst = self.topo.nodes.get(link["dst"])
            if not src or not dst:
                continue
            
            x1, y1 = self._tx(src["x"], src["y"])
            x2, y2 = self._tx(dst["x"], dst["y"])
            
            pkts = link["pkts"]
            width = 1 + min(3, pkts // 200)
            color = "#388bfd" if pkts > 100 else "#1f6feb"
            
            self.create_line(x1, y1, x2, y2, fill=color, width=width)
    
    def _draw_nodes(self, nodes_to_draw: List[str]):
        """Dessine les noeuds"""
        size = int(40 * self._scale)
        half = size // 2
        
        for ip in nodes_to_draw:
            node = self.topo.nodes.get(ip)
            if not node:
                continue
            
            x, y = self._tx(node["x"], node["y"])
            
            icon_info = self.ICONS.get(node["type"], self.ICONS["host"])
            letter, color, _ = icon_info
            
            if node["suspect"]:
                color = THEME["error"]
            
            # Outline si sélectionné
            outline = "#ffffff" if ip == self._selected else THEME["border"]
            outline_w = 2 if ip == self._selected else 1
            
            # Box simple
            self.create_rectangle(
                x - half, y - half,
                x + half, y + half + 15,
                fill=THEME["bg_node"], outline=outline, width=outline_w
            )
            
            # Barre de couleur
            self.create_rectangle(
                x - half, y - half,
                x + half, y - half + 3,
                fill=color, outline=""
            )
            
            # Lettre
            self.create_text(x, y - 5, text=letter,
                           font=("Consolas", max(10, int(12 * self._scale)), "bold"),
                           fill=THEME["text"])
            
            # IP court
            parts = ip.split(".")
            label = f".{parts[-1]}" if len(parts) == 4 else ip[:6]
            self.create_text(x, y + half + 5, text=label,
                           font=("Consolas", max(8, int(9 * self._scale))),
                           fill=THEME["text_dim"])
    
    def _draw_legend(self, total: int, displayed: int):
        """Légende avec info de limitation"""
        x, y = 10, 10
        
        self.create_rectangle(x, y, x + 130, y + 140,
                            fill=THEME["bg_card"], outline=THEME["border"])
        
        self.create_text(x + 65, y + 12, text="Légende",
                        font=("Segoe UI", 9, "bold"), fill=THEME["text"])
        
        y_pos = y + 30
        for type_id, (letter, color, name) in self.ICONS.items():
            self.create_rectangle(x + 10, y_pos - 6, x + 26, y_pos + 6,
                                fill=THEME["bg_node"], outline=color)
            self.create_text(x + 18, y_pos, text=letter,
                           font=("Consolas", 8, "bold"), fill=THEME["text"])
            self.create_text(x + 35, y_pos, text=name,
                           font=("Segoe UI", 8), fill=THEME["text_dim"], anchor="w")
            y_pos += 18
        
        # Info limitation
        if total > displayed:
            self.create_text(x + 65, y + 125, 
                           text=f"Affichés: {displayed}/{total}",
                           font=("Segoe UI", 7), fill=THEME["warning"])
    
    # Events
    
    def _wheel(self, e):
        factor = 1.15 if (e.delta > 0 if hasattr(e, 'delta') else e.num == 4) else 0.87
        self._scale = max(0.3, min(2.5, self._scale * factor))
        self._schedule_redraw()
    
    def _press(self, e):
        self._dragging = True
        self._drag_start = (e.x, e.y)
        
        # Check node click
        clicked = self._find_node(e.x, e.y)
        if clicked and clicked != self._selected:
            self._selected = clicked
            if self._on_select:
                self._on_select(clicked)
            self._schedule_redraw()
    
    def _drag(self, e):
        if not self._dragging or not self._drag_start:
            return
        
        dx = e.x - self._drag_start[0]
        dy = e.y - self._drag_start[1]
        self._pan_x += dx
        self._pan_y += dy
        self._drag_start = (e.x, e.y)
        
        # Redraw immédiat pendant le drag (sans throttle lourd)
        if abs(dx) > 5 or abs(dy) > 5:
            self._do_redraw()
    
    def _release(self, e):
        self._dragging = False
        self._drag_start = None
    
    def _find_node(self, sx: int, sy: int) -> Optional[str]:
        for ip in self.topo.get_top_nodes(MAX_NODES_DISPLAY):
            node = self.topo.nodes.get(ip)
            if not node:
                continue
            nx, ny = self._tx(node["x"], node["y"])
            if abs(nx - sx) < 30 and abs(ny - sy) < 35:
                return ip
        return None
    
    def center(self):
        if not self.topo.nodes:
            return
        nodes = [self.topo.nodes[ip] for ip in self.topo.get_top_nodes(MAX_NODES_DISPLAY)]
        if not nodes:
            return
        xs = [n["x"] for n in nodes]
        ys = [n["y"] for n in nodes]
        cx = (min(xs) + max(xs)) / 2
        cy = (min(ys) + max(ys)) / 2
        w, h = self.winfo_width(), self.winfo_height()
        self._pan_x = w/2 - cx * self._scale
        self._pan_y = h/2 - cy * self._scale
        self._schedule_redraw()
    
    def fit(self):
        if not self.topo.nodes:
            return
        nodes = [self.topo.nodes[ip] for ip in self.topo.get_top_nodes(MAX_NODES_DISPLAY)]
        if not nodes:
            return
        xs = [n["x"] for n in nodes]
        ys = [n["y"] for n in nodes]
        tw = max(xs) - min(xs) + 200
        th = max(ys) - min(ys) + 200
        w, h = self.winfo_width(), self.winfo_height()
        self._scale = min(w/tw, h/th, 2.0) * 0.85
        self.center()


class TopologyPanel(ctk.CTkFrame):
    """
    Panneau principal contenant la vue topologique et sa barre d'outils.
    
    Utilité :
    - Intégrer le TopologyCanvas dans l'interface principale.
    - Fournir les commandes (Pause, Clear, Fit, Zoom).
    - Afficher les détails du noeud sélectionné dans un panneau latéral.
    - Gérer la boucle de mise à jour automatique.

    Fonctions associées :
    - add_packet(pkt) : Point d'entrée pour les nouveaux paquets venant du Sniffer.
    - _on_select(ip) : Callback déclenché au clic sur un noeud (affiche détails).
    - _update_stats() : Met à jour les compteurs et graphiques en temps réel.
    """
    
    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color=THEME["bg_panel"], **kw)
        
        self.topo = get_topology()
        self._update_job = None
        
        # Toolbar
        toolbar = ctk.CTkFrame(self, fg_color=THEME["bg_card"], height=50, corner_radius=8)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))
        toolbar.pack_propagate(False)
        
        self._stats = ctk.CTkLabel(toolbar, text="0 appareils",
                                  font=ctk.CTkFont(size=12),
                                  text_color=THEME["text_dim"])
        self._stats.pack(side="left", padx=15, pady=10)
        
        # Boutons
        btn_cfg = {"width": 80, "height": 28, "corner_radius": 6,
                   "fg_color": THEME["bg_node"], "hover_color": THEME["border"],
                   "font": ctk.CTkFont(size=10)}
        
        ctk.CTkButton(toolbar, text="Effacer", command=self._clear,
                     hover_color=THEME["error"], 
                     **{k:v for k,v in btn_cfg.items() if k!="hover_color"}
        ).pack(side="right", padx=5, pady=10)
        
        ctk.CTkButton(toolbar, text="Relayout", command=self._relayout, **btn_cfg
        ).pack(side="right", padx=5, pady=10)
        
        ctk.CTkButton(toolbar, text="Ajuster", command=self._fit, **btn_cfg
        ).pack(side="right", padx=5, pady=10)
        
        ctk.CTkButton(toolbar, text="Centrer", command=self._center, **btn_cfg
        ).pack(side="right", padx=5, pady=10)
        
        # Main
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=10, pady=5)
        main.grid_columnconfigure(0, weight=4)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)
        
        # Canvas
        canvas_frame = ctk.CTkFrame(main, fg_color=THEME["bg_card"], corner_radius=8)
        canvas_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        self._canvas = TopologyCanvas(canvas_frame)
        self._canvas.pack(fill="both", expand=True, padx=2, pady=2)
        self._canvas.set_callback(self._on_select)
        
        # Info panel
        info = ctk.CTkFrame(main, fg_color=THEME["bg_card"], corner_radius=8, width=240)
        info.grid(row=0, column=1, sticky="nsew")
        info.grid_propagate(False)
        
        ctk.CTkLabel(info, text="Détails", font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text"]).pack(anchor="w", padx=12, pady=(12, 8))
        
        self._info = ctk.CTkTextbox(info, font=ctk.CTkFont(family="Consolas", size=10),
                                   fg_color=THEME["bg_node"], text_color=THEME["text_dim"],
                                   corner_radius=6)
        self._info.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._info.insert("1.0", "Cliquez sur un appareil...")
        self._info.configure(state="disabled")
        
        # Stats par type
        ctk.CTkLabel(info, text="Répartition", font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=THEME["text"]).pack(anchor="w", padx=12, pady=(5, 5))
        
        self._types_frame = ctk.CTkFrame(info, fg_color="transparent")
        self._types_frame.pack(fill="x", padx=8, pady=(0, 12))
        
        # Démarrer les updates
        self._start_updates()
    
    def _start_updates(self):
        """Démarre la boucle d'update"""
        self._do_update()
    
    def _do_update(self):
        """Update périodique"""
        try:
            self._update_stats()
            
            # Redraw seulement si dirty
            if self.topo._dirty:
                self._canvas.redraw()
                self.topo._dirty = False
                
        except Exception as e:
            print(f"[!] Update error: {e}")
        
        # Planifier le prochain update
        self._update_job = self.after(UPDATE_INTERVAL, self._do_update)
    
    def _update_stats(self):
        stats = self.topo.get_stats()
        
        displayed = min(stats['nodes'], MAX_NODES_DISPLAY)
        extra = f" (top {displayed})" if stats['nodes'] > MAX_NODES_DISPLAY else ""
        
        self._stats.configure(
            text=f"{stats['nodes']} appareils{extra} | "
                 f"{stats['links']} liens | "
                 f"{stats['packets']:,} pkts"
        )
        
        # Types
        for w in self._types_frame.winfo_children():
            w.destroy()
        
        for t, count in sorted(stats.get("types", {}).items(), key=lambda x: -x[1])[:4]:
            if count > 0:
                icon_info = TopologyCanvas.ICONS.get(t, ("?", "#666", t))
                _, color, name = icon_info
                
                row = ctk.CTkFrame(self._types_frame, fg_color="transparent")
                row.pack(fill="x", pady=1)
                
                ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=9),
                            text_color=THEME["text_dim"]).pack(side="left")
                
                ctk.CTkLabel(row, text=str(count), font=ctk.CTkFont(size=9, weight="bold"),
                            text_color=color).pack(side="right", padx=5)
    
    def _on_select(self, ip: str):
        if ip not in self.topo.nodes:
            return
        
        n = self.topo.nodes[ip]
        icon_info = TopologyCanvas.ICONS.get(n["type"], ("?", "#666", "Inconnu"))
        _, _, typename = icon_info
        
        total = n["pkts_in"] + n["pkts_out"]
        comms = ", ".join(list(n["communities"])[:2]) or "N/A"
        
        txt = f"""{typename}
{'─' * 24}

IP: {ip}
{'SUSPECT' if n['suspect'] else 'Normal'}

Trafic:
  In:  {n['pkts_in']:,}
  Out: {n['pkts_out']:,}
  Tot: {total:,}

Communities: {comms}
"""
        
        self._info.configure(state="normal")
        self._info.delete("1.0", "end")
        self._info.insert("1.0", txt)
        self._info.configure(state="disabled")
    
    def _center(self):
        self._canvas.center()
    
    def _fit(self):
        self._canvas.fit()
    
    def _relayout(self):
        self.topo._layout_done = False
        self.topo._dirty = True
        self._canvas.redraw()
    
    def _clear(self):
        self.topo.clear()
        self._canvas.redraw()
        self._update_stats()
    
    def add_packet(self, pkt: dict):
        self.topo.add_packet(pkt)
    
    def destroy(self):
        """Cleanup"""
        if self._update_job:
            self.after_cancel(self._update_job)
        super().destroy()
