
class GraphiqueSecu(tk.Frame):
    """
    Graphique Donut (Matplotlib) affichant la distribution des protocoles de sécurité.
    
    Utilité :
    - Visualiser la répartition des événements de sécurité.
    - Identifier les protocoles les plus actifs ou problématiques.
    - S'intégrer dans le tableau de bord de sécurité.

    Fonctions associées :
    - _build() : Initialise le widget Tkinter et intègre la figure Matplotlib.
    - update(data, colors) : Met à jour les données du graphique et redessine le donut.
    """
    
    def __init__(self, parent, title="", **kwargs):
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._fig = None
        self._ax = None
        self._canvas = None
        self._build()
    
    def _build(self):
        # Titre
        tk.Label(self, text=self._title, font=("Segoe UI", 12, "bold"),
                 fg=THEME["text_secondary"], bg=THEME["bg_card"]).pack(pady=(10, 5))
        
        # Figure
        self._fig = Figure(figsize=(3, 2.5), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)
        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Init vide
        self.update({"No Data": 1}, ["#444444"])

    def update(self, data: dict, colors: list = None):
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

        # Donut Chart
        wedges, texts, autotexts = self._ax.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=90,
            colors=chart_colors, pctdistance=0.85, 
            textprops=dict(color=text_color, fontsize=9)
        )
        
        # Cercle central pour faire le trou (Donut)
        centre_circle = plt.Circle((0,0), 0.70, fc=THEME["bg_card"])
        self._ax.add_artist(centre_circle)
        
        # Style labels
        for t in texts:
            t.set_color(THEME["text_secondary"])
            t.set_fontsize(8)
            
        self._ax.axis('equal')  # Equal aspect ratio
        self._fig.tight_layout()
        
        try:
            self._canvas.draw_idle()
        except:
            pass
