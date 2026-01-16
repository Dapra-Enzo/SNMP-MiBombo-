#!/usr/bin/env python3
"""
MiBombo Suite - Report Generator
Générateur de rapports professionnels avec analyse approfondie.
"""

import os
import io
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import Counter
from dataclasses import dataclass, field

PDF_AVAILABLE = False
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    PDF_AVAILABLE = True
except ImportError:
    pass


class ReportColors:
    PRIMARY = "#1e3a5f"
    SECONDARY = "#3b82f6"
    SUCCESS = "#10b981"
    WARNING = "#f59e0b"
    DANGER = "#ef4444"
    INFO = "#6366f1"
    DARK = "#1f2937"
    LIGHT = "#f3f4f6"


@dataclass
class ReportData:
    period_start: datetime
    period_end: datetime
    station_name: str
    total_packets: int = 0
    authorized_packets: int = 0
    suspect_packets: int = 0
    alerts_critical: int = 0
    alerts_warning: int = 0
    alerts_info: int = 0
    alerts_list: List = field(default_factory=list)
    top_sources: List[Tuple[str, int]] = field(default_factory=list)
    top_destinations: List[Tuple[str, int]] = field(default_factory=list)
    top_communities: List[Tuple[str, int]] = field(default_factory=list)
    devices: List[Dict] = field(default_factory=list)
    new_devices: int = 0
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    anomalies: Dict[str, int] = field(default_factory=dict)
    snmp_versions: Dict[str, int] = field(default_factory=dict)
    pdu_types: Dict[str, int] = field(default_factory=dict)


class DataAnalyzer:
    @staticmethod
    def calculate_risk_score(data: ReportData) -> Tuple[int, str, str]:
        score = 0
        if data.alerts_critical > 0:
            score += min(40, data.alerts_critical * 10)
        if data.alerts_warning > 0:
            score += min(20, data.alerts_warning * 4)
        if data.total_packets > 0:
            score += int((data.suspect_packets / data.total_packets) * 25)
        score += min(15, sum(data.anomalies.values()) * 3)
        score = min(100, score)
        
        if score < 25: return score, "FAIBLE", ReportColors.SUCCESS
        elif score < 50: return score, "MODÉRÉ", ReportColors.WARNING
        elif score < 75: return score, "ÉLEVÉ", ReportColors.DANGER
        else: return score, "CRITIQUE", ReportColors.DANGER
    
    @staticmethod
    def identify_attack_patterns(data: ReportData) -> List[Dict]:
        patterns = []
        attack_map = {
            "FLOOD": ("Flood Attack", "CRITICAL", "Implémenter rate limiting"),
            "NETWORK_SCAN": ("Network Scan", "HIGH", "Bloquer sources suspectes"),
            "BRUTE_FORCE": ("Brute Force", "HIGH", "Renforcer authentification"),
            "COMMUNITY_ENUM": ("Community Enum", "MEDIUM", "Utiliser community complexes"),
            "TRAP_STORM": ("Trap Storm", "HIGH", "Filtrer les traps"),
            "AUTH_FAILURE": ("Auth Failure", "MEDIUM", "Vérifier credentials"),
        }
        for key, (name, sev, rec) in attack_map.items():
            if data.anomalies.get(key, 0) > 0:
                patterns.append({"type": name, "severity": sev, "count": data.anomalies[key], "recommendation": rec})
        return patterns
    
    @staticmethod
    def generate_recommendations(data: ReportData) -> List[Dict]:
        recs = []
        v1, v2 = data.snmp_versions.get("v1", 0), data.snmp_versions.get("v2c", 0)
        if v1 + v2 > 0:
            recs.append({"priority": "HIGH", "title": "Migration SNMPv3",
                "description": f"{v1+v2} paquets SNMPv1/v2c vulnérables",
                "action": "Migrer vers SNMPv3 avec authPriv"})
        
        for comm, cnt in data.top_communities[:3]:
            if comm.lower() in ["public", "private", "admin", "cisco"]:
                recs.append({"priority": "HIGH", "title": f"Community '{comm}'",
                    "description": f"Community par défaut utilisée {cnt} fois",
                    "action": "Remplacer par une community unique et complexe"})
                break
        
        if data.total_packets > 100 and data.suspect_packets / data.total_packets > 0.1:
            recs.append({"priority": "HIGH", "title": "Trafic suspect élevé",
                "description": f"{data.suspect_packets/data.total_packets*100:.1f}% suspect",
                "action": "Investiguer et renforcer filtrage"})
        
        total_alerts = data.alerts_critical + data.alerts_warning + data.alerts_info
        if total_alerts > 50:
            recs.append({"priority": "MEDIUM", "title": "Volume alertes élevé",
                "description": f"{total_alerts} alertes générées", "action": "Ajuster seuils détection"})
        
        return sorted(recs, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["priority"], 3))


class PDFReportGenerator:
    def __init__(self):
        if not PDF_AVAILABLE:
            raise ImportError("pip install reportlab")
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle('MainTitle', fontSize=28, textColor=colors.HexColor(ReportColors.PRIMARY),
            spaceAfter=30, alignment=TA_CENTER, fontName='Helvetica-Bold'))
        self.styles.add(ParagraphStyle('SectionTitle', fontSize=16, textColor=colors.HexColor(ReportColors.PRIMARY),
            spaceBefore=20, spaceAfter=10, fontName='Helvetica-Bold'))
        self.styles.add(ParagraphStyle('SubTitle', fontSize=12, textColor=colors.HexColor(ReportColors.SECONDARY),
            spaceBefore=15, spaceAfter=8, fontName='Helvetica-Bold'))
        self.styles.add(ParagraphStyle('Body', fontSize=10, textColor=colors.HexColor(ReportColors.DARK),
            spaceAfter=8, alignment=TA_JUSTIFY))
    
    def generate(self, data: ReportData) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=20*mm, rightMargin=20*mm)
        elements = []
        
        # Titre
        elements.append(Spacer(1, 30*mm))
        elements.append(Paragraph("🔬 MiBombo Suite", self.styles['MainTitle']))
        elements.append(Paragraph("Rapport d'Analyse SNMP", self.styles['Normal']))
        elements.append(Spacer(1, 15*mm))
        
        info = [["Station:", data.station_name],
                ["Période:", f"{data.period_start.strftime('%d/%m/%Y')} - {data.period_end.strftime('%d/%m/%Y')}"],
                ["Généré:", datetime.now().strftime("%d/%m/%Y %H:%M")]]
        t = Table(info, colWidths=[40*mm, 100*mm])
        t.setStyle(TableStyle([('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor(ReportColors.PRIMARY))]))
        elements.append(t)
        elements.append(Spacer(1, 20*mm))
        
        # Score risque
        risk_score, risk_level, risk_color = DataAnalyzer.calculate_risk_score(data)
        elements.append(Paragraph("Score de Risque Global", self.styles['SubTitle']))
        risk_style = ParagraphStyle('Risk', fontSize=48, textColor=colors.HexColor(risk_color), alignment=TA_CENTER)
        elements.append(Paragraph(f"<b>{risk_score}</b>/100", risk_style))
        elements.append(Paragraph(f"<para alignment='center'>Niveau: <b>{risk_level}</b></para>", self.styles['Normal']))
        elements.append(PageBreak())
        
        # Résumé
        elements.append(Paragraph("📋 Résumé Exécutif", self.styles['SectionTitle']))
        total_alerts = data.alerts_critical + data.alerts_warning + data.alerts_info
        suspect_pct = (data.suspect_packets / data.total_packets * 100) if data.total_packets else 0
        
        summary = [[f"{data.total_packets:,}\nPaquets", f"{total_alerts}\nAlertes", 
                   f"{suspect_pct:.1f}%\nSuspects", f"{len(data.devices)}\nAppareils"]]
        t = Table(summary, colWidths=[40*mm]*4)
        t.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER'), ('FONTSIZE', (0,0), (-1,-1), 14),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'), ('BOX', (0,0), (-1,-1), 1, colors.HexColor(ReportColors.LIGHT)),
            ('INNERGRID', (0,0), (-1,-1), 1, colors.HexColor(ReportColors.LIGHT))]))
        elements.append(t)
        elements.append(Spacer(1, 10*mm))
        
        # Points clés
        elements.append(Paragraph("Points Clés", self.styles['SubTitle']))
        if data.alerts_critical > 0:
            elements.append(Paragraph(f"⚠️ <b>{data.alerts_critical} alertes critiques</b> nécessitent attention immédiate", self.styles['Body']))
        if data.new_devices > 0:
            elements.append(Paragraph(f"📡 <b>{data.new_devices} nouveaux appareils</b> détectés", self.styles['Body']))
        patterns = DataAnalyzer.identify_attack_patterns(data)
        if patterns:
            elements.append(Paragraph(f"🔍 <b>{len(patterns)} patterns d'attaque</b> identifiés", self.styles['Body']))
        if not data.alerts_critical and not patterns:
            elements.append(Paragraph("✅ <b>Aucun problème majeur</b> détecté sur la période", self.styles['Body']))
        elements.append(PageBreak())
        
        # Stats détaillées
        elements.append(Paragraph("📊 Statistiques Détaillées", self.styles['SectionTitle']))
        stats = [["Métrique", "Valeur", "Pourcentage"],
                ["Total Paquets", f"{data.total_packets:,}", "100%"],
                ["Autorisés", f"{data.authorized_packets:,}", f"{(data.authorized_packets/data.total_packets*100):.1f}%" if data.total_packets else "0%"],
                ["Suspects", f"{data.suspect_packets:,}", f"{suspect_pct:.1f}%"],
                ["Alertes Critiques 🔴", str(data.alerts_critical), ""],
                ["Alertes Warning 🟠", str(data.alerts_warning), ""],
                ["Alertes Info 🟢", str(data.alerts_info), ""]]
        t = Table(stats, colWidths=[60*mm, 50*mm, 50*mm])
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor(ReportColors.PRIMARY)),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(ReportColors.LIGHT)),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor(ReportColors.LIGHT)]),
            ('ALIGN', (1,0), (-1,-1), 'CENTER')]))
        elements.append(t)
        elements.append(Spacer(1, 10*mm))
        
        # Top Sources
        elements.append(Paragraph("Top 10 Sources IP", self.styles['SubTitle']))
        if data.top_sources:
            src = [["#", "IP Source", "Paquets", "%"]]
            for i, (ip, cnt) in enumerate(data.top_sources[:10], 1):
                src.append([str(i), ip, f"{cnt:,}", f"{(cnt/data.total_packets*100):.1f}%" if data.total_packets else "0%"])
            t = Table(src, colWidths=[10*mm, 70*mm, 40*mm, 40*mm])
            t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor(ReportColors.SECONDARY)),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(ReportColors.LIGHT)),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor(ReportColors.LIGHT)]),
                ('ALIGN', (0,0), (0,-1), 'CENTER'), ('ALIGN', (2,0), (-1,-1), 'CENTER')]))
            elements.append(t)
        elements.append(Spacer(1, 10*mm))
        
        # Versions SNMP
        elements.append(Paragraph("Distribution SNMP", self.styles['SubTitle']))
        if data.snmp_versions:
            total_v = sum(data.snmp_versions.values())
            ver = [["Version", "Paquets", "%", "Sécurité"]]
            sec_map = {"v1": "⚠️ Faible", "v2c": "⚠️ Faible", "v3": "✅ Forte"}
            for v, c in sorted(data.snmp_versions.items()):
                ver.append([v.upper(), f"{c:,}", f"{(c/total_v*100):.1f}%" if total_v else "0%", sec_map.get(v, "?")])
            t = Table(ver, colWidths=[40*mm, 40*mm, 40*mm, 40*mm])
            t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor(ReportColors.INFO)),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(ReportColors.LIGHT)),
                ('ALIGN', (0,0), (-1,-1), 'CENTER')]))
            elements.append(t)
        elements.append(Spacer(1, 10*mm))
        
        # Types PDU
        elements.append(Paragraph("Types de Requêtes", self.styles['SubTitle']))
        if data.pdu_types:
            total_p = sum(data.pdu_types.values())
            pdu = [["Type", "Nombre", "%"]]
            icons = {"get": "📥", "getnext": "📤", "getbulk": "📦", "set": "✏️", "response": "📨", "trap": "🔔"}
            for p, c in sorted(data.pdu_types.items(), key=lambda x: -x[1])[:8]:
                pdu.append([f"{icons.get(p.lower(), '📋')} {p.upper()}", f"{c:,}", f"{(c/total_p*100):.1f}%" if total_p else "0%"])
            t = Table(pdu, colWidths=[60*mm, 50*mm, 50*mm])
            t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor(ReportColors.PRIMARY)),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(ReportColors.LIGHT)),
                ('ALIGN', (1,0), (-1,-1), 'CENTER')]))
            elements.append(t)
        elements.append(PageBreak())
        
        # Sécurité
        elements.append(Paragraph("🔒 Analyse de Sécurité", self.styles['SectionTitle']))
        elements.append(Paragraph(f"<b>Score de Risque: {risk_score}/100 ({risk_level})</b>", self.styles['Body']))
        elements.append(Paragraph("Ce score évalue la posture de sécurité basée sur les alertes, anomalies et trafic suspect.", self.styles['Body']))
        elements.append(Spacer(1, 5*mm))
        
        # Anomalies
        elements.append(Paragraph("Anomalies Détectées", self.styles['SubTitle']))
        if data.anomalies and sum(data.anomalies.values()) > 0:
            anom = [["Type", "Occurrences", "Sévérité"]]
            sev_map = {"FLOOD": "🔴 CRITICAL", "NETWORK_SCAN": "🟠 HIGH", "BRUTE_FORCE": "🔴 CRITICAL",
                       "TRAP_STORM": "🟠 HIGH", "COMMUNITY_ENUM": "🟡 MEDIUM", "AUTH_FAILURE": "🟡 MEDIUM"}
            for a, c in sorted(data.anomalies.items(), key=lambda x: -x[1]):
                if c > 0:
                    anom.append([a, str(c), sev_map.get(a, "⚪ LOW")])
            t = Table(anom, colWidths=[70*mm, 40*mm, 50*mm])
            t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor(ReportColors.DANGER)),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(ReportColors.LIGHT)),
                ('ALIGN', (1,0), (-1,-1), 'CENTER')]))
            elements.append(t)
        else:
            elements.append(Paragraph("✅ <b>Aucune anomalie majeure détectée</b>", self.styles['Body']))
        elements.append(Spacer(1, 10*mm))
        
        # Patterns d'attaque
        if patterns:
            elements.append(Paragraph("Patterns d'Attaque", self.styles['SubTitle']))
            for p in patterns:
                sev_color = {"CRITICAL": ReportColors.DANGER, "HIGH": ReportColors.WARNING, "MEDIUM": ReportColors.INFO}.get(p["severity"], ReportColors.DARK)
                elements.append(Paragraph(f"<b>{p['type']}</b> <font color='{sev_color}'>[{p['severity']}]</font> - {p['count']} occurrences", self.styles['Body']))
                elements.append(Paragraph(f"<i>→ {p['recommendation']}</i>", self.styles['Body']))
        elements.append(PageBreak())
        
        # Recommandations
        elements.append(Paragraph("💡 Recommandations", self.styles['SectionTitle']))
        recs = DataAnalyzer.generate_recommendations(data)
        if recs:
            for i, r in enumerate(recs, 1):
                prio_color = {"HIGH": ReportColors.DANGER, "MEDIUM": ReportColors.WARNING, "LOW": ReportColors.SUCCESS}.get(r["priority"], ReportColors.DARK)
                elements.append(Paragraph(f"<b>{i}. {r['title']}</b> <font color='{prio_color}'>[{r['priority']}]</font>", self.styles['Body']))
                elements.append(Paragraph(f"{r['description']}", self.styles['Body']))
                elements.append(Paragraph(f"<b>Action:</b> {r['action']}", self.styles['Body']))
                elements.append(Spacer(1, 3*mm))
        else:
            elements.append(Paragraph("✅ <b>Aucune recommandation urgente</b>", self.styles['Body']))
        elements.append(Spacer(1, 15*mm))
        
        # Conclusion
        elements.append(Paragraph("📝 Conclusion", self.styles['SectionTitle']))
        elements.append(Paragraph(f"""Ce rapport couvre la période du {data.period_start.strftime('%d/%m/%Y')} au {data.period_end.strftime('%d/%m/%Y')}.
        <b>{data.total_packets:,} paquets SNMP</b> ont été analysés. Le score de risque global est de <b>{risk_score}/100 ({risk_level})</b>.
        {'Des actions correctives sont recommandées.' if risk_score >= 50 else 'La situation est sous contrôle.'}""", self.styles['Body']))
        
        doc.build(elements, onFirstPage=self._hf, onLaterPages=self._hf)
        buf.seek(0)
        return buf.read()
    
    def _hf(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica-Bold', 9)
        canvas.setFillColor(colors.HexColor(ReportColors.PRIMARY))
        canvas.drawString(20*mm, A4[1]-12*mm, "MiBombo Suite")
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor(ReportColors.DARK))
        canvas.drawRightString(A4[0]-20*mm, A4[1]-12*mm, datetime.now().strftime("%d/%m/%Y"))
        canvas.drawString(20*mm, 10*mm, "Confidentiel")
        canvas.drawRightString(A4[0]-20*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()


class HTMLReportGenerator:
    def generate(self, data: ReportData) -> str:
        risk_score, risk_level, risk_color = DataAnalyzer.calculate_risk_score(data)
        recs = DataAnalyzer.generate_recommendations(data)
        patterns = DataAnalyzer.identify_attack_patterns(data)
        total_alerts = data.alerts_critical + data.alerts_warning + data.alerts_info
        suspect_pct = (data.suspect_packets / data.total_packets * 100) if data.total_packets else 0
        
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>MiBombo Report</title>
<style>
:root{{--primary:#1e3a5f;--secondary:#3b82f6;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--dark:#1f2937;--light:#f3f4f6}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;padding:20px}}
.container{{max-width:1000px;margin:0 auto;background:#fff;border-radius:20px;box-shadow:0 25px 50px -12px rgba(0,0,0,.25);overflow:hidden}}
.header{{background:var(--primary);color:#fff;padding:40px;text-align:center}}
.header h1{{font-size:2.2em;margin-bottom:10px}}
.risk-badge{{display:inline-block;padding:15px 30px;border-radius:50px;font-size:1.4em;font-weight:bold;margin-top:20px;background:{risk_color};color:#fff}}
.content{{padding:40px}}
.section{{margin-bottom:35px}}
.section-title{{font-size:1.4em;color:var(--primary);margin-bottom:15px;padding-bottom:8px;border-bottom:3px solid var(--secondary)}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:25px}}
.metric{{background:var(--light);border-radius:12px;padding:20px;text-align:center}}
.metric-value{{font-size:2em;font-weight:bold;color:var(--primary)}}
.metric-label{{color:var(--dark);font-size:.9em}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:var(--primary);color:#fff;padding:12px;text-align:left}}
td{{padding:10px 12px;border-bottom:1px solid var(--light)}}
tr:nth-child(even){{background:var(--light)}}
.rec{{background:var(--light);border-left:4px solid var(--secondary);padding:15px;margin:10px 0;border-radius:0 8px 8px 0}}
.rec.high{{border-left-color:var(--danger)}}
.rec.medium{{border-left-color:var(--warning)}}
.footer{{background:var(--dark);color:#fff;text-align:center;padding:15px;font-size:.85em}}
@media(max-width:600px){{.metrics{{grid-template-columns:repeat(2,1fr)}}}}
</style></head>
<body><div class="container">
<div class="header">
<h1>🔬 MiBombo Suite</h1>
<p>Rapport d'Analyse SNMP - {data.station_name}</p>
<p>{data.period_start.strftime('%d/%m/%Y')} - {data.period_end.strftime('%d/%m/%Y')}</p>
<div class="risk-badge">Score: {risk_score}/100 ({risk_level})</div>
</div>
<div class="content">
<div class="section">
<h2 class="section-title">📊 Vue d'ensemble</h2>
<div class="metrics">
<div class="metric"><div class="metric-value">{data.total_packets:,}</div><div class="metric-label">Paquets</div></div>
<div class="metric"><div class="metric-value">{total_alerts}</div><div class="metric-label">Alertes</div></div>
<div class="metric"><div class="metric-value">{suspect_pct:.1f}%</div><div class="metric-label">Suspects</div></div>
<div class="metric"><div class="metric-value">{len(data.devices)}</div><div class="metric-label">Appareils</div></div>
</div></div>
<div class="section">
<h2 class="section-title">📈 Statistiques</h2>
<table><tr><th>Métrique</th><th>Valeur</th><th>%</th></tr>
<tr><td>Autorisés</td><td>{data.authorized_packets:,}</td><td>{(data.authorized_packets/data.total_packets*100):.1f}%</td></tr>
<tr><td>Suspects</td><td>{data.suspect_packets:,}</td><td>{suspect_pct:.1f}%</td></tr>
<tr><td style="color:var(--danger)">Alertes Critiques 🔴</td><td>{data.alerts_critical}</td><td></td></tr>
<tr><td style="color:var(--warning)">Alertes Warning 🟠</td><td>{data.alerts_warning}</td><td></td></tr>
<tr><td style="color:var(--success)">Alertes Info 🟢</td><td>{data.alerts_info}</td><td></td></tr>
</table></div>
<div class="section">
<h2 class="section-title">🔝 Top Sources IP</h2>
<table><tr><th>#</th><th>IP</th><th>Paquets</th><th>%</th></tr>
{''.join(f"<tr><td>{i+1}</td><td><code>{ip}</code></td><td>{cnt:,}</td><td>{(cnt/data.total_packets*100):.1f}%</td></tr>" for i,(ip,cnt) in enumerate(data.top_sources[:10]))}
</table></div>
<div class="section">
<h2 class="section-title">🔒 Anomalies</h2>
{'<p>✅ Aucune anomalie détectée</p>' if not data.anomalies or sum(data.anomalies.values())==0 else f'<table><tr><th>Type</th><th>Occurrences</th><th>Sévérité</th></tr>{"".join(f"<tr><td>{a}</td><td>{c}</td><td>{"🔴 CRITICAL" if a in ["FLOOD","BRUTE_FORCE"] else "🟠 HIGH" if a in ["NETWORK_SCAN","TRAP_STORM"] else "🟡 MEDIUM"}</td></tr>" for a,c in data.anomalies.items() if c>0)}</table>'}
</div>
<div class="section">
<h2 class="section-title">💡 Recommandations</h2>
{'<p>✅ Aucune recommandation urgente</p>' if not recs else ''.join(f'<div class="rec {r["priority"].lower()}"><b>{r["title"]}</b> [{r["priority"]}]<br/>{r["description"]}<br/><b>Action:</b> {r["action"]}</div>' for r in recs)}
</div></div>
<div class="footer">Généré le {datetime.now().strftime('%d/%m/%Y %H:%M')} - MiBombo Suite - Confidentiel</div>
</div></body></html>"""
        return html


class TelegramReportGenerator:
    def generate(self, data: ReportData) -> str:
        risk_score, risk_level, _ = DataAnalyzer.calculate_risk_score(data)
        total_alerts = data.alerts_critical + data.alerts_warning + data.alerts_info
        suspect_pct = (data.suspect_packets / data.total_packets * 100) if data.total_packets else 0
        risk_emoji = "🟢" if risk_score < 25 else "🟡" if risk_score < 50 else "🟠" if risk_score < 75 else "🔴"
        
        rpt = f"""📊 <b>RAPPORT MIBOMBO</b>
{'━'*35}
📍 <code>{data.station_name}</code>
📅 {data.period_start.strftime('%d/%m/%Y')} → {data.period_end.strftime('%d/%m/%Y')}

{risk_emoji} <b>RISQUE: {risk_score}/100 ({risk_level})</b>

━━━ 📈 STATISTIQUES ━━━

📦 <b>Paquets</b>
├ Total: <code>{data.total_packets:,}</code>
├ Autorisés: <code>{data.authorized_packets:,}</code>
└ Suspects: <code>{data.suspect_packets:,}</code> ({suspect_pct:.1f}%)

⚠️ <b>Alertes</b>
├ 🔴 Critiques: <code>{data.alerts_critical}</code>
├ 🟠 Warning: <code>{data.alerts_warning}</code>
└ 🟢 Info: <code>{data.alerts_info}</code>

📡 <b>Appareils</b>: {len(data.devices)} (+{data.new_devices} nouveaux)

━━━ 🔝 TOP 5 SOURCES ━━━
"""
        for i, (ip, cnt) in enumerate(data.top_sources[:5], 1):
            pct = (cnt / data.total_packets * 100) if data.total_packets else 0
            bar = "█" * int(pct/5) + "░" * (20-int(pct/5))
            rpt += f"\n{i}. <code>{ip}</code>\n   {bar} {cnt:,} ({pct:.1f}%)"
        
        rpt += "\n\n━━━ 🔍 ANOMALIES ━━━\n"
        if data.anomalies and sum(data.anomalies.values()) > 0:
            for a, c in sorted(data.anomalies.items(), key=lambda x: -x[1]):
                if c > 0:
                    emoji = "🔴" if a in ["FLOOD", "BRUTE_FORCE"] else "🟠" if a in ["NETWORK_SCAN", "TRAP_STORM"] else "🟡"
                    rpt += f"\n{emoji} {a}: <code>{c}</code>"
        else:
            rpt += "\n✅ Aucune anomalie"
        
        recs = DataAnalyzer.generate_recommendations(data)
        if recs:
            rpt += "\n\n━━━ 💡 ACTIONS ━━━"
            for r in recs[:3]:
                emoji = "🔴" if r["priority"] == "HIGH" else "🟠" if r["priority"] == "MEDIUM" else "🟢"
                rpt += f"\n\n{emoji} <b>{r['title']}</b>\n└ {r['action'][:50]}..."
        
        rpt += f"\n\n{'━'*35}\n🤖 <i>MiBombo - {datetime.now().strftime('%d/%m/%Y %H:%M')}</i>"
        return rpt


def generate_report(packets=None, alerts=None, devices=None, station_name="Station MiBombo", period_days=7, format="pdf"):
    packets, alerts, devices = packets or [], alerts or [], devices or []
    now = datetime.now()
    start = now - timedelta(days=period_days)
    
    src_counts = Counter(p.get("ip_src", "?") for p in packets)
    dst_counts = Counter(p.get("ip_dst", "?") for p in packets)
    comm_counts = Counter(p.get("snmp_community", "?") for p in packets if p.get("snmp_community"))
    
    snmp_ver = Counter()
    for p in packets:
        v = p.get("snmp_version", "?")
        if v in [0, "0", "v1"]: snmp_ver["v1"] += 1
        elif v in [1, "1", "v2c"]: snmp_ver["v2c"] += 1
        elif v in [3, "3", "v3"]: snmp_ver["v3"] += 1
    
    pdu_counts = Counter(str(p.get("snmp_pdu_type", "?")).lower() for p in packets)
    hourly = Counter()
    for p in packets:
        ts = p.get("timestamp")
        if ts:
            try:
                if isinstance(ts, str): ts = datetime.fromisoformat(ts)
                hourly[ts.hour] += 1
            except: pass
    
    suspect = sum(1 for p in packets if p.get("authorized") == False)
    anomalies = Counter(a.get("type", "?") for a in alerts)
    
    data = ReportData(
        period_start=start, period_end=now, station_name=station_name,
        total_packets=len(packets), authorized_packets=len(packets)-suspect, suspect_packets=suspect,
        alerts_critical=sum(1 for a in alerts if a.get("severity")=="critical"),
        alerts_warning=sum(1 for a in alerts if a.get("severity")=="warning"),
        alerts_info=sum(1 for a in alerts if a.get("severity")=="info"),
        alerts_list=alerts, top_sources=src_counts.most_common(10), top_destinations=dst_counts.most_common(10),
        top_communities=comm_counts.most_common(10), devices=devices,
        new_devices=sum(1 for d in devices if d.get("new")),
        hourly_distribution=dict(hourly), anomalies=dict(anomalies),
        snmp_versions=dict(snmp_ver), pdu_types=dict(pdu_counts)
    )
    
    if format.lower() == "pdf":
        if not PDF_AVAILABLE: raise ImportError("pip install reportlab")
        return PDFReportGenerator().generate(data)
    elif format.lower() == "html":
        return HTMLReportGenerator().generate(data).encode('utf-8')
    elif format.lower() == "telegram":
        return TelegramReportGenerator().generate(data)
    else:
        raise ValueError(f"Format non supporté: {format}")
