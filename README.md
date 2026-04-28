# 📋 HANDOVER DOCUMENT — Mobile API Misuse Detector
## Document de transfert complet pour continuer le travail sur ce projet
 
> **But de ce document** : Transmettre l'intégralité du contexte, des décisions, du code et des prochaines étapes à un autre assistant IA pour continuer le développement.
 
---
 
## 👤 Contexte étudiant
 
- **Niveau** : Étudiant en binôme, cours de **Sécurité Mobile** (université)
- **Langue** : Français (mélange français/darija/arabe dans les messages)
- **Localisation** : Marrakech, Maroc
- **Situation** : Le projet a été choisi parmi 3 options proposées par le professeur
---
 
## 🎯 Projet choisi
 
**Projet n°12 — Mobile API Misuse Detector (détection d'abus côté backend)**
 
### Description originale du prof
 
> Objectif : analyser logs API (backend) pour repérer abus liés aux clients mobiles : burst, erreurs auth, endpoints martelés.
 
**Fonctionnalités demandées :**
- Import logs (Nginx/Express/Spring) + user-agent mobile
- Détection : spikes, bruteforce login, enumeration (défensif) — IA
- Clustering des patterns d'abus + alerting
- Recommandations anti-abus : rate-limit, CAPTCHA adaptatif, lockouts
- Couvre : Chap. 4, 14 — Lab 3 (trafic) + volet DevSecOps
---
 
## 📁 Base de code
 
### Repo cloné (base du projet)
 
```
https://github.com/domino79/vulnsentinel
```
 
**Ce que fait VulnSentinel (existant) :**
- Flask web app Python
- Parser de logs Apache/Nginx (regex)
- Détection SQL Injection, XSS (regex basiques)
- Détection brute force basique
- Dashboard HTML Flask simple
**Langage de base :** Python + Flask
 
---
 
## 🏗️ Architecture complète décidée
 
```
[Émulateur Android AVD]
        │ trafic HTTP/HTTPS réel
        ▼
[mitmproxy port 8080]
        │ addon nginx_logger.py → format Nginx
        ▼
[logs/nginx_from_mitm.log]
        │
        ├──► [parser/mobile_parser.py] → DataFrame pandas
        │
        ├──► [detection/rules.py] → alertes (brute force, spikes, enum, hammering)
        │
        ├──► [ai/clustering.py] → K-Means clustering (scikit-learn)
        │
        ├──► [recommendations/advisor.py] → rate-limit, lockout, CAPTCHA
        │
        └──► [dashboard/streamlit_app.py] → Streamlit + Plotly (refresh 5s)
 
[benchmark/run_benchmark.py] → Precision / Recall / F1 (Faker vs Émulateur)
```
 
---
 
## 📂 Structure des fichiers décidée
 
```
vulnsentinel/                          ← repo cloné
│
├── app.py                             ✅ Flask existant (garder)
├── log_parser.py                      ✅ Existant (garder)
├── requirements.txt                   ⚠️ À mettre à jour
├── test_pipeline.py                   🆕 À créer
├── log_watcher.py                     🆕 À créer
│
├── generator/
│   └── log_generator.py               🆕 Générer logs Faker (méthode V1)
│
├── mitm_addons/
│   └── nginx_logger.py                🆕 Addon mitmproxy → format Nginx
│
├── parser/
│   └── mobile_parser.py               🆕 Parser Nginx → DataFrame pandas
│
├── detection/
│   └── rules.py                       🆕 4 règles de détection
│
├── ai/
│   ├── clustering.py                  🆕 K-Means clustering
│   └── feature_extractor.py          🆕 Features par IP
│
├── dashboard/
│   └── streamlit_app.py               🆕 Dashboard Streamlit temps réel
│
├── recommendations/
│   └── advisor.py                     🆕 Recommandations anti-abus
│
├── benchmark/
│   └── run_benchmark.py               🆕 Benchmark Faker vs Émulateur
│
├── logs/
│   ├── nginx_from_mitm.log            🆕 Logs réels (mitmproxy)
│   └── benchmark_simulated_run*.txt  🆕 Logs simulés pour benchmark
│
└── samples/
    └── mobile_api_logs.txt            🆕 Logs Faker générés
```
 
---
 
## 📦 requirements.txt final
 
```txt
flask>=2.3.0
werkzeug>=2.3.0
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
faker>=19.0.0
streamlit>=1.28.0
plotly>=5.17.0
mitmproxy>=10.0.0
requests>=2.31.0
```
 
---
 
## 💻 Code complet de chaque module
 
---
 
### MODULE 1 : generator/log_generator.py
 
```python
"""
Générateur de logs API mobiles simulés.
Produit des logs Nginx réalistes incluant des attaques typiques.
Méthode V1 (Faker) — utilisée pour le benchmark.
"""
 
import random
import datetime
import json
import os
from faker import Faker
 
fake = Faker()
 
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Dart/3.0 (dart:io) - Flutter App",
    "okhttp/4.11.0",
    "CFNetwork/1400.0.4 Darwin/22.0.0",
    "ReactNativeApp/1.2.3",
]
 
API_ENDPOINTS = [
    "/api/v1/login", "/api/v1/logout", "/api/v1/register",
    "/api/v1/user/profile", "/api/v1/user/settings",
    "/api/v1/products", "/api/v1/orders", "/api/v1/payment",
    "/api/v1/notifications", "/api/v1/search",
    "/api/v1/refresh-token", "/api/v1/password-reset",
]
 
HTTP_CODES_NORMAL = [200, 200, 200, 201, 204, 304]
HTTP_CODES_ATTACK = [401, 403, 429, 400, 500]
 
 
def generate_normal_log(ip, timestamp):
    return {"ip": ip, "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": random.choice(["GET", "POST", "GET", "GET"]),
            "endpoint": random.choice(API_ENDPOINTS), "status": random.choice(HTTP_CODES_NORMAL),
            "size": random.randint(200, 5000), "user_agent": random.choice(MOBILE_USER_AGENTS), "type": "normal"}
 
def generate_brute_force_log(ip, timestamp):
    return {"ip": ip, "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": "POST", "endpoint": "/api/v1/login", "status": 401,
            "size": random.randint(50, 200), "user_agent": random.choice(MOBILE_USER_AGENTS), "type": "brute_force"}
 
def generate_spike_log(ip, timestamp):
    return {"ip": ip, "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": random.choice(["GET", "POST"]), "endpoint": random.choice(API_ENDPOINTS),
            "status": random.choice([200, 429]), "size": random.randint(100, 1000),
            "user_agent": random.choice(MOBILE_USER_AGENTS), "type": "spike"}
 
def generate_enumeration_log(ip, timestamp, index):
    return {"ip": ip, "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": "GET", "endpoint": f"/api/v1/user/{index}", "status": random.choice([200, 404]),
            "size": random.randint(50, 500), "user_agent": random.choice(MOBILE_USER_AGENTS), "type": "enumeration"}
 
 
def generate_logs(n_normal=500, n_brute_force_ips=3, n_spike_ips=2, n_enum_ips=2,
                  output_file="samples/mobile_api_logs.txt"):
    logs = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
 
    normal_ips = [fake.ipv4() for _ in range(50)]
    for i in range(n_normal):
        ts = base_time + datetime.timedelta(seconds=i * 5)
        logs.append(generate_normal_log(random.choice(normal_ips), ts))
 
    bf_ips = [fake.ipv4() for _ in range(n_brute_force_ips)]
    for ip in bf_ips:
        for j in range(random.randint(20, 50)):
            ts = base_time + datetime.timedelta(minutes=30, seconds=j * 2)
            logs.append(generate_brute_force_log(ip, ts))
 
    spike_ips = [fake.ipv4() for _ in range(n_spike_ips)]
    for ip in spike_ips:
        for j in range(random.randint(100, 200)):
            ts = base_time + datetime.timedelta(minutes=60, seconds=j * 0.5)
            logs.append(generate_spike_log(ip, ts))
 
    enum_ips = [fake.ipv4() for _ in range(n_enum_ips)]
    for ip in enum_ips:
        for idx in range(1, random.randint(50, 100)):
            ts = base_time + datetime.timedelta(minutes=90, seconds=idx * 1)
            logs.append(generate_enumeration_log(ip, ts, idx))
 
    random.shuffle(logs)
 
    lines = []
    for log in logs:
        line = (f'{log["ip"]} - - [{log["timestamp"]}] '
                f'"{log["method"]} {log["endpoint"]} HTTP/1.1" '
                f'{log["status"]} {log["size"]} "-" "{log["user_agent"]}"')
        lines.append(line)
 
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
 
    print(f"[✓] {len(logs)} logs générés dans '{output_file}'")
    return logs
 
 
if __name__ == "__main__":
    generate_logs()
```
 
---
 
### MODULE 2 : mitm_addons/nginx_logger.py
 
```python
"""
Addon mitmproxy : convertit les flows HTTP interceptés en logs Nginx Combined.
Utilisé avec : mitmdump -s mitm_addons/nginx_logger.py --listen-port 8080
"""
 
import datetime
import os
from mitmproxy import http, ctx
 
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "nginx_from_mitm.log")
NGINX_FORMAT = '{ip} - - [{timestamp}] "{method} {path} {http_ver}" {status} {size} "-" "{ua}"'
 
 
class NginxLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        self.log_file = open(LOG_FILE, "a", buffering=1)
        ctx.log.info(f"[NginxLogger] Logging to: {LOG_FILE}")
 
    def response(self, flow: http.HTTPFlow) -> None:
        try:
            ip       = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"
            ts       = datetime.datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
            method   = flow.request.method
            path     = flow.request.path
            http_ver = f"HTTP/{flow.request.http_version}"
            status   = flow.response.status_code if flow.response else 0
            size     = len(flow.response.content) if flow.response and flow.response.content else 0
            ua       = flow.request.headers.get("User-Agent", "unknown")
 
            line = NGINX_FORMAT.format(ip=ip, timestamp=ts, method=method,
                                       path=path, http_ver=http_ver,
                                       status=status, size=size, ua=ua)
            self.log_file.write(line + "\n")
        except Exception as e:
            ctx.log.error(f"[NginxLogger] Error: {e}")
 
    def done(self):
        self.log_file.close()
 
 
addons = [NginxLogger()]
```
 
---
 
### MODULE 3 : parser/mobile_parser.py
 
```python
import re
import pandas as pd
from datetime import datetime
 
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/[\d\.]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"[^"]*" "(?P<user_agent>[^"]*)"'
)
 
MOBILE_UA_PATTERNS = ["Mobile", "Android", "iPhone", "iPad", "okhttp", "Dart", "CFNetwork", "ReactNative", "Flutter"]
 
def is_mobile_request(user_agent):
    return any(p.lower() in user_agent.lower() for p in MOBILE_UA_PATTERNS)
 
def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    try:
        ts = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S +0000")
    except ValueError:
        ts = None
    return {
        "ip": data["ip"], "timestamp": ts, "method": data["method"],
        "endpoint": data["endpoint"], "status": int(data["status"]),
        "size": int(data["size"]), "user_agent": data["user_agent"],
        "is_mobile": is_mobile_request(data["user_agent"]),
    }
 
def parse_log_file(filepath):
    records = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                records.append(parsed)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["hour"]          = df["timestamp"].dt.hour
    df["minute"]        = df["timestamp"].dt.minute
    df["is_auth_fail"]  = (df["endpoint"].str.contains("login") & (df["status"] == 401)).astype(int)
    df["is_rate_limit"] = (df["status"] == 429).astype(int)
    df["is_404"]        = (df["status"] == 404).astype(int)
    return df
```
 
---
 
### MODULE 4 : detection/rules.py
 
```python
from dataclasses import dataclass
import pandas as pd
 
@dataclass
class Alert:
    type: str
    ip: str
    severity: str   # LOW / MEDIUM / HIGH / CRITICAL
    count: int
    details: str
    endpoint: str = ""
 
def detect_brute_force(df, threshold=10, window_minutes=5):
    alerts = []
    login_fails = df[(df["endpoint"].str.contains("login", na=False)) & (df["status"] == 401)].copy()
    if login_fails.empty:
        return alerts
    for ip, group in login_fails.groupby("ip"):
        count = len(group)
        if count >= threshold:
            severity = "CRITICAL" if count >= 30 else "HIGH" if count >= 20 else "MEDIUM"
            alerts.append(Alert(type="BRUTE_FORCE", ip=ip, severity=severity, count=count,
                                details=f"{count} échecs de login en {window_minutes} min",
                                endpoint="/api/v1/login"))
    return alerts
 
def detect_request_spikes(df, threshold_per_minute=60):
    alerts = []
    if df.empty or "timestamp" not in df.columns:
        return alerts
    df = df.copy()
    df["minute"] = df["timestamp"].dt.floor("T")
    counts = df.groupby(["ip", "minute"]).size().reset_index(name="count")
    spikes = counts[counts["count"] >= threshold_per_minute]
    for _, row in spikes.iterrows():
        alerts.append(Alert(type="REQUEST_SPIKE", ip=row["ip"], severity="HIGH",
                            count=int(row["count"]),
                            details=f"{row['count']} req/min à {row['minute']}"))
    return alerts
 
def detect_endpoint_enumeration(df, threshold_unique=20):
    alerts = []
    for ip, group in df.groupby("ip"):
        unique_endpoints = group["endpoint"].nunique()
        nb_404 = (group["status"] == 404).sum()
        ratio_404 = nb_404 / max(len(group), 1)
        if unique_endpoints >= threshold_unique and ratio_404 > 0.3:
            alerts.append(Alert(type="ENDPOINT_ENUMERATION", ip=ip, severity="MEDIUM",
                                count=int(unique_endpoints),
                                details=f"{unique_endpoints} endpoints distincts, {ratio_404:.0%} de 404"))
    return alerts
 
def detect_endpoint_hammering(df, threshold=100):
    alerts = []
    counts = df.groupby(["ip", "endpoint"]).size().reset_index(name="count")
    heavy = counts[counts["count"] >= threshold]
    for _, row in heavy.iterrows():
        alerts.append(Alert(type="ENDPOINT_HAMMERING", ip=row["ip"], severity="MEDIUM",
                            count=int(row["count"]),
                            details=f"{row['count']} requêtes sur {row['endpoint']}",
                            endpoint=row["endpoint"]))
    return alerts
 
def run_all_detections(df):
    alerts = []
    alerts.extend(detect_brute_force(df))
    alerts.extend(detect_request_spikes(df))
    alerts.extend(detect_endpoint_enumeration(df))
    alerts.extend(detect_endpoint_hammering(df))
    return alerts
```
 
---
 
### MODULE 5 : ai/clustering.py
 
```python
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
 
CLUSTER_LABELS = {
    0: {"name": "Comportement normal",  "color": "#27ae60"},
    1: {"name": "Comportement suspect", "color": "#f39c12"},
    2: {"name": "Attaquant probable",   "color": "#e74c3c"},
    3: {"name": "Bot / Scanner",        "color": "#8e44ad"},
}
 
def extract_ip_features(df):
    if df.empty:
        return pd.DataFrame()
    features = df.groupby("ip").agg(
        total_requests=("ip", "count"),
        unique_endpoints=("endpoint", "nunique"),
        auth_failures=("is_auth_fail", "sum"),
        rate_limit_hits=("is_rate_limit", "sum"),
        nb_404=("is_404", "sum"),
        avg_response_size=("size", "mean"),
        is_mobile=("is_mobile", "mean"),
    ).reset_index()
    features["auth_fail_ratio"]  = features["auth_failures"]  / features["total_requests"].clip(lower=1)
    features["rate_limit_ratio"] = features["rate_limit_hits"] / features["total_requests"].clip(lower=1)
    features["404_ratio"]        = features["nb_404"]          / features["total_requests"].clip(lower=1)
    return features
 
def run_clustering(features, n_clusters=4):
    if features.empty or len(features) < n_clusters:
        return features
    feature_cols = ["total_requests", "unique_endpoints", "auth_fail_ratio",
                    "rate_limit_ratio", "404_ratio", "avg_response_size"]
    X = features[feature_cols].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    features = features.copy()
    features["cluster"] = kmeans.fit_predict(X_scaled)
    if len(features) > n_clusters:
        score = silhouette_score(X_scaled, features["cluster"])
        print(f"[✓] Silhouette Score: {score:.3f}")
    cluster_stats = features.groupby("cluster").agg(
        avg_auth_fail=("auth_fail_ratio", "mean"),
        avg_404=("404_ratio", "mean"),
        avg_requests=("total_requests", "mean"),
    )
    danger_score = cluster_stats["avg_auth_fail"] * 5 + cluster_stats["avg_404"] * 3 + cluster_stats["avg_requests"].rank() * 0.5
    sorted_clusters = danger_score.sort_values().index.tolist()
    label_map = {c: i for i, c in enumerate(sorted_clusters)}
    features["cluster_label"] = features["cluster"].map(label_map)
    features["cluster_name"]  = features["cluster_label"].map(lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["name"])
    features["cluster_color"] = features["cluster_label"].map(lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["color"])
    return features
```
 
---
 
### MODULE 6 : recommendations/advisor.py
 
```python
def generate_recommendations(alerts):
    alert_types = {a.type for a in alerts}
    recommendations = []
 
    if "BRUTE_FORCE" in alert_types:
        recommendations.append({
            "title": "Activer le rate limiting sur /login",
            "priority": "CRITICAL",
            "description": "Limiter à 5 tentatives par IP par minute.",
            "code": """
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)
@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("5 per minute")
def login(): ...
"""
        })
        recommendations.append({"title": "Account Lockout après 5 échecs",
                                  "priority": "HIGH",
                                  "description": "Bloquer 15 minutes après 5 tentatives.", "code": None})
 
    if "REQUEST_SPIKE" in alert_types:
        recommendations.append({"title": "CAPTCHA adaptatif",
                                  "priority": "HIGH",
                                  "description": "Déclencher CAPTCHA si comportement suspect.", "code": None})
        recommendations.append({
            "title": "Nginx rate limiting",
            "priority": "MEDIUM",
            "description": "Limiter le débit au niveau Nginx.",
            "code": "limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;\nlimit_req zone=api burst=10 nodelay;"
        })
 
    if "ENDPOINT_ENUMERATION" in alert_types:
        recommendations.append({"title": "Masquer les erreurs 404 détaillées",
                                  "priority": "MEDIUM",
                                  "description": "Retourner un message générique.", "code": None})
 
    recommendations.append({"title": "Enhanced Logging",
                              "priority": "LOW",
                              "description": "Enregistrer IP, user-agent, endpoint, payload size. Conserver 90 jours.", "code": None})
    return recommendations
```
 
---
 
### MODULE 7 : dashboard/streamlit_app.py
 
```python
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import streamlit as st
import pandas as pd
import plotly.express as px
import time
 
from generator.log_generator import generate_logs
from parser.mobile_parser import parse_log_file
from detection.rules import run_all_detections
from ai.clustering import extract_ip_features, run_clustering
from recommendations.advisor import generate_recommendations
 
st.set_page_config(page_title="Mobile API Misuse Detector", page_icon="🔐", layout="wide")
st.title("🔐 Mobile API Misuse Detector")
 
# Sidebar
st.sidebar.header("⚙️ Configuration")
log_file = st.sidebar.text_input("Fichier de logs", value="logs/nginx_from_mitm.log")
if st.sidebar.button("🔄 Régénérer logs simulés"):
    generate_logs()
    st.sidebar.success("Logs régénérés !")
n_clusters = st.sidebar.slider("Clusters IA", 2, 6, 4)
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh 5s", value=False)
 
# Chargement
@st.cache_data(ttl=5)
def load_data(filepath, _k=0):
    if not os.path.exists(filepath):
        # Fallback logs simulés
        generate_logs(output_file="samples/mobile_api_logs.txt")
        return parse_log_file("samples/mobile_api_logs.txt")
    return parse_log_file(filepath)
 
df = load_data(log_file)
if df.empty:
    st.error("Aucune donnée.")
    st.stop()
 
alerts   = run_all_detections(df)
features = extract_ip_features(df)
clustered = run_clustering(features, n_clusters=n_clusters)
 
# Métriques
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total requêtes",    f"{len(df):,}")
c2.metric("Requêtes mobiles",  f"{df['is_mobile'].sum():,}")
c3.metric("Alertes",           len(alerts))
c4.metric("IPs uniques",       df["ip"].nunique())
 
st.divider()
 
# Alertes
st.subheader("🚨 Alertes")
if alerts:
    alert_df = pd.DataFrame([{"Type": a.type, "IP": a.ip, "Sévérité": a.severity,
                               "Count": a.count, "Détails": a.details} for a in alerts])
    st.dataframe(alert_df, use_container_width=True)
else:
    st.success("Aucune alerte.")
 
st.divider()
 
# Clustering
st.subheader("🤖 Clustering IA")
col_a, col_b = st.columns(2)
with col_a:
    fig = px.scatter(clustered, x="total_requests", y="auth_fail_ratio",
                     color="cluster_name", size="unique_endpoints",
                     hover_data=["ip", "nb_404"],
                     title="Clusters de comportement par IP")
    st.plotly_chart(fig, use_container_width=True)
with col_b:
    fig2 = px.pie(clustered["cluster_name"].value_counts().reset_index(),
                  names="cluster_name", values="count", title="Distribution clusters")
    st.plotly_chart(fig2, use_container_width=True)
 
st.divider()
 
# Trafic par heure
st.subheader("📈 Trafic par heure")
traffic = df.groupby("hour").size().reset_index(name="requêtes")
fig3 = px.bar(traffic, x="hour", y="requêtes", color="requêtes", color_continuous_scale="reds")
st.plotly_chart(fig3, use_container_width=True)
 
st.divider()
 
# Recommandations
st.subheader("💡 Recommandations")
for r in generate_recommendations(alerts):
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["priority"], "⚪")
    with st.expander(f"{icon} {r['title']}"):
        st.write(r["description"])
        if r.get("code"):
            st.code(r["code"], language="python")
 
# Auto-refresh
if auto_refresh:
    time.sleep(5)
    st.rerun()
```
 
---
 
### MODULE 8 : log_watcher.py (surveillance temps réel)
 
```python
import time, os, sys, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser.mobile_parser import parse_log_line
from detection.rules import run_all_detections
 
LOG_FILE = "logs/nginx_from_mitm.log"
 
class LogWatcher:
    def __init__(self, filepath, callback=None):
        self.filepath = filepath
        self.callback = callback
        self.records  = []
        self._running = False
 
    def watch(self, poll_interval=1.0):
        self._running = True
        while self._running and not os.path.exists(self.filepath):
            print(f"[⏳] Attente fichier {self.filepath}...")
            time.sleep(2)
        with open(self.filepath, "r") as f:
            f.seek(0, 2)
            while self._running:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                parsed = parse_log_line(line)
                if parsed:
                    self.records.append(parsed)
                    df = pd.DataFrame(self.records)
                    if self.callback:
                        self.callback(df, parsed)
 
    def stop(self):
        self._running = False
 
def on_new_log(df, latest):
    print(f"[+] {latest['ip']} | {latest['method']} {latest['endpoint']} | {latest['status']}")
    if len(df) % 50 == 0:
        alerts = run_all_detections(df)
        if alerts:
            print(f"\n{'='*50}")
            for a in alerts:
                print(f"  [{a.severity}] {a.type} — {a.ip}")
            print('='*50 + "\n")
 
if __name__ == "__main__":
    watcher = LogWatcher(LOG_FILE, callback=on_new_log)
    try:
        watcher.watch(poll_interval=0.5)
    except KeyboardInterrupt:
        watcher.stop()
```
 
---
 
### MODULE 9 : App Android (MainActivity.java)
 
```java
package com.example.apitrafficgen;
 
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import okhttp3.*;
 
public class MainActivity extends AppCompatActivity {
 
    // 10.0.2.2 = IP de la machine hôte depuis l'émulateur Android
    private static final String BASE_URL = "http://10.0.2.2:80/api/v1";
    private final OkHttpClient client = new OkHttpClient();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
 
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
 
        TextView logView = findViewById(R.id.logView);
 
        // Bouton 1 : Trafic normal
        Button btnNormal = findViewById(R.id.btnNormal);
        btnNormal.setOnClickListener(v -> executor.execute(() -> {
            for (int i = 0; i < 20; i++) {
                sendRequest("GET", "/products", null);
                sendRequest("GET", "/user/profile", null);
                sleep(500);
            }
            runOnUiThread(() -> logView.append("\n[✓] Trafic normal envoyé"));
        }));
 
        // Bouton 2 : Brute force
        Button btnBrute = findViewById(R.id.btnBrute);
        btnBrute.setOnClickListener(v -> executor.execute(() -> {
            String body = "{\"username\":\"admin\",\"password\":\"wrong\"}";
            for (int i = 0; i < 30; i++) {
                sendRequest("POST", "/login", body);
                sleep(200);
            }
            runOnUiThread(() -> logView.append("\n[!] Brute force (30 tentatives)"));
        }));
 
        // Bouton 3 : Spike
        Button btnSpike = findViewById(R.id.btnSpike);
        btnSpike.setOnClickListener(v -> {
            for (int t = 0; t < 5; t++) {
                executor.execute(() -> {
                    for (int i = 0; i < 40; i++) {
                        sendRequest("GET", "/products", null);
                        sleep(50);
                    }
                });
            }
            runOnUiThread(() -> logView.append("\n[!] Spike (200 req rapides)"));
        });
 
        // Bouton 4 : Énumération
        Button btnEnum = findViewById(R.id.btnEnum);
        btnEnum.setOnClickListener(v -> executor.execute(() -> {
            for (int i = 1; i <= 50; i++) {
                sendRequest("GET", "/user/" + i, null);
                sleep(100);
            }
            runOnUiThread(() -> logView.append("\n[!] Énumération (50 IDs)"));
        }));
    }
 
    private void sendRequest(String method, String path, String jsonBody) {
        try {
            Request.Builder builder = new Request.Builder()
                .url(BASE_URL + path)
                .header("User-Agent", "MobileApp/1.0 (Android 11; Pixel 6) OkHttp/4.11.0");
            if ("POST".equals(method) && jsonBody != null) {
                builder.post(RequestBody.create(jsonBody, MediaType.parse("application/json")));
            } else { builder.get(); }
            client.newCall(builder.build()).execute();
        } catch (IOException ignored) {}
    }
 
    private void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}
```
 
**build.gradle (app) — dépendance OkHttp :**
```gradle
implementation 'com.squareup.okhttp3:okhttp:4.11.0'
```
 
**res/xml/network_security_config.xml :**
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```
 
---
 
### MODULE 10 : Nginx config (nginx.conf / sites-available)
 
```nginx
server {
    listen 80;
    server_name localhost;
    access_log /var/log/nginx/mobile_api_access.log combined;
 
    location /api/v1/products     { return 200 '{"products":[]}'; add_header Content-Type application/json; }
    location /api/v1/login        { return 401 '{"error":"Invalid credentials"}'; add_header Content-Type application/json; }
    location /api/v1/user/        { return 200 '{"user":{"id":1}}'; add_header Content-Type application/json; }
    location /api/v1/             { return 200 '{"status":"ok"}'; add_header Content-Type application/json; }
    location /                    { return 404 '{"error":"Not found"}'; add_header Content-Type application/json; }
}
```
 
---
 
### MODULE 11 : benchmark/run_benchmark.py
 
*(Voir le fichier GUIDE_V2_RealLogs_Benchmark.md section F.2 pour le code complet — ~150 lignes)*
 
**Résumé** : compare Precision/Recall/F1/FPR entre logs Faker (3 runs) et logs réels (émulateur). Produit `benchmark/benchmark_results.csv` et `benchmark/benchmark_summary.json`.
 
---
 
## 🔧 Commandes de lancement
 
```bash
# 1. Setup
pip install -r requirements.txt
 
# 2. Démarrer émulateur AVD
emulator -avd Pixel_6_API_30
 
# 3. Configurer proxy
adb shell settings put global http_proxy 10.0.2.2:8080
 
# 4. Lancer mitmproxy avec addon
mitmdump -s mitm_addons/nginx_logger.py --listen-port 8080
 
# 5. Lancer Nginx
sudo systemctl start nginx    # Linux
nginx                          # Windows/Mac
 
# 6. Watcher temps réel
python log_watcher.py
 
# 7. Dashboard
streamlit run dashboard/streamlit_app.py
 
# 8. Test pipeline complet
python test_pipeline.py
 
# 9. Benchmark
python benchmark/run_benchmark.py
```
 
---
 
## ✅ État d'avancement
 
| Module | Statut | Notes |
|---|---|---|
| VulnSentinel cloné | ✅ Fait | Repo de base opérationnel |
| generator/log_generator.py | 📝 Code fourni | À créer dans le repo |
| mitm_addons/nginx_logger.py | 📝 Code fourni | À créer |
| parser/mobile_parser.py | 📝 Code fourni | À créer |
| detection/rules.py | 📝 Code fourni | À créer |
| ai/clustering.py | 📝 Code fourni | À créer |
| recommendations/advisor.py | 📝 Code fourni | À créer |
| dashboard/streamlit_app.py | 📝 Code fourni | À créer |
| log_watcher.py | 📝 Code fourni | À créer |
| App Android (Java) | 📝 Code fourni | Nouveau projet Android Studio |
| Nginx config | 📝 Fourni | À appliquer |
| benchmark/run_benchmark.py | 📝 Code fourni | À créer |
| Tests manuels émulateur | ⏳ À faire | Nécessite Android Studio installé |
| Benchmark complet | ⏳ À faire | Après tests émulateur |
 
---
 
## ⚠️ Points d'attention importants
 
1. **AVD** : Choisir **Google APIs** et NON **Google Play** (obligatoire pour configurer le proxy)
2. **IP hôte** : L'émulateur accède à la machine hôte via `10.0.2.2` (et non `127.0.0.1`)
3. **mitmproxy** : Doit tourner **avant** de lancer l'app Android
4. **Nginx** : Doit tourner sur le port **80** de la machine hôte
5. **Benchmark ground truth** : Pour les logs réels, il faut **noter manuellement** les IPs qui ont fait les tests d'attaque (boutons de l'app Android)
6. **Silhouette Score** : Si < 0.4, augmenter ou réduire le nombre de clusters K
7. **Python version** : Utiliser Python 3.10+
---
 
## 📚 Références clés
 
| Ressource | URL |
|---|---|
| VulnSentinel (base) | https://github.com/domino79/vulnsentinel |
| mitmproxy docs | https://docs.mitmproxy.org |
| Android AVD setup | https://developer.android.com/studio/run/emulator |
| HTTP Toolkit (alternative mitmproxy) | https://httptoolkit.com/docs/guides/android |
| OWASP API Security Top 10 | https://owasp.org/www-project-api-security |
| Scikit-learn K-Means | https://scikit-learn.org/stable/modules/clustering.html#k-means |
| Streamlit docs | https://docs.streamlit.io |
 
---
 
## 🎓 Chapitres du cours couverts
 
| Chapitre | Thème |
|---|---|
| Chap. 4 | Analyse de trafic réseau mobile |
| Chap. 14 | Sécurité des API REST mobiles |
| Lab 3 | Analyse de trafic (trafic mobile simulé + réel) |
| DevSecOps | Recommandations automatiques rate-limit / lockout / CAPTCHA |
 
---
 
*Fin du document de transfert — Mobile API Misuse Detector*
*Projet Binôme — Cours Sécurité Mobile — Université Marrakech*
*Généré le 28/04/2025 — Claude Sonnet 4.6*
