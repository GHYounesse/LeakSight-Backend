# 🛡️ LeakSight Backend – Threat Intelligence Monitoring API  

This project is a **FastAPI-based backend** for a **Threat Intelligence Monitoring App**.  
It monitors **Telegram channels** for threat intelligence updates, allows users to **CRUD IOCs (Indicators of Compromise)**, and provides **IOC enrichment** using multiple free cybersecurity APIs.  
Additionally, it stays up-to-date with the latest **cybersecurity news** and streams updates via **WebSockets**.  

---

## 🚀 Features  

- 📡 **Telegram Monitoring** – Collect threat intelligence from monitored channels.  
- 📂 **IOC Management** – Create, Read, Update, Delete IOCs (IP, domains, URLs, hashes, etc.).  
- 🔎 **IOC Enrichment** – Query multiple free APIs like VirusTotal, Shodan, AlienVault, AbuseIPDB, etc.  
- 📰 **Cybersecurity News Feed** – Stay updated with the latest threat intel reports.  
- 🔐 **Secure Authentication** – JWT-based authentication with refresh tokens and brute-force protection.  
- ⚡ **Fast & Async** – Built on **FastAPI** + **MongoDB** + **Redis**.  
- 🔔 **WebSocket Notifications** – Real-time alerts for new IOCs and events.  

---

## 📂 Project Structure  
```css

LEAKSIGHT-BACKEND
│── app/
│ ├── api/ # API routes
│ ├── crud/ # Database operations
│ ├── models/ # Pydantic & DB models
│ ├── services/ # Business logic (Telegram, IOC enrichment, etc.)
│ ├── utils/ # Helper functions
│ ├── config.py # Settings & env management
│ ├── database.py # MongoDB connection
│ ├── dependencies.py # Security & auth dependencies
│ ├── main.py # FastAPI app entry point
│ ├── worker.py # Background tasks & Redis worker
│── static/ # Static files (if needed)
│── venv/ # Virtual environment
│── .env # Environment variables (see below)
│── requirements.txt # Python dependencies
│── run.py # App launcher
```
---

## ⚙️ Installation  

### 1️⃣ Clone the repository  

```bash
git clone https://github.com/GHYounesse/LeakSight-Backend.git
cd LeakSight-Backend
```
### 2️⃣ Create & activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

```
### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Setup .env

Create a .env file in the root directory with your configuration.

Example .env:
```
# MongoDB
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=leaksight_db

# JWT
SECRET_KEY=supersecretkey
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=60

# Security
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# API Keys (Fake placeholders – replace with real ones)
MZ_AUTH_KEY=fake_mz_key
VT_AUTH_KEY=fake_vt_key
SHODAN_AUTH_KEY=fake_shodan_key
ALIEN_VAULT_KEY=fake_alien_key
HA_AUTH_KEY=fake_ha_key
URLS_AUTH_KEY=fake_urls_key
ABUSEIPDB_AUTH_KEY=fake_abuseipdb_key

# Telegram
TELEGRAM_API_ID=123456
TELEGRAM_API_HASH=fakehash
TELEGRAM_PHONE=+10000000000

# Token generation
TOKEN_EXPIRY_HOURS=12
TOKEN_LENGTH=32

# Frontend & Email
FRONTEND_URL=http://localhost:3000
SMTP_SERVER=smtp.mailtrap.io
SMTP_PORT=587
SMTP_USERNAME=fake_smtp_user
SMTP_PASSWORD=fake_smtp_pass
FROM_EMAIL=alerts@leaksight.io

# GROQ
GROQ_API_KEY=fake_groq_key
GROQ_API_URL=https://api.groq.com
MODEL=gpt-neo

# WebSocket
WEBSOCKET_HOST=localhost
WEBSOCKET_PORT=8001
```


## 🗄️ Running Services
### 1️⃣ Start MongoDB

If using Docker:
```bash
docker run -d --name leaksight-mongo -p 27017:27017 mongo:latest
```

### 2️⃣ Start Redis
```bash
docker run -d --name leaksight-redis -p 6379:6379 redis:latest
```


## ▶️ Running the App
### 1️⃣ Run FastAPI
```bash
py.exe run.py
```

The API will be available at:
👉 http://localhost:8080

### 2️⃣ Run Background Worker That Normalizes Feeds
```bash
python app/worker.py
```
### 3️⃣ Run the Telegram Monitor script
```bash
python utils.telegram_leak_monitor.py
```
