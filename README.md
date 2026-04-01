<div align="center">

<img src="https://img.shields.io/badge/CyberMitra-Security%20Automation-red?style=for-the-badge&logo=shield&logoColor=white" alt="CyberMitra"/>

# 🛡️ CyberMitra — Security Automation Backend

### *Analyze URLs, Passwords & Files for Potential Threats — Powered by VirusTotal API*

[![Live Demo](https://img.shields.io/badge/🌐%20Live%20Demo-cyber--mitra.vercel.app-blue?style=for-the-badge)](https://cyber-mitra.vercel.app)
[![Java](https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen?style=for-the-badge&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Docker](https://img.shields.io/badge/Docker-Containerized-blue?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=for-the-badge&logo=vercel&logoColor=white)](https://vercel.com/)
[![Railway](https://img.shields.io/badge/Backend-Railway-purple?style=for-the-badge&logo=railway&logoColor=white)](https://railway.app/)

</div>

---

## 📌 What is CyberMitra?

**CyberMitra** is a backend-driven cybersecurity verification platform that helps users detect potential threats in real time — without storing any user data.

It integrates **VirusTotal API** and other security APIs to provide accurate, real-time threat analysis for:

- 🔗 **URLs** — Detects phishing links, malicious domains via VirusTotal
- 🔐 **Passwords** — Evaluates strength, checks against known vulnerabilities  
- 📁 **Files** — Scans file content using external security APIs

> **Privacy First** — No database. No data stored. Every scan is stateless.

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────┐
│     Frontend (HTML + CSS + JS)       │
│         hosted on Vercel             │
└──────────────┬───────────────────────┘
               │  REST API calls
               ▼
┌──────────────────────────────────────┐
│      Spring Boot Backend             │
│      hosted on Railway / Render      │
│                                      │
│  ┌────────────┐   ┌───────────────┐  │
│  │ Controller │──▶│   Service     │  │
│  │  Layer     │   │   Layer       │  │
│  └────────────┘   └──────┬────────┘  │
└─────────────────────────┼────────────┘
                          │  External API calls
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │  VirusTotal  │ │  Password    │ │   Other      │
  │     API      │ │  Check APIs  │ │  Security    │
  │              │ │              │ │    APIs      │
  └──────────────┘ └──────────────┘ └──────────────┘
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔗 URL Scanner | Real-time phishing & malicious URL detection via VirusTotal API |
| 🔐 Password Analyzer | Strength scoring + vulnerability detection |
| 📁 File Scanner | External API-based file threat analysis |
| 🚫 No Database | Stateless — zero data retention, privacy first |
| 🐳 Docker | Fully containerized backend |
| 🌐 Full Deployment | Frontend on Vercel, Backend on Railway / Render |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Java 21 |
| **Framework** | Spring Boot 3.x |
| **Build Tool** | Maven |
| **Frontend** | HTML + CSS + JavaScript |
| **Security APIs** | VirusTotal API + additional threat intelligence APIs |
| **Container** | Docker |
| **Frontend Deploy** | Vercel |
| **Backend Deploy** | Railway / Render |
| **Architecture** | Controller → Service (Layered, Stateless) |

---

## 📁 Project Structure

```
CyberMitra/
├── src/main/java/
│   ├── controller/           # REST API endpoints
│   │   ├── UrlController.java
│   │   ├── PasswordController.java
│   │   └── FileController.java
│   ├── service/              # Business logic + API integration
│   │   ├── UrlScanService.java
│   │   ├── PasswordService.java
│   │   └── FileService.java
│   └── config/               # App configuration
├── cybersafe-frontend/        # HTML + CSS + JS frontend
│   ├── index.html
│   ├── style.css
│   └── script.js
├── Dockerfile                 # Container configuration
├── pom.xml                    # Maven dependencies
└── README.md
```

---

## 🚀 Quick Start — Run Locally

### Prerequisites
- Java 21+
- Maven 3.9+
- Docker (optional)
- VirusTotal API Key — [Get free key here](https://www.virustotal.com/gui/join-us)

### Option 1: Run with Docker 🐳 (Recommended)

```bash
# Clone the repository
git clone https://github.com/iamvineetupadhyay/CyberMitra.git
cd CyberMitra

# Build Docker image
docker build -t cybermitra .

# Run with your API key
docker run -p 8080:8080 \
  -e VIRUSTOTAL_API_KEY=your_api_key_here \
  cybermitra
```

### Option 2: Run with Maven

```bash
# Clone the repository
git clone https://github.com/iamvineetupadhyay/CyberMitra.git
cd CyberMitra

# Add API key in application.properties
# virustotal.api.key=your_api_key_here

# Run
./mvnw spring-boot:run
```

Backend runs at: `http://localhost:8080`

---

## 📡 API Endpoints

### URL Scanner
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/url` | Scan URL via VirusTotal |

### Password Analyzer
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/password` | Analyze password strength |

### File Scanner
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/file` | Upload and scan a file |

### Sample Request
```json
POST /api/scan/url
Content-Type: application/json

{
  "url": "https://suspicious-site.com"
}
```

### Sample Response
```json
{
  "url": "https://suspicious-site.com",
  "status": "MALICIOUS",
  "riskLevel": "HIGH",
  "detectedBy": 23,
  "totalEngines": 90,
  "source": "VirusTotal"
}
```

---

## 🌐 Live Demo

> 🔗 **[cyber-mitra.vercel.app](https://cyber-mitra.vercel.app)**

---

## 🗺️ Roadmap — What's Coming Next

- [ ] **VAJRA Integration** — Advanced threat intelligence module ⚡
- [ ] **React Migration** — Moving frontend from HTML/CSS/JS → React
- [ ] **Bulk URL Scanning** — Scan multiple URLs simultaneously
- [ ] **Scan Analytics Dashboard** — Visual threat report UI
- [ ] **Real-time Threat Feeds** — Live threat intelligence integration
- [ ] **Browser Extension** — Scan URLs directly from browser

---

## 📈 What I Learned

- Integrating **third-party security APIs** (VirusTotal) in Spring Boot
- Building a **stateless backend** — no database, pure API orchestration
- **Containerizing** a Spring Boot application with Docker
- **Multi-platform deployment** — Railway + Render + Vercel
- Writing clean **layered architecture** (Controller → Service)
- Handling **external API rate limits** and error responses gracefully

---

## 👨‍💻 Author

**Vineet Kumar Upadhyay**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/iamvineetupadhyay)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat-square&logo=github)](https://github.com/iamvineetupadhyay)
[![Email](https://img.shields.io/badge/Email-iec.vineet@gmail.com-red?style=flat-square&logo=gmail)](mailto:iec.vineet@gmail.com)

> *"Building production-grade systems from scratch — one commit at a time."*

---

<div align="center">

⭐ **If this helped you, please star the repo!** ⭐

</div>
