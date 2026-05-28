# OrcaSOC 🐋

OrcaSOC is an advanced, AI-powered Cyber Threat Intelligence (CTI) Telegram Bot designed to monitor, analyze, and alert on emerging cybersecurity threats in real-time. By leveraging the power of Google's Gemini API, OrcaSOC provides concise summaries, actionable insights, and severity assessments for vulnerabilities, exploits, data breaches, and more.

## 🌟 Features

- **AI-Powered Analysis**: Utilizes Google's Gemini API (`gemini-2.0-flash`) to summarize threats, assess risks, and provide actionable recommendations.
- **Multi-Source Threat Intelligence**: Aggregates data from NVD (CVEs), Exploit-DB, GitHub PoCs, Ransomware monitors, Data Breach alerts (HIBP), Reddit, and various RSS feeds.
- **Automated Workflow**: Runs seamlessly via GitHub Actions every 15 minutes, ensuring you are always up-to-date without the need for a dedicated VPS.
- **Smart Filtering & Relevance Engine**: Filters out noise and ranks alerts based on severity and relevance to your environment.
- **Multi-Channel Notifications**: Sends alerts primarily via Telegram, with optional support for Discord webhooks and Email.
- **State Management**: Automatically commits and pushes state data (`data/state.json`) to the repository to prevent duplicate alerts across runs.

## 🏗️ Architecture

OrcaSOC is built with a modular architecture to ensure scalability and ease of maintenance:

1. **Collectors**: Modules responsible for fetching data from various sources (e.g., `cve_collector.py`, `github_collector.py`, `ransomware_monitor.py`).
2. **AI Engine**: Integrates with Gemini API for processing raw data (`summarizer.py`, `ai_threat_analyst.py`, `classifier.py`, `relevance_engine.py`).
3. **Storage**: Manages state and persistence using local JSON files and SQLite databases (`persistence.py`, `state_manager.py`).
4. **Notifier**: Handles the delivery of alerts to configured channels (`telegram_sender.py`, `discord_sender.py`, `email_sender.py`).
5. **GitHub Actions**: Orchestrates the execution of the bot on a scheduled cron job (`bot.yml`).

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/OrcaSOC.git
cd OrcaSOC
```

### 2. Configure Environment Variables

Copy the example environment file and fill in your details:

```bash
cp .env.example .env
```

**Required Variables:**
- `TELEGRAM_BOT_TOKEN`: Your Telegram Bot token (from @BotFather).
- `TELEGRAM_CHAT_ID`: The ID of the chat/channel where alerts will be sent.
- `GEMINI_API_KEY`: Your Google Gemini API key.

### 3. GitHub Actions Setup

To run OrcaSOC automatically without a server, configure the following secrets in your GitHub repository (`Settings > Secrets and variables > Actions`):

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `TELEGRAM_ADMIN_IDS` (Optional)
- `GEMINI_API_KEY`
- `NVD_API_KEY` (Optional, for higher rate limits)
- `HIBP_API_KEY` (Optional, for breach data)
- `GITHUB_TOKEN` (Optional, for GitHub API access)

The workflow is pre-configured in `.github/workflows/bot.yml` to run every 15 minutes. It will automatically commit changes to the `data/` directory to maintain state.

## 🧠 AI Pipeline

OrcaSOC's AI pipeline is powered entirely by the **Gemini API**. The workflow is as follows:

1. **Classification**: The `classifier.py` categorizes incoming data (e.g., CVE, Exploit, Ransomware) and assigns an initial relevance score.
2. **Relevance Scoring**: The `relevance_engine.py` evaluates the content against high-value keywords and severity metrics to filter out noise.
3. **Summarization**: The `summarizer.py` generates a concise, 3-sentence summary focusing on the threat, affected entities, and required actions.
4. **Threat Analysis**: The `ai_threat_analyst.py` provides a deep dive into *Why it matters*, *Risk Assessment*, and *Actionable Recommendations*.

## 📡 Threat Intelligence Sources

- **Vulnerabilities**: NVD API, CVE Details RSS
- **Exploits**: Exploit-DB, PacketStorm
- **Code & PoCs**: GitHub Repository Search
- **Data Breaches**: Have I Been Pwned (HIBP) API
- **Ransomware**: Ransomware.live API
- **Community & News**: Reddit (r/cybersecurity, r/netsec, etc.), Hacker News, BleepingComputer, Threatpost, Dark Reading

## 🤖 Telegram Commands

Interact with OrcaSOC directly via Telegram:

- `/start` - Subscribe to threat intelligence alerts.
- `/stop` - Unsubscribe from alerts.
- `/status` - Get bot status and statistics.
- `/stats` - Get threat statistics (Admin only).
- `/force_run` - Force a collection run immediately (Admin only).
- `/broadcast` - Broadcast a message to all users (Admin only).
- `/help` - Show available commands.

## 📸 Example Alert

*(Mock Example of a Telegram Alert)*

🚨 **CRITICAL THREAT DETECTED** 🚨

**Title:** CVE-2026-XXXX: Remote Code Execution in Example Service
**Category:** Vulnerability (CVE)
**Severity:** 9.8/10 🔴

**Summary:**
A critical unauthenticated Remote Code Execution (RCE) vulnerability has been discovered in Example Service v2.0. Attackers can exploit this flaw to gain full control over affected systems. Immediate patching is required.

**Why this matters:**
- Critical vulnerability with potential for widespread exploitation.
- Public PoC/exploit available increases risk.

**Actionable Recommendations:**
- Check if affected systems are in your environment.
- Prioritize patching or apply mitigations immediately.
- Monitor vendor advisories for updates.

**Source:** NVD
[View Details](https://nvd.nist.gov/vuln/detail/CVE-2026-XXXX)

---

*Built with ❤️ by the Cybersecurity Community.*
