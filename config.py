"""
Configuration for OrcaSOC - AI-Powered Cyber Threat Intelligence Bot
"""
import os
from pathlib import Path

# === Base Paths ===
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# === Telegram Configuration ===
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_ADMIN_IDS = list(map(int, os.getenv("TELEGRAM_ADMIN_IDS", "").split(","))) if os.getenv("TELEGRAM_ADMIN_IDS") else []

# === Discord Configuration (Optional) ===
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# === Email Configuration (Optional) ===
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_RECIPIENTS = os.getenv("EMAIL_RECIPIENTS", "").split(",") if os.getenv("EMAIL_RECIPIENTS") else []

# === AI Configuration (Gemini API) ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
AI_ENABLED = bool(GEMINI_API_KEY)

# === Severity Thresholds ===
MIN_SEVERITY_TO_ALERT = float(os.getenv("MIN_SEVERITY_TO_ALERT", "5.0"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "10"))

# === Collection Settings ===
MAX_ITEMS_PER_SOURCE = int(os.getenv("MAX_ITEMS_PER_SOURCE", "20"))
SUMMARY_MAX_LENGTH = int(os.getenv("SUMMARY_MAX_LENGTH", "2000"))
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))

# === Duplicate Detection ===
DUPLICATE_SIMILARITY_THRESHOLD = float(os.getenv("DUPLICATE_SIMILARITY_THRESHOLD", "0.85"))
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# === Rate Limiting ===
RATE_LIMIT_MESSAGES_PER_MINUTE = int(os.getenv("RATE_LIMIT_MESSAGES_PER_MINUTE", "20"))

# === Bot Commands ===
COMMANDS = {
    "start": "Subscribe to threat intelligence alerts",
    "stop": "Unsubscribe from alerts",
    "status": "Get bot status and statistics",
    "stats": "Get threat statistics (admin only)",
    "force_run": "Force a collection run (admin only)",
    "broadcast": "Broadcast a message to all users (admin only)",
    "help": "Show available commands",
}

# === Data Files ===
USERS_DB = DATA_DIR / "users.db"
NEWS_DB = DATA_DIR / "news.db"
STATE_FILE = DATA_DIR / "state.json"
EMBEDDINGS_DB = DATA_DIR / "embeddings.db"

# === Source URLs ===
SOURCES = {
    "cve": {
        "nvd_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "cve_details_rss": "https://cvedetails.com/cves-by-jooby.php",
    },
    "exploit": {
        "exploitdb_rss": "https://www.exploit-db.com/rss.xml",
        "packetstorm": "https://rss.packetstormsecurity.com/files/",
    },
    "github": {
        "poc_search_url": "https://api.github.com/search/repositories",
        "security_repos": [
            "PoC-in-GitHub",
            "nomi-sec",
            "/trickest",
        ],
    },
    "ai": {
        "huggingface_api": "https://huggingface.co/api/models",
        "paperswithcode": "https://paperswithcode.com/api/v1/papers/",
    },
    "reddit": {
        "subreddits": [
            "cybersecurity",
            "netsec",
            "Malware",
            "ThreatIntelligence",
            "redteamsec",
            "blueteamsec",
        ],
    },
    "rss": {
        "feeds": [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
            "https://threatpost.com/feed/",
            "https://www.darkreading.com/rss.xml",
            "https://krebsonsecurity.com/feed/",
            "https://www.schneier.com/blog/atom.xml",
        ],
    },
    "ransomware": {
        "ransomware_live": "https://ransomware.live/api/v2/recent",
    },
    "leaks": {
        "breach_notice": "https://haveibeenpwned.com/api/v3/breaches",
    },
}

# === Categories ===
THREAT_CATEGORIES = [
    "cve",
    "exploit",
    "github_poc",
    "ai_tool",
    "red_team_tool",
    "malware_analysis",
    "threat_report",
    "data_breach",
    "ransomware",
    "osint_tool",
    "dfir_tool",
    "security_research",
    "ai_model",
    "prompt_injection",
    "jailbreak",
    "dataset",
]

# === Severity Mapping ===
SEVERITY_LEVELS = {
    "CRITICAL": {"min": 9.0, "color": "🔴", "label": "CRITICAL"},
    "HIGH": {"min": 7.0, "color": "🟠", "label": "HIGH"},
    "MEDIUM": {"min": 4.0, "color": "🟡", "label": "MEDIUM"},
    "LOW": {"min": 0.0, "color": "🟢", "label": "LOW"},
}

# === Logging ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
