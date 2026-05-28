"""
Email Sender - Sends alerts via SMTP
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class EmailSender:
    """
    Sends threat intelligence alerts via email.
    Supports HTML emails with formatted alerts.
    """

    def __init__(self, smtp_host: str, smtp_port: int, username: str,
                 password: str, config: Dict[str, Any] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.config = config or {}
        self.from_name = self.config.get("from_name", "CTI Bot")
        self.use_tls = self.config.get("use_tls", True)

    def send_alert(self, recipient: str, alert: Dict[str, Any]) -> bool:
        """Send a single alert via email."""
        subject = self._format_subject(alert)
        html_body = self._format_html_alert(alert)
        text_body = self._format_text_alert(alert)

        return self._send_email(recipient, subject, html_body, text_body)

    def send_alerts(self, recipient: str, alerts: List[Dict[str, Any]]) -> int:
        """Send multiple alerts in a digest email."""
        if not alerts:
            return 0

        subject = f"CTI Bot Alert Digest - {len(alerts)} new threats"
        html_body = self._format_html_digest(alerts)
        text_body = self._format_text_digest(alerts)

        if self._send_email(recipient, subject, html_body, text_body):
            return len(alerts)
        return 0

    def send_digest(self, recipients: List[str], alerts: List[Dict[str, Any]],
                    period: str = "daily") -> int:
        """Send a digest email to multiple recipients."""
        success = 0
        for recipient in recipients:
            if self.send_alerts(recipient, alerts):
                success += 1
        return success

    def _send_email(self, recipient: str, subject: str,
                    html_body: str, text_body: str) -> bool:
        """Send an email via SMTP."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.username}>"
            msg["To"] = recipient

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email sent to {recipient}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Error sending email to {recipient}: {e}")
            return False

    def _format_subject(self, alert: Dict[str, Any]) -> str:
        """Format email subject for an alert."""
        severity = alert.get("severity_label", "MEDIUM")
        category = alert.get("category", "ALERT")
        title = alert.get("title", "Unknown")[:80]

        return f"[{severity}] {category.upper()}: {title}"

    def _format_html_alert(self, alert: Dict[str, Any]) -> str:
        """Format a single alert as HTML."""
        severity = alert.get("severity_label", "MEDIUM")
        severity_score = alert.get("severity", 5.0)
        category = alert.get("category", "general")
        title = alert.get("title", "Unknown")
        url = alert.get("url", "")
        summary = alert.get("summary", "").replace("\n", "<br>")
        source = alert.get("source", "Unknown")

        color = "#FF0000" if severity == "CRITICAL" else \
                "#FFA500" if severity == "HIGH" else \
                "#FFFF00" if severity == "MEDIUM" else "#00FF00"

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="border-left: 5px solid {color}; padding-left: 15px; margin: 20px 0;">
                <h2 style="margin-top: 0; color: {color};">
                    {severity} ({severity_score}/10) - {category.upper()}
                </h2>
                <h3>{title}</h3>
                <p><strong>Source:</strong> {source}</p>
                <p>{summary}</p>
                {'<p><a href="' + url + '" style="color: #0066cc;">View Source</a></p>' if url else ''}
                {self._format_downloads_html(alert)}
                {self._format_ai_analysis_html(alert)}
            </div>
        </body>
        </html>
        """
        return html

    def _format_text_alert(self, alert: Dict[str, Any]) -> str:
        """Format a single alert as plain text."""
        severity = alert.get("severity_label", "MEDIUM")
        title = alert.get("title", "Unknown")
        url = alert.get("url", "")
        summary = alert.get("summary", "")
        source = alert.get("source", "Unknown")

        text = f"""
[{severity}] {title}
Source: {source}
URL: {url}

{summary}
"""
        if alert.get("download_links"):
            text += "\nDownloads:\n" + "\n".join(alert["download_links"][:5])

        return text

    def _format_html_digest(self, alerts: List[Dict[str, Any]]) -> str:
        """Format multiple alerts as HTML digest."""
        alert_sections = []
        for alert in alerts:
            alert_sections.append(self._format_html_alert(alert))

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h1>🛡️ Cyber Threat Intelligence Digest</h1>
            <p>{len(alerts)} alerts found</p>
            <hr>
            {''.join(alert_sections)}
        </body>
        </html>
        """
        return html

    def _format_text_digest(self, alerts: List[Dict[str, Any]]) -> str:
        """Format multiple alerts as text digest."""
        sections = [f"CTI Bot Alert Digest - {len(alerts)} alerts\n" + "=" * 50]

        for i, alert in enumerate(alerts, 1):
            sections.append(f"\n--- Alert {i} ---")
            sections.append(self._format_text_alert(alert))

        return "\n".join(sections)

    def _format_downloads_html(self, alert: Dict[str, Any]) -> str:
        """Format download links as HTML."""
        if not alert.get("download_links"):
            return ""

        links_html = "<p><strong>Downloads:</strong></p><ul>"
        for link in alert["download_links"][:5]:
            display = link[:60] + "..." if len(link) > 60 else link
            links_html += f'<li><a href="{link}">{display}</a></li>'
        links_html += "</ul>"

        return links_html

    def _format_ai_analysis_html(self, alert: Dict[str, Any]) -> str:
        """Format AI analysis as HTML."""
        if not alert.get("ai_analysis"):
            return ""

        analysis = alert["ai_analysis"].replace("\n", "<br>")
        return f'<div style="background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px;"><strong>🤖 AI Analysis:</strong><br>{analysis}</div>'

    def test_connection(self) -> bool:
        """Test SMTP connection."""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
            return True
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False
