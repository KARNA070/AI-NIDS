"""
email_alert.py
--------------
Sends SMTP email alerts for high-severity intrusion detections.
Configure via environment variables or pass kwargs directly.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class EmailAlerter:
    """
    Thin wrapper around Python's smtplib for sending alert emails.

    Configuration (in priority order):
      1. Constructor kwargs
      2. Environment variables:
           NIDS_SMTP_HOST, NIDS_SMTP_PORT, NIDS_SMTP_USER,
           NIDS_SMTP_PASS, NIDS_ALERT_TO
    """

    def __init__(
        self,
        smtp_host: str = None,
        smtp_port: int = None,
        smtp_user: str = None,
        smtp_pass: str = None,
        recipient: str = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host or os.getenv("NIDS_SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = smtp_port or int(os.getenv("NIDS_SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.getenv("NIDS_SMTP_USER", "")
        self.smtp_pass = smtp_pass or os.getenv("NIDS_SMTP_PASS", "")
        self.recipient = recipient or os.getenv("NIDS_ALERT_TO", "")
        self.use_tls   = use_tls

        if not self.smtp_user or not self.smtp_pass or not self.recipient:
            raise ValueError(
                "Email alerter requires smtp_user, smtp_pass, and recipient. "
                "Set them via constructor args or environment variables "
                "(NIDS_SMTP_USER, NIDS_SMTP_PASS, NIDS_ALERT_TO)."
            )

    def send(self, subject: str, body: str) -> None:
        """Compose and dispatch an alert email."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.smtp_user
        msg["To"]      = self.recipient

        # Plain-text body
        msg.attach(MIMEText(body, "plain"))

        # HTML body (same content, styled)
        html_body = self._to_html(body)
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_user, self.recipient, msg.as_string())
            logger.info(f"Alert email sent to {self.recipient}: {subject}")
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed. Check credentials.")
            raise
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            raise
        except OSError as e:
            logger.error(f"Network error sending email: {e}")
            raise

    @staticmethod
    def _to_html(plain_text: str) -> str:
        """Wrap plain alert text in minimal HTML for email clients."""
        lines = plain_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        lines_html = "".join(f"<p>{l}</p>" for l in lines.splitlines())
        return f"""
        <html><body style="font-family:monospace;background:#111;color:#0f0;padding:20px;">
        <h2 style="color:#f00;">🚨 NIDS Intrusion Alert</h2>
        {lines_html}
        </body></html>
        """
