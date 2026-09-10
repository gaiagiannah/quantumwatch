import os
import requests
from typing import Dict, Any

class AlertDispatcher:
    """
    Dispatches emergency threat notifications to Slack/Discord/Custom webhooks.
    """
    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url or os.getenv("QUANTUMWATCH_WEBHOOK_URL", "")

    def send_alert(self, assessment: Dict[str, Any]) -> bool:
        """Sends structured JSON payload if a high-risk or sanctioned address is identified."""
        if not self.webhook_url:
            print("[-] No Webhook URL provided. Skipping alert dispatch.")
            return False

        # Format alert payload
        is_critical = assessment["composite_score"] >= 75.0 or assessment["is_sanctioned"]
        
        payload = {
            "text": f"🚨 *QUANTUMWATCH SECURITY ALERT* [{assessment['risk_tier']}]",
            "attachments": [
                {
                    "color": "#FF0000" if is_critical else "#FFA500",
                    "fields": [
                        {"title": "Target Address", "value": f"`{assessment['address']}`", "short": False},
                        {"title": "Composite Score", "value": f"{assessment['composite_score']}/100", "short": True},
                        {"title": "OFAC Sanctioned", "value": "YES" if assessment['is_sanctioned'] else "NO", "short": True},
                        {"title": "Public Key Exposed", "value": "YES" if assessment['pubkey_exposed'] else "NO", "short": True},
                        {"title": "Secured Value", "value": f"${assessment['secp256k1_value_usd']:,.2f}", "short": True},
                        {"title": "PQC Migration Needed", "value": "YES" if assessment['pqc_migration_required'] else "NO", "short": True}
                    ]
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"[-] Failed to dispatch webhook alert: {e}")
            return False