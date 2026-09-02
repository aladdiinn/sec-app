import requests
import os
from logging_config import setup_logging

logger = setup_logging("soar-engine")

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://localhost:8005")

class ActionHandler:
    @staticmethod
    def isolate_host(server_id: int):
        logger.warning(f"Executing ACTION: Isolate Host for server {server_id}")
        payload = {"server_id": server_id, "action": "isolate"}
        try:
            # Command sent to integration service which talks to agents
            requests.post(f"{INTEGRATION_SERVICE_URL}/agent/command", json=payload)
        except Exception as e:
            logger.error(f"Failed to isolate host {server_id}: {e}")

    @staticmethod
    def block_ip(ip_address: str):
        logger.warning(f"Executing ACTION: Block IP {ip_address}")
        payload = {"ip": ip_address, "action": "block"}
        # Example: talk to firewall or cloud API
        logger.info(f"IP {ip_address} added to blocklist.")

    @staticmethod
    def notify_analyst(message: str):
        logger.info(f"Executing ACTION: Notify Analyst - {message}")
        # In real world: send to Slack/Teams/Email

def execute_playbook(playbook_data: dict, context: dict):
    logger.info(f"Running Playbook: {playbook_data['name']}")
    
    for action in playbook_data.get("actions", []):
        action_name = action.get("name")
        params = action.get("params", {})
        
        # Replace placeholders with context data
        # e.g., if params["server_id"] == "{{server_id}}"
        
        if action_name == "isolate_host":
            ActionHandler.isolate_host(context.get("server_id"))
        elif action_name == "block_ip":
            ActionHandler.block_ip(context.get("source_ip"))
        elif action_name == "notify":
            ActionHandler.notify_analyst(f"Alert triggered: {context.get('alert_title')}")
