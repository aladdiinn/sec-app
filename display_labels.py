"""
display_labels.py — Central source of truth for display terminology across BSmart SOC.
Internal database tables, columns, API routes, and agent payloads remain 'app' / 'applications'.
All user-facing templates, navigation, badges, emails, PDF/CSV headers, and audit logs use these labels.
"""

LABELS = {
    # Singular
    "website": "Website",
    "website_lower": "website",
    "website_upper": "WEBSITE",
    
    # Plural
    "websites": "Websites",
    "websites_lower": "websites",
    "websites_upper": "WEBSITES",
    
    # Navigation & Headers
    "total_websites": "Total Websites",
    "total_websites_upper": "TOTAL WEBSITES",
    "add_website": "Add Website",
    "add_website_upper": "ADD WEBSITE",
    "onboard_website": "Onboard Website",
    
    # Incidents & Monitoring
    "website_incident": "Website Incident",
    "website_incidents": "Website Incidents",
    "website_security": "Website Security Monitoring",
    "website_telemetry": "Website Telemetry",
    "website_log": "Website Log",
    "website_logs": "Website Logs",
    "website_node": "Website",
    "website_nodes": "Websites",
    
    # Contextual compound terms
    "servers_and_websites": "Servers and Websites",
    "all_services_assigned": "All services assigned to projects",
    
    # Exports & Reports
    "report_websites_header": "Monitored Websites",
    "csv_website_column": "Website",

    # Legacy Aliases for seamless migration
    "app_node": "Website",
    "app_nodes": "Websites",
    "app_node_upper": "WEBSITE",
    "app_nodes_upper": "WEBSITES",
    "total_apps": "Total Websites",
    "total_apps_upper": "TOTAL WEBSITES",
}

def get_label(key: str, default: str = "") -> str:
    """Retrieve a display label by key with safe fallback."""
    return LABELS.get(key, default or key.replace("_", " ").title())

def format_website_count(count: int) -> str:
    """Format website count with proper singular/plural grammar."""
    return f"{count} Website" if count == 1 else f"{count} Websites"
