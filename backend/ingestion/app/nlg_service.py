def generate_natural_language_summary(source: str, normalized_data: dict) -> str:

    event_id = normalized_data.get("event_id", "unknown event")
    user = normalized_data.get("user", "unknown user")
    action = normalized_data.get("action", "unknown action")
    status = normalized_data.get("status", "unknown status")
    ip = normalized_data.get("ip", "unknown IP")

    status_txt = "succeeded" if status == "success" else "failed"

    action_descriptions = {
        'login': "logged in",
        'logout': "logged out",
        'file_access': "accessed a file",
        'file_modification': "modified a file",
        'file_deletion': "deleted a file",
        'data_export': "exported data",
        'permission_change': "changed permissions",
        'configuration_change': "changed system configuration",
        'network_connection': "established a network connection",
        'process_start': "started a process",
        'process_stop': "stopped a process",
        'privilege_escalation': "escalated privileges",
        'malware_detection': "detected malware",
        'anomaly_detection': "detected an anomaly",
        'password_change': "changed password",
        'connection_denyed': "denied a connection",
    }

    action_txt = action_descriptions.get(action, f"performed {action}")

    if source == 'auth':
        summary = f"{user} {action_txt} and the attempt {status_txt}"
        if ip:
            summary += f"from IP: {ip}"
    elif source == 'firewall':
        direction = "incoming" if action in action.lower() else "outgoing"
        summary = f"Firewall {status} {direction} connection" 
        if ip:
            summary += f" to/from: {ip}"
    elif source == 'windows':
        summary = f"System {status_txt} {action_txt}"
        if user: 
            summary += f"by {user}"
    else: 
        summary = f"System event: {action} with status {status}"
    
    return summary.strip() + "."