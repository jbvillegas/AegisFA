def normalize_log(source, raw_data): 

    normalized = {
        "event_id": None,
        "user": None,
        "ip": None,
        "action": None,
        "status": None,
    }

    if source == 'windows':
        normalized["event_id"] = raw_data.get("EventID")
        normalized["user"] = raw_data.get("User")
        normalized["ip"] = raw_data.get("IpAddress")
        normalized["action"] = raw_data.get("EventType")
        normalized["status"] = raw_data.get("Status")
    elif source == 'firewall':
        normalized["event_id"] = raw_data.get("rule_id")
        normalized["ip"] = raw_data.get("src_ip")
        normalized["action"] = raw_data.get("action")
        normalized["status"] = 'success' if raw_data.get("action") == 'allow' else 'failure'
    elif source == 'auth':
        normalized["event_id"] = raw_data.get("id")
        normalized["user"] = raw_data.get("username")
        normalized["ip"] = raw_data.get("source_ip")
        normalized["action"] = 'login'
        normalized["status"] = raw_data.get("result")
    
    return normalized 
         