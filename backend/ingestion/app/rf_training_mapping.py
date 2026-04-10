from typing import Iterable 

## CICIDS2019 RF TRAINING & MITRE ATT&CK correlation.
_BENIGN_ALIASES = {
	"benign",
	"normal",
	"normal_traffic",
}

_KNOWN_ATTACK_ALIASES = {
	"dos_hulk": "dos_hulk",
	"dos_goldeneye": "dos_goldeneye",
	"dos_slowhttptest": "dos_slowhttptest",
	"dos_slowloris": "dos_slowloris",
	"ddos": "ddos",
	"bot": "bot",
	"infiltration": "infiltration",
	"web_attack_brute_force": "web_attack_bruteforce",
	"web_attack_xss": "web_attack_xss",
	"web_attack_sql_injection": "web_attack_sql_injection",
	"heartbleed": "heartbleed",
	"ftp_patator": "ftp_patator",
	"ssh_patator": "ssh_patator",
	"portscan": "portscan",
	"syn": "syn",
	"udp_lag": "udp_lag",
}


def normalize_token(value: str) -> str:
	
	normalized = str(value or "").strip().lower()
	for char in ("-", "/", " "):
		normalized = normalized.replace(char, "_")
	while "__" in normalized:
		normalized = normalized.replace("__", "_")
	return normalized.strip("_")


def map_cicids2019_label(raw_label: str) -> str:
	"""Map CICIDS label values to a stable multi-class taxonomy."""
	token = normalize_token(raw_label)
	if not token:
		return "unknown"
	if token in _BENIGN_ALIASES:
		return "benign"
	if token in _KNOWN_ATTACK_ALIASES:
		return _KNOWN_ATTACK_ALIASES[token]
	return token


def map_cicids2019_labels(raw_labels: Iterable[str]) -> list[str]:
	##VECTORS MAPPING: Map raw CICIDS2019 labels to a stable multi-class taxonomy for RF training.
	return [map_cicids2019_label(label) for label in raw_labels]


# MITRE ATT&CK Technique Mappings for CICIDS Attack Classes
# Severity mapping reflects the inherent danger of each attack type
# Used to calculate confidence-adjusted severity for classifications
_CLASS_SEVERITY_MAPPING = {
	"benign": "low",
	"drdos_dns": "high",
	"drdos_ldap": "high",
	"drdos_mssql": "high",
	"drdos_ntp": "high",
	"drdos_netbios": "high",
	"drdos_snmp": "high",
	"drdos_ssdp": "high",
	"drdos_udp": "high",
	"dos_hulk": "medium",
	"dos_goldeneye": "medium",
	"dos_slowhttptest": "medium",
	"dos_slowloris": "medium",
	"ddos": "critical",
	"bot": "critical",
	"infiltration": "critical",
	"web_attack_bruteforce": "high",
	"web_attack_xss": "high",
	"web_attack_sql_injection": "high",
	"heartbleed": "critical",
	"ftp_patator": "high",
	"ssh_patator": "high",
	"portscan": "medium",
	"syn": "high",
	"udp_lag": "high",
}

_CLASS_TO_MITRE = {
	"benign": {
		"techniques": [],
		"summary": "Normal traffic, no adversarial activity detected.",
		"severity": "low",
	},
	"drdos_dns": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via DNS amplification.",
		"severity": "high",
	},
	"drdos_ldap": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via LDAP amplification.",
		"severity": "high",
	},
	"drdos_mssql": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via MSSQL amplification.",
		"severity": "high",
	},
	"drdos_ntp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via NTP amplification.",
		"severity": "high",
	},
	"drdos_netbios": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via NetBIOS amplification.",
		"severity": "high",
	},
	"drdos_snmp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via SNMP amplification.",
		"severity": "high",
	},
	"drdos_ssdp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via SSDP amplification.",
		"severity": "high",
	},
	"drdos_udp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
			{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
		],
		"summary": "DDoS attack via UDP amplification.",
		"severity": "high",
	},
	"dos_hulk": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "DoS attack using HTTP GET flooding (HULK).",
		"severity": "medium",
	},
	"dos_goldeneye": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "DoS attack using HTTP GET/POST flooding (GoldenEye).",
		"severity": "medium",
	},
	"dos_slowhttptest": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Slow HTTP DoS attack (SlowHTTP).",
		"severity": "medium",
	},
	"dos_slowloris": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Slow client connection DoS attack (Slowloris).",
		"severity": "medium",
	},
	"ddos": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Distributed Denial of Service attack.",
		"severity": "critical",
	},
	"bot": {
		"techniques": [
			{"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
		],
		"summary": "Botnet command and control communication.",
		"severity": "critical",
	},
	"infiltration": {
		"techniques": [
			{"id": "T1199", "name": "Trusted Relationship", "tactic": "Initial Access"},
		],
		"summary": "Potential data infiltration or unauthorized access.",
		"severity": "critical",
	},
	"web_attack_bruteforce": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "Web application brute force attack.",
		"severity": "high",
	},
	"web_attack_xss": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "Cross-site scripting (XSS) attack.",
		"severity": "high",
	},
	"web_attack_sql_injection": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "SQL injection attack on web application.",
		"severity": "high",
	},
	"heartbleed": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "Heartbleed vulnerability exploitation.",
		"severity": "critical",
	},
	"ftp_patator": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "FTP credential brute force attack.",
		"severity": "high",
	},
	"ssh_patator": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "SSH credential brute force attack.",
		"severity": "high",
	},
	"portscan": {
		"techniques": [
			{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
		],
		"summary": "Network port scanning reconnaissance.",
		"severity": "medium",
	},
	"syn": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "SYN flood denial of service attack.",
		"severity": "high",
	},
	"udp_lag": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "UDP-based denial of service causing network lag.",
		"severity": "high",
	},
}


def get_mitre_for_class(attack_class: str) -> dict:
	
	class_normalized = normalize_token(attack_class)
	return _CLASS_TO_MITRE.get(class_normalized, {
		"techniques": [],
		"summary": f"Unknown attack class: {attack_class}",
		"severity": "medium",
	})


def calculate_severity(attack_class: str, confidence: float) -> str:
	"""
	Calculate final severity based on base class severity and RF prediction confidence.
	
	Args:
		attack_class: CICIDS attack class label
		confidence: RF classifier prediction confidence (0.0-1.0)
	
	Returns:
		Severity level: 'low', 'medium', 'high', or 'critical'
	"""
	class_normalized = normalize_token(attack_class)
	base_severity = _CLASS_SEVERITY_MAPPING.get(class_normalized, "medium")
	
	# Confidence thresholds for severity adjustment
	# Lower confidence reduces severity by one level
	# Higher confidence can elevate low-confidence predictions
	if confidence < 0.5:
		# Low confidence - reduce severity by one level
		severity_hierarchy = ["low", "medium", "high", "critical"]
		try:
			current_idx = severity_hierarchy.index(base_severity)
			adjusted_idx = max(0, current_idx - 1)
			return severity_hierarchy[adjusted_idx]
		except ValueError:
			return "medium"
	elif confidence >= 0.8:
		# High confidence - elevate benign/low to medium if deserved
		if base_severity == "low" and attack_class != "benign":
			return "medium"
		return base_severity
	else:
		# Medium confidence (0.5-0.8) - use base severity
		return base_severity


def get_mitre_with_confidence(attack_class: str, confidence: float) -> dict:
	"""
	Get MITRE mapping enriched with confidence-adjusted severity.
	
	Args:
		attack_class: CICIDS attack class label
		confidence: RF classifier prediction confidence (0.0-1.0)
	
	Returns:
		Dict with MITRE techniques, summary, base severity, and adjusted severity
	"""
	mitre_data = get_mitre_for_class(attack_class)
	adjusted_severity = calculate_severity(attack_class, confidence)
	
	return {
		**mitre_data,
		"adjusted_severity": adjusted_severity,
		"confidence_score": round(confidence, 3),
	}


