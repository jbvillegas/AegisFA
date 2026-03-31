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
_CLASS_TO_MITRE = {
	"benign": {
		"techniques": [],
		"summary": "Normal traffic, no adversarial activity detected.",
	},
	"drdos_dns": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via DNS amplification.",
	},
	"drdos_ldap": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via LDAP amplification.",
	},
	"drdos_mssql": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via MSSQL amplification.",
	},
	"drdos_ntp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via NTP amplification.",
	},
	"drdos_netbios": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via NetBIOS amplification.",
	},
	"drdos_snmp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via SNMP amplification.",
	},
	"drdos_ssdp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via SSDP amplification.",
	},
	"drdos_udp": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
		],
		"summary": "DDoS attack via UDP amplification.",
	},
	"dos_hulk": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "DoS attack using HTTP GET flooding (HULK).",
	},
	"dos_goldeneye": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "DoS attack using HTTP GET/POST flooding (GoldenEye).",
	},
	"dos_slowhttptest": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Slow HTTP DoS attack (SlowHTTP).",
	},
	"dos_slowloris": {
		"techniques": [
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Slow client connection DoS attack (Slowloris).",
	},
	"ddos": {
		"techniques": [
			{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
			{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
		],
		"summary": "Distributed Denial of Service attack.",
	},
	"bot": {
		"techniques": [
			{"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
		],
		"summary": "Botnet command and control communication.",
	},
	"infiltration": {
		"techniques": [
			{"id": "T1199", "name": "Trusted Relationship", "tactic": "Initial Access"},
		],
		"summary": "Potential data infiltration or unauthorized access.",
	},
	"web_attack_bruteforce": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "Web application brute force attack.",
	},
	"web_attack_xss": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "Cross-site scripting (XSS) attack.",
	},
	"web_attack_sql_injection": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "SQL injection attack on web application.",
	},
	"heartbleed": {
		"techniques": [
			{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
		],
		"summary": "Heartbleed vulnerability exploitation.",
	},
	"ftp_patator": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "FTP credential brute force attack.",
	},
	"ssh_patator": {
		"techniques": [
			{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
		],
		"summary": "SSH credential brute force attack.",
	},
	"portscan": {
		"techniques": [
			{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
		],
		"summary": "Network port scanning reconnaissance.",
	},
}


def get_mitre_for_class(attack_class: str) -> dict:
	
	class_normalized = normalize_token(attack_class)
	return _CLASS_TO_MITRE.get(class_normalized, {
		"techniques": [],
		"summary": f"Unknown attack class: {attack_class}",
	})

