"""
One-time script to seed the correlation_rules table with 10 default
MITRE ATT&CK correlation rules.

Usage:
    cd backend/ingestion
    python -m scripts.seed_rules
"""

import os
from dotenv import load_dotenv

load_dotenv()

from supabase import create_client

DEFAULT_RULES = [
    # 1. Brute Force Login (T1110)
    {
        "name": "Brute Force Login",
        "mitre_technique": "T1110",
        "severity": "high",
        "rule_logic": {
            "type": "threshold",
            "filter": [
                {"field": "action", "op": "eq", "value": "login"},
                {"field": "result", "op": "eq", "value": "failure"},
            ],
            "group_by": ["source_ip"],
            "threshold": 5,
            "window_seconds": 300,
            "base_confidence": 0.85,
        },
    },
    # 2. Successful Login After Brute Force (T1110.001)
    {
        "name": "Successful Login After Brute Force",
        "mitre_technique": "T1110.001",
        "severity": "critical",
        "rule_logic": {
            "type": "sequence",
            "steps": [
                [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "result", "op": "eq", "value": "failure"},
                ],
                [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "result", "op": "eq", "value": "success"},
                ],
            ],
            "group_by": ["source_ip", "username"],
            "window_seconds": 600,
            "base_confidence": 0.9,
        },
    },
    # 3. Privilege Escalation After Login (T1078)
    {
        "name": "Privilege Escalation After Login",
        "mitre_technique": "T1078",
        "severity": "critical",
        "rule_logic": {
            "type": "sequence",
            "steps": [
                [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "result", "op": "eq", "value": "success"},
                ],
                [{"field": "action", "op": "eq", "value": "privilege_escalation"}],
            ],
            "group_by": ["username"],
            "window_seconds": 300,
            "base_confidence": 0.9,
        },
    },
    # 4. Lateral Movement Detection (T1021)
    {
        "name": "Lateral Movement Detection",
        "mitre_technique": "T1021",
        "severity": "high",
        "rule_logic": {
            "type": "distinct_value",
            "filter": [
                {"field": "action", "op": "eq", "value": "login"},
                {"field": "result", "op": "eq", "value": "success"},
            ],
            "group_by": ["username"],
            "distinct_field": "source_ip",
            "distinct_threshold": 3,
            "window_seconds": 1800,
            "base_confidence": 0.75,
        },
    },
    # 5. Data Exfiltration (T1041)
    {
        "name": "Data Exfiltration",
        "mitre_technique": "T1041",
        "severity": "critical",
        "rule_logic": {
            "type": "existence",    
            "filter": [
                {"field": "action", "op": "eq", "value": "data_export"},
                {"field": "result", "op": "eq", "value": "success"},
            ],
            "base_confidence": 0.8,
        },
    },
    # 6. Reconnaissance Port Scanning (T1046)
    {
        "name": "Reconnaissance Port Scanning",
        "mitre_technique": "T1046",
        "severity": "medium",
        "rule_logic": {
            "type": "time_rate",
            "filter": [
                {
                    "field": "action",
                    "op": "in",
                    "value": [
                        "connection_attempt",
                        "port_scan",
                        "network_connection",
                    ],
                }
            ],
            "group_by": ["source_ip"],
            "rate_per_minute": 20,
            "window_seconds": 60,
            "base_confidence": 0.7,
        },
    },
    # 7. Sensitive File Access (T1005)
    {
        "name": "Sensitive File Access",
        "mitre_technique": "T1005",
        "severity": "high",
        "rule_logic": {
            "type": "existence",
            "filter": [
                {"field": "action", "op": "eq", "value": "file_access"},
                {
                    "field": "reason",
                    "op": "regex",
                    "value": "(shadow|passwd|sam|ntds|credentials|secret|\\.pem|\\.key)",
                },
            ],
            "base_confidence": 0.8,
        },
    },
    # 8. Suspicious External IP Communication (T1071)
    {
        "name": "Suspicious External IP Communication",
        "mitre_technique": "T1071",
        "severity": "medium",
        "rule_logic": {
            "type": "existence",
            "filter": [
                {
                    "field": "source_ip",
                    "op": "regex",
                    "value": "^(?!10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.).*$",
                },
                {
                    "field": "action",
                    "op": "in",
                    "value": ["data_export", "file_access", "network_connection"],
                },
            ],
            "base_confidence": 0.6,
        },
    },
    # 9. Credential Stuffing (T1078.001)
    {
        "name": "Credential Stuffing",
        "mitre_technique": "T1078.001",
        "severity": "high",
        "rule_logic": {
            "type": "distinct_value",
            "filter": [
                {"field": "action", "op": "eq", "value": "login"},
                {"field": "result", "op": "eq", "value": "failure"},
            ],
            "group_by": ["source_ip"],
            "distinct_field": "username",
            "distinct_threshold": 3,
            "window_seconds": 600,
            "base_confidence": 0.8,
        },
    },
    # 10. Full Attack Chain (T1110 + T1041)
    {
        "name": "Full Attack Chain Detection",
        "mitre_technique": "T1110,T1041",
        "severity": "critical",
        "rule_logic": {
            "type": "sequence",
            "steps": [
                [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "result", "op": "eq", "value": "failure"},
                ],
                [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "result", "op": "eq", "value": "success"},
                ],
                [{"field": "action", "op": "eq", "value": "privilege_escalation"}],
                [{"field": "action", "op": "eq", "value": "data_export"}],
            ],
            "group_by": ["username"],
            "window_seconds": 3600,
            "base_confidence": 0.95,
        },
    },
]


def seed_rules():
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"],
    )

    for rule in DEFAULT_RULES:
        supabase.table("correlation_rules").upsert(
            {
                "org_id": None,
                "name": rule["name"],
                "mitre_technique": rule["mitre_technique"],
                "severity": rule["severity"],
                "rule_logic": rule["rule_logic"],
            },
            on_conflict="name",
        ).execute()
        print(f"  Seeded: {rule['name']} ({rule['mitre_technique']})")

    print(f"\nDone -- seeded {len(DEFAULT_RULES)} correlation rules.")


if __name__ == "__main__":
    seed_rules()
