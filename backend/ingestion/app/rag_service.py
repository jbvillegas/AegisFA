import json

from . import supabase_client
from .openai_client import get_openai_client, get_embedding

def analyze_threats(
    log_entries: list[dict],
    source_type: str,
    detections: list[dict] = None,
) -> dict:
    
    client = get_openai_client()
    findings = _detect_threats(client, log_entries, source_type)
    mitre_context = _retrieve_mitre_techniques(findings, source_type)
    summary_result = _generate_incident_summary(
        client, log_entries, source_type, findings, mitre_context,
        detections=detections,
    )

    threat_level = _determine_threat_level(findings)

    return {
        "threat_level": threat_level,
        "threats_found": len(findings),
        "summary": summary_result["summary"],
        "detailed_findings": findings,
        "mitre_techniques": summary_result["mitre_techniques"],
        "attack_vector": summary_result["attack_vector"],
        "timeline": summary_result["timeline"],
        "impacted_assets": summary_result["impacted_assets"],
        "confidence_score": summary_result["confidence_score"],
        "remediation_steps": summary_result["remediation_steps"],
    }

def _detect_threats(client, log_entries: list[dict], source_type: str) -> list[dict]:
    entries_json = json.dumps(log_entries[:200], default=str)

    system_prompt = (
        "You are a security threat analyst. Analyze the following log entries "
        "for potential security threats including: brute force attempts, "
        "unauthorized access, privilege escalation, suspicious IPs, "
        "anomalous patterns, malware indicators, lateral movement, "
        "data exfiltration, and reconnaissance activity.\n\n"
        "Return ONLY a JSON object with this exact structure:\n"
        '{"threats": [{"threat_type": "string", "severity": "low|medium|high|critical", '
        '"description": "string", "affected_entries": [0, 1], '
        '"indicators": ["specific IPs, usernames, or patterns observed"]}]}'
    )

    user_prompt = (
        f"Source type: {source_type}\n"
        f"Log entries ({len(log_entries)} total):\n{entries_json}"
    )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )

    try:
        parsed = json.loads(response.choices[0].message.content)
        return parsed.get("threats", [])
    except (json.JSONDecodeError, IndexError):
        return [{
            "threat_type": "unknown",
            "severity": "low",
            "description": "Analysis could not parse model response.",
        }]
    
def _retrieve_mitre_techniques(
    findings: list[dict],
    source_type: str,
) -> list[dict]:
    
    query_parts = [f"Security log analysis of {source_type} logs."]
    for finding in findings[:10]:
        query_parts.append(
            f"{finding.get('threat_type', '')}: {finding.get('description', '')}"
        )
    query_text = "\n".join(query_parts)

    query_embedding = get_embedding(query_text)

    result = supabase_client.rpc(
        "match_mitre_techniques",
        {
            "query_embedding": query_embedding,
            "match_threshold": 0.3,
            "match_count": 5,
        },
    ).execute()

    return result.data if result.data else []

def _generate_incident_summary(
    client,
    log_entries: list[dict],
    source_type: str,
    findings: list[dict],
    mitre_context: list[dict],
    detections: list[dict] = None,
) -> dict:

    mitre_text = ""
    if mitre_context:
        mitre_parts = []
        for tech in mitre_context:
            mitre_parts.append(
                f"- {tech['technique_id']} ({tech['name']}): "
                f"{tech['description'][:300]}... "
                f"Tactic: {tech['tactic']}. "
                f"Detection: {(tech.get('detection') or '')[:200]}"
            )
        mitre_text = "Relevant MITRE ATT&CK techniques:\n" + "\n".join(mitre_parts)

    detection_text = ""
    if detections:
        det_parts = []
        for det in detections:
            det_parts.append(
                f"- Rule '{det['rule_name']}' (MITRE {det['mitre_technique']}): "
                f"{det['description']} [confidence: {det['confidence']:.2f}]"
            )
        detection_text = "Correlation rule detections:\n" + "\n".join(det_parts)

    findings_text = json.dumps(findings[:15], indent=2, default=str)
    sample_entries = json.dumps(log_entries[:20], default=str)

    system_prompt = (
        "You are a senior forensic analyst writing an incident report. "
        "Based on the threat findings, log data, MITRE ATT&CK context, "
        "and correlation rule detections provided, "
        "generate a structured incident summary.\n\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "summary": "2-4 paragraph natural language incident summary in plain English",\n'
        '  "attack_vector": "primary attack method identified",\n'
        '  "timeline": [{"timestamp": "ISO or relative", "event": "description"}],\n'
        '  "impacted_assets": ["list of affected IPs, users, systems"],\n'
        '  "confidence_score": 0.0 to 1.0,\n'
        '  "mitre_techniques": [{"id": "T1110", "name": "Brute Force", '
        '"relevance": "explanation of how this technique applies"}],\n'
        '  "remediation_steps": ["step 1", "step 2", "step 3", "step 4", "step 5"]\n'
        "}"
    )

    user_prompt = (
        f"Source type: {source_type}\n"
        f"Total log entries: {len(log_entries)}\n\n"
        f"Sample log entries:\n{sample_entries}\n\n"
        f"Threat findings:\n{findings_text}\n\n"
        f"{mitre_text}\n\n"
        f"{detection_text}"
    )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    try:
        result = json.loads(response.choices[0].message.content)
        return {
            "summary": result.get("summary", "Analysis completed but summary generation failed."),
            "attack_vector": result.get("attack_vector", "Unknown"),
            "timeline": result.get("timeline", []),
            "impacted_assets": result.get("impacted_assets", []),
            "confidence_score": float(result.get("confidence_score", 0.5)),
            "mitre_techniques": result.get("mitre_techniques", []),
            "remediation_steps": result.get("remediation_steps", []),
        }
    except (json.JSONDecodeError, IndexError, ValueError):
        return {
            "summary": f"Detected {len(findings)} potential threats. Manual review recommended.",
            "attack_vector": "Unknown",
            "timeline": [],
            "impacted_assets": [],
            "confidence_score": 0.3,
            "mitre_techniques": [],
            "remediation_steps": [
                "Review logs manually",
                "Check affected systems",
                "Update security policies",
            ],
        }

def _determine_threat_level(findings: list[dict]) -> str:
    """Return the highest severity found across all findings."""
    severities = [f.get("severity", "low") for f in findings]
    for level in ("critical", "high", "medium", "low"):
        if level in severities:
            return level
    return "none"
