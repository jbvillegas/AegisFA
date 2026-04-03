import json
from . import supabase_client
from .openai_client import get_openai_client, get_embedding

def _compact_log_entries(
    log_entries: list[dict],
    max_entries: int = 60,
    max_fields: int = 16,
    max_value_len: int = 120,
) -> list[dict]:
    ##Compact log entries for more efficient LLM processing. Limits number of entries, fields, and value lengths.
    compacted: list[dict] = []

    for entry in log_entries[:max_entries]:
        if not isinstance(entry, dict):
            compacted.append({"value": str(entry)[:max_value_len]})
            continue

        slim: dict = {}
        for idx, (key, value) in enumerate(entry.items()):
            if idx >= max_fields:
                break
            if isinstance(value, (dict, list)):
                slim[key] = str(value)[:max_value_len]
            else:
                slim[key] = str(value)[:max_value_len]

        compacted.append(slim)

    return compacted

def analyze_threats(
    log_entries: list[dict],
    source_type: str,
    detections: list[dict] = None,
    rf_context: dict | None = None,
) -> dict:
    
    client = get_openai_client()
    findings = _detect_threats(client, log_entries, source_type)
    mitre_context = _retrieve_mitre_techniques(findings, source_type)
    summary_result = _generate_incident_summary(
        client, log_entries, source_type, findings, mitre_context,
        detections=detections,
    )

    threat_level = _determine_threat_level(findings)
    rf_risk_score = _score_rf_risk(rf_context)
    blended_threat_level = _blend_threat_level(
        base_level=threat_level,
        detections=detections,
        rf_context=rf_context,
        rf_risk_score=rf_risk_score,
    )
    blended_threats_found = _blend_threats_found(
        findings_count=len(findings),
        detections=detections,
        rf_context=rf_context,
        rf_risk_score=rf_risk_score,
    )

    return {
        "threat_level": blended_threat_level,
        "threats_found": blended_threats_found,
        "summary": summary_result["summary"],
        "detailed_findings": findings,
        "mitre_techniques": summary_result["mitre_techniques"],
        "attack_vector": summary_result["attack_vector"],
        "timeline": summary_result["timeline"],
        "impacted_assets": summary_result["impacted_assets"],
        "confidence_score": summary_result["confidence_score"],
        "remediation_steps": summary_result["remediation_steps"],
        "verdict_sources": {
            "llm_findings": len(findings),
            "correlation_detections": len(detections or []),
            "rf_risk_score": rf_risk_score,
        },
    }

def _detect_threats(client, log_entries: list[dict], source_type: str) -> list[dict]:
    compact_entries = _compact_log_entries(log_entries, max_entries=40, max_fields=14, max_value_len=100)
    entries_json = json.dumps(compact_entries, default=str)

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
        f"Log entries ({len(log_entries)} total, sampled/compacted for analysis):\n{entries_json}"
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
    sample_entries = json.dumps(
        _compact_log_entries(log_entries, max_entries=20, max_fields=12, max_value_len=80),
        default=str,
    )

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


def _severity_to_score(level: str) -> int:
    mapping = {
        "none": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return mapping.get(str(level or "none").strip().lower(), 0)


def _score_to_severity(score: int) -> str:
    mapping = {
        0: "none",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }
    safe = max(0, min(4, int(score)))
    return mapping[safe]


def _max_detection_severity(detections: list[dict] | None) -> str:
    max_score = 0
    for detection in detections or []:
        max_score = max(max_score, _severity_to_score(detection.get("severity", "none")))
    return _score_to_severity(max_score)


def _score_rf_risk(rf_context: dict | None) -> float:
    if not rf_context:
        return 0.0

    total = int(rf_context.get("total", 0) or 0)
    if total <= 0:
        return 0.0

    average_confidence = float(rf_context.get("average_confidence", 0.0) or 0.0)
    by_severity = rf_context.get("by_severity", {}) or {}
    high_conf_anomaly = int(rf_context.get("high_conf_anomaly_count", 0) or 0)
    high_conf_security = int(rf_context.get("high_conf_security_count", 0) or 0)
    high_conf_error = int(rf_context.get("high_conf_error_count", 0) or 0)

    critical_ratio = float(by_severity.get("critical", 0) or 0) / total
    high_ratio = float(by_severity.get("high", 0) or 0) / total
    anomaly_ratio = high_conf_anomaly / total
    security_ratio = high_conf_security / total
    error_ratio = high_conf_error / total

    score = (
        (0.30 * average_confidence) +
        (0.30 * critical_ratio) +
        (0.18 * high_ratio) +
        (0.12 * anomaly_ratio) +
        (0.07 * security_ratio) +
        (0.03 * error_ratio)
    )
    return max(0.0, min(1.0, score))


def _blend_threat_level(
    base_level: str,
    detections: list[dict] | None,
    rf_context: dict | None,
    rf_risk_score: float,
) -> str:
    base_score = _severity_to_score(base_level)
    detection_score = _severity_to_score(_max_detection_severity(detections))
    blended_score = max(base_score, detection_score)

    high_conf_total = 0
    if rf_context:
        high_conf_total = (
            int(rf_context.get("high_conf_anomaly_count", 0) or 0) +
            int(rf_context.get("high_conf_security_count", 0) or 0) +
            int(rf_context.get("high_conf_error_count", 0) or 0)
        )

    # Conservative promotion: only boost when RF signal is strong and repeated.
    if rf_risk_score >= 0.75 and high_conf_total >= 8:
        blended_score = min(4, blended_score + 1)

    return _score_to_severity(blended_score)


def _blend_threats_found(
    findings_count: int,
    detections: list[dict] | None,
    rf_context: dict | None,
    rf_risk_score: float,
) -> int:
    blended = max(int(findings_count or 0), len(detections or []))

    if not rf_context:
        return blended

    high_conf_total = (
        int(rf_context.get("high_conf_anomaly_count", 0) or 0) +
        int(rf_context.get("high_conf_security_count", 0) or 0) +
        int(rf_context.get("high_conf_error_count", 0) or 0)
    )

    if rf_risk_score >= 0.65:
        blended += min(3, high_conf_total // 8)

    if blended == 0 and rf_risk_score >= 0.8 and high_conf_total >= 10:
        blended = 1

    return blended
