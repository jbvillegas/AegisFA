import json
import os
from . import supabase_client
from .openai_client import get_openai_client, get_embedding


MITRE_MATCH_THRESHOLD = float(os.getenv("MITRE_MATCH_THRESHOLD", "0.45"))
MITRE_MIN_SIMILARITY = float(os.getenv("MITRE_MIN_SIMILARITY", "0.40"))
CONFIDENCE_CONSISTENCY_BONUS = float(os.getenv("CONFIDENCE_CONSISTENCY_BONUS", "0.12"))

DDOS_FAMILY_PROFILE = {
    "primary": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
    },
    "supporting": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
        {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "hints": [
        "DNS amplification",
        "UDP amplification",
        "reflection attack",
        "volumetric DDoS",
        "packet rate spikes",
        "flow bytes per second",
        "flow packets per second",
        "short-lived high-volume flows",
        "spoofed source IP",
    ],
}


def _extract_key_indicators(log_entries: list[dict], limit: int = 24) -> list[str]:
    indicators = []
    seen = set()
    interesting_keys = {
        "ip",
        "src_ip",
        "source_ip",
        "dst_ip",
        "destination_ip",
        "username",
        "user",
        "account",
        "port",
        "src_port",
        "dst_port",
        "destination_port",
        "process",
        "command",
        "protocol",
        "destination_port",
        "flow_duration",
        "flow_bytes_s",
        "flow_packets_s",
        "fwd_packets_s",
        "bwd_packets_s",
        "syn_flag_count",
        "down_up_ratio",
        "packet_length_mean",
        "packet_length_std",
        "total_fwd_packets",
        "total_backward_packets",
    }

    for entry in log_entries[:120]:
        if not isinstance(entry, dict):
            continue

        for key, value in entry.items():
            key_norm = str(key or "").strip().lower()
            if not key_norm:
                continue

            if key_norm not in interesting_keys and not any(token in key_norm for token in ("ip", "user", "port", "process", "command", "flow", "packet", "flag", "ratio")):
                continue

            value_str = str(value or "").strip()
            if not value_str:
                continue

            marker = f"{key_norm}:{value_str[:80]}"
            if marker in seen:
                continue
            seen.add(marker)
            indicators.append(marker)

            if len(indicators) >= limit:
                return indicators

    return indicators


def _top_rf_categories(rf_context: dict | None, limit: int = 5) -> list[str]:
    if not rf_context:
        return []

    by_category = rf_context.get("by_category") or {}
    if not isinstance(by_category, dict):
        return []

    ordered = sorted(
        [(str(category), int(count or 0)) for category, count in by_category.items()],
        key=lambda item: item[1],
        reverse=True,
    )

    return [f"{category}:{count}" for category, count in ordered[:limit] if count > 0]


def _build_attack_family_hints(source_type: str, rf_context: dict | None, findings: list[dict]) -> list[str]:
    hints: list[str] = []
    source_token = str(source_type or "").strip().lower()
    categories = " ".join(_top_rf_categories(rf_context, limit=5)).lower()
    finding_text = " ".join(
        f"{item.get('threat_type', '')} {item.get('description', '')}"
        for item in (findings or [])[:10]
        if isinstance(item, dict)
    ).lower()

    if any(token in source_token for token in ("dns", "drdos", "ddos", "dos", "flow")) or any(
        token in categories for token in ("drdos", "ddos", "dos")
    ) or any(token in finding_text for token in ("dns", "amplification", "reflection", "denial of service", "udp flood")):
        hints.extend([
            f"MITRE ATT&CK {DDOS_FAMILY_PROFILE['primary']['id']} {DDOS_FAMILY_PROFILE['primary']['name']}",
            *DDOS_FAMILY_PROFILE["hints"],
        ])

    if any(token in source_token for token in ("udp", "dns")) or any(token in categories for token in ("drdos_dns", "drdos_udp")):
        hints.extend([
            "high destination port variance",
            "amplification source diversity",
            "reflective traffic burst",
        ])

    return hints


def _build_family_profile_text(source_type: str, rf_context: dict | None, findings: list[dict]) -> str:
    hints = _build_attack_family_hints(source_type, rf_context, findings)
    if not hints:
        return ""

    supporting = ", ".join(
        f"{item['id']} {item['name']}" for item in DDOS_FAMILY_PROFILE["supporting"]
    )
    return (
        "Family profile: DNS/UDP reflected denial-of-service analysis. "
        f"Primary technique: {DDOS_FAMILY_PROFILE['primary']['id']} {DDOS_FAMILY_PROFILE['primary']['name']}. "
        f"Supporting techniques: {supporting}. "
        f"Family hints: {'; '.join(hints)}"
    )


def _build_mitre_query_text(
    findings: list[dict],
    source_type: str,
    detections: list[dict] | None,
    rf_context: dict | None,
    log_entries: list[dict],
) -> str:
    query_parts = [f"Security log analysis of {source_type} logs."]

    family_profile_text = _build_family_profile_text(source_type, rf_context, findings)
    if family_profile_text:
        query_parts.append(family_profile_text)

    for finding in findings[:10]:
        query_parts.append(
            f"finding={finding.get('threat_type', '')}; severity={finding.get('severity', '')}; detail={finding.get('description', '')}"
        )

    for detection in (detections or [])[:10]:
        query_parts.append(
            "detection="
            f"{detection.get('rule_name', '')}; "
            f"mitre={detection.get('mitre_technique', '')}; "
            f"severity={detection.get('severity', '')}; "
            f"confidence={detection.get('confidence', '')}; "
            f"detail={detection.get('description', '')}"
        )

    categories = _top_rf_categories(rf_context)
    if categories:
        query_parts.append(f"rf_top_categories={', '.join(categories)}")

    indicators = _extract_key_indicators(log_entries)
    if indicators:
        query_parts.append(f"key_indicators={'; '.join(indicators)}")

    return "\n".join(query_parts)

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
    mitre_context = _retrieve_mitre_techniques(
        findings,
        source_type,
        detections=detections,
        rf_context=rf_context,
        log_entries=log_entries,
    )
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
    llm_confidence = _clamp01(summary_result.get("confidence_score", 0.5))
    retrieval_strength = _score_retrieval_strength(summary_result.get("mitre_techniques", []))
    correlation_strength = _score_correlation_evidence(detections)
    consistency_bonus = _compute_evidence_consistency_bonus(
        mitre_techniques=summary_result.get("mitre_techniques", []),
        detections=detections,
        rf_context=rf_context,
    )
    computed_confidence = _clamp01(
        (0.20 * llm_confidence)
        + (0.20 * retrieval_strength)
        + (0.30 * rf_risk_score)
        + (0.30 * correlation_strength)
        + consistency_bonus
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
        "confidence_score": computed_confidence,
        "remediation_steps": summary_result["remediation_steps"],
        "verdict_sources": {
            "llm_findings": len(findings),
            "correlation_detections": len(detections or []),
            "rf_risk_score": rf_risk_score,
            "llm_confidence": llm_confidence,
            "retrieval_strength": retrieval_strength,
            "correlation_strength": correlation_strength,
            "evidence_consistency_bonus": consistency_bonus,
            "computed_confidence_score": computed_confidence,
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
    detections: list[dict] | None = None,
    rf_context: dict | None = None,
    log_entries: list[dict] | None = None,
) -> list[dict]:

    query_text = _build_mitre_query_text(
        findings=findings,
        source_type=source_type,
        detections=detections,
        rf_context=rf_context,
        log_entries=log_entries or [],
    )

    query_embedding = get_embedding(query_text)

    result = supabase_client.rpc(
        "match_mitre_techniques",
        {
            "query_embedding": query_embedding,
            "match_threshold": MITRE_MATCH_THRESHOLD,
            "match_count": 5,
        },
    ).execute()

    family_rows = []
    family_profile_text = _build_family_profile_text(source_type, rf_context, findings)
    if family_profile_text:
        family_query_embedding = get_embedding(family_profile_text)
        family_result = supabase_client.rpc(
            "match_mitre_techniques",
            {
                "query_embedding": family_query_embedding,
                "match_threshold": max(0.35, MITRE_MATCH_THRESHOLD * 0.85),
                "match_count": 8,
            },
        ).execute()
        family_rows = family_result.data if family_result.data else []

    raw_rows = result.data if result.data else []
    raw_rows.extend(family_rows)

    deduped_rows = []
    seen_ids = set()
    filtered_rows = []
    for row in raw_rows:
        if not isinstance(row, dict):
            continue
        technique_id = _normalize_technique_id(row.get("technique_id") or row.get("id"))
        if technique_id and technique_id in seen_ids:
            continue
        if technique_id:
            seen_ids.add(technique_id)
        similarity = row.get("similarity")
        try:
            similarity_value = float(similarity)
        except (TypeError, ValueError):
            continue
        if similarity_value < MITRE_MIN_SIMILARITY:
            continue
        filtered_rows.append(row)

    return filtered_rows


def _normalize_technique_id(value) -> str:
    if not value:
        return ""
    return str(value).strip().upper()


def _merge_mitre_techniques(llm_techniques, mitre_context: list[dict]) -> list[dict]:
    context_by_id = {}
    for item in mitre_context or []:
        if not isinstance(item, dict):
            continue
        context_id = _normalize_technique_id(item.get("technique_id") or item.get("id"))
        if context_id:
            context_by_id[context_id] = item

    merged = []
    for item in llm_techniques or []:
        if not isinstance(item, dict):
            continue

        technique_id = _normalize_technique_id(item.get("id") or item.get("technique_id"))
        context = context_by_id.get(technique_id, {})
        if not technique_id:
            technique_id = _normalize_technique_id(context.get("technique_id") or context.get("id"))

        merged.append({
            "id": technique_id,
            "technique_id": technique_id,
            "name": item.get("name") or context.get("name") or "Unknown technique",
            "tactic": item.get("tactic") or context.get("tactic"),
            "relevance": item.get("relevance") or context.get("description") or "",
            "similarity": item.get("similarity") or context.get("similarity") or context.get("similarity_score"),
        })

    # Backfill with top context techniques if the LLM omitted them entirely.
    if not merged and mitre_context:
        for item in mitre_context[:5]:
            technique_id = _normalize_technique_id(item.get("technique_id") or item.get("id"))
            if not technique_id:
                continue
            merged.append({
                "id": technique_id,
                "technique_id": technique_id,
                "name": item.get("name") or "Unknown technique",
                "tactic": item.get("tactic"),
                "relevance": item.get("description") or "",
                "similarity": item.get("similarity") or item.get("similarity_score"),
            })

    # Remove duplicates while preserving order.
    deduped = []
    seen = set()
    for item in merged:
        key = item.get("technique_id")
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped

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

    family_profile_text = _build_family_profile_text(source_type, None, findings)

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
        f"{family_profile_text}\n\n"
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
        merged_mitre = _merge_mitre_techniques(result.get("mitre_techniques", []), mitre_context)
        return {
            "summary": result.get("summary", "Analysis completed but summary generation failed."),
            "attack_vector": result.get("attack_vector", "Unknown"),
            "timeline": result.get("timeline", []),
            "impacted_assets": result.get("impacted_assets", []),
            "confidence_score": float(result.get("confidence_score", 0.5)),
            "mitre_techniques": merged_mitre,
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
    by_category = rf_context.get("by_category", {}) or {}
    high_conf_anomaly = int(rf_context.get("high_conf_anomaly_count", 0) or 0)
    high_conf_security = int(rf_context.get("high_conf_security_count", 0) or 0)
    high_conf_error = int(rf_context.get("high_conf_error_count", 0) or 0)

    critical_ratio = float(by_severity.get("critical", 0) or 0) / total
    high_ratio = float(by_severity.get("high", 0) or 0) / total
    anomaly_ratio = high_conf_anomaly / total
    security_ratio = high_conf_security / total
    error_ratio = high_conf_error / total

    benign_count = 0
    if isinstance(by_category, dict):
        for category, count in by_category.items():
            normalized = str(category or "").strip().lower()
            if normalized in {"benign", "normal", "normal_traffic"}:
                benign_count += int(count or 0)

    non_benign_ratio = max(0.0, min(1.0, (total - benign_count) / total))
    high_conf_total_ratio = max(0.0, min(1.0, (high_conf_anomaly + high_conf_security + high_conf_error) / total))

    # Severity-weighted category score: accounts for the actual threat weight
    # of each classified category, even when the model has few classes.
    _CATEGORY_THREAT_WEIGHT = {
        "benign": 0.0, "normal": 0.0, "normal_traffic": 0.0,
        "ddos": 0.95, "dos": 0.9, "bot": 0.9,
        "infiltration": 0.95, "heartbleed": 0.95,
        "drdos_dns": 0.9, "drdos_ldap": 0.9, "drdos_mssql": 0.9,
        "drdos_ntp": 0.9, "drdos_netbios": 0.9, "drdos_snmp": 0.9,
        "drdos_ssdp": 0.9, "drdos_udp": 0.9,
        "web_bruteforce": 0.85, "web_xss": 0.85, "web_sql_injection": 0.85,
        "ssh_patator": 0.8, "ftp_patator": 0.8, "portscan": 0.75,
        "dos_hulk": 0.85, "dos_goldeneye": 0.85,
        "dos_slowhttptest": 0.8, "dos_slowloris": 0.8,
        "syn": 0.85, "udp_lag": 0.8,
    }
    category_threat_score = 0.0
    if isinstance(by_category, dict) and total > 0:
        weighted_sum = 0.0
        for category, count in by_category.items():
            normalized = str(category or "").strip().lower()
            weight = _CATEGORY_THREAT_WEIGHT.get(normalized, 0.5)
            weighted_sum += weight * int(count or 0)
        category_threat_score = min(1.0, weighted_sum / total)

    score = (
        (0.15 * average_confidence) +
        (0.10 * critical_ratio) +
        (0.06 * high_ratio) +
        (0.03 * anomaly_ratio) +
        (0.02 * security_ratio) +
        (0.01 * error_ratio) +
        (0.10 * non_benign_ratio) +
        (0.05 * high_conf_total_ratio) +
        (0.48 * category_threat_score)
    )
    return max(0.0, min(1.0, score))


def _clamp01(value) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, numeric))


def _score_retrieval_strength(mitre_techniques: list[dict] | None) -> float:
    # Observed embedding similarity ceiling for MITRE technique descriptions is
    # approximately 0.70-0.72.  Raw similarities therefore rarely exceed that,
    # which would cap this component at ~70%.  We rescale so that the practical
    # ceiling maps to ~1.0, giving the retrieval component its full weight.
    _SIMILARITY_FLOOR = 0.35   # below this we treat as noise
    _SIMILARITY_CEILING = 0.72 # observed practical max for good matches

    scores = []
    for item in mitre_techniques or []:
        if not isinstance(item, dict):
            continue
        similarity = item.get("similarity") or item.get("similarity_score")
        if similarity is None:
            continue
        try:
            numeric = float(similarity)
        except (TypeError, ValueError):
            continue
        raw = _clamp01(numeric if numeric <= 1 else numeric / 100)
        # Rescale into [0, 1] relative to the observed floor/ceiling
        if raw <= _SIMILARITY_FLOOR:
            scaled = 0.0
        else:
            scaled = min(1.0, (raw - _SIMILARITY_FLOOR) / (_SIMILARITY_CEILING - _SIMILARITY_FLOOR))
        scores.append(scaled)

    if not scores:
        return 0.0

    top = sorted(scores, reverse=True)[:3]
    return sum(top) / len(top)


def _score_correlation_evidence(detections: list[dict] | None) -> float:
    detections = detections or []
    if not detections:
        return 0.0

    severity_weights = {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75,
        "critical": 1.0,
    }
    points = []
    for detection in detections[:30]:
        if not isinstance(detection, dict):
            continue
        severity = str(detection.get("severity", "medium")).strip().lower()
        base = severity_weights.get(severity, 0.5)
        confidence = _clamp01(detection.get("confidence", 0.5))
        points.append((0.6 * base) + (0.4 * confidence))

    if not points:
        return 0.0

    mean_points = sum(points) / len(points)
    volume_boost = min(0.2, len(points) * 0.02)
    return _clamp01(mean_points + volume_boost)


def _extract_retrieved_mitre_ids(mitre_techniques: list[dict] | None) -> set[str]:
    ids = set()
    for item in mitre_techniques or []:
        if not isinstance(item, dict):
            continue
        technique_id = item.get("technique_id") or item.get("id")
        if technique_id:
            ids.add(_normalize_technique_id(technique_id))
    return ids


def _extract_detection_mitre_ids(detections: list[dict] | None) -> set[str]:
    ids = set()
    for detection in detections or []:
        if not isinstance(detection, dict):
            continue
        raw = detection.get("mitre_technique") or detection.get("technique_id")
        if not raw:
            continue
        raw_text = str(raw)
        for token in raw_text.replace(";", ",").split(","):
            normalized = _normalize_technique_id(token)
            if normalized.startswith("T"):
                ids.add(normalized)
    return ids


def _extract_rf_expected_mitre_ids(rf_context: dict | None) -> set[str]:
    if not rf_context:
        return set()

    by_category = rf_context.get("by_category") or {}
    if not isinstance(by_category, dict) or not by_category:
        return set()

    ordered_categories = sorted(
        [(str(category), int(count or 0)) for category, count in by_category.items()],
        key=lambda item: item[1],
        reverse=True,
    )

    from .rf_training_mapping import get_mitre_for_class

    ids = set()
    for category, _ in ordered_categories[:3]:
        mapped = get_mitre_for_class(category)
        for technique in mapped.get("techniques", []):
            technique_id = technique.get("id") or technique.get("technique_id")
            normalized = _normalize_technique_id(technique_id)
            if normalized.startswith("T"):
                ids.add(normalized)
    return ids


def _parent_technique_id(technique_id: str) -> str:
    """Return the parent technique ID (e.g. T1498.002 -> T1498)."""
    normalized = _normalize_technique_id(technique_id)
    if "." in normalized:
        return normalized.split(".")[0]
    return normalized


def _ids_overlap(set_a: set[str], set_b: set[str]) -> bool:
    """Check if two sets of MITRE technique IDs overlap, considering parent IDs.

    E.g. {T1498.002} overlaps with {T1498} because T1498.002's parent is T1498.
    """
    if set_a.intersection(set_b):
        return True
    # Expand both sets with parent IDs and check again
    expanded_a = set_a | {_parent_technique_id(tid) for tid in set_a}
    expanded_b = set_b | {_parent_technique_id(tid) for tid in set_b}
    return bool(expanded_a.intersection(expanded_b))


def _compute_evidence_consistency_bonus(
    mitre_techniques: list[dict] | None,
    detections: list[dict] | None,
    rf_context: dict | None,
) -> float:
    retrieved_ids = _extract_retrieved_mitre_ids(mitre_techniques)
    detection_ids = _extract_detection_mitre_ids(detections)
    rf_ids = _extract_rf_expected_mitre_ids(rf_context)

    # --- Part 1: MITRE ID overlap bonus (up to 60% of cap) ---
    id_bonus = 0.0
    if retrieved_ids and detection_ids and _ids_overlap(retrieved_ids, detection_ids):
        id_bonus += 0.30
    if retrieved_ids and rf_ids and _ids_overlap(retrieved_ids, rf_ids):
        id_bonus += 0.18
    if detection_ids and rf_ids and _ids_overlap(detection_ids, rf_ids):
        id_bonus += 0.12

    # --- Part 2: Signal agreement bonus (up to 40% of cap) ---
    # When multiple independent sources agree that an attack is present,
    # that is evidence consistency even without exact MITRE ID overlap.
    active_sources = 0
    if retrieved_ids:                       # MITRE retrieval found matches
        active_sources += 1
    if detections:                          # Correlation rules fired
        active_sources += 1
    if rf_ids:                              # RF classified as attack (non-benign)
        active_sources += 1

    # Signal agreement: 2 sources = partial bonus, 3 sources = full bonus
    if active_sources >= 3:
        signal_bonus = 0.40
    elif active_sources >= 2:
        signal_bonus = 0.25
    else:
        signal_bonus = 0.0

    total_ratio = min(1.0, id_bonus + signal_bonus)
    return _clamp01(min(CONFIDENCE_CONSISTENCY_BONUS, CONFIDENCE_CONSISTENCY_BONUS * total_ratio))


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
