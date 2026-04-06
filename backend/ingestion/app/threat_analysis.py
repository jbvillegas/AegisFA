import json, re, torch
from .service import load_model

BATCH_SIZE = 10

def analyze_threats(log_entries, source_type):
    model, tokenizer = load_model()
    all_findings = []

    for i in range(0, len(log_entries), BATCH_SIZE):
        batch = log_entries[i:i + BATCH_SIZE]

        system_prompt = (
            "You are a security threat analyst. Analyze the following log entries "
            "for potential security threats including: brute force attempts, "
            "unauthorized access, privilege escalation, suspicious IPs, "
            "anomalous patterns, and malware indicators. "
            "Return ONLY a JSON object with this structure: "
            '{"threats": [{"threat_type": "string", "severity": "low|medium|high|critical", '
            '"description": "string", "affected_entries": [0, 1]}]}'
        )
        user_prompt = f"Source type: {source_type}\nLog entries:\n{json.dumps(batch)}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(text, return_tensors="pt")

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.1,
                do_sample=True,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id
            )

        new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
        response = tokenizer.decode(new_tokens, skip_special_tokens=True)
        print(f"MODEL RESPONSE:\n{response}")

        try:
            json_match = re.search(r'(\{.*\})', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group(1))
                all_findings.extend(parsed.get("threats", []))
        except Exception:
            all_findings.append({
                "threat_type": "unknown",
                "severity": "low",
                "description": "Analysis could not be completed for this batch"
            })

    threat_level = determine_threat_level(all_findings)
    try:
        summary = generate_nlp_summary(all_findings, log_entries, source_type)
    except Exception:
        summary = f"Detected {len(all_findings)} potential threats across {len(log_entries)} log entries. Highest severity: {threat_level}."

    return {
        "threat_level": threat_level,
        "threats_found": len(all_findings),
        "summary": summary,
        "detailed_findings": all_findings
    }


def determine_threat_level(findings):
    severities = [f.get("severity", "low") for f in findings]
    for level in ["critical", "high", "medium", "low"]:
        if level in severities:
            return level
    return "none"

def generate_nlp_summary(all_findings, log_entries, source_type):
    model, tokenizer = load_model()

    system_prompt = (
        "You are a security analyst writing a brief incident summary for your team. "
        "Based on the threat findings and log data provided, write a clear 2-3 sentence "
        "summary in plain English. Mention specific details like IPs, usernames, and "
        "actions where available. Do not return JSON — write only a natural language paragraph."
    )
    user_prompt = (
        f"Source type: {source_type}\n"
        f"Total log entries analyzed: {len(log_entries)}\n"
        f"Threat findings: {json.dumps(all_findings)}"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt")

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=0.3,
            do_sample=True,
            top_p=0.9,
            pad_token_id=tokenizer.eos_token_id
        )

    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
    summary = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
    return summary

