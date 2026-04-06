"""
One-time script to seed the mitre_techniques table with MITRE ATT&CK data.

Usage:
    cd backend/ingestion
    python -m scripts.seed_mitre
"""

import os
import sys
import json
import time

import requests
from dotenv import load_dotenv

# Load env before importing app modules
load_dotenv()

from supabase import create_client
from app.openai_client import get_embedding

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
EMBEDDING_BATCH_DELAY = 0.5  # seconds between API calls (rate-limit safe)


def download_stix_data() -> dict:
    """Download the MITRE ATT&CK STIX 2.1 bundle."""
    print("Downloading MITRE ATT&CK STIX data...")
    response = requests.get(STIX_URL, timeout=60)
    response.raise_for_status()
    return response.json()


def extract_techniques(stix_bundle: dict) -> list[dict]:
    """Extract active attack-pattern objects from the STIX bundle."""
    techniques = []

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Technique ID from external_references
        technique_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue

        # Tactics from kill_chain_phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactic": ", ".join(tactics) if tactics else "unknown",
            "platform": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", ""),
            "mitigation": "",
            "url": url or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
        })

    return techniques


def build_embedding_text(technique: dict) -> str:
    """Build the text to embed for semantic search."""
    parts = [
        f"MITRE ATT&CK Technique {technique['technique_id']}: {technique['name']}",
        f"Tactic: {technique['tactic']}",
        f"Description: {technique['description'][:1000]}",
    ]
    if technique["detection"]:
        parts.append(f"Detection: {technique['detection'][:500]}")
    if technique["platform"]:
        parts.append(f"Platforms: {', '.join(technique['platform'])}")
    return "\n".join(parts)


def seed_database(techniques: list[dict]):
    """Generate embeddings and upsert techniques into Supabase."""
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"],
    )

    total = len(techniques)
    for i, tech in enumerate(techniques):
        print(f"[{i + 1}/{total}] Embedding {tech['technique_id']}: {tech['name']}")

        embedding_text = build_embedding_text(tech)
        embedding = get_embedding(embedding_text)

        supabase.table("mitre_techniques").upsert(
            {
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "description": tech["description"],
                "tactic": tech["tactic"],
                "platform": tech["platform"],
                "detection": tech["detection"],
                "mitigation": tech["mitigation"],
                "url": tech["url"],
                "embedding": embedding,
            },
            on_conflict="technique_id",
        ).execute()

        time.sleep(EMBEDDING_BATCH_DELAY)

    print(f"\nDone — seeded {total} MITRE ATT&CK techniques.")


def main():
    stix_data = download_stix_data()
    techniques = extract_techniques(stix_data)
    print(f"Extracted {len(techniques)} active techniques from STIX data.")
    seed_database(techniques)


if __name__ == "__main__":
    main()
