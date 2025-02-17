import re
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load MITRE ATT&CK mappings from external JSON file
def load_mappings(file_path):
    try:
        with open(file_path, 'r') as f:
            mappings = json.load(f)
        logging.info(f"Successfully loaded MITRE ATT&CK mappings from {file_path}")
        return mappings
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON from file: {file_path}")
        raise

# Build dictionaries for tactics and techniques
def build_ttp_dictionaries(mappings):
    tactics = {tactic['id']: tactic['name'].lower() for tactic in mappings['tactics']}
    techniques = {technique['id']: technique['name'].lower() for technique in mappings['techniques']}
    return tactics, techniques

# Function to extract TTPs from text
def extract_ttp(text, mappings_file='static/mitre_attack_mappings.json'):
    # Load mappings if not provided
    mappings = load_mappings(mappings_file)
    MITRE_TACTICS, MITRE_TECHNIQUES = build_ttp_dictionaries(mappings)

    # Normalize text for case-insensitive matching
    normalized_text = text.lower()

    # Extract Tactics
    tactics = [
        [tactic_id, MITRE_TACTICS[tactic_id].capitalize()]
        for tactic_id, tactic_name in MITRE_TACTICS.items()
        if tactic_name in normalized_text
    ]

    # Extract Techniques
    techniques = [
        [technique_id, MITRE_TECHNIQUES[technique_id].capitalize()]
        for technique_id, technique_name in MITRE_TECHNIQUES.items()
        if technique_name in normalized_text
    ]

    # Log results
    logging.info(f"Extracted Tactics: {tactics}")
    logging.info(f"Extracted Techniques: {techniques}")

    return {
        "TTPs": {
            "Tactics": tactics,
            "Techniques": techniques
        }
    }