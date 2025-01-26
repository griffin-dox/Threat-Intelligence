import re
import json

# Load MITRE ATT&CK mappings from external JSON file
def load_mappings(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Load the mappings
mappings = load_mappings('static/mitre_attack_mappings.json')

# Build dictionaries for tactics and techniques
MITRE_TACTICS = {tactic['id']: tactic['name'] for tactic in mappings['tactics']}
MITRE_TECHNIQUES = {technique['id']: technique['name'] for technique in mappings['techniques']}

# Function to extract TTPs from text
def extract_ttp(text):
    tactics = []
    techniques = []
    
    for tactic_id, tactic_name in MITRE_TACTICS.items():
        if re.search(tactic_name, text, re.IGNORECASE):
            tactics.append([tactic_id, tactic_name])
    
    for technique_id, technique_name in MITRE_TECHNIQUES.items():
        if re.search(technique_name, text, re.IGNORECASE):
            techniques.append([technique_id, technique_name])

    return {
        "TTPs": {
            "Tactics": tactics,
            "Techniques": techniques
        }
    }
