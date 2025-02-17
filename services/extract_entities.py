import re
# main_extraction.py

from static.regex_pattern import THREAT_ACTOR_PATTERN, TARGETED_ENTITIES_PATTERN, MALWARE_NAME_PATTERN
from static.keywords import SECTOR_KEYWORDS, COUNTRY_KEYWORDS, REGION_KEYWORDS

def extract_threat_actor(text):
    """Extract threat actor names using predefined regex and remove duplicates (case insensitive)."""
    threat_actors = set()
    
    for match in THREAT_ACTOR_PATTERN.findall(text):
        normalized_name = match.lower().replace(" ", "-")  # Normalize case and spaces
        threat_actors.add(normalized_name)
    
    return sorted(threat_actors)

def extract_targeted_entities(text):
    """Extract targeted entities (sectors, countries, regions, organizations)."""
    matches = TARGETED_ENTITIES_PATTERN.findall(text)
    entities = set()

    for match in matches:
        extracted_entities = {entity.strip().lower() for entity in re.split(r',| and | or ', match)}
        for entity in extracted_entities:
            if (
                entity in SECTOR_KEYWORDS or
                entity in COUNTRY_KEYWORDS or
                entity in REGION_KEYWORDS
            ):
                entities.add(entity.title())

    return sorted(entities)

def extract_malware_names(text):
    """Extract malware names using predefined regex."""
    return sorted(set(MALWARE_NAME_PATTERN.findall(text)))