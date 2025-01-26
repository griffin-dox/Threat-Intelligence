import spacy
from typing import List

# Load spaCy's English model
nlp = spacy.load("en_core_web_sm")

def extract_threat_actor(sanitized_text: str) -> List[str]:
    """
    Extracts threat actor names from the sanitized text while avoiding the mistaken inclusion of good organizations
    by using contextual clues.

    Args:
        sanitized_text (str): Input text to analyze.

    Returns:
        List[str]: A list of detected threat actor names.
    """
    doc = nlp(sanitized_text)
    threat_actors = []

    # Keywords commonly used in threat actor mentions
    keywords = ["threat actor", "group", "team", "cyber", "espionage"]

    for sent in doc.sents:
        # Check if any keyword related to threat actors is mentioned in the sentence
        if any(keyword in sent.text.lower() for keyword in keywords):
            for ent in sent.ents:
                if ent.label_ in ["ORG", "PERSON"]:
                    # Exclude known patterns that indicate the organization is a legitimate actor
                    if not any(exclusion in ent.text.lower() for exclusion in ["research", "intelligence", "company", "corporation"]):
                        # Further logic can be applied here for contextual filtering
                        if "team" in sent.text.lower() or "group" in sent.text.lower():
                            threat_actors.append(ent.text)

    return list(set(threat_actors))

def extract_targeted_entities(sanitized_text: str) -> List[str]:
    """
    Extracts targeted entities, including industries, sectors, or organizations, from the sanitized text.

    Args:
        sanitized_text (str): Input text to analyze.

    Returns:
        List[str]: A list of detected targeted entities or industries.
    """
    doc = nlp(sanitized_text)
    targeted_entities = []

    # Keywords commonly associated with targets
    keywords = ["target", "victim", "industry", "sector", "organization", "entities"]

    for sent in doc.sents:
        if any(keyword in sent.text.lower() for keyword in keywords):
            for ent in sent.ents:
                if ent.label_ in ["ORG", "GPE", "NORP"]:  # ORG: Organization, GPE: Geo-Political Entity, NORP: Nationalities/Religious/Political groups
                    targeted_entities.append(ent.text)

    return list(set(targeted_entities))  # Remove duplicates