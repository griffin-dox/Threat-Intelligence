import re
import json

def extract_threat_actor(text):
    """
    Extracts the threat actor name from a given text.

    Parameters:
        text (str): The input text containing possible threat actor names.

    Returns:
        dict: A dictionary containing the extracted threat actor name.
    """
    # Updated regex pattern to capture threat actor names
    threat_actor_pattern = r"(?:tracking|threat\s+actor|actor\s+group|APT\s+group|hacker\s+group|sponsored\s+by|behind\s+it|caused\s+by|campaign|cyber\s+espionage|state-backed|state-sponsored|politically\s+motivated|criminal\s+group|suspected\s+group)\s+(?:as\s+)?([A-Z][a-zA-Z0-9\-]+(?:\s+[A-Za-z0-9\-]+)*)"

    # Find all matches in the text
    matches = re.findall(threat_actor_pattern, text)

    # Extract and clean the threat actor name
    threat_actor = list(set(matches))

    # Return the threat actor name or a default message if none is found
    return {"threat_actor": threat_actor[0] if threat_actor else "None found."}

def extract_targeted_entities(text):
    """
    Extracts victim names or targeted entities from the text, focusing on organization names or industries.
    
    Parameters:
        text (str): The input text containing victim references.
    
    Returns:
        dict: A dictionary containing a list of potential victim names or organizations.
    """
    # Define regex patterns to capture organizations, industries, and locations
    victim_patterns = [
        # Captures organization names or targeted companies
        r"\b(?:Organization|Company|Corporation|Institute|Association|Manufacturer|Firm|Enterprise|Group)\s*[:\-\s]+([A-Za-z0-9\s&,\-\.]+)",  
        
        # Captures sectors, industries, or types of organizations
        r"\b(?:Sector|Industry|Field)\s*[:\-\s]+([A-Za-z0-9\s&,\-\.]+)",  # e.g., aerospace industry, defense sector
        
        # Captures country names in a variety of formats
        r"\b(?:Country|Nation)\s*[:\-\s]+([A-Za-z\s]+(?:[A-Za-z\s]*[A-Za-z]))",  # e.g., United States, Canada, U.K.
        
        # Captures references to specific industry types directly within text
        r"\b(?:aerospace|cybersecurity|technology|manufacturing|defense|finance|energy|healthcare|telecommunications|automotive|education|biotech|pharmaceutical)\b",  # industries like aerospace, cybersecurity
        
        # Captures targeted organizations or industries linked to geopolitical regions like U.S. (e.g., U.S. aerospace)
        r"\b(?:U\.S\.|United States|U\.K\.|UK|Canada|Germany|France|Russia|China|India)\s*(?:aerospace|cybersecurity|technology|defense|manufacturing|energy|healthcare)?\s*(?:industry|sector|company)?",  # U.S. aerospace, UK defense, etc.
    ]
    
    victims = []
    
    # Search for matches in the text based on defined patterns
    for pattern in victim_patterns:
        matches = re.findall(pattern, text)
        victims.extend([match.strip() for match in matches])
    
    # Remove duplicates and handle case where no matches are found
    victims = list(set(victims))  # Remove duplicates
    if not victims:
        return {"targeted_entities": ["None found."]}
    
    return {"targeted_entities": victims}