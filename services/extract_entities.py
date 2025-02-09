import re
import spacy

# Load spaCy's NLP model
nlp = spacy.load("en_core_web_sm")

# Regular expressions for structured extraction
THREAT_ACTOR_PATTERNS = re.compile(
    r"\b(?:APT\d{1,3}|Lazarus(?: Group)?|Fancy Bear|Cozy Bear|Carbanak|Sandworm|DarkSide|REvil|Conti|LockBit|"
    r"Team [A-Za-z0-9]+|[A-Za-z0-9]+ Group|Hacker Group|Cybercriminal Group)\b",
    re.IGNORECASE
)

MALWARE_PATTERNS = re.compile(
    r"\b(?:Shamoon|Emotet|WannaCry|Ryuk|TrickBot|Cobalt Strike|Locky|NotPetya|Stuxnet|Flame|Mirai|"
    r"[A-Za-z0-9]+Loader|[A-Za-z0-9]+Stealer|[A-Za-z0-9]+RAT|Infostealer|Spyware|Adware|Rootkit|Ransomware)\b",
    re.IGNORECASE
)

TARGETED_ENTITY_PATTERNS = re.compile(
    r"\b(?:Energy|Finance|Healthcare|Government|Retail|Manufacturing|Telecom|Education|Defense|Transportation|"
    r"Critical Infrastructure|Supply Chain|Financial Services|Health Services|"
    r"[A-Za-z0-9]+ Corporation|[A-Za-z0-9]+ Inc\.|[A-Za-z0-9]+ Ltd\.|Ministry of [A-Za-z]+|National Security Agency)\b",
    re.IGNORECASE
)

# Priority lookup lists
THREAT_ACTORS_LIST = {"lazarus group", "apt29", "fancy bear", "revil", "darkside", "sandworm", "lockbit", "conti"}
MALWARE_NAMES_LIST = {"shamoon", "emotet", "wannacry", "ryuk", "trickbot", "cobalt strike", "locky", "notpetya", "stuxnet"}
TARGETED_ENTITIES_LIST = {"microsoft", "google", "nsa", "tesla", "us department of defense", "financial sector"}

# **Junk Terms to Remove**
JUNK_WORDS = {
    "attack", "command", "tcp", "process", "certificate", "tool", "settings", "file", "data", "windows", "network", "target", "sys", "delete", "exploit", "load backdoor file", "exfiltration", "ftp", "control", "keys.dat", "presumed", "settings.vwx", "encryption", "malicious", "malware", "payload"
}

# **Extract entities using regex and wordlist**
def extract_entities(text, regex_pattern, wordlist):
    extracted = set(match.lower() for match in regex_pattern.findall(text))
    extracted |= {word.lower() for word in text.split() if word.lower() in wordlist}
    return extracted

# **Extract Threat Actors**
def extract_threat_actors(text):
    doc = nlp(text)
    extracted = extract_entities(text, THREAT_ACTOR_PATTERNS, THREAT_ACTORS_LIST)
    extracted |= {ent.text.lower() for ent in doc.ents if ent.label_ == "ORG"}
    return extracted - JUNK_WORDS  # Remove unwanted system terms

# **Extract Malware Names**
def extract_malware_names(text):
    extracted = extract_entities(text, MALWARE_PATTERNS, MALWARE_NAMES_LIST)
    return extracted - JUNK_WORDS

# **Extract Targeted Entities**
def extract_targeted_entities(text):
    doc = nlp(text)
    extracted = extract_entities(text, TARGETED_ENTITY_PATTERNS, TARGETED_ENTITIES_LIST)
    extracted |= {ent.text.lower() for ent in doc.ents if ent.label_ in ["ORG", "GPE"]}
    return extracted - JUNK_WORDS

# **Extract from Filename**
def extract_from_filename(filename):
    clean_filename = re.sub(r"[_\-]", " ", filename.lower())  # Normalize separators
    clean_filename = re.sub(r"\.pdf$", "", clean_filename)  # Remove extension
    return {
        "Threat Actor(s)": extract_threat_actors(clean_filename),
        "Malware(s)": extract_malware_names(clean_filename),
        "Targeted Entities": extract_targeted_entities(clean_filename),
    }

# **Extract from Text**
def extract_from_text(text, existing_entities):
    extracted_threat_actors = existing_entities["Threat Actor(s)"] | extract_threat_actors(text)
    extracted_malware = existing_entities["Malware(s)"] | extract_malware_names(text)
    extracted_entities = existing_entities["Targeted Entities"] | extract_targeted_entities(text)
    return {
        "Threat Actor(s)": sorted(extracted_threat_actors),
        "Malware(s)": sorted(extracted_malware),
        "Targeted Entities": sorted(extracted_entities),
    }

# **Final Cleanup & Prioritization**
def post_process_extracted_data(extracted_data, filename_data):
    threat_actors = set(filename_data["Threat Actor(s)"]) | extracted_data["Threat Actor(s)"]
    malware_names = set(filename_data["Malware(s)"]) | extracted_data["Malware(s)"]
    targeted_entities = set(filename_data["Targeted Entities"]) | extracted_data["Targeted Entities"]

    # **Ensure No Overlap**
    threat_actors -= malware_names  # Malware should not be classified as actors
    targeted_entities -= threat_actors  # Entities should not contain actors
    targeted_entities -= malware_names  # Entities should not contain malware

    return {
        "Threat Actor(s)": sorted(threat_actors),
        "Malware(s)": sorted(malware_names),
        "Targeted Entities": sorted(targeted_entities),
    }

# **Main Function**
def extract_all(filename, text):
    extracted_from_filename = extract_from_filename(filename)
    extracted_from_text = extract_from_text(text, extracted_from_filename)
    return post_process_extracted_data(extracted_from_text, extracted_from_filename)
