import re
import spacy
from spacy.matcher import PhraseMatcher

# Load the spaCy model
nlp = spacy.load("en_core_web_sm")

# Function to extract IoCs (IP addresses, Domains, Email addresses, File hashes)
def extract_iocs(text):
    # Replace '[.]' with '.' to handle obfuscated emails
    text = text.replace('[.]', '.')

    iocs = {
        'IP addresses': [],
        'Domains': [],
        'Email addresses': [],
        'File hashes': {
            'MD5': [],
            'SHA1': [],
            'SHA256': []
        }
    }

    # Process the text with spaCy
    doc = nlp(text)

    # Extract Email addresses using spaCy's NER (if the model detects it)
    for ent in doc.ents:
        if ent.label_ == 'EMAIL':
            iocs['Email addresses'].append(ent.text)

    # Extract IP addresses using regex (spaCy does not recognize IPs by default)
    ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    iocs['IP addresses'] = list(set(ip_addresses))  # Removing duplicates using set

    # Extract Domains using regex (spaCy does not recognize domains by default)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.(?:com|org|net|co|[a-z]{2,})\b', text)
    iocs['Domains'] = list(set(domains))  # Removing duplicates using set

    # Extract File hashes (MD5, SHA1, SHA256) using regex
    md5_hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    sha1_hashes = re.findall(r'\b[a-fA-F0-9]{40}\b', text)
    sha256_hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', text)

    # Removing duplicates using set
    iocs['File hashes']['MD5'] = list(set(md5_hashes))
    iocs['File hashes']['SHA1'] = list(set(sha1_hashes))
    iocs['File hashes']['SHA256'] = list(set(sha256_hashes))

    # For domains, use PhraseMatcher for custom matching
    matcher = PhraseMatcher(nlp.vocab)
    domain_patterns = [nlp.make_doc(domain) for domain in iocs['Domains']]
    matcher.add('DOMAIN', domain_patterns)

    # Search for domain patterns in the document
    matches = matcher(doc)
    for match_id, start, end in matches:
        span = doc[start:end]
        if span.text not in iocs['Domains']:
            iocs['Domains'].append(span.text)

    return iocs
