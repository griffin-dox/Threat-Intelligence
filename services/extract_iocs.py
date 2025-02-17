import re
import spacy
from spacy.matcher import PhraseMatcher
from static.keywords import file_extensions

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
    # Handle obfuscation
    text = text.replace('[.]', '.').replace('(dot)', '.').replace('[at]', '@').replace('(at)', '@')

    # Regex for emails
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    extracted_emails = set(re.findall(email_regex, text))

    # SpaCy NER for emails
    for ent in doc.ents:
        if ent.label_ == 'EMAIL':
            extracted_emails.add(ent.text)

    # Validate extracted emails
    iocs['Email addresses'] = [email for email in extracted_emails if '@' in email and '.' in email.split('@')[-1]]

    # Extract IP addresses using regex (spaCy does not recognize IPs by default)
    ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    iocs['IP addresses'] = list(set(ip_addresses))  # Removing duplicates using set

    # Extract Domains using regex (spaCy does not recognize domains by default)
    domains = re.findall(r'\b(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
    iocs['Domains'] = list(set(domains))  # Removing duplicates using set

    # Filter out domains that resemble file names
    iocs['Domains'] = [domain for domain in iocs['Domains'] if not any(ext in domain.lower() for ext in file_extensions)]

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
