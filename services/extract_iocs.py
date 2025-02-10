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
    domains = re.findall(r'\b(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
    iocs['Domains'] = list(set(domains))  # Removing duplicates using set

    # Filter out domains that resemble file names
    file_extensions = [
    '.exe', '.pdf', '.docx', '.jpg', '.png', '.zip', '.tar', '.rar', '.txt', '.pptx', '.xls', 
    '.bat', '.dll', '.jar', '.msi', '.vbs', '.cmd', '.bin', '.sh', '.ps1', '.apk', '.app', '.run', '.items','.etc','.conf','.log','.bak','.old','.temp','.tmp','.swp','.swo','.swn','.attribute','.windll','.ps1', '.cmd', '.scr', '.reg', '.pif', '.gadget', '.jar', '.cab', '.torrent', '.xz', '.bin', '.tar.gz','.ini', '.conf', '.log', '.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.swn', '.attribute','.windll'
    '.dmg', '.iso', '.eml', '.htm', '.html', '.js', '.wsf', '.svg', '.json', '.csv', '.chm', '.vbe','.py','.git','.c','.cpp','.h','.hpp','.java','.class','.php','.asp','.aspx','.jsp','.cs','.vb','.vb','.vbs','.js','.ts','.css','.scss','.less','.html','.htm','.xml','.yml','.yaml','.json','.sql','.pl','.rb','.go','.swift','.kt','.kts','.sh','.bash','.zsh','.ps1','.cmd','.scr','.reg','.pif','.gadget','.jar','.cab','.torrent','.xz','.bin','.tar.gz','.ini','.conf','.log','.bak','.old','.temp','.tmp','.swp','.swo','.swn','.attribute','.windll','.ps1', '.cmd', '.scr', '.reg', '.pif', '.gadget', '.jar', '.cab', '.torrent', '.xz', '.bin', '.tar.gz','.ini', '.conf', '.log', '.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.swn', '.attribute','.windll', '.dat', '.dll', '.sys'
    ]
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
