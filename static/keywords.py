import re
# Sector Keywords

SECTOR_KEYWORDS = {
    "aerospace", "finance", "government", "healthcare", "education", "military", "energy", "telecom",
    "infrastructure", "technology", "manufacturing", "aviation", "automotive", "pharmaceuticals", "retail",
    "supply chain", "transportation", "hospitality", "legal", "media", "law enforcement", "judiciary",
    "public sector", "defense", "research institutions", "academic institutions", "banking",
    "critical infrastructure", "telecommunications", "nuclear energy", "maritime", "cybersecurity",
    "semiconductor", "space exploration", "biotechnology", "fintech", "artificial intelligence",
    "satellite communications", "chemical industry", "defence"
}

# Country Keywords
COUNTRY_KEYWORDS = {
    "colombia", "ecuador", "ukraine", "armenia", "azerbaijan", "russia", "belarus", "moldova", "vietnam",
    "thailand", "indonesia", "malaysia", "europe", "united states", "china", "iran", "north korea",
    "south korea", "japan", "india", "pakistan", "germany", "france", "united kingdom", "saudi arabia",
    "brazil", "mexico", "canada", "turkey", "israel", "south africa", "nigeria", "argentina", "australia",
    "new zealand", "uae", "singapore"
}

# Region Keywords
REGION_KEYWORDS = {
    "nagorno-karabakh", "transnistria", "luhansk", "donetsk", "crimea", "south china sea", "balkan region",
    "middle east", "asia-pacific", "latin america", "western europe", "eastern europe", "north africa",
    "sub-saharan africa", "central asia", "arctic region", "indo-pacific"
}

MALWARE_TAGS = {
    "backdoor", "trojan", "worm", "virus", "ransomware", "spyware", "adware", "rootkit", "keylogger",
    "botnet", "fileless malware", "payload delivery", "data exfiltration", "cryptojacking malware",
    "sql injection", "cross-site scripting", "buffer overflow", "zero-day exploit", "brute force attack",
    "man-in-the-middle", "denial-of-service", "packet spoofing", "session hijacking",
    
    # Additional Tags:
    "phishing", "spear phishing", "whaling", "credential stuffing", "password spraying",
    "iot malware", "mobile malware", "mac malware", "linux malware", "ransomware-as-a-service",
    "malvertising", "watering hole attack", "drive-by download", "dns hijacking", "domain shadowing",
    "privilege escalation", "lateral movement", "command and control", "remote access trojan",
    "social engineering", "insider threat", "supply chain attack", "deepfake malware",
    "advanced persistent threat", "logic bomb", "time bomb", "polymorphic malware",
    "metamorphic malware", "sandbox evasion", "anti-forensics", "steganography",
    "network sniffing", "port scanning", "reverse shell", "exploit kit", "malware dropper",
    "multi-stage malware", "credential dumping", "kerberoasting", "pass-the-hash",
    "golden ticket attack", "silver ticket attack", "dll injection", "process hollowing",
    "api hooking", "registry manipulation", "persistence mechanism", "scheduled task",
    "service abuse", "wmi abuse", "powershell abuse", "living off the land",
    "cloud malware", "container escape", "server-side request forgery", "xml external entity",
    "insecure deserialization", "race condition", "integer overflow", "use after free",
    "format string vulnerability", "heap spraying", "return-oriented programming",
    "code injection", "memory corruption", "unvalidated input", "directory traversal",
    "path traversal", "privilege abuse", "misconfiguration", "default credentials",
    "weak encryption", "broken authentication", "security mismanagement", "shadow it",
    "unpatched software", "vulnerable library", "third-party risk", "zero trust violation"
}

file_extensions = [
    '.exe', '.pdf', '.docx', '.jpg', '.png', '.zip', '.tar', '.rar', '.txt', '.pptx', '.xls', 
    '.bat', '.dll', '.jar', '.msi', '.vbs', '.cmd', '.bin', '.sh', '.ps1', '.apk', '.app', '.run', '.items','.etc','.conf','.log','.bak','.old','.temp','.tmp','.swp','.swo','.swn','.attribute','.windll','.ps1', '.cmd', '.scr', '.reg', '.pif', '.gadget', '.jar', '.cab', '.torrent', '.xz', '.bin', '.tar.gz','.ini', '.conf', '.log', '.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.swn', '.attribute','.windll'
    '.dmg', '.iso', '.eml', '.htm', '.html', '.js', '.wsf', '.svg', '.json', '.csv', '.chm', '.vbe','.py','.git','.c','.cpp','.h','.hpp','.java','.class','.php','.asp','.aspx','.jsp','.cs','.vb','.vb','.vbs','.js','.ts','.css','.scss','.less','.html','.htm','.xml','.yml','.yaml','.json','.sql','.pl','.rb','.go','.swift','.kt','.kts','.sh','.bash','.zsh','.ps1','.cmd','.scr','.reg','.pif','.gadget','.jar','.cab','.torrent','.xz','.bin','.tar.gz','.ini','.conf','.log','.bak','.old','.temp','.tmp','.swp','.swo','.swn','.attribute','.windll','.ps1', '.cmd', '.scr', '.reg', '.pif', '.gadget', '.jar', '.cab', '.torrent', '.xz', '.bin', '.tar.gz','.ini', '.conf', '.log', '.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.swn', '.attribute','.windll', '.dat', '.dll', '.sys'
]

ADDITIONAL_PATTERNS = {
    "FilePath": re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),  # Windows file paths
    "CommandLine": re.compile(r"(?:cmd\.exe|powershell\.exe).*?(?=\\n|$)", re.IGNORECASE)  # Command-line arguments
}