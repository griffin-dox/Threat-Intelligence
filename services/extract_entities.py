import re

def extract_threat_actor(text):
    threat_actor_pattern = re.compile(r'(?i)\b(AeroBlade|Blind Eagle|APT-C-36|Cloud Atlas|Gamaredon|Scarred Manticore|Transparent Tribe|APT-36|Sharp Panda|MuddyWater|Turla|Wizard Spider|Sandworm Team|OilRig|MERCURY|Static Kitten|Fancy Bear|Cozy Bear|Equation Group|DarkSide|REvil|Lazarus|Lazarus Group|APT41|FIN7|TA505|Wizard Spider|Cobalt Group|Carbanak|UNC1878|SilverTerrier|Evil Corp|Silent Ransom Group|FIN8|BlueNoroff|Charming Kitten|Chollima|APT28|APT29|Bronze Butler|DragonFly|Elderwood Group|GCMAN|GoldenJackal|Ke3chang|Magic Hound|Night Dragon|Nomadic Octopus|Tonto Team)\b', re.IGNORECASE)
    return sorted(set(threat_actor_pattern.findall(text)))

def extract_targeted_entities(text):
    targeted_entities_pattern = re.compile(r'(?i)(?:targeting|affecting|such as|including|against|compromising|infiltrating|focused on) ([\w,\s&-]+?)(?=, and|, or|\.|\()', re.IGNORECASE)
    sector_keywords = {s.lower() for s in ["aerospace", "finance", "government", "healthcare", "education", "military", "energy", "telecom", "infrastructure", "technology", "manufacturing", "aviation", "automotive", "pharmaceuticals", "retail", "supply chain", "transportation", "hospitality", "legal", "media", "law enforcement", "judiciary", "public sector", "defense", "research institutions", "academic institutions", "banking", "critical infrastructure", "telecommunications", "nuclear energy", "maritime", "cybersecurity", "semiconductor", "space exploration", "biotechnology", "fintech", "artificial intelligence", "satellite communications", "chemical industry","Defence"]}
    country_keywords = {c.lower() for c in ["Colombia", "Ecuador", "Ukraine", "Armenia", "Azerbaijan", "Russia", "Belarus", "Moldova", "Vietnam", "Thailand", "Indonesia", "Malaysia", "Europe", "United States", "China", "Iran", "North Korea", "South Korea", "Japan", "India","Indian", "Pakistan", "Germany", "France", "United Kingdom", "Saudi Arabia", "Brazil", "Mexico", "Canada", "Turkey", "Israel", "South Africa", "Nigeria", "Argentina", "Australia", "New Zealand", "UAE", "Singapore"]}
    region_keywords = {r.lower() for r in ["Nagorno-Karabakh", "Transnistria", "Luhansk", "Donetsk", "Crimea", "South China Sea", "Balkan Region", "Middle East", "Asia-Pacific", "Latin America", "Western Europe", "Eastern Europe", "North Africa", "Sub-Saharan Africa", "Central Asia", "Arctic Region", "Indo-Pacific"]}
    organization_pattern = re.compile(r'(?i)\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)* (Inc|Corp|Ltd|LLC|Group|Foundation|University|Institute|Agency|Commission|Ministry|Department|Authority|Organization|Council|Consortium|Division|Research Lab|Center|Bureau|Office|Task Force|Alliance|Consortium))\b', re.IGNORECASE)
    
    matches = targeted_entities_pattern.findall(text)
    entities = set()
    
    for match in matches:
        extracted_entities = {entity.strip().lower() for entity in re.split(r',| and | or ', match)}
        for entity in extracted_entities:
            if entity in sector_keywords or entity in country_keywords or entity in region_keywords or organization_pattern.match(entity):
                entities.add(entity.title())
    
    return sorted(entities)

def extract_malware_names(text):
    malware_pattern = re.compile(r'(?i)\b(Trojan/Win\\.[\w.-]+|Emotet|TrickBot|Ryuk|Conti|Maze|Cobalt Strike|QakBot|Agent Tesla|Dridex|Zeus|Remcos|Nanocore|Gootkit|FormBook|RedLine Stealer|Vidar|Hancitor|IcedID|Raccoon Stealer|QuasarRAT|SoulSearcher|CrimsonRAT|PowerShower|LIONTAIL|VictoryDll|SloughRAT|PlugX|ToddyCat|Hive|Holy Ghost Ransomware|Black Basta|Clop|LockBit|AvosLocker|Ragnar Locker|BumbleBee|DarkGate|NJRat|DarkComet|XLoader|Android Joker|Jigsaw Ransomware|Sodinokibi|Zloader|Babuk|Netwalker|Snake Keylogger|AsyncRAT|BianLian|CylanceRAT|DarkSide|EKANS|GhostRAT|Havex|Industroyer|Javali|KARMA|MacOS EvilQuest|Mozi|Necurs|Olympic Destroyer|PonyFinal|Raspberry Robin|ShadowHammer|TurlaSnake|WannaMine|XMRig|Zloader|Mirai|Gafgyt|Trik|DanaBot|Hancitor|SmokeLoader|Satori|Sysrv|Varenyky|VBShower|Zloader|ShellBot|CoinMiner|Mispadu|BackSwap|TA505|TFlower|Glupteba|RevengeRAT|Adwind|Cerberus|Kinsing|FickerStealer|Infostealer)\b', re.IGNORECASE)
    return sorted(set(malware_pattern.findall(text)))

