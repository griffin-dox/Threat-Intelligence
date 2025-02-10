import json
import re

def extract_threat_actor(text):
    threat_actor_pattern = re.compile(r'(?i)\b(AeroBlade|Blind Eagle|APT-C-36|Cloud Atlas|Gamaredon|Scarred Manticore|Transparent Tribe|APT-36|Sharp Panda|MuddyWater|Turla|Wizard Spider|Sandworm Team|OilRig|MERCURY|Static Kitten|Fancy Bear|Cozy Bear|Equation Group|DarkSide|REvil|Lazarus|Lazarus group)\b')
    matches = sorted(set(threat_actor_pattern.findall(text)))
    return matches

def extract_targeted_entities(text):
    targeted_entities_pattern = re.compile(r'(?i)(?:targeting|affecting|such as|including|against|compromising|infiltrating|focused on) ([\w,\s&-]+?)(?=, and|, or|\.|\()')
    sector_keywords = {"aerospace", "finance", "government", "healthcare", "education", "military", "energy", "telecom", "infrastructure", "technology", "manufacturing", "aviation", "automotive", "pharmaceuticals", "retail", "supply chain", "transportation", "hospitality", "legal", "media", "law enforcement", "judiciary"}
    country_keywords = {"Colombia", "Ecuador", "Ukraine", "Armenia", "Azerbaijan", "Russia", "Belarus", "Moldova", "Vietnam", "Thailand", "Indonesia"}
    region_keywords = {"Nagorno-Karabakh", "Transnistria", "Luhansk", "Donetsk", "Crimea"}
    organization_pattern = re.compile(r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)* (Inc|Corp|Ltd|LLC|Group|Foundation|University|Institute|Agency|Commission|Ministry|Department|Authority))\b')
    
    matches = targeted_entities_pattern.findall(text)
    entities = set()
    
    for match in matches:
        extracted_entities = {entity.strip() for entity in re.split(r',| and | or ', match)}
        for entity in extracted_entities:
            if entity.lower() in sector_keywords or entity in country_keywords or entity in region_keywords or organization_pattern.match(entity):
                entities.add(entity)
    
    return sorted(entities)

def extract_malware_names(text):
    malware_pattern = re.compile(r'(?i)\b(Trojan/Win\.[\w.-]+|Emotet|TrickBot|Ryuk|Conti|Maze|Cobalt Strike|QakBot|Agent Tesla|Dridex|Zeus|Remcos|Nanocore|Gootkit|FormBook|RedLine Stealer|Vidar|Hancitor|IcedID|Raccoon Stealer|QuasarRAT|SoulSearcher|CrimsonRAT|PowerShower|LIONTAIL|VictoryDll|SloughRAT)\b')
    matches = sorted(set(malware_pattern.findall(text)))
    return matches