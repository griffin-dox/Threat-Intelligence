import re

# Threat Actor Extraction
THREAT_ACTOR_PATTERN = re.compile(
    r'(?i)\b(AeroBlade|Blind Eagle|APT-C-36|Cloud Atlas|Gamaredon|Scarred Manticore|Transparent Tribe|APT-36|'
    r'Sharp Panda|MuddyWater|Turla|Wizard Spider|Sandworm Team|OilRig|MERCURY|Static Kitten|Fancy Bear|Cozy Bear|'
    r'Equation Group|DarkSide|REvil|Lazarus|Lazarus Group|APT41|FIN7|TA505|Wizard Spider|Cobalt Group|Carbanak|'
    r'UNC1878|SilverTerrier|Evil Corp|Silent Ransom Group|FIN8|BlueNoroff|Charming Kitten|Chollima|APT28|APT29|'
    r'Bronze Butler|DragonFly|Elderwood Group|GCMAN|GoldenJackal|Ke3chang|Magic Hound|Night Dragon|Nomadic Octopus|'
    r'Tonto Team)\b', re.IGNORECASE
)

# Targeted Entities Extraction
TARGETED_ENTITIES_PATTERN = re.compile(
    r'(?i)(?:targeting|affecting|such as|including|against|compromising|infiltrating|focused on) ([\w,\s&-]+?)(?=, and|, or|\.|\()', re.IGNORECASE
)

# Malware Name Extraction
MALWARE_NAME_PATTERN = re.compile(
    r'(?i)\b(Trojan/Win\\.[\w.-]+|Emotet|TrickBot|Ryuk|Conti|Maze|Cobalt Strike|QakBot|Agent Tesla|Dridex|Zeus|Remcos|Nanocore|'
    r'Gootkit|FormBook|RedLine Stealer|Vidar|Hancitor|IcedID|Raccoon Stealer|QuasarRAT|SoulSearcher|CrimsonRAT|PowerShower|'
    r'LIONTAIL|VictoryDll|SloughRAT|PlugX|ToddyCat|Hive|Holy Ghost Ransomware|Black Basta|Clop|LockBit|AvosLocker|Ragnar Locker|'
    r'BumbleBee|DarkGate|NJRat|DarkComet|XLoader|Android Joker|Jigsaw Ransomware|Sodinokibi|Zloader|Babuk|Netwalker|Snake Keylogger|'
    r'AsyncRAT|BianLian|CylanceRAT|DarkSide|EKANS|GhostRAT|Havex|Industroyer|Javali|KARMA|MacOS EvilQuest|Mozi|Necurs|Olympic Destroyer|'
    r'PonyFinal|Raspberry Robin|ShadowHammer|TurlaSnake|WannaMine|XMRig|Mirai|Gafgyt|Trik|DanaBot|Hancitor|SmokeLoader|Satori|Sysrv|'
    r'Varenyky|VBShower|Zloader|ShellBot|CoinMiner|Mispadu|BackSwap|TA505|TFlower|Glupteba|RevengeRAT|Adwind|Cerberus|Kinsing|'
    r'FickerStealer|Infostealer)\b', re.IGNORECASE
)

HASH_PATTERNS = {
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),  # Case-insensitive SHA1
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),  # Case-insensitive SHA256
    "MD5": re.compile(r"\b[a-f0-9]{32}\b(?![:a-f0-9]{33})"),  # Improved MD5
    "SSDeep": re.compile(r"\b(3[2-9]|[1248]\d{2,4}|16384):[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+\b"),
    "TLSH": re.compile(r"\b[0-9A-F]{32}\b(?![:0-9A-F]{33})")  # Improved TLSH
}