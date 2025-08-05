
from app.config import  settings

THREAT_INTEL_SOURCES = {
    "virustotal": {
        "api_key": settings.VT_AUTH_KEY,
        "base_url": "https://www.virustotal.com/api/v3",
        "enabled": True
    },
    "alienvault": {
        "api_key": settings.ALIEN_VAULT_KEY,
        "base_url": "https://otx.alienvault.com/api/v1",
        "enabled": True
    },
    "shodan": {
        "api_key": settings.SHODAN_AUTH_KEY,
        "base_url": "https://api.shodan.io",
        "enabled": True
    },
    "malwarebazaar": {
        "api_key": settings.MZ_AUTH_KEY,
        "base_url": "https://mb-api.abuse.ch/api/v1/",
        "enabled": True
    },
    "hybridanalysis": {
        "api_key": settings.HA_AUTH_KEY,
        "base_url": "https://www.hybrid-analysis.com/api/v2/",
        "enabled": True
    },
    "urlscan": {
        "api_key": settings.URLS_AUTH_KEY,
        "base_url": "https://urlscan.io/api/v1",
        "enabled": True
    },
    "abuseipdb": {
        "api_key": settings.ABUSEIPDB_AUTH_KEY,
        "base_url": "https://api.abuseipdb.com/api/v2/",
        "enabled": True
    },
    
    
    
}
