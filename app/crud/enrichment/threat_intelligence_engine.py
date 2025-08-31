import aiohttp
import asyncio
from .threat_intels import THREAT_INTEL_SOURCES
from app.models.enrichment.models import ThreatSeverity
import httpx
import base64
from datetime import datetime
import re
import json
from typing import List,Dict, Any
from app.dependencies import logger

class ThreatIntelligenceEngine:
    def __init__(self):
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """Analyze file hash across multiple threat intelligence sources"""
        tasks = []
        
        if THREAT_INTEL_SOURCES["virustotal"]["enabled"]:
            tasks.append(self._query_virustotal_hash(hash_value))
        
        if THREAT_INTEL_SOURCES["hybridanalysis"]["enabled"]:
            tasks.append(self._query_hybridanalysis_hash(hash_value))
        
        if THREAT_INTEL_SOURCES["alienvault"]["enabled"]:
            tasks.append(self._query_alienvault_hash(hash_value))
        
        if THREAT_INTEL_SOURCES["malwarebazaar"]["enabled"]:
            tasks.append(self._query_malwarebazaar_hash(hash_value))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._merge_hash_results(results)
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain across multiple threat intelligence sources"""
        tasks = []
        
        if THREAT_INTEL_SOURCES["virustotal"]["enabled"]:
            tasks.append(self._query_virustotal_domain(domain))
        
        if THREAT_INTEL_SOURCES["alienvault"]["enabled"]:
            tasks.append(self._query_alienvault_domain(domain))
            
        if THREAT_INTEL_SOURCES["urlscan"]["enabled"]:
            tasks.append(self._query_urlscan_domain(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._merge_domain_results(results)
    
    async def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP address across multiple threat intelligence sources"""
        tasks = []
        
        if THREAT_INTEL_SOURCES["virustotal"]["enabled"]:
            tasks.append(self._query_virustotal_ip(ip))
        
        if THREAT_INTEL_SOURCES["alienvault"]["enabled"]:
            tasks.append(self._query_alienvault_ip(ip))
        
        if THREAT_INTEL_SOURCES["abuseipdb"]["enabled"]:
            tasks.append(self._query_abuseipdb_ip(ip))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._merge_ip_results(results)
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL across multiple threat intelligence sources"""
        tasks = []
        
        # Make sure the configuration keys match the function names
        if THREAT_INTEL_SOURCES["virustotal"]["enabled"]:
            tasks.append(self._query_virustotal_url(url))
        
        if THREAT_INTEL_SOURCES["urlscan"]["enabled"]:
            tasks.append(self._query_urlscan_url(url))
        
        if THREAT_INTEL_SOURCES["alienvault"]["enabled"]:  # Fixed typo
            tasks.append(self._query_alient_vault_url(url))
        
        try:
            # Use return_exceptions=True to handle individual failures gracefully
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return self._merge_url_results(results)
        except Exception as e:
            # Log the error and return a meaningful error response
            
            logger.error(f"Error in analyze_url: {e}")
            return {
                "sources": [],
                "error": str(e),
                "verdict": "ERROR"
            }
    async def _query_virustotal_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query VirusTotal for file hash information"""
        headers = {
            "x-apikey": THREAT_INTEL_SOURCES["virustotal"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['virustotal']['base_url']}/files/{hash_value}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "virustotal",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "virustotal",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "virustotal",
                "status": "error",
                "error": str(e)
            }
    
    async def _query_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal for domain information"""
        headers = {
            "x-apikey": THREAT_INTEL_SOURCES["virustotal"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['virustotal']['base_url']}/domains/{domain}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "virustotal",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "virustotal",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "virustotal",
                "status": "error",
                "error": str(e)
            }
    
    async def _query_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for IP information"""
        headers = {
            "x-apikey": THREAT_INTEL_SOURCES["virustotal"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['virustotal']['base_url']}/ip_addresses/{ip}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "virustotal",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "virustotal",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "virustotal",
                "status": "error",
                "error": str(e)
            }
    
    

    async def _query_abuseipdb_ip(self,ip: str) -> Dict[str, Any]:
        url = f'{THREAT_INTEL_SOURCES["abuseipdb"]["base_url"]}check'
        
        headers = {
            "Key": THREAT_INTEL_SOURCES["abuseipdb"]["api_key"],
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return {
                    "source": "abuseipdb",
                    "status": "success",
                    "data": response.json()
                }
            else:
                return {
                    "source": "abuseipdb",
                    "status": "error",
                    "error": f"HTTP {response.status_code} - {response.text}"
                }

    async def _query_alienvault_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query AlienVault OTX for file hash information"""
        headers = {
            "X-OTX-API-KEY": THREAT_INTEL_SOURCES["alienvault"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['alienvault']['base_url']}/indicators/file/{hash_value}/general",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "alienvault",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "alienvault",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "alienvault",
                "status": "error",
                "error": str(e)
            }
    
    async def _query_malwarebazaar_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query MalwareBazaar for file hash information"""
        url = THREAT_INTEL_SOURCES['malwarebazaar']['base_url']
        headers = {
            "Auth-Key": THREAT_INTEL_SOURCES["malwarebazaar"]["api_key"],
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "query": "get_info",
            "hash": hash_value
        }
        
       
        async with httpx.AsyncClient(http2=False) as client:
            try:
                response = await client.post(url, headers=headers, data=data)
                

                if response.status_code == 200:
                    return {
                        "source": "malwarebazaar",
                        "status": "success",
                        "data": response.json()
                    }
                else:
                    return {
                        "source": "malwarebazaar",
                        "status": "error",
                        "error": f"HTTP {response.status_code}",
                        "raw": response.text
                    }
            except Exception as e:
                return {
                    "source": "malwarebazaar",
                    "status": "error",
                    "error": str(e)
                }
    
    async def _query_alienvault_domain(self, domain: str) -> Dict[str, Any]:
        """Query AlienVault OTX for domain information"""
        headers = {
            "X-OTX-API-KEY": THREAT_INTEL_SOURCES["alienvault"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['alienvault']['base_url']}/indicators/domain/{domain}/general",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "alienvault",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "alienvault",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "alienvault",
                "status": "error",
                "error": str(e)
            }
    
    
    async def _query_urlscan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Submit a domain or URL to URLScan.io for scanning
        """
        headers = {
            "API-Key": THREAT_INTEL_SOURCES["urlscan"]["api_key"],
            "Content-Type": "application/json"
        }

        url = f'{THREAT_INTEL_SOURCES["urlscan"]["base_url"]}/scan/'
        json_data = {
            "url": domain,
            "visibility": "private"  # You can also set "private" if needed
        }
        

        try:
            async with self.session.post(url, headers=headers, json=json_data) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info("URLScan.io Response:", data)
                    return {
                        "source": "urlscan",
                        "status": "success",
                        "data": data  # Contains `uuid`, `result`, `api` links, etc.
                    }
                else:
                    logger.error("URLScan.io Response:", f"HTTP {response.status} - {await response.text()}")
                    return {
                        "source": "urlscan",
                        "status": "error",
                        "error": f"HTTP {response.status} - {await response.text()}"
                    }
        except Exception as e:
            return {
                "source": "urlscan",
                "status": "error",
                "error": str(e)
            }

    async def _query_alienvault_ip(self, ip: str) -> Dict[str, Any]:
        """Query AlienVault OTX for IP information"""
        headers = {
            "X-OTX-API-KEY": THREAT_INTEL_SOURCES["alienvault"]["api_key"]
        }
        
        try:
            async with self.session.get(
                f"{THREAT_INTEL_SOURCES['alienvault']['base_url']}/indicators/IPv4/{ip}/general",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "alienvault",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "alienvault",
                        "status": "error",
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            return {
                "source": "alienvault",
                "status": "error",
                "error": str(e)
            }
    
    


    async def _query_hybridanalysis_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query Hybrid Analysis for file hash information"""
        headers = {
            "api-key": THREAT_INTEL_SOURCES["hybridanalysis"]["api_key"],
            "User-Agent": "Falcon Sandbox"
        }

        url = f"{THREAT_INTEL_SOURCES['hybridanalysis']['base_url']}/search/hash"
        params = {"hash": hash_value}

        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "hybridanalysis",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "hybridanalysis",
                        "status": "error",
                        "error": f"HTTP {response.status} - {await response.text()}"
                    }
        except Exception as e:
            return {
                "source": "hybridanalysis",
                "status": "error",
                "error": str(e)
            }

    

    
    def _merge_hash_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge results from multiple sources for hash analysis"""
        merged_data = {
            "sources": [],
            "malware_signatures": [],
            
            "severity": ThreatSeverity.LOW,
            "confidence_score": 0.0,
            "reputation_score": 0.0,
            "malware_families": [],
            "attack_techniques": [],
            "targeted_countries": [],
            "name": [],
            "description": [],
            "references": [],
            "tags": [],
            
            "hashes": [],
            "signatures": [],
            "file_info": {},
            "hash_tools": {},
            "trid": [],
            "timestamps": {},
            "code_signing": [],
            "delivery_method": None,
            "intelligence": {},
            "file_info_links": [],
            "yara_rules": [],
            "vendor_intel": [],
            "reports": []
        }

        
        for result in results:
            if isinstance(result, dict) and result.get("status") == "success":
                source = result.get("source")
                source_data = result.get("data", {})

                if source == "virustotal":
                    attributes = source_data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    total_count = sum(stats.values())
                    malicious_count = stats.get("malicious", 0)

                    if total_count:
                        reputation_score = (malicious_count / total_count) * 100
                        merged_data["reputation_score"] = max(merged_data["reputation_score"], reputation_score)

                    for engine, data in attributes.get("last_analysis_results", {}).items():
                        if data.get("category") in {"malicious", "suspicious", "malware"}:
                            result_name = data.get("result")
                            if result_name:
                                merged_data["malware_signatures"].append(result_name)

                    if attributes.get("tags"):
                        merged_data["tags"].extend(attributes.get("tags"))

                elif source == "alienvault":
                    pulse_info = source_data.get("pulse_info", {})
                    count = pulse_info.get("count", 0)

                    if count >= 10:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.9)
                    elif count >= 5:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.8)
                    elif count > 0:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.7)

                    for pulse in pulse_info.get("pulses", []):
                        if name := pulse.get("name"):
                            merged_data["name"].append(name)
                        if desc := pulse.get("description"):
                            merged_data["description"].append(desc)
                        if refs := pulse.get("references"):
                            merged_data["references"].extend(refs)
                        if families := pulse.get("malware_families"):
                            merged_data["malware_families"].extend(families)
                        if attacks := pulse.get("attack_ids"):
                            merged_data["attack_techniques"].extend(attacks)
                        if countries := pulse.get("targeted_countries"):
                            merged_data["targeted_countries"].extend(countries)
                        if tags := pulse.get("tags"):
                            merged_data["tags"].extend(tags)

                elif source == "malwarebazaar":
                   
                    for entry in source_data.get("data", []):
                    
                        merged_data["hashes"] = {
                            "sha256": entry.get("sha256_hash"),
                            "sha3_384": entry.get("sha3_384_hash"),
                            "sha1": entry.get("sha1_hash"),
                            "md5": entry.get("md5_hash"),
                        }

                        merged_data["file_info"] = {
                            "file_name": entry.get("file_name"),
                            "file_size": entry.get("file_size"),
                            "file_type": entry.get("file_type"),
                            "mime_type": entry.get("file_type_mime"),
                            "reporter": entry.get("reporter"),
                            "origin_country": entry.get("origin_country"),
                            "anonymous": bool(entry.get("anonymous")),
                        }

                        merged_data["signatures"] = list(set(
                            merged_data.get("signatures", []) + [entry.get("signature")]
                            if entry.get("signature") else []
                        ))

                        merged_data["hash_tools"] = {
                            "imphash": entry.get("imphash"),
                            "tlsh": entry.get("tlsh"),
                            "telfhash": entry.get("telfhash"),
                            "gimphash": entry.get("gimphash"),
                            "ssdeep": entry.get("ssdeep"),
                            "dhash_icon": entry.get("dhash_icon"),
                            "magika": entry.get("magika"),
                        }

                        merged_data["trid"] = entry.get("trid", [])

                        merged_data["timestamps"] = {
                            "first_seen": entry.get("first_seen"),
                            "last_seen": entry.get("last_seen")
                        }

                        merged_data["tags"] = list(set(
                            merged_data.get("tags", []) + entry.get("tags", [])
                        ))
                        merged_data["code_signing"] = entry.get("code_sign", [])
                        merged_data["delivery_method"] = entry.get("delivery_method")
                        merged_data["intelligence"] = entry.get("intelligence", {})
                        merged_data["file_info_links"] = [
                            i.get("value") for i in entry.get("file_information", []) if i.get("value")
                        ]
                        merged_data["yara_rules"] = [
                            {
                                "name": r.get("rule_name"),
                                "author": r.get("author"),
                                "description": r.get("description")
                            } for r in entry.get("yara_rules", [])
                        ]
                        vendor_intel = entry.get("vendor_intel", {})
                        
                        merged_data["vendor_intel"] = vendor_intel
       
                elif source == "hybridanalysis":
                    

                    
                    reports = source_data.get("reports", [])

                    for i, report in enumerate(reports, start=1):
                        

                        # Save individual report to JSON file
                        with open(f"output_{i}.json", "w", encoding="utf-8") as f:
                            json.dump(report, f, indent=4, ensure_ascii=False)

                        # Extract severity based on verdict
                        verdict = report.get("verdict", "").lower()
                        logger.info("verdict:",verdict)
                        if verdict == "malicious":
                            merged_data["severity"] = ThreatSeverity.HIGH
                        elif verdict == "suspicious":
                            merged_data["severity"] = ThreatSeverity.MEDIUM
                        elif verdict == "no specific threat":
                            merged_data["severity"] = ThreatSeverity.LOW

                        # Append other useful data
                        merged_data["reports"].append({
                            "report_id": report.get("id"),
                            "environment": report.get("environment_description"),
                            "verdict": verdict,
                            "state": report.get("state")
                        })

                    

                merged_data["sources"].append(source)
        
        if merged_data["reputation_score"] > 50:
                    merged_data["severity"] = ThreatSeverity.CRITICAL
        elif merged_data["reputation_score"] > 20:
                    merged_data["severity"] = ThreatSeverity.HIGH
        elif merged_data["reputation_score"] > 5:
                    merged_data["severity"] = ThreatSeverity.MEDIUM    
        for key in ["malware_signatures", "name", "description", "references", "tags", "malware_families", "attack_techniques", "targeted_countries", "sources"]:
            if isinstance(merged_data.get(key), list):
                if merged_data[key] and isinstance(merged_data[key][0], dict):
                    # Skip or apply custom logic
                    pass
                else:
                    merged_data[key] = list(set(merged_data[key]))
        
        return merged_data
    def _merge_domain_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge results from multiple sources for domain analysis"""
        
        # with open(f"output.json", "w", encoding="utf-8") as f:
        #     json.dump(results, f, indent=4, ensure_ascii=False)
                
        merged_data = {
        "reputation_score": 0,
        "confidence_score": 0,
        "severity": ThreatSeverity.LOW,
        "sources": [],
        "threat_indicators": [],
        "domain_info": {},
        "security_details": {},
        "certificates": {},
        "dns_records": [],
        "whois_info": {},
        "scan_results": {},
        "risk_factors": []
        }
        
        for result in results:
            if isinstance(result, dict) and result.get("status") == "success":
                source_data = result.get("data", {})
                source_name = result.get("source")
                logger.info("Source: %s", source_name)

                # Process VirusTotal data
                if source_name == "virustotal":
                    vt_data = source_data.get("data", {})
                    attributes = vt_data.get("attributes", {})
                    
                    # Analysis statistics
                    stats = attributes.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    harmless_count = stats.get("harmless", 0)
                    undetected_count = stats.get("undetected", 0)
                    total_count = sum(stats.values())
                    
                    if total_count > 0:
                        reputation_score = ((malicious_count + suspicious_count * 0.5) / total_count) * 100
                        merged_data["reputation_score"] = max(merged_data["reputation_score"], reputation_score)
                    
                    # Domain information
                    merged_data["domain_info"].update({
                        "tld": attributes.get("tld"),
                        "creation_date": datetime.fromtimestamp(attributes.get("creation_date", 0)).isoformat() if attributes.get("creation_date") else None,
                        "expiration_date": datetime.fromtimestamp(attributes.get("expiration_date", 0)).isoformat() if attributes.get("expiration_date") else None,
                        "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).isoformat() if attributes.get("last_analysis_date") else None,
                        "registrar": attributes.get("registrar"),
                        "reputation": attributes.get("reputation", 0)
                    })
                    
                    # Security analysis
                    merged_data["security_details"].update({
                        "malicious_detections": malicious_count,
                        "suspicious_detections": suspicious_count,
                        "harmless_detections": harmless_count,
                        "undetected": undetected_count,
                        "total_engines": total_count,
                        "tags": attributes.get("tags", []),
                        "categories": list(attributes.get("categories", {}).keys())
                    })
                    
                    # DNS Records
                    dns_records = attributes.get("last_dns_records", [])
                    merged_data["dns_records"] = dns_records
                    
                    # Extract IP addresses from DNS records
                    ip_addresses = []
                    for record in dns_records:
                        if record.get("type") == "A":
                            ip_addresses.append(record.get("value"))
                    
                    if ip_addresses:
                        merged_data["domain_info"]["ip_addresses"] = ip_addresses
                    
                    # HTTPS Certificate information
                    cert_info = attributes.get("last_https_certificate", {})
                    if cert_info:
                        cert_validity = cert_info.get("validity", {})
                        cert_subject = cert_info.get("subject", {})
                        cert_issuer = cert_info.get("issuer", {})
                        
                        merged_data["certificates"] = {
                            "subject_cn": cert_subject.get("CN"),
                            "issuer": cert_issuer.get("CN"),
                            "issuer_organization": cert_issuer.get("O"),
                            "valid_from": cert_validity.get("not_before"),
                            "valid_until": cert_validity.get("not_after"),
                            "serial_number": cert_info.get("serial_number"),
                            "signature_algorithm": cert_info.get("cert_signature", {}).get("signature_algorithm"),
                            "key_algorithm": cert_info.get("public_key", {}).get("algorithm"),
                            "certificate_size": cert_info.get("size"),
                            "thumbprint": cert_info.get("thumbprint"),
                            "alternative_names": cert_info.get("extensions", {}).get("subject_alternative_name", [])
                        }
                    
                    # WHOIS information parsing
                    whois_data = attributes.get("whois", "")
                    if whois_data:
                        whois_parsed = self.parse_whois_data(whois_data)
                        merged_data["whois_info"].update(whois_parsed)
                    
                    # Risk assessment
                    risk_factors = []
                    if malicious_count > 5:
                        risk_factors.append(f"High malicious detections: {malicious_count}")
                        merged_data["severity"] = ThreatSeverity.HIGH
                    elif malicious_count > 2:
                        risk_factors.append(f"Moderate malicious detections: {malicious_count}")
                        merged_data["severity"] = ThreatSeverity.MEDIUM
                    
                    if suspicious_count > 0:
                        risk_factors.append(f"Suspicious detections: {suspicious_count}")
                    
                    # Check for recent registration (potential indicator)
                    creation_timestamp = attributes.get("creation_date", 0)
                    if creation_timestamp:
                        days_since_creation = (datetime.now().timestamp() - creation_timestamp) / (24 * 3600)
                        if days_since_creation < 30:
                            risk_factors.append(f"Recently registered domain ({int(days_since_creation)} days ago)")
                    
                    merged_data["risk_factors"].extend(risk_factors)
                    
                # Process AlienVault/OTX data
                elif source_name == "alienvault":
                    pulse_info = source_data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    
                    if pulse_count > 0:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.8)
                        merged_data["severity"] = ThreatSeverity.HIGH
                        
                        pulses = pulse_info.get("pulses", [])
                        threat_indicators = []
                        
                        for pulse in pulses:
                            threat_indicators.append({
                                "pulse_name": pulse.get("name"),
                                "description": pulse.get("description"),
                                "created": pulse.get("created"),
                                "modified": pulse.get("modified"),
                                "tags": pulse.get("tags", []),
                                "adversary": pulse.get("adversary"),
                                "malware_families": pulse.get("malware_families", [])
                            })
                        
                        merged_data["threat_indicators"] = threat_indicators
                        merged_data["risk_factors"].append(f"Found in {pulse_count} threat intelligence pulse(s)")
                    
                    # Related threat intelligence
                    related_info = pulse_info.get("related", {})
                    if related_info:
                        alienvault_related = related_info.get("alienvault", {})
                        other_related = related_info.get("other", {})
                        
                        merged_data["security_details"]["related_adversaries"] = (
                            alienvault_related.get("adversary", []) + 
                            other_related.get("adversary", [])
                        )
                        merged_data["security_details"]["related_malware"] = (
                            alienvault_related.get("malware_families", []) + 
                            other_related.get("malware_families", [])
                        )
                        merged_data["security_details"]["related_industries"] = (
                            alienvault_related.get("industries", []) + 
                            other_related.get("industries", [])
                        )
                    
                # Process URLScan data
                elif source_name == "urlscan":
                    
                    scan_uuid = source_data.get("uuid")
                    scan_result_url = source_data.get("result")
                    scan_api_url = source_data.get("api")
                    scan_visibility = source_data.get("visibility")
                    scan_country = source_data.get("country")
                    scan_url = source_data.get("url")
                    
                    merged_data["scan_results"] = {
                        "urlscan_uuid": scan_uuid,
                        "result_url": scan_result_url,
                        "api_url": scan_api_url,
                        "visibility": scan_visibility,
                        "scan_country": scan_country,
                        "scanned_url": scan_url,
                        "submission_successful": source_data.get("message") == "Submission successful"
                    }
                    
                    if scan_uuid:
                        merged_data["risk_factors"].append("Domain submitted for behavioral analysis")
                
                merged_data["sources"].append(source_name)
                
                # Final risk assessment
        if merged_data["reputation_score"] > 50:
                    merged_data["severity"] = ThreatSeverity.CRITICAL
        elif merged_data["reputation_score"] > 20:
                    merged_data["severity"] = ThreatSeverity.HIGH
        elif merged_data["reputation_score"] > 5:
                    merged_data["severity"] = ThreatSeverity.MEDIUM
                
                # Calculate overall confidence score
        source_count = len(merged_data["sources"])
        base_confidence = min(source_count * 0.3, 1.0)
                
        if merged_data["threat_indicators"]:
                    base_confidence += 0.3
        if merged_data["security_details"].get("malicious_detections", 0) > 0:
                    base_confidence += 0.4
                
        merged_data["confidence_score"] = max(merged_data["confidence_score"], base_confidence)
                
        return merged_data
    def parse_whois_data(self,whois_text):
        """Parse WHOIS data into structured format"""
        whois_info = {}
        
        patterns = {
            "creation_date": r"Creation Date:\s*(.+)",
            "expiry_date": r"Registry Expiry Date:\s*(.+)",
            "registrar": r"Registrar:\s*(.+)",
            "registrar_abuse_email": r"Registrar Abuse Contact Email:\s*(.+)",
            "registrar_abuse_phone": r"Registrar Abuse Contact Phone:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "domain_status": r"Domain Status:\s*(.+)",
            "dnssec": r"DNSSEC:\s*(.+)"
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, whois_text, re.IGNORECASE)
            if matches:
                if key == "name_servers":
                    whois_info[key] = matches  # Keep all name servers
                else:
                    whois_info[key] = matches[0].strip()
        
        return whois_info
   
    def _merge_ip_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge results from multiple sources for comprehensive IP analysis"""
        merged_data = {
            "sources": [],
            "geographic_info": {},
            "threat_actors": [],
            "severity": ThreatSeverity.LOW,
            "confidence_score": 0.0,
            "reputation_score": 0.0,
            "malware_families": [],
            "threat_types": [],
            "network_info": {},
            "certificate_info": {},
            "detection_engines": {
                "total": 0,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            },
            "abuse_reports": {},
            "tags": [],
            "last_seen": None,
            "verdict": "UNKNOWN"
        }
        
        for result in results:
            # Remove debug output - should not be in production code
            # Debug output should use logging instead
            
            if isinstance(result, dict) and result.get("status") == "success":
                source_data = result.get("data", {})
                source_name = result.get("source")
                
                # Add source to list immediately
                if source_name:
                    merged_data["sources"].append(source_name)
                
                # Process VirusTotal data
                if source_name == "virustotal":
                    vt_data = source_data.get("data", {})
                    attributes = vt_data.get("attributes", {})
                    
                    # Detection statistics
                    stats = attributes.get("last_analysis_stats", {})
                    merged_data["detection_engines"]["malicious"] += stats.get("malicious", 0)
                    merged_data["detection_engines"]["suspicious"] += stats.get("suspicious", 0)
                    merged_data["detection_engines"]["harmless"] += stats.get("harmless", 0)
                    merged_data["detection_engines"]["undetected"] += stats.get("undetected", 0)
                    merged_data["detection_engines"]["total"] = sum([
                        merged_data["detection_engines"]["malicious"],
                        merged_data["detection_engines"]["suspicious"],
                        merged_data["detection_engines"]["harmless"],
                        merged_data["detection_engines"]["undetected"]
                    ])
                    
                    # Calculate reputation score
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    total_count = sum(stats.values())
                    
                    if total_count > 0:
                        # Weight malicious higher than suspicious
                        weighted_score = (malicious_count * 1.0 + suspicious_count * 0.5) / total_count
                        reputation_score = weighted_score * 100
                        merged_data["reputation_score"] = max(merged_data["reputation_score"], reputation_score)
                    
                    # Geographic and network information - only update if not already set
                    geo_updates = {
                        "country": attributes.get("country"),
                        "continent": attributes.get("continent"),
                        "network": attributes.get("network"),
                        "asn": attributes.get("asn"),
                        "as_owner": attributes.get("as_owner"),
                        "regional_internet_registry": attributes.get("regional_internet_registry")
                    }
                    for key, value in geo_updates.items():
                        if value and not merged_data["geographic_info"].get(key):
                            merged_data["geographic_info"][key] = value
                    
                    # Extract threat types from detection results
                    analysis_results = attributes.get("last_analysis_results", {})
                    threat_types = set()
                    malware_families = set()
                    
                    for engine, result_data in analysis_results.items():
                        if result_data.get("category") in ["malicious", "suspicious"]:
                            result_type = result_data.get("result", "").lower()
                            if "phishing" in result_type:
                                threat_types.add("phishing")
                            elif "malware" in result_type:
                                threat_types.add("malware")
                                malware_families.add(result_type)
                            elif "trojan" in result_type:
                                threat_types.add("trojan")
                                malware_families.add(result_type)
                            elif "botnet" in result_type:
                                threat_types.add("botnet")
                            elif "suspicious" in result_type:
                                threat_types.add("suspicious_activity")
                    
                    merged_data["threat_types"].extend(list(threat_types))
                    merged_data["malware_families"].extend(list(malware_families))
                    
                    # Certificate information (if available)
                    cert_info = attributes.get("last_https_certificate", {})
                    if cert_info:
                        merged_data["certificate_info"] = {
                            "subject": cert_info.get("subject", {}).get("CN"),
                            "issuer": cert_info.get("issuer", {}).get("CN"),
                            "validity_not_after": cert_info.get("validity", {}).get("not_after"),
                            "validity_not_before": cert_info.get("validity", {}).get("not_before"),
                            "serial_number": cert_info.get("serial_number"),
                            "thumbprint": cert_info.get("thumbprint_sha256")
                        }
                    
                    # Tags and reputation
                    merged_data["tags"].extend(attributes.get("tags", []))
                    vt_reputation = attributes.get("reputation", 0)
                    if vt_reputation < 0:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.8)
                    
                    # Last analysis date
                    last_analysis = attributes.get("last_analysis_date")
                    if last_analysis:
                        if merged_data["last_seen"] is None or last_analysis > merged_data["last_seen"]:
                            merged_data["last_seen"] = last_analysis
                
                # Process AbuseIPDB data
                elif source_name == "abuseipdb":
                    abuse_data = source_data.get("data", {})
                    
                    # Abuse confidence score
                    abuse_confidence = abuse_data.get("abuseConfidenceScore", 0)
                    merged_data["abuse_reports"]["abuseipdb"] = {
                        "confidence_score": abuse_confidence,
                        "total_reports": abuse_data.get("totalReports", 0),
                        "distinct_users": abuse_data.get("numDistinctUsers", 0),
                        "last_reported": abuse_data.get("lastReportedAt"),
                        "is_whitelisted": abuse_data.get("isWhitelisted", False),
                        "usage_type": abuse_data.get("usageType"),
                        "isp": abuse_data.get("isp"),
                        "domain": abuse_data.get("domain"),
                        "is_tor": abuse_data.get("isTor", False)
                    }
                    
                    # Update geographic info if not already set
                    if not merged_data["geographic_info"].get("country"):
                        merged_data["geographic_info"]["country"] = abuse_data.get("countryCode")
                    
                    # Factor abuse confidence into overall confidence
                    if abuse_confidence > 75:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.9)
                    elif abuse_confidence > 50:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.7)
                    elif abuse_confidence > 25:
                        merged_data["confidence_score"] = max(merged_data["confidence_score"], 0.5)
                
                # Process AlienVault/OTX data
                elif source_name == "alientvault":
                    data = source_data
                    indicator = data.get("indicator")
                    reputation = data.get("reputation", 0)
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    
                    # Geographic Info - only update if not already set
                    geo_info = {
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code2"),
                        "continent": data.get("continent_code"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "asn": data.get("asn", "").strip(),
                    }
                    for key, value in geo_info.items():
                        if value and not merged_data["geographic_info"].get(key):
                            merged_data["geographic_info"][key] = value
                    
                    # Tags and Threat Context from Pulses
                    all_pulse_tags = []
                    for pulse in pulses:
                        pulse_tags = [tag.lower() for tag in pulse.get("tags", [])]
                        all_pulse_tags.extend(pulse_tags)
                    
                    # Infer malware families from known tags
                    known_malware = {
                        "cobaltstrike", "stealc", "ghostrat", "asyncrat", "remcosrat",
                        "quasarrat", "formbook", "masslogger", "sharkstealer", "rhadamanthys",
                        "guloader", "mirai", "mozi", "tsunami", "xworm", "netsupport"
                    }
                    detected_malware = [tag for tag in all_pulse_tags if tag in known_malware]
                    
                    # Classify threat types
                    threat_types = []
                    if "cobaltstrike" in all_pulse_tags or any("rat" in tag for tag in all_pulse_tags):
                        threat_types.append("C2")
                    if "stealc" in all_pulse_tags or "sharkstealer" in all_pulse_tags:
                        threat_types.append("Infostealer")
                    if "mirai" in all_pulse_tags or "mozi" in all_pulse_tags:
                        threat_types.append("Botnet")
                    if "powershell" in all_pulse_tags or "ps1" in all_pulse_tags or "encoded" in all_pulse_tags:
                        threat_types.append("Script-Based Attack")
                    
                    # Update merged data
                    merged_data["tags"].extend(all_pulse_tags)
                    merged_data["malware_families"].extend(detected_malware)
                    merged_data["threat_types"].extend(threat_types)
                    
                    # Reputation & Confidence
                    merged_data["reputation_score"] = max(merged_data["reputation_score"], float(reputation))
                    
                    # Confidence score: Based on number of pulses and presence of high-risk tags
                    confidence = 0.3  # base
                    if pulses:
                        confidence += min(0.6, 0.1 * len(pulses))  # up to +0.6
                    if "cobaltstrike" in all_pulse_tags or "stealc" in all_pulse_tags:
                        confidence += 0.4  # strong signal
                    merged_data["confidence_score"] = max(merged_data["confidence_score"], min(confidence, 1.0))
                    
                    # Network Info
                    network_updates = {
                        "ip": indicator,
                        "asn": data.get("asn", "").strip(),
                        "whois": data.get("whois")
                    }
                    for key, value in network_updates.items():
                        if value and not merged_data["network_info"].get(key):
                            merged_data["network_info"][key] = value
                    
                    # Last seen: Use latest pulse creation/modification
                    for pulse in pulses:
                        modified = pulse.get("modified")
                        created = pulse.get("created")
                        candidate = max(modified, created) if modified and created else modified or created
                        if candidate and (merged_data["last_seen"] is None or candidate > merged_data["last_seen"]):
                            merged_data["last_seen"] = candidate
                    
                    # Store pulse information in abuse reports
                    merged_data["abuse_reports"]["alienvault"] = {
                        "total_reports": len(pulses),
                        "report_names": [p.get("name", "") for p in pulses],
                        "urls": data.get("pulse_info", {}).get("references", [])
                    }
        
        # Determine overall severity and verdict based on collected data
        malicious_detections = merged_data["detection_engines"]["malicious"]
        suspicious_detections = merged_data["detection_engines"]["suspicious"]
        abuse_confidence = max([
            report.get("confidence_score", 0) 
            for report in merged_data["abuse_reports"].values() 
            if isinstance(report, dict)
        ], default=0)
        
        # Set severity and verdict
        if malicious_detections >= 5 or abuse_confidence >= 75:
            merged_data["severity"] = ThreatSeverity.CRITICAL
            merged_data["verdict"] = "MALICIOUS"
        elif malicious_detections >= 2 or suspicious_detections >= 3 or abuse_confidence >= 50:
            merged_data["severity"] = ThreatSeverity.HIGH
            merged_data["verdict"] = "SUSPICIOUS"
        elif malicious_detections >= 1 or suspicious_detections >= 1 or abuse_confidence >= 25:
            merged_data["severity"] = ThreatSeverity.MEDIUM
            merged_data["verdict"] = "POTENTIALLY_MALICIOUS"
        elif merged_data["detection_engines"]["harmless"] > 0:
            merged_data["severity"] = ThreatSeverity.LOW
            merged_data["verdict"] = "CLEAN"
        
        # Handle AlienVault-specific severity overrides
        if "alienvault" in merged_data["sources"]:
            high_risk_tags = ["cobaltstrike", "stealc"]
            medium_risk_tags = ["mirai", "mozi"]
            
            if any(tag in merged_data["tags"] for tag in high_risk_tags) or any("rat" in tag for tag in merged_data["tags"]):
                merged_data["severity"] = max(merged_data["severity"], ThreatSeverity.CRITICAL)
                merged_data["verdict"] = "MALICIOUS"
            elif any(tag in merged_data["tags"] for tag in medium_risk_tags):
                merged_data["severity"] = max(merged_data["severity"], ThreatSeverity.HIGH)
                if merged_data["verdict"] == "UNKNOWN":
                    merged_data["verdict"] = "SUSPICIOUS"
        
        # Calculate final confidence score
        total_sources = len(merged_data["sources"])
        detection_ratio = malicious_detections / max(merged_data["detection_engines"]["total"], 1)
        
        base_confidence = min(0.9, total_sources * 0.3 + detection_ratio * 0.7)
        merged_data["confidence_score"] = max(merged_data["confidence_score"], base_confidence)
        
        # Remove duplicates and clean up
        merged_data["threat_actors"] = list(set(merged_data["threat_actors"]))
        merged_data["threat_types"] = list(set(merged_data["threat_types"]))
        merged_data["malware_families"] = list(set(merged_data["malware_families"]))
        merged_data["sources"] = list(set(merged_data["sources"]))
        merged_data["tags"] = list(set(merged_data["tags"]))
        
        return merged_data
    
    
    
    
    
    
    async def _query_alient_vault_url(self, url_to_check: str) -> Dict[str, Any]:
        """Query AlienVault OTX for URL threat info"""
        headers = {
            "X-OTX-API-KEY": THREAT_INTEL_SOURCES["alienvault"]["api_key"]  # Fixed typo
        }

        base_url = THREAT_INTEL_SOURCES["alienvault"]["base_url"]  # Fixed typo
        url = f"{base_url}/indicators/url/{url_to_check}/general"

        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "alien_vault",  # Fixed typo
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "alien_vault",  # Fixed typo
                        "status": "error",
                        "error": f"HTTP {response.status} - {await response.text()}"
                    }
        except Exception as e:
            return {
                "source": "alien_vault",  # Fixed typo
                "status": "error",
                "error": str(e)
            }

    
    

    async def _query_urlscan_url(self, target_url: str) -> Dict[str, Any]:
        """
        Submit a URL to URLScan.io for scanning.

        Args:
            target_url (str): The URL to be scanned.

        Returns:
            Dict[str, Any]: A dictionary containing scan result or error details.
        """
        headers = {
            "API-Key": THREAT_INTEL_SOURCES["urlscan"]["api_key"],
            "Content-Type": "application/json"
        }

        payload = {
            "url": target_url,
            "visibility": "private"
        }

        base_url = THREAT_INTEL_SOURCES["urlscan"]["base_url"]  # e.g., https://urlscan.io/api/v1
        scan_url = f"{base_url}/scan/"

        try:
            async with self.session.post(scan_url, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "urlscan",
                        "status": "success",
                        "data": data
                    }
                else:
                    # Attempt to parse JSON error
                    try:
                        error_json = await response.json()
                        error_message = error_json.get("message", "Unknown error")
                    except Exception:
                        error_message = await response.text()

                    return {
                        "source": "urlscan",
                        "status": "error",
                        "error": f"HTTP {response.status} - {error_message}"
                    }

        except Exception as e:
            return {
                "source": "urlscan",
                "status": "error",
                "error": str(e)
            }


    async def _query_virustotal_url(self, url_to_check: str) -> Dict[str, Any]:
        """Query VirusTotal for URL analysis"""
        headers = {
            "x-apikey": THREAT_INTEL_SOURCES["virustotal"]["api_key"]
        }

        # Encode the URL in URL-safe base64 without padding
        url_bytes = url_to_check.encode("utf-8")
        url_id = base64.urlsafe_b64encode(url_bytes).decode().strip("=")

        vt_url = f'{THREAT_INTEL_SOURCES["virustotal"]["base_url"]}/urls/{url_id}'  # Added missing slash

        try:
            async with self.session.get(vt_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "virustotal",
                        "status": "success",
                        "data": data
                    }
                else:
                    return {
                        "source": "virustotal",
                        "status": "error",
                        "error": f"HTTP {response.status} - {await response.text()}"
                    }
        except Exception as e:
            return {
                "source": "virustotal",
                "status": "error",
                "error": str(e)
            }






    def _merge_url_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced URL results merger with comprehensive data extraction"""
        
        merged_data = {
            "sources": [],
            "url": None,
            "final_url": None,
            "redirection_chain": [],
            "geographic_info": {
                "country": None,
                "location": None
            },
            "threat_actors": [],
            "severity": ThreatSeverity.LOW,
            "confidence_score": 0.0,
            "reputation_score": 0.0,
            "malware_families": [],
            
            "network_info": {
                "domain": None,
                "hostname": None,
                "tld": None,
                "ip_addresses": [],
                "asn_info": {}
            },
            
            "detection_engines": {
                "total": 0,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "timeout": 0
            },
            
            "tags": [],
            "categories": {},
            "threat_names": [],
            "http_info": {
                "response_code": None,
                "content_length": None,
                "content_sha256": None,
                "headers": {},
                "title": None
            },
            "submission_info": {
                "first_submission": None,
                "last_analysis": None,
                "times_submitted": 0
            },
            "pulses": [],
            "outgoing_links": [],
            "last_seen": None,
            "verdict": "UNKNOWN"
        }
        
        logger.debug(f"Processing {len(results)} results")
        
        # Tracking variables for verdict calculation
        total_engines = 0
        malicious_count = 0
        suspicious_count = 0
        
        for result in results:
            # Handle exceptions that might be returned by asyncio.gather
            if isinstance(result, Exception):
                logger.error(f"Exception in result: {result}")
                continue
                
            if not isinstance(result, dict) or result.get("status") != "success":
                logger.warning(f"Skipping failed result: {result}")
                continue
                
            source_data = result.get("data", {})
            source_name = result.get("source")
            
            if not source_name:
                continue
                
            # Add source to list
            merged_data["sources"].append(source_name)
            
            # Process VirusTotal data
            if source_name == "virustotal":
                self._process_virustotal_data(source_data, merged_data)
                
                # Update verdict calculation variables
                if "data" in source_data and "attributes" in source_data["data"]:
                    attrs = source_data["data"]["attributes"]
                    if "last_analysis_stats" in attrs:
                        stats = attrs["last_analysis_stats"]
                        total_engines += sum(stats.values())
                        malicious_count += stats.get("malicious", 0)
                        suspicious_count += stats.get("suspicious", 0)
            
            # Process URLScan data
            elif source_name == "urlscan":
                self._process_urlscan_data(source_data, merged_data)
            
            # Process AlienVault/OTX data
            elif source_name == "alien_vault":
                self._process_alienvault_data(source_data, merged_data)
        
        # Calculate final verdict and severity
        merged_data["verdict"] = self._calculate_verdict(
            total_engines, malicious_count, suspicious_count, merged_data
        )
        merged_data["severity"] = self._calculate_severity(
            malicious_count, suspicious_count, total_engines, merged_data
        )
        
        # Calculate confidence score based on number of sources and detections
        merged_data["confidence_score"] = self._calculate_confidence_score(
            len(merged_data["sources"]), malicious_count, total_engines
        )
        
        # Calculate reputation score (0-100, lower is worse)
        if total_engines > 0:
            merged_data["reputation_score"] = max(0, 100 - ((malicious_count + suspicious_count) / total_engines * 100))
        
        return merged_data

    def _process_virustotal_data(self, vt_data: Dict[str, Any], merged_data: Dict[str, Any]) -> None:
        """Process VirusTotal specific data"""
        if "data" not in vt_data or "attributes" not in vt_data["data"]:
            return
            
        attrs = vt_data["data"]["attributes"]
        
        # Basic URL information
        merged_data["url"] = attrs.get("url")
        merged_data["final_url"] = attrs.get("last_final_url")
        merged_data["redirection_chain"] = attrs.get("redirection_chain", [])
        
        # Network information
        merged_data["network_info"]["domain"] = attrs.get("domain")
        merged_data["network_info"]["tld"] = attrs.get("tld")
        
        # HTTP information
        merged_data["http_info"]["response_code"] = attrs.get("last_http_response_code")
        merged_data["http_info"]["content_length"] = attrs.get("last_http_response_content_length")
        merged_data["http_info"]["content_sha256"] = attrs.get("last_http_response_content_sha256")
        merged_data["http_info"]["headers"] = attrs.get("last_http_response_headers", {})
        merged_data["http_info"]["title"] = attrs.get("title")
        
        # Detection statistics
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            merged_data["detection_engines"].update({
                "total": sum(stats.values()),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            })
        
        # Threat information
        merged_data["threat_names"].extend(attrs.get("threat_names", []))
        merged_data["categories"].update(attrs.get("categories", {}))
        merged_data["tags"].extend(attrs.get("tags", []))
        merged_data["outgoing_links"].extend(attrs.get("outgoing_links", []))
        
        # Submission information
        if attrs.get("first_submission_date"):
            merged_data["submission_info"]["first_submission"] = datetime.fromtimestamp(
                attrs["first_submission_date"]
            ).isoformat()
        
        if attrs.get("last_analysis_date"):
            merged_data["submission_info"]["last_analysis"] = datetime.fromtimestamp(
                attrs["last_analysis_date"]
            ).isoformat()
            merged_data["last_seen"] = merged_data["submission_info"]["last_analysis"]
        
        merged_data["submission_info"]["times_submitted"] = attrs.get("times_submitted", 0)
        merged_data["reputation_score"] = attrs.get("reputation", 0)

    def _process_urlscan_data(self, urlscan_data: Dict[str, Any], merged_data: Dict[str, Any]) -> None:
        """Process URLScan specific data"""
        # URLScan provides submission confirmation and analysis links
        if urlscan_data.get("uuid"):
            merged_data["network_info"]["urlscan_uuid"] = urlscan_data["uuid"]
            merged_data["network_info"]["urlscan_result"] = urlscan_data.get("result")
            merged_data["network_info"]["urlscan_api"] = urlscan_data.get("api")
        
        # Geographic information
        if urlscan_data.get("country"):
            merged_data["geographic_info"]["country"] = urlscan_data["country"].upper()
        
        # URL information
        if not merged_data["url"] and urlscan_data.get("url"):
            merged_data["url"] = urlscan_data["url"]
        
        # Visibility and options
        merged_data["network_info"]["urlscan_visibility"] = urlscan_data.get("visibility")
        merged_data["network_info"]["urlscan_options"] = urlscan_data.get("options", {})

    def _process_alienvault_data(self, otx_data: Dict[str, Any], merged_data: Dict[str, Any]) -> None:
        """Process AlienVault OTX specific data"""
        # Basic indicator information
        if not merged_data["url"] and otx_data.get("indicator"):
            merged_data["url"] = otx_data["indicator"]
        
        # Network information
        merged_data["network_info"]["domain"] = otx_data.get("domain")
        merged_data["network_info"]["hostname"] = otx_data.get("hostname")
        
        # External links for further investigation
        if otx_data.get("alexa"):
            merged_data["network_info"]["alexa_info"] = otx_data["alexa"]
        if otx_data.get("whois"):
            merged_data["network_info"]["whois_info"] = otx_data["whois"]
        
        # Process pulse information (threat intelligence feeds)
        if "pulse_info" in otx_data and "pulses" in otx_data["pulse_info"]:
            for pulse in otx_data["pulse_info"]["pulses"]:
                pulse_info = {
                    "id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse.get("tags", []),
                    "references": pulse.get("references", []),
                    "malware_families": pulse.get("malware_families", []),
                    "adversary": pulse.get("adversary"),
                    "targeted_countries": pulse.get("targeted_countries", []),
                    "industries": pulse.get("industries", []),
                    "tlp": pulse.get("TLP"),
                    "author": pulse.get("author", {}).get("username")
                }
                merged_data["pulses"].append(pulse_info)
                
                # Extract threat information from pulses
                merged_data["tags"].extend(pulse.get("tags", []))
                merged_data["malware_families"].extend(pulse.get("malware_families", []))
                if pulse.get("adversary"):
                    merged_data["threat_actors"].append(pulse.get("adversary"))
        
        # Process related indicators
        if "pulse_info" in otx_data and "related" in otx_data["pulse_info"]:
            related = otx_data["pulse_info"]["related"]
            merged_data["network_info"]["related_indicators"] = {
                "alienvault_count": related.get("alienvault", {}).get("unique_indicators", 0),
                "other_sources_count": related.get("other", {}).get("unique_indicators", 0)
            }

    def _calculate_verdict(self, total_engines: int, malicious: int, suspicious: int, 
                        merged_data: Dict[str, Any]) -> str:
        """Calculate overall verdict based on detection statistics and threat intelligence"""
        
        # High confidence malicious if multiple engines detect it
        if malicious >= 5:
            return "MALICIOUS"
        
        # Medium confidence malicious
        if malicious >= 2:
            return "SUSPICIOUS"
        
        # Check for suspicious indicators
        if suspicious >= 3 or (malicious >= 1 and suspicious >= 1):
            return "SUSPICIOUS"
        
        # Check threat intelligence indicators
        threat_indicators = [
            bool(merged_data["threat_names"]),
            bool(merged_data["pulses"]),
            "phishing" in merged_data["tags"],
            "malware" in merged_data["tags"],
            any("malicious" in cat.lower() for cat in merged_data["categories"].values())
        ]
        
        if sum(threat_indicators) >= 2:
            return "SUSPICIOUS"
        elif sum(threat_indicators) >= 1:
            return "POTENTIALLY_SUSPICIOUS"
        
        # If we have enough data and no threats detected
        if total_engines >= 10 and malicious == 0 and suspicious == 0:
            return "CLEAN"
        
        return "UNKNOWN"

    def _calculate_severity(self, malicious: int, suspicious: int, total_engines: int,
                        merged_data: Dict[str, Any]) -> ThreatSeverity:
        """Calculate threat severity"""
        
        # Critical severity indicators
        if malicious >= 10 or any(name.lower() in ["ransomware", "trojan", "rootkit"] 
                                for name in merged_data["threat_names"]):
            return ThreatSeverity.CRITICAL
        
        # High severity
        if malicious >= 5 or (malicious >= 2 and suspicious >= 2):
            return ThreatSeverity.HIGH
        
        # Medium severity
        if malicious >= 2 or suspicious >= 5 or bool(merged_data["pulses"]):
            return ThreatSeverity.MEDIUM
        
        return ThreatSeverity.LOW

    def _calculate_confidence_score(self, source_count: int, malicious: int, total_engines: int) -> float:
        """Calculate confidence score (0.0 to 1.0)"""
        
        # Base confidence from number of sources
        source_confidence = min(source_count / 3.0, 1.0) * 0.3
        
        # Detection confidence
        if total_engines > 0:
            detection_confidence = min(total_engines / 50.0, 1.0) * 0.4
        else:
            detection_confidence = 0.0
        
        # Agreement confidence (how consistent are the results)
        if total_engines > 0:
            agreement_ratio = malicious / total_engines
            if agreement_ratio > 0.8 or agreement_ratio < 0.1:  # High agreement
                agreement_confidence = 0.3
            elif agreement_ratio > 0.6 or agreement_ratio < 0.2:  # Medium agreement
                agreement_confidence = 0.2
            else:  # Low agreement
                agreement_confidence = 0.1
        else:
            agreement_confidence = 0.0
        
        return min(source_confidence + detection_confidence + agreement_confidence, 1.0)