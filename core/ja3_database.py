"""
JA3 & JA4 TLS Fingerprint Database and Real-World Threat Intelligence lookup.
Maps TLS Client Hello fingerprints to actual vulnerabilities, C2 frameworks, and APT campaigns.
"""

JA3_SIGNATURES = {
    # Malicious / Threat Fingerprints with Real CVE & Threat Actor Correlations
    "3b2a1060b2984534f3780f2d93e1cf70": {
        "name": "Cobalt Strike Beacon (Default Malleable Profile)",
        "category": "Malware C2 / Post-Exploitation",
        "cve_correlation": "Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965)",
        "risk": "CRITICAL",
        "description": "Standard default TLS handshake used by Cobalt Strike Beacon agents after exploiting RCE vulnerabilities."
    },
    "fa84f73809623e10037a34eb60bf3d2b": {
        "name": "PowerShell Empire Reverse HTTPS Agent",
        "category": "Post-Exploitation Agent",
        "cve_correlation": "ProxyShell (CVE-2021-34473), Follina (CVE-2022-30190)",
        "risk": "HIGH",
        "description": "PowerShell-based post-exploitation framework establishing encrypted reverse shell connection."
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "name": "Metasploit Meterpreter Reverse HTTPS",
        "category": "Exploitation Payload",
        "cve_correlation": "EternalBlue (CVE-2017-0144), Apache Struts (CVE-2017-5638)",
        "risk": "HIGH",
        "description": "Standard Metasploit Meterpreter payload establishing encrypted command channel."
    },
    "7717255a268e2082b2605f8842410a70": {
        "name": "Tor Anonymization Client / Circuit",
        "category": "Anonymization Network",
        "cve_correlation": "Unauthorized Anonymized Proxy / Perimeter Bypass",
        "risk": "MEDIUM",
        "description": "Tor encrypted relay connection. Indicates potential internal perimeter bypass or covert relay."
    },
    "6734f37d976077357e4e107d92b85292": {
        "name": "AsyncRAT / Quasar RAT Ransomware Dropper",
        "category": "Remote Access Trojan / Ransomware",
        "cve_correlation": "Outlook RCE (CVE-2023-23397), OneNote Malware Droppers",
        "risk": "CRITICAL",
        "description": "AsyncRAT encrypted command-and-control connection utilized prior to ransomware deployment."
    },
    "51c64c77e60da94539665c40464f1d43": {
        "name": "TrickBot / BazarBackdoor Banking Trojan",
        "category": "Botnet Infrastructure",
        "cve_correlation": "Zerologon (CVE-2020-1472), Ryuk Ransomware Staging",
        "risk": "CRITICAL",
        "description": "TrickBot botnet infrastructure communication fingerprint used for enterprise domain escalation."
    },
    "9a2f7c00e12d45a9871bc3298fa11122": {
        "name": "DNS-over-HTTPS Covert Exfiltration (iodine / dnscat2)",
        "category": "Data Exfiltration / Tunnel",
        "cve_correlation": "SUNBURST / SolarWinds Supply Chain Exfil Tactics",
        "risk": "HIGH",
        "description": "Covert DNS-over-HTTPS data staging client exfiltrating sensitive files over encrypted HTTPS."
    },

    # Legitimate / Standard Fingerprints
    "cdb5840456437bd7738ee96fc6a4182a": {
        "name": "Google Chrome (Modern Windows/Mac)",
        "category": "Standard Web Browser",
        "cve_correlation": "None (Legitimate User Activity)",
        "risk": "LOW",
        "description": "Standard Google Chrome desktop browser TLS ClientHello."
    },
    "b32309a26951912be7dba376398207b3": {
        "name": "Mozilla Firefox (Modern Desktop)",
        "category": "Standard Web Browser",
        "cve_correlation": "None (Legitimate User Activity)",
        "risk": "LOW",
        "description": "Standard Firefox desktop browser TLS handshake."
    },
    "73b88b29b4e3498877ee3d538e137839": {
        "name": "Apple Safari (macOS / iOS)",
        "category": "Standard Web Browser",
        "cve_correlation": "None (Legitimate User Activity)",
        "risk": "LOW",
        "description": "Apple Safari browser TLS Client Hello fingerprint."
    },
    "3505c21f92e03aa37227bf0225d3512e": {
        "name": "Python requests / urllib3",
        "category": "Scripting Library",
        "cve_correlation": "Automated Script / Internal Tool",
        "risk": "LOW",
        "description": "Standard Python HTTP client. Requires baseline context inspection."
    }
}

def lookup_ja3(ja3_hash):
    """Look up a JA3 hash in the threat intel signature database."""
    if not ja3_hash:
        return {"name": "Unknown / Missing JA3", "category": "Unknown", "cve_correlation": "None", "risk": "LOW", "description": "No TLS fingerprint captured."}
    
    if ja3_hash in JA3_SIGNATURES:
        return JA3_SIGNATURES[ja3_hash]
    
    return {
        "name": f"Uncategorized Fingerprint ({ja3_hash[:8]}...)",
        "category": "Unclassified TLS Client",
        "cve_correlation": "Unclassified Signature",
        "risk": "INFO",
        "description": "TLS fingerprint not present in threat intelligence database."
    }
