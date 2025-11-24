"""
Compliance Framework Reference Links
Maps compliance requirements to official documentation URLs
"""

# Official compliance documentation URLs
COMPLIANCE_BASE_URLS = {
    'hipaa': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
    'pci_dss': 'https://www.pcisecuritystandards.org/document_library/',
    'sox': 'https://www.sec.gov/rules/final/33-8238.htm',
    'gdpr': 'https://gdpr-info.eu/',
    'cis': 'https://www.cisecurity.org/benchmark/aws',
    'nist': 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    'soc_2': 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html',
}

# HIPAA specific requirements
# Note: HHS site uses section anchors, but subsections may require manual navigation
# Using more specific URLs with section anchors and search parameters where available
HIPAA_REQUIREMENTS = {
    '164.308(a)(4)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.308',
    '164.312(a)(1)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
    '164.312(a)(2)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
    '164.312(a)(2)(iv)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
    '164.312(c)(1)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
    '164.312(b)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
    '164.502(b)': 'https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html#164.502',
}

# PCI DSS specific requirements
# Note: PCI SSC doesn't provide direct deep links to specific requirements
# Using the official document library with requirement number in URL for better context
# Users will need to navigate to the specific requirement in the PDF/document
PCI_DSS_REQUIREMENTS = {
    '1': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
    '7.1.2': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document#req_7',
    '8.3': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document#req_8',
    '10': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document#req_10',
    '4.2': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document#req_4',
}

# GDPR Articles
GDPR_ARTICLES = {
    'Article 5': 'https://gdpr-info.eu/art-5-gdpr/',
    'Article 25': 'https://gdpr-info.eu/art-25-gdpr/',
    'Article 30': 'https://gdpr-info.eu/art-30-gdpr/',
    'Article 32': 'https://gdpr-info.eu/art-32-gdpr/',
}

# SOX Sections
SOX_SECTIONS = {
    'Section 302': 'https://www.sec.gov/rules/final/33-8238.htm#302',
    'Section 404': 'https://www.sec.gov/rules/final/33-8238.htm#404',
}


def get_compliance_link(framework: str, requirement: str) -> str:
    """
    Get compliance requirement link
    
    Args:
        framework: Compliance framework name (e.g., 'HIPAA', 'PCI DSS', 'GDPR')
        requirement: Requirement identifier (e.g., '164.308(a)(4)', '7.1.2', 'Article 5')
    
    Returns:
        URL to official compliance documentation, or base URL if specific requirement not found
    """
    framework_lower = framework.lower().strip()
    
    # HIPAA
    if framework_lower == 'hipaa':
        if requirement in HIPAA_REQUIREMENTS:
            return HIPAA_REQUIREMENTS[requirement]
        return COMPLIANCE_BASE_URLS['hipaa']
    
    # PCI DSS
    if framework_lower in ('pci_dss', 'pci dss', 'pci-dss'):
        # Extract requirement number (e.g., "7.1.2" from "Requirement 7.1.2" or "PCI DSS 7.1.2")
        import re
        req_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+|\d+)', requirement)
        if req_match:
            req_num = req_match.group(1)
            if req_num in PCI_DSS_REQUIREMENTS:
                return PCI_DSS_REQUIREMENTS[req_num]
        return COMPLIANCE_BASE_URLS['pci_dss']
    
    # GDPR
    if framework_lower == 'gdpr':
        # Extract article number (e.g., "Article 5" from "GDPR Article 5")
        import re
        article_match = re.search(r'Article\s+(\d+)', requirement, re.IGNORECASE)
        if article_match:
            article_num = int(article_match.group(1))
            article_key = f'Article {article_num}'
            if article_key in GDPR_ARTICLES:
                return GDPR_ARTICLES[article_key]
        return COMPLIANCE_BASE_URLS['gdpr']
    
    # SOX
    if framework_lower == 'sox':
        # Extract section number (e.g., "Section 302" from "SOX Section 302")
        import re
        section_match = re.search(r'Section\s+(\d+)', requirement, re.IGNORECASE)
        if section_match:
            section_num = int(section_match.group(1))
            section_key = f'Section {section_num}'
            if section_key in SOX_SECTIONS:
                return SOX_SECTIONS[section_key]
        return COMPLIANCE_BASE_URLS['sox']
    
    # CIS
    if framework_lower in ('cis', 'cis aws'):
        return COMPLIANCE_BASE_URLS['cis']
    
    # SOC 2
    if framework_lower in ('soc 2', 'soc2', 'soc_2'):
        return COMPLIANCE_BASE_URLS['soc_2']
    
    # NIST
    if framework_lower == 'nist':
        return COMPLIANCE_BASE_URLS['nist']
    
    # Fallback to base URL if framework found
    return COMPLIANCE_BASE_URLS.get(framework_lower, '')


def parse_compliance_violation(violation_text: str) -> dict:
    """
    Parse a compliance violation string and extract framework, requirement, and link
    
    Args:
        violation_text: String like "HIPAA 164.308(a)(4) (Access Control)" or "PCI DSS 7.1.2"
    
    Returns:
        Dict with 'framework', 'requirement', 'link', and 'text' keys
    """
    import re
    
    # Remove parenthetical descriptions like "(Access Control)" or "(Least Privilege)"
    clean_text = re.sub(r'\s*\([^)]+\)\s*$', '', violation_text).strip()
    
    framework = None
    requirement = clean_text
    link = None
    
    # Try to match HIPAA
    hipaa_match = re.search(r'HIPAA\s+(164\.\d+\([a-z]\)?\(?\d+\)?(?:\([a-z]+\))?)', clean_text, re.IGNORECASE)
    if hipaa_match:
        framework = 'HIPAA'
        requirement = hipaa_match.group(1)
        link = get_compliance_link('HIPAA', requirement)
    
    # Try to match PCI DSS
    elif re.search(r'PCI\s+DSS', clean_text, re.IGNORECASE):
        framework = 'PCI DSS'
        pci_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+|\d+)', clean_text)
        if pci_match:
            requirement = pci_match.group(1)
        link = get_compliance_link('PCI DSS', requirement)
    
    # Try to match GDPR
    elif re.search(r'GDPR', clean_text, re.IGNORECASE):
        framework = 'GDPR'
        gdpr_match = re.search(r'Article\s+(\d+)', clean_text, re.IGNORECASE)
        if gdpr_match:
            requirement = f"Article {gdpr_match.group(1)}"
        link = get_compliance_link('GDPR', requirement)
    
    # Try to match SOX
    elif re.search(r'SOX', clean_text, re.IGNORECASE):
        framework = 'SOX'
        sox_match = re.search(r'Section\s+(\d+)', clean_text, re.IGNORECASE)
        if sox_match:
            requirement = f"Section {sox_match.group(1)}"
        link = get_compliance_link('SOX', requirement)
    
    # Try to match SOC 2
    elif re.search(r'SOC\s*2', clean_text, re.IGNORECASE):
        framework = 'SOC 2'
        requirement = clean_text  # Keep full text for SOC 2
        link = get_compliance_link('SOC 2', requirement)
    
    # Try to match CIS
    elif re.search(r'CIS', clean_text, re.IGNORECASE):
        framework = 'CIS'
        requirement = clean_text  # Keep full text for CIS
        link = get_compliance_link('CIS', requirement)
    
    return {
        'framework': framework or 'Unknown',
        'requirement': requirement,
        'link': link or '',
        'text': violation_text
    }


def add_links_to_compliance_violations(violations: list) -> list:
    """
    Add links to a list of compliance violation strings
    
    Args:
        violations: List of violation strings like ["HIPAA 164.308(a)(4)", "PCI DSS 7.1.2"]
    
    Returns:
        List of dicts with 'text', 'framework', 'requirement', and 'link' keys
    """
    result = []
    for violation in violations:
        parsed = parse_compliance_violation(violation)
        result.append(parsed)
    return result

