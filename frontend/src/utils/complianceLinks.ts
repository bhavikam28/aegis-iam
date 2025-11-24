/**
 * Compliance Framework Reference Links
 * Maps compliance requirements to official documentation URLs
 */

export interface ComplianceLink {
  framework: string;
  requirement: string;
  url: string;
  description?: string;
}

// Official compliance documentation URLs
const COMPLIANCE_BASE_URLS = {
  hipaa: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  pci_dss: 'https://www.pcisecuritystandards.org/document_library/',
  sox: 'https://www.sec.gov/rules/final/33-8238.htm',
  gdpr: 'https://gdpr-info.eu/',
  cis: 'https://www.cisecurity.org/benchmark/aws',
  nist: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
  'soc 2': 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html',
  soc2: 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html',
};

// HIPAA specific requirements
const HIPAA_REQUIREMENTS: Record<string, string> = {
  '164.308(a)(4)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.308',
  '164.312(a)(1)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
  '164.312(a)(2)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
  '164.312(a)(2)(iv)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
  '164.312(c)(1)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
  '164.312(b)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.312',
  '164.502(b)': 'https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html#164.502',
};

// PCI DSS specific requirements
// Note: PCI SSC document library doesn't support direct deep links to specific requirements
// Links go to the document library - users need to search for the requirement number in the PDF
const PCI_DSS_REQUIREMENTS: Record<string, string> = {
  '1': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
  '7.1.2': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
  '8.3': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
  '10': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
  '4.2': 'https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document',
};

// GDPR Articles
const GDPR_ARTICLES: Record<string, string> = {
  'Article 5': 'https://gdpr-info.eu/art-5-gdpr/',
  'Article 25': 'https://gdpr-info.eu/art-25-gdpr/',
  'Article 30': 'https://gdpr-info.eu/art-30-gdpr/',
  'Article 32': 'https://gdpr-info.eu/art-32-gdpr/',
};

// SOX Sections
const SOX_SECTIONS: Record<string, string> = {
  'Section 302': 'https://www.sec.gov/rules/final/33-8238.htm#302',
  'Section 404': 'https://www.sec.gov/rules/final/33-8238.htm#404',
};

/**
 * Get compliance requirement link
 */
export function getComplianceLink(framework: string, requirement: string): string | null {
  const frameworkLower = framework.toLowerCase();
  
  if (frameworkLower === 'hipaa' && HIPAA_REQUIREMENTS[requirement]) {
    return HIPAA_REQUIREMENTS[requirement];
  }
  
  if (frameworkLower === 'pci_dss' || frameworkLower === 'pci dss') {
    const req = requirement.match(/(\d+\.\d+\.\d+)/)?.[1] || requirement.match(/(\d+\.\d+)/)?.[1];
    if (req && PCI_DSS_REQUIREMENTS[req]) {
      return PCI_DSS_REQUIREMENTS[req];
    }
    return COMPLIANCE_BASE_URLS.pci_dss;
  }
  
  if (frameworkLower === 'gdpr') {
    const article = requirement.match(/Article (\d+)/i)?.[0];
    if (article && GDPR_ARTICLES[article]) {
      return GDPR_ARTICLES[article];
    }
    return COMPLIANCE_BASE_URLS.gdpr;
  }
  
  if (frameworkLower === 'sox') {
    const section = requirement.match(/Section (\d+)/i)?.[0];
    if (section && SOX_SECTIONS[section]) {
      return SOX_SECTIONS[section];
    }
    return COMPLIANCE_BASE_URLS.sox;
  }
  
  if (frameworkLower === 'cis' || frameworkLower === 'cis aws') {
    return COMPLIANCE_BASE_URLS.cis;
  }
  
  if (frameworkLower === 'nist') {
    return COMPLIANCE_BASE_URLS.nist;
  }
  
  if (frameworkLower === 'soc 2' || frameworkLower === 'soc2') {
    return COMPLIANCE_BASE_URLS['soc 2'];
  }
  
  // Fallback to base URL
  return COMPLIANCE_BASE_URLS[frameworkLower as keyof typeof COMPLIANCE_BASE_URLS] || null;
}

/**
 * Format compliance requirement text with clickable link
 * Returns JSX-ready format or plain text with markdown link
 */
export function formatComplianceRequirement(
  framework: string,
  requirement: string,
  format: 'markdown' | 'html' = 'markdown'
): string {
  const link = getComplianceLink(framework, requirement);
  
  if (!link) {
    return requirement;
  }
  
  if (format === 'markdown') {
    return `[${requirement}](${link})`;
  }
  
  return `<a href="${link}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:text-blue-800 underline">${requirement}</a>`;
}

/**
 * Extract compliance requirements from text and add links
 */
export function addComplianceLinks(text: string): string {
  // HIPAA patterns: 164.308(a)(4), 164.312(a)(1), etc.
  text = text.replace(
    /(HIPAA\s+)?(164\.\d+\([a-z]\)?\(?\d+\)?)/gi,
    (match, prefix, req) => {
      const link = getComplianceLink('hipaa', req);
      if (link) {
        return `[${match}](${link})`;
      }
      return match;
    }
  );
  
  // PCI DSS patterns: PCI DSS 7.1.2, Requirement 8.3, etc.
  text = text.replace(
    /(PCI\s+DSS\s+)?(?:Requirement\s+)?(\d+\.\d+(?:\.\d+)?)/gi,
    (match, prefix, req) => {
      const link = getComplianceLink('pci_dss', req);
      if (link) {
        return `[${match}](${link})`;
      }
      return match;
    }
  );
  
  // GDPR patterns: Article 5, Article 25, etc.
  text = text.replace(
    /(GDPR\s+)?(Article\s+\d+)/gi,
    (match, prefix, article) => {
      const link = getComplianceLink('gdpr', article);
      if (link) {
        return `[${match}](${link})`;
      }
      return match;
    }
  );
  
  // SOX patterns: Section 302, Section 404, etc.
  text = text.replace(
    /(SOX\s+)?(Section\s+\d+)/gi,
    (match, prefix, section) => {
      const link = getComplianceLink('sox', section);
      if (link) {
        return `[${match}](${link})`;
      }
      return match;
    }
  );
  
  return text;
}

