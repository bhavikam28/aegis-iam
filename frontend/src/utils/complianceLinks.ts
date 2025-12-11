/**
 * Compliance Framework Reference Links
 * 
 * Maps compliance requirements to their official documentation URLs
 */

interface ComplianceLinks {
  [key: string]: {
    [key: string]: string;
  };
}

const complianceLinks: ComplianceLinks = {
  // HIPAA Links - HHS Official Documentation (Different pages for each)
  'hipaa': {
    'access controls': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/administrative-safeguards/index.html',
    'access control': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/administrative-safeguards/index.html',
    'audit logging': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/audit-controls/index.html',
    'audit': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/audit-controls/index.html',
    'logging': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/audit-controls/index.html',
    'data protection': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/physical-safeguards/index.html',
    'encryption': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/encryption/index.html',
    'minimum necessary': 'https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/minimum-necessary-requirement/index.html',
    'phi': 'https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/protected-health-information/index.html',
    'ephi': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
    'information access': 'https://www.hhs.gov/hipaa/for-professionals/security/guidance/administrative-safeguards/index.html',
    'default': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html'
  },
  
  // PCI DSS Links - Official PCI Security Standards
  'pci': {
    'access controls': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'access control': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'logging': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'audit': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'encryption': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'least privilege': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'cardholder': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'default': 'https://www.pcisecuritystandards.org/document_library/'
  },
  'pci dss': {
    'access controls': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'access control': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'logging': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'audit': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'encryption': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'least privilege': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'cardholder': 'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
    'default': 'https://www.pcisecuritystandards.org/document_library/'
  },
  
  // SOX Links - SEC Official Rules (Section-specific)
  'sox': {
    'section 404': 'https://www.sec.gov/rules/final/33-8238.htm',
    'section 302': 'https://www.sec.gov/rules/final/33-8238.htm',
    'access controls': 'https://www.sec.gov/rules/final/33-8238.htm',
    'segregation of duties': 'https://www.sec.gov/rules/final/33-8238.htm',
    'audit': 'https://www.sec.gov/rules/final/33-8238.htm',
    'logging': 'https://www.sec.gov/rules/final/33-8238.htm',
    'change management': 'https://www.sec.gov/rules/final/33-8238.htm',
    'controls': 'https://www.sec.gov/rules/final/33-8238.htm',
    'financial': 'https://www.sec.gov/rules/final/33-8238.htm',
    'integrity': 'https://www.sec.gov/rules/final/33-8238.htm',
    'default': 'https://www.sec.gov/rules/final/33-8238.htm'
  },
  
  // GDPR Links - Official GDPR Resources
  'gdpr': {
    'data protection': 'https://gdpr.eu/article-32-security-of-processing/',
    'access controls': 'https://gdpr.eu/article-32-security-of-processing/',
    'encryption': 'https://gdpr.eu/article-32-security-of-processing/',
    'logging': 'https://gdpr.eu/article-30-records-processing-activities/',
    'audit': 'https://gdpr.eu/article-30-records-processing-activities/',
    'privacy': 'https://gdpr.eu/tag/gdpr/',
    'personal data': 'https://gdpr.eu/eu-gdpr-personal-data/',
    'processing': 'https://gdpr.eu/article-32-security-of-processing/',
    'default': 'https://gdpr.eu/tag/gdpr/'
  },
  
  // CIS Benchmarks Links
  'cis': {
    'aws foundations': 'https://www.cisecurity.org/benchmark/amazon_web_services',
    'iam': 'https://www.cisecurity.org/benchmark/amazon_web_services',
    'logging': 'https://www.cisecurity.org/benchmark/amazon_web_services',
    'monitoring': 'https://www.cisecurity.org/benchmark/amazon_web_services',
    'cloudtrail': 'https://www.cisecurity.org/benchmark/amazon_web_services',
    'default': 'https://www.cisecurity.org/benchmark/amazon_web_services'
  },
  
  // General AWS Best Practices
  'aws': {
    'iam': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'security': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'least privilege': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
    'mfa': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html',
    'default': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
  }
};

/**
 * Get compliance link for a specific framework and requirement
 * Returns the official documentation URL or null if not found
 */
export function getComplianceLink(framework: string, requirement: string): string | null {
  if (!framework || !requirement) return null;
  
  // Normalize inputs to lowercase for case-insensitive matching
  const normalizedFramework = framework.toLowerCase().trim();
  const normalizedRequirement = requirement.toLowerCase().trim();
  
  // Get framework links
  const frameworkLinks = complianceLinks[normalizedFramework];
  if (!frameworkLinks) return null;
  
  // Try to find exact match first
  if (frameworkLinks[normalizedRequirement]) {
    return frameworkLinks[normalizedRequirement];
  }
  
  // Try to find partial match (e.g., "Access Controls (164.308(a)(4))" matches "access controls")
  for (const key in frameworkLinks) {
    if (normalizedRequirement.includes(key) || key.includes(normalizedRequirement)) {
      return frameworkLinks[key];
    }
  }
  
  // Return default link for the framework
  return frameworkLinks['default'] || null;
}

