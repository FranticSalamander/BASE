**`TLP:CLEAR`**

# M365 Security Configuration Baseline for Defender (TO BE MODIFIED)

Microsoft 365 (M365) Defender is a cloud-based enterprise defense suite that
coordinates prevention, detection, investigation, and response. This set
of tools and features are used to detect many types of attacks.

This baseline focuses on the features of Defender for Office 365, but
some settings are actually configured in the Microsoft Purview
compliance portal. However, for simplicity, both the
M365 Defender and Microsoft Purview compliance portal
items are contained in this baseline.

Generally, use of Microsoft Defender is not required by the baselines of
the core M365 products (Exchange Online, Teams, etc.). This baseline serves as
a guide should an agency elect to use Defender as their tool of choice. Please
note that some of the controls in the core baselines require the use of a
dedicated security tool, such as Defender.

In addition to these controls, agencies should consider using a cloud
access security broker to secure their environments as they adopt zero
trust principles.

The Secure Cloud Business Applications (BASE) project run by the Cybersecurity
and Infrastructure Security Agency (CISA) provides guidance and capabilities to
secure federal civilian executive branch (FCEB) agencies' cloud business
application environments and protect federal information that is created,
accessed, shared, and stored in those environments.

The CISA BASE SCBs for M365 help secure federal information assets stored within
M365 cloud business application environments through consistent, effective, and
manageable security configurations. CISA created baselines tailored to the federal
government's threats and risk tolerance with the knowledge that every organization
has different threat models and risk tolerance. Non-governmental organizations may
also find value in applying these baselines to reduce risks.

The information in this document is provided “as is” for INFORMATIONAL PURPOSES
ONLY. CISA does not endorse any commercial product or service, including any
subjects of analysis. Any reference to specific commercial entities or commercial
products, processes, or services by service mark, trademark, manufacturer, or
otherwise does not constitute or imply endorsement, recommendation, or favoritism
by CISA. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

> This document is marked TLP:CLEAR. Recipients may share this information without restriction. Information is subject to standard copyright rules. For more information on the Traffic Light Protocol, see https://www.cisa.gov/tlp.

## License Compliance and Copyright
Portions of this document are adapted from documents in Microsoft's [M365](https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE) and [Azure](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) GitHub repositories. The respective documents are subject to copyright and are adapted under the terms of the Creative Commons Attribution 4.0 International license. Sources are linked throughout this document. The United States government has adapted selections of these documents to develop innovative and scalable configuration standards to strengthen the security of widely used cloud-based software services.

## Assumptions
The agency has identified a set of user accounts that are considered sensitive accounts. See [Key Terminology](#key-terminology) for a detailed description of sensitive accounts.

The **License Requirements** sections of this document assume the organization is using an [M365 E3](https://www.microsoft.com/en-us/microsoft-365/compare-microsoft-365-enterprise-plans) or [G3](https://www.microsoft.com/en-us/microsoft-365/government) license level at a minimum. Therefore, only licenses not included in E3/G3 are listed.

## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The following are key terms and descriptions used in this document.

**Sensitive Accounts**: This term denotes a set of user accounts that have
access to sensitive and high-value information. As a result, these accounts
may be at a higher risk of being targeted.

# Baseline Policies

**`TLP:CLEAR`**
