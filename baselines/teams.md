**`TLP:CLEAR`**
# CISA M365 Security Configuration Baseline for Teams

Microsoft 365 (M365) Teams is a cloud-based text and live chat workspace that supports video calls, chat messaging, screen sharing, and file sharing. This secure configuration baseline (SCB) provides specific policies to strengthen Microsoft Teams' security.

The Secure Cloud Business Applications (BASE) project run by the Cybersecurity and Infrastructure Security Agency (CISA) provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA BASE SCBs for M365 help secure federal information assets stored within M365 cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise does not constitute or imply endorsement, recommendation, or favoritism by CISA. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.


> This document is marked TLP:CLEAR. Recipients may share this information without restriction. Information is subject to standard copyright rules. For more information on the Traffic Light Protocol, see https://www.cisa.gov/tlp.

## License Compliance and Copyright 
Portions of this document are adapted from documents in Microsoft's [M365](https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE) and [
  Azure](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) GitHub repositories. The respective documents are subject to copyright and are adapted under the terms of the Creative Commons Attribution 4.0 International license. Source documents are linked throughout this document. The United States government has adapted selections of these documents to develop innovative and scalable configuration standards to strengthen the security of widely used cloud-based software services.

## Assumptions
The **License Requirements** sections of this document assume the organization is using an [M365 E3](https://www.microsoft.com/en-us/microsoft-365/compare-microsoft-365-enterprise-plans) or [G3](https://www.microsoft.com/en-us/microsoft-365/government) license level at a minimum. Therefore, only licenses not included in E3/G3 are listed.

## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

Access to Teams can be controlled by the user type. In this baseline,
the types of users are defined as follows:

1.  **Internal users**: Members of the agency's M365 tenant.

2.  **External users**: Members of a different M365 tenant.

3.  **Business to Business (B2B) guest users**: External users who are
    formally invited to collaborate with the team and added to the
    agency's Azure Active Directory (Azure AD) as guest users. These users
    authenticate with their home organization/tenant and are granted
    access to the team by virtue of being listed as guest users on the
    tenant's Azure AD.

4.  **Unmanaged users**: Users who are not members of any M365 tenant or
    organization (e.g., personal Microsoft accounts).

5.  **Anonymous users**: Teams users joining calls who are not
    authenticated through the agency's tenant; these users include unmanaged
    users, external users (except for B2B guests), and true anonymous
    users (i.e., users who are not logged in to any Microsoft or
    organization account, such as dial-in users[^1]).

# Baseline Policies

**`TLP:CLEAR`**