**`TLP:CLEAR`**

# CISA M365 Security Configuration Baseline for Azure Active Directory

Microsoft 365 (M365) Azure Active Directory (Azure AD) is a cloud-based identity and access control service that provides security and functional capabilities. This Secure Configuration Baseline (SCB) provides specific policies to help secure Azure AD.

The Secure Cloud Business Applications (BASE) project run by the Cybersecurity and Infrastructure Security Agency (CISA) provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies’ cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA BASE SCBs for M365 help secure federal information assets stored within M365 cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government’s threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided “as is” for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

> This document is marked TLP:CLEAR. Recipients may share this information without restriction. Information is subject to standard copyright rules. For more information on the Traffic Light Protocol, see https://www.cisa.gov/tlp.

## License Compliance and Copyright
Portions of this document are adapted from documents in Microsoft’s [M365](https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE) and [Azure](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) GitHub repositories. The respective documents are subject to copyright and are adapted under the terms of the Creative Commons Attribution 4.0 International license. Sources are linked throughout this document. The United States government has adapted selections of these documents to develop innovative and scalable configuration standards to strengthen the security of widely used cloud-based software services.

## Assumptions
The **License Requirements** sections of this document assume the organization is using an [M365 E3](https://www.microsoft.com/en-us/microsoft-365/compare-microsoft-365-enterprise-plans) or [G3](https://www.microsoft.com/en-us/microsoft-365/government) license level at a minimum. Therefore, only licenses not included in E3/G3 are listed.

Some of the policies in this baseline may link to Microsoft instruction pages which assume that an agency has created emergency access accounts in Azure AD and [implemented strong security measures](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access#create-emergency-access-accounts) to protect the credentials of those accounts.

## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The following are key terms and descriptions used in this document.

**Hybrid Azure Active Directory (AD)**: This term denotes the scenario
when an organization has an on-premises AD domain that contains the
master user directory but federates access to the cloud M365
Azure AD tenant.

**Resource Tenant & Home Tenant**: In scenarios where guest users are involved the **resource tenant** hosts the M365 target resources that the guest user is accessing. The **home tenant** is the one that hosts the guest user's identity.

## Highly Privileged Roles

This section provides a list of what CISA considers highly privileged [built-in roles in Azure Active Directory](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference). This list is referenced in numerous baseline policies throughout this document. Agencies should consider this reference as a minimum list and can apply the respective baseline policies to additional Azure AD roles as necessary.

- Global Administrator
- Privileged Role Administrator
- User Administrator
- SharePoint Administrator
- Exchange Administrator
- Hybrid Identity Administrator
- Application Administrator
- Cloud Application Administrator

Throughout this document, this list of highly privileged roles is referenced in numerous baseline policies. Agencies should consider this list a foundational reference and apply respective baseline policies to additional Azure AD roles as necessary.

## Conditional Access Policies

Numerous policies in this baseline rely on Azure AD Conditional Access. Conditional Access is a feature that allows administrators to limit access to resources using conditions such as user or group membership, device, IP location, and real-time risk detection. This section provides guidance and tools when implementing baseline policies which rely on Azure AD Conditional Access.

As described in Microsoft’s literature related to conditional access policies, CISA recommends initially setting a policy to **Report-only** when it is created and then performing thorough hands-on testing to help prevent unintended consequences before toggling the policy from **Report-only** to **On**. The policy will only be enforced when it is set to **On**. One tool that can assist with running test simulations is the [What If tool](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool). Microsoft also describes [Conditional Access insights and reporting](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting) that can assist with testing.

# Baseline Policies


## 1. Properties

Configuration of properties within Microsoft Entra ID

### Policies
#### MS.Entra.1.1v2
Name field will be set to the organisation name
<!--Policy: MS.Entra.1.1v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.2v2
Country or region field will be set to Australia
<!--Policy: MS.Entra.1.2v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.3v2
Data location field will be set to Australia datacenters
<!--Policy: MS.Entra.1.3v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.4v2
Notification language field will be set to English
<!--Policy: MS.Entra.1.4v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.5v2
Tenant ID field will be unique to each tenant
<!--Policy: MS.Entra.1.5v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.6v2
Technical contact field will be set to technical contact email for the tenant
<!--Policy: MS.Entra.1.6v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.7v2
Global privacy contact field will be set to privacy contact email for the tenant
<!--Policy: MS.Entra.1.7v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.8v2
Privacy statement URL field will be set to th privacy statement web address
<!--Policy: MS.Entra.1.8v2; Criticality: Shall-->
- _Last modified:_ March 2024

#### MS.Entra.1.9v2
Access management for Azure resources field will be set to No
<!--Policy: MS.Entra.1.9v2; Criticality: Shall-->
- _Last modified:_ March 2024

### Resources

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/properties/)

### Implementation
For details on how and where to check these settings read the [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/properties/) of ASD's Blueprint for Secure Cloud.


## 2. User Settings

Configuration for Users - User settings in Entra ID portal

### Policies
#### MS.Entra.2.1v2
User cannot register application
<!--Policy: MS.Entra.2.1v2; Criticality: SHALL -->
- _Justification:_  Administrator	It is recommended organisations develops a service request process and/or limited developers group to enable creation of new applications. This will enable limiting of access to Microsoft Entra ID.
- _Last modified:_ March 2024

#### MS.Entra.2.2v2
Restrict non-admin users from creating tenants
<!--Policy: MS.Entra.2.2v2; Criticality: SHALL -->
- _Last modified:_ March 2024


### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/tenant/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/users/user-settings/)



### Implementation
For details on how and where to check these settings read the [Configuration](https://blueprint.asd.gov.au/configuration/entra-id/properties/) and [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/tenant/) of ASD's Blueprint for Secure Cloud.

## 3. Security Defaults

Security Defaults Policies

### Policies
#### MS.Entra.3.1v1
Security Defaults will be Disabled
<!--Policy: MS.Entra.3.1v1; Criticality: SHALL -->
- _Justification:_ Settings (MFA, Conditional Access, etc.) are managed at a more granular level than Security Defaults provides.
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/authentication/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 4. Security Defaults

User Configurations

### Policies
#### MS.Entra.4.1v1
Configure Break Glass User Account 1
<!--Policy: MS.Entra.4.1v1; Criticality: SHALL -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Jan 2024

#### MS.Entra.4.2v1
Configure Break Glass User Account 2
<!--Policy: MS.Entra.4.1v1; Criticality: SHALL -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/users/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation


## 5. Authorisation Policy

User Configurations

### Policies
#### MS.Entra.5.1v1
Allowed to sign up to email based subscriptions
<!--Policy: MS.Entra.5.1v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.2v1
Allowed to use SSPR
<!--Policy: MS.Entra.5.2v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.3v1
Allow email verified users to join organisation
<!--Policy: MS.Entra.5.3v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.4v1
Allow invites from none
<!--Policy: MS.Entra.5.4v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.5v1
Do not block Msol PowerShell
<!--Policy: MS.Entra.5.5v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.6v1
Default user role must be configured correctly
<!--Policy: MS.Entra.5.6v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024




### Resources

- [Design Documentation]()

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation


## 6. Cross Tenant Access Policy
Cross Tenant Access Policy


### Policies
#### MS.Entra.6.1v1
Inbound trust setting will be configured correctly
<!--Policy: MS.Entra.6.1v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024


## 7. Conditional Access Policy (CAP) - Admin SignIn Frequency
Admin SignIn Frequency

### Policies
#### MS.Entra.7.1v1
Expire administration sessions
<!--Policy: MS.Entra.7.1v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure administrators sessions do not remain active for longer than 4 hours.
- _Last modified:_ Jan 2024


#### MS.Entra.7.2v1
Expire administration sessions
<!--Policy: MS.Entra.7.2v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.3v1
Expire administration sessions
<!--Policy: MS.Entra.7.3v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.4v1
Expire administration sessions
<!--Policy: MS.Entra.7.4v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.5v1
Expire administration sessions
<!--Policy: MS.Entra.7.5v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.6v1
Expire administration sessions
<!--Policy: MS.Entra.7.6v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.7v1
Expire administration sessions
<!--Policy: MS.Entra.7.7v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.8v1
Expire administration sessions
<!--Policy: MS.Entra.7.8v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.9v1
Expire administration sessions
<!--Policy: MS.Entra.7.9v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.10v1
Expire administration sessions
<!--Policy: MS.Entra.7.10v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.11v1
Expire administration sessions
<!--Policy: MS.Entra.7.11v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](null)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 8. CAP - Countries Not Allowed
Blocks all connections from countries not in the allowed countries list.

### Policies
#### MS.Entra.8.1v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.1v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure administrators sessions do not remain active for longer than 4 hours.
- _Last modified:_ Jan 2024


#### MS.Entra.8.2v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.2v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.3v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.3v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.4v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.4v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.5v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.5v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.6v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.6v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.7v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.7v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.8v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.8v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.9v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.9v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.10v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.10v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.11v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.11v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.12v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.12v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.13v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.13v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024


### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 9. CAP - Guest Access Block
Deny all guest and external users by default.

### Policies
#### MS.Entra.9.1v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.1v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024


#### MS.Entra.9.2v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.2v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.3v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.3v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.4v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.4v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.5v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.5v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.6v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.6v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.7v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.7v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.8v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.8v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.9v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.9v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.9.10v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.9.10v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 10. CAP - Guest Access Grant
Deny all guest and external users by default.

### Policies
#### MS.Entra.10.1v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.1v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024


#### MS.Entra.10.2v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.2v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.3v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.3v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.4v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.4v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.5v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.5v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.6v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.6v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.7v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.7v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.8v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.8v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.9v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.7v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.10.10v1
Deny all guest and external users by default.
<!--Policy: MS.Entra.10.10v1; Criticality: SHALL -->
- _Justification:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 11. CAP - High Risk SignIns
Risk based policies

### Policies
#### MS.Entra.11.1v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.1v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024


#### MS.Entra.11.2v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.2v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024

#### MS.Entra.11.3v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.3v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024

#### MS.Entra.11.4v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.4v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.11.5v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.5v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024

#### MS.Entra.11.6v1
Block Legacy Authentication and high risk logins
<!--Policy: MS.Entra.11.6v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024


### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 12. CAP - Legacy Authentication Block
Risk based policies


### Policies
#### MS.Entra.12.1v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.1v1; Criticality: SHALL -->
- _Justification:_ Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024


#### MS.Entra.12.2v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.2v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.3v1
BASE
<!--Policy: MS.Entra.12.3v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.4v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.4v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.5v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.5v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.6v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.6v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.7v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.7v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.8v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.8v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2). 
- _Last modified:_ Jan 2024

#### MS.Entra.12.9v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.7v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024

#### MS.Entra.12.10v1
Block Legacy Authentication and high risk logins	
<!--Policy: MS.Entra.12.10v1; Criticality: SHALL -->
- _Justification:_Blocks all connections from insecure legacy protocols like ActiveSync, IMAP, POP3, etc., and all high-risk authentications (requires Entra ID Premium P2).
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 13. CAP - MFA Guest B2B Access
BASE

### Policies
#### MS.Entra.13.1v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.1v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024


#### MS.Entra.13.2v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.2v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA.
- _Last modified:_ Jan 2024

#### MS.Entra.13.3v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.3v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA.
- _Last modified:_ Jan 2024

#### MS.Entra.13.4v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.4v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

#### MS.Entra.13.5v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.5v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

#### MS.Entra.13.6v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.6v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

#### MS.Entra.13.7v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.7v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA.
- _Last modified:_ Jan 2024

#### MS.Entra.13.8v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.8v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

#### MS.Entra.13.9v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.9v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

#### MS.Entra.13.10v1
Require multi-factor authentication for guest access
<!--Policy: MS.Entra.13.10v1; Criticality: SHALL -->
- _Justification:_MS005: Meets the requirement to enforce MFA for all users. This is a fallback policy given all users require MFA. 
- _Last modified:_ Jan 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 14. CAP - Session Based Policies
Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
### Policies
#### MS.Entra.14.1v1
Expire user sessions
<!--Policy: MS.Entra.14.1v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024


#### MS.Entra.14.2v1
Expire user sessions
<!--Policy: MS.Entra.14.2v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.3v1
Expire user sessions
<!--Policy: MS.Entra.14.3v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.14.4v1
Expire user sessions
<!--Policy: MS.Entra.14.4v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.5v1
Expire user sessions
<!--Policy: MS.Entra.14.5v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.6v1
Expire user sessions
<!--Policy: MS.Entra.14.6v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.7v1
Expire user sessions
<!--Policy: MS.Entra.14.7v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.14.8v1
Expire user sessions
<!--Policy: MS.Entra.14.8v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.9v1
Expire user sessions
<!--Policy: MS.Entra.14.9v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.10v1
Expire user sessions
<!--Policy: MS.Entra.14.10v1; Criticality: SHALL -->
- _Justification:_ Enforces a sign-in frequency to ensure non-privileged users are required to complete an MFA prompt daily.
- _Last modified:_ Jan 2024

#### MS.Entra.14.11v1
Expire user sessions after 12 hours	
<!--Policy: MS.Entra.14.11v1; Criticality: SHALL -->
- _Justification:_ 	Removes legacy sessions.
- _Last modified:_ Jan 2024


### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation

## 15. CAP - Terms of Use Grant
Terms of Use Policy

### Policies
#### MS.Entra.15.1v1
Terms of Use Policy
<!--Policy: MS.Entra.15.1v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024


#### MS.Entra.15.2v1
Terms of Use Policy
<!--Policy: MS.Entra.15.2v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.3v1
Terms of Use Policy
<!--Policy: MS.Entra.15.3v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.15.4v1
Terms of Use Policy
<!--Policy: MS.Entra.15.4v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.5v1
Terms of Use Policy
<!--Policy: MS.Entra.15.5v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.6v1
Terms of Use Policy
<!--Policy: MS.Entra.15.6v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.7v1
Terms of Use Policy
<!--Policy: MS.Entra.15.7v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024

#### MS.Entra.15.8v1
Terms of Use Policy
<!--Policy: MS.Entra.15.8v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.9v1
Terms of Use Policy
<!--Policy: MS.Entra.15.9v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.10v1
Terms of Use Policy
<!--Policy: MS.Entra.15.10v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ Jan 2024

#### MS.Entra.15.11v1
Terms of Use Policy
<!--Policy: MS.Entra.15.11v1; Criticality: SHALL -->
- _Justification:_ 	Removes legacy sessions.
- _Last modified:_ Jan 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation


**`TLP:CLEAR`**
