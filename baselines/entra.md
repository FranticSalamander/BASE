**`TLP:CLEAR`**

# CISA M365 Security Configuration Baseline for Azure Active Directory

Microsoft 365 (M365) Azure Active Directory (Azure AD) is a cloud-based identity and access control service that provides security and functional capabilities. This Secure Configuration Baseline (SCB) provides specific policies to help secure Azure AD.

The Secure Cloud Business Applications (SCuBA) project run by the Cybersecurity and Infrastructure Security Agency (CISA) provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies’ cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for M365 help secure federal information assets stored within M365 cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government’s threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

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


## 1. Groups

Groups Policies

### Policies
#### MS.Entra.1.1v1
The Group Expiry will be set to 180 Days
<!--Policy: MS.Entra.1.1v1; Criticality: SHALL -->
- _Rationale:_ Limit group sprawl by ensuring that groups that are no longer in use are deleted.
- _Last modified:_ Jan 2024

#### MS.Entra.1.2v1
The Group Naming Policy will be Unrestricted but with guidelines
<!--Policy: MS.Entra.1.2v1; Criticality: SHALL -->
- _Rationale:_ Avoid fixed organisation based group naming conventions to avoid issues with changing organisation structures.
- _Last modified:_ Jan 2024

#### MS.Entra.1.3v1
Configured: Guest Access: Disabled
<!--Policy: MS.Entra.1.3v1; Criticality: SHALL -->
- _Rationale:_ Do not allow people outside of the organisation to access teams and channels.
- _Last modified:_ Jan 2024

#### MS.Entra.1.4v1
Guest will not be be Group Owner
<!--Policy: MS.Entra.1.4v1; Criticality: SHALL -->
- _Rationale:_ Do not allow people outside of the organisation to access teams and channels.
- _Last modified:_ Jan 2024

#### MS.Entra.1.5v1
Guest cannot be added by non-administrators
<!--Policy: MS.Entra.1.5v1; Criticality: SHALL -->
- _Rationale:_ Only Administrators should add guests to a tenant..
- _Last modified:_ Jan 2024

#### MS.Entra.1.6v1
Any user with acknowledgement of responsibilities can create Groups
<!--Policy: MS.Entra.1.6v1; Criticality: SHALL -->
- _Rationale:_ Encourage rather than block collaboration
- _Last modified:_ Jan 2024

#### MS.Entra.1.7v1
MIP labels
<!--Policy: MS.Entra.1.7v1; Criticality: SHALL -->
- _Rationale:_ 
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/groups/)

- [Design Documentation](https://blueprint.asd.gov.au/design/shared-services/teams/organisation-access/)

- [Design Documentation](https://blueprint.asd.gov.au/design/shared-services/microsoft-365/services-and-addins/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation


## 2. Authentication Strength

Authentication Strength Policies

### Policies
#### MS.Entra.2.1v1
Multifactor authentication will be configured correctly
<!--Policy: MS.Entra.2.1v1; Criticality: SHALL -->
- _Rationale:_ to manage the Authentication methods policy.
- _Last modified:_ Jan 2024

#### MS.Entra.2.2v1
Passwordless MFA will be configured correctly
<!--Policy: MS.Entra.2.2v1; Criticality: SHALL -->
- _Rationale:_ to manage the Authentication methods policy for passwordless MFA.
- _Last modified:_ Jan 2024

#### MS.Entra.2.3v1
Phishing Resistant MFA will be configured correctly
<!--Policy: MS.Entra.2.3v1; Criticality: SHALL -->
- _Rationale:_ to manage the Authentication methods policy for passwordless MFA.
- _Last modified:_ Jan 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/authentication/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation


## 3. Security Defaults

Security Defaults Policies

### Policies
#### MS.Entra.3.1v1
Security Defaults will be Disabled
<!--Policy: MS.Entra.3.1v1; Criticality: SHALL -->
- _Rationale:_ Settings (MFA, Conditional Access, etc.) are managed at a more granular level than Security Defaults provides.
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
- _Rationale:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Jan 2024

#### MS.Entra.4.2v1
Configure Break Glass User Account 2
<!--Policy: MS.Entra.4.1v1; Criticality: SHALL -->
- _Rationale:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
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
- _Rationale:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.2v1
Allowed to use SSPR
<!--Policy: MS.Entra.5.2v1; Criticality: SHALL -->
- _Rationale:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.3v1
Allow email verified users to join organisation
<!--Policy: MS.Entra.5.3v1; Criticality: SHALL -->
- _Rationale:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.4v1
Allow invites from none
<!--Policy: MS.Entra.5.4v1; Criticality: SHALL -->
- _Rationale:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.5v1
Do not block Msol PowerShell
<!--Policy: MS.Entra.5.5v1; Criticality: SHALL -->
- _Rationale:_
- _Last modified:_ Jan 2024

#### MS.Entra.5.6v1
Default user role must be configured correctly
<!--Policy: MS.Entra.5.6v1; Criticality: SHALL -->
- _Rationale:_
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
- _Rationale:_
- _Last modified:_ Jan 2024


## 7. Conditional Access Policy (CAP) - Admin SignIn Frequency
Admin SignIn Frequency

### Policies
#### MS.Entra.7.1v1
Expire administration sessions
<!--Policy: MS.Entra.7.1v1; Criticality: SHALL -->
- _Rationale:_ Enforces a sign-in frequency to ensure administrators sessions do not remain active for longer than 4 hours.
- _Last modified:_ Jan 2024


#### MS.Entra.7.2v1
Expire administration sessions
<!--Policy: MS.Entra.7.2v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.3v1
Expire administration sessions
<!--Policy: MS.Entra.7.3v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.4v1
Expire administration sessions
<!--Policy: MS.Entra.7.4v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.5v1
Expire administration sessions
<!--Policy: MS.Entra.7.5v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.6v1
Expire administration sessions
<!--Policy: MS.Entra.7.6v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.7v1
Expire administration sessions
<!--Policy: MS.Entra.7.7v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.7.8v1
Expire administration sessions
<!--Policy: MS.Entra.7.8v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
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
- _Rationale:_ Enforces a sign-in frequency to ensure administrators sessions do not remain active for longer than 4 hours.
- _Last modified:_ Jan 2024


#### MS.Entra.8.2v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.2v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.3v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.3v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.4v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.4v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.5v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.5v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.6v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.6v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.7v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.7v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.8v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.8v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.9v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.7v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024

#### MS.Entra.8.10v1
Blocks all connections from countries not in the allowed countries list.
<!--Policy: MS.Entra.8.8v1; Criticality: SHALL -->
- _Rationale:_Enforces a sign-in frequency 
- _Last modified:_ Jan 2024


### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/conditional-access/)

- [Configuration Documentation](null)

### License Requirements

- N/A

### Implementation




**`TLP:CLEAR`**
