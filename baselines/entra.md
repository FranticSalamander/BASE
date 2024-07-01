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
- _Justification:_  It is recommended organisations develops a service request process and/or limited developers group to enable creation of new applications. This will enable limiting of access to Microsoft Entra ID.
- _Last modified:_ March 2024

#### MS.Entra.2.2v2
Restrict non-admin users from creating tenants
<!--Policy: MS.Entra.2.2v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.3v2
Users cannot create security groups
<!--Policy: MS.Entra.2.3v2; Criticality: SHALL -->
- _Justification:_ Enables for centrally controlled group creation
- _Last modified:_ March 2024

#### MS.Entra.2.4v2
Guest user access is restricted to properties and memberships of their own directory objects 
<!--Policy: MS.Entra.2.4v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.5v2
Restrict access to Microsoft Entra admin centre	
<!--Policy: MS.Entra.2.5v2; Criticality: SHALL -->
- _Justification:_ Application Administrators require access to the portal. This is provided at an app level through the Application Administrator role.
- _Last modified:_ March 2024

#### MS.Entra.2.6v2
Do not allow users to connect their work or school account with LinkedIn	
<!--Policy: MS.Entra.2.6v2; Criticality: SHALL -->
- _Justification:_ Organisations should disable integration and ability to share information with third-parties
- _Last modified:_ March 2024

#### MS.Entra.2.7v2
Show keep user signed in 
<!--Policy: MS.Entra.2.7v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.8v2
Guest user access is restricted to properties and memberships of their own directory objects 
<!--Policy: MS.Entra.2.8v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.9v2
No one in the organization can invite guest users including admins
<!--Policy: MS.Entra.2.9v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.10v2
Disable guest self-service sign up via user flows	
<!--Policy: MS.Entra.2.10v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.11v2
Allow external users to remove themselves from your organization
 <!--Policy: MS.Entra.2.11v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.12v2
Allow collaboration invitations to be sent to any domain (most inclusive)
<!--Policy: MS.Entra.2.12v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.13v2
User cannot use preview features for My Apps	
<!--Policy: MS.Entra.2.13v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.2.14v2
Administrators cannot access My Staff	
<!--Policy: MS.Entra.2.14v2; Criticality: SHALL -->
- _Last modified:_ March 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/tenant/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/users/user-settings/)

- [Guest Roles](https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions)

### Implementation
For details on how and where to check these settings read the [Configuration](https://blueprint.asd.gov.au/configuration/entra-id/properties/) and [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/tenant/) of ASD's Blueprint for Secure Cloud.

## 3. Per-User MFA(Incomplete)

Configuration of users within Microsoft Entra ID



### Resources

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/users/per-user-mfa/)

### License Requirements

- N/A

### Implementation

## 4. BreakGlass account setup

Two emergency access accounts configured in alignment to Microsoft and security best practice are to exist.

### Policies
#### MS.Entra.4.1v2
Accounts are not to be associated with any individual user.
<!--Policy: MS.Entra.4.1v2; Criticality: SHOULD -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Mar 2024

#### MS.Entra.4.2v2
User type should be Member
<!--Policy: MS.Entra.4.2v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.3v2
Account should be enabled
<!--Policy: MS.Entra.4.3v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.4v2
Usage location should be Australia
<!--Policy: MS.Entra.4.4v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.5v2
Emergency access accounts will be assigned the Global Administrator role.
<!--Policy: MS.Entra.4.5v2; Criticality: SHALL -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Mar 2024

#### MS.Entra.4.6v2
Groups
<!--Policy: MS.Entra.4.6v2; Criticality: SHALL -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.7v2
Accounts are not to be associated with any individual user.
<!--Policy: MS.Entra.4.7v2; Criticality: SHOULD -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Mar 2024

#### MS.Entra.4.8v2
User type should be Member
<!--Policy: MS.Entra.4.8v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.9v2
Account should be enabled
<!--Policy: MS.Entra.4.9v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.10v2
Usage location should be Australia
<!--Policy: MS.Entra.4.10v2; Criticality: SHOULD -->
- _Last modified:_ Mar 2024

#### MS.Entra.4.11v2
Emergency access accounts will be assigned the Global Administrator role.
<!--Policy: MS.Entra.4.11v2; Criticality: SHALL -->
- _Justification:_ Two emergency access accounts configured in alignment to Microsoft and security best practice.
- _Last modified:_ Mar 2024

#### MS.Entra.4.12v2
Groups
<!--Policy: MS.Entra.4.12v2; Criticality: SHALL -->
- _Last modified:_ Mar 2024




### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/users/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/users/break-glass-accounts/)

### License Requirements

- N/A

### Implementation


## 5. Groups - General

Configuration of external identities within Microsoft Entra ID
#### MS.Entra.5.1v2
Owners can manage group membership requests in My Groups
<!--Policy: MS.Entra.5.1v2; Criticality: SHALL -->
- _Last modified:_ Mar 2024

#### MS.Entra.5.2v2
Restrict user ability to access groups features in My Groups
<!--Policy: MS.Entra.5.2v2; Criticality: SHALL -->
- _Last modified:_ Mar 2024

#### MS.Entra.5.3v2
Users cannot create security groups
<!--Policy: MS.Entra.5.3v2; Criticality: SHALL -->
- _Last modified:_ March 2024

#### MS.Entra.5.4v2
Users cannot create Microsoft 365  groups
<!--Policy: MS.Entra.5.4v2; Criticality: SHALL -->
- _Last modified:_ March 2024




### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/groups/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/groups/general/)

### License Requirements

- N/A

### Implementation

## 6. Groups - Expiration
Configuration of expiration of groups within Microsoft Entra ID

#### MS.Entra.6.1v2
Groups will have a lifetime of 180 days
<!--Policy: MS.Entra.6.1v2; Criticality: SHALL -->
- _Justification:_ Limit group sprawl by ensuring that groups that are no longer in use are deleted
- _Last modified:_ March 2024

#### MS.Entra.6.2v2
Configuration for Email contact for groups with no owners	
<!--Policy: MS.Entra.6.2v2; Criticality: SHALL -->
- _Justification:_ Limit group sprawl by ensuring that groups that are no longer in use are deleted
- _Last modified:_ March 2024


#### MS.Entra.6.3v2
Expiration Enabled for all Microsoft 365 groups
<!--Policy: MS.Entra.6.3v2; Criticality: SHALL -->
- _Justification:_ Limit group sprawl by ensuring that groups that are no longer in use are deleted
- _Last modified:_ March 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/groups/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/groups/expiration/)

### License Requirements

- N/A

### Implementation

## 7. Naming Policy
Configuration of naming policies within Microsoft Entra ID

#### MS.Entra.7.1v2
Block word list will not be configured
<!--Policy: MS.Entra.7.1v2; Criticality: SHALL -->
- _Justification:_ Avoid fixed organisation based group naming conventions to avoid issues with 
changing organisation structures - However The organisation should determine what naming policy
meets their business requirements.
- _Last modified:_ May 2024

#### MS.Entra.7.2v2
Block word list will not be configured
<!--Policy: MS.Entra.7.2v2; Criticality: SHALL -->
- _Justification:_ Avoid fixed organisation based group naming conventions to avoid issues with 
changing organisation structures - However The organisation should determine what naming policy
meets their business requirements.
- _Last modified:_ May 2024


#### MS.Entra.7.3v2
Block word list will not be configured
<!--Policy: MS.Entra.7.3v2; Criticality: SHALL -->
- _Justification:_ Avoid fixed organisation based group naming conventions to avoid issues with 
changing organisation structures - However The organisation should determine what naming policy
meets their business requirements.
- _Last modified:_ May 2024

### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/groups/)

- [Design Documentation](https://blueprint.asd.gov.au/design/shared-services/microsoft-365/microsoft365-groups/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/groups/naming-policy/)


## 8. Devices - Device Settings
Microsoft Entra join and registration settings

#### MS.Entra.8.1v1
Multifactor Authentication Enabled
<!--Policy: MS.Entra.8.1v1; Criticality: SHALL -->
- _Justification:_ This setting enables you to select the users who can register their devices as Microsoft Entra joined devices. The default is All.
- _Last modified:_ June 2024


#### MS.Entra.8.2v1
User Device Quota Maximum number of devices per user
<!--Policy: MS.Entra.8.2v1; Criticality: SHALL -->
- _Justification:_ This setting enables you to select the maximum number of Microsoft Entra joined or Microsoft Entra registered devices that a user can have in Microsoft Entra ID.
- _Last modified:_ June 2024


#### MS.Entra.8.3v1
Local Admin Password is Enabled
<!--Policy: MS.Entra.8; Criticality: SHALL -->
- _Justification:_ Local Admin Password
- _Last modified:_ June 2024


#### MS.Entra.8.4v1
Azure AD Registration
<!--Policy: MS.Entra.8; Criticality: SHALL -->
- _Justification:_ Azure AD Registration
- _Last modified:_ June 2024


### Resources
- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/devices/)

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/client/device-enrolment/#windows-autopilot-overview)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/devices/device-settings/)




## 9. Devices - Enterprise State Roaming

#### MS.Entra.9.1v2
All users may sync settings and app data across devices
<!--Policy: MS.Entra.9.1v2; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ June 2024


### Resources
- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/devices/)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/devices/enterprise-state-roaming/)




## 10. Applications - Enterprise Applications - Consent and Permissions - Admin consent settings

#### MS.Entra.10.1v1
Users can request admin consent to apps they are unable to consent to​. Recommended approach is to configure the admin consent workflow.
<!--Policy: MS.Entra.10.1v1; Criticality: SHALL -->
- _Justification:_ Enabling it can easily allow phishing attacks into your Microsoft 365 environment and breach your business security. 
- _Last modified:_ June 2024


#### MS.Entra.10.2v1
Selected users will receive email notifications for requests
<!--Policy: MS.Entra.10.2v1; Criticality: SHALL -->
- _Justification:_ Enable or disable email notifications to the reviewers when a request is made.
- _Last modified:_ June 2024


#### MS.Entra.10.3v1
Selected users will receive request expiration reminders​
<!--Policy: MS.Entra.10.3v1; Criticality: SHALL -->
- _Justification:_ Enable or disable reminder email notifications to the reviewers when a request is about to expire. 
- _Last modified:_ June 2024


#### MS.Entra.10.4v1
Consent request expires after (days)​
<!--Policy: MS.Entra.10.4v1; Criticality: SHALL -->
- _Justification:_ Specify how long requests stay valid.
- _Last modified:_ June 2024


### Resources

- [Design Documentation](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)
  
  [Design Documentation](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/applications/enterprise-applications/consent-and-permissions/admin-consent-settings/)


## 11. Applications - Enterprise Applications - Consent and Permissions - User consent settings

#### MS.Entra.11.1v1
Users are not allowed to consent for applications to access your organization’s data
<!--Policy: MS.Entra.11.1v1; Criticality: SHALL -->
- _Justification:_ prevent users (other than local administrators) from installing or uninstalling applications
- _Last modified:_ June 2024

#### MS.Entra.11.2v1
Group owners are not allowed to consent for applications to access your organization’s data for the groups they own
<!--Policy: MS.Entra.11.2v1; Criticality: SHALL -->
- _Note:_ This Setting is now managed from teams instead of Entra so test 11.2v1 may be depreciated
- _Justification:_ 
- _Last modified:_ June 2024

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/applications/enterprise-applications/consent-and-permissions/user-consent-settings/)



## 12. Applications - Enterprise Applications - User settings

#### MS.Entra.12.1v1
Users cannnot add gallery apps to My Apps
<!--Policy: MS.Entra.11.1v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ July 2024

#### MS.Entra.12.2v1
Users cannot only see Office 365 apps in the Office 365 portal	
<!--Policy: MS.Entra.11.2v1; Criticality: SHALL -->
- _Justification:_ 
- _Last modified:_ July 2024

- [Configuration Documentation](https://blueprint.asd.gov.au/configuration/entra-id/applications/enterprise-applications/user-settings/)
