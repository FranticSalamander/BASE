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
- _Justification:_ Settings (MFA, Conditional Access, etc.) are managed at a more granular level than Security Defaults provides.
- _Last modified:_ Jan 2024



### Resources

- [Design Documentation](https://blueprint.asd.gov.au/design/platform/identity/authentication/)

- [Configuration Documentation](null)


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


## 6. Cross Tenant Access Policy
Cross Tenant Access Policy


### Policies
#### MS.Entra.6.1v1
Inbound trust setting will be configured correctly
<!--Policy: MS.Entra.6.1v1; Criticality: SHALL -->
- _Justification:_
- _Last modified:_ Jan 2024
