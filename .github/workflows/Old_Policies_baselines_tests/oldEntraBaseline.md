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
