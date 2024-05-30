
#
# MS.Entra.5.1v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowedToSignUpEmailBasedSubscriptions,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowedToSignUpEmailBasedSubscriptions == true
    Details := "Requirement not met: 'AllowedToSignUpEmailBasedSubscriptions' must be set to true"
    
}
#--

#
# MS.Entra.5.2v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowedToUseSspr,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowedToUseSspr == true
    Details := "Requirement not met: 'AllowedToUseSSPR' must be set to true"
    
}
#--

#
# MS.Entra.5.3v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowEmailVerifiedUsersToJoinOrganization,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowEmailVerifiedUsersToJoinOrganization == true
    Details := "Requirement not met: 'AllowEmailVerifiedUsersToJoinOrganization' must be set to true"
    
}
#--

#
# MS.Entra.5.4v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowInvitesFrom,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowInvitesFrom == "none"
    Details := "Requirement not met: 'AllowInvitesFrom' must be set to 'none'"
    
}
#--

#
# MS.Entra.5.5v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.BlockMsolPowerShell,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.BlockMsolPowerShell == false
    Details := "Requirement not met: 'BlockMsolPowerShell' must be set to false"
    
}
#--

#
# MS.Entra.5.6v1
#--


default DefaultUserRolePermissionsMatch(_) := false
DefaultUserRolePermissionsMatch(Policy) := true if {
    Policy.DefaultUserRolePermissions == {
                                           "AllowedToCreateApps":  false,
                                           "AllowedToCreateSecurityGroups":  false,
                                           "AllowedToCreateTenants":  true,
                                           "AllowedToReadBitlockerKeysForOwnedDevice":  true,
                                           "AllowedToReadOtherUsers":  true
                                         }
}

DefaultUserRolePermissions[Policy.DefaultUserRolePermissions] {
    Policy := input.authorisation_policy[_]

    

    # Match all simple conditions
    DefaultUserRolePermissionsMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.5.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : DefaultUserRolePermissions,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(DefaultUserRolePermissions) > 0
    Details := "Requirement not met: 'DefaultUserRolePermissions' must be configured correctly"
    
}
#--

# #--
# ############
# # MS.Entra.2 #
# ############


# #
# # MS.Entra.2.1v1 #This test layout works when there are multiple settings using the same name
# #--
# default MultifactorAuthenticationConditionsMatch(_) := false
# MultifactorAuthenticationConditionsMatch(Policy) := true if {
#     Policy.DisplayName =="Multifactor authentication"
#     Policy.Description == "Combinations of methods that satisfy strong authentication, such as a password + SMS"
#     Policy.AllowedCombinations == [
#                                      "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor",
#                                     "deviceBasedPush",
#                                     "temporaryAccessPassOneTime",
#                                     "temporaryAccessPassMultiUse",
#                                     "password,microsoftAuthenticatorPush",
#                                     "password,softwareOath",
#                                     "password,hardwareOath",
#                                     "password,sms",
#                                     "password,voice",
#                                     "federatedMultiFactor",
#                                     "microsoftAuthenticatorPush,federatedSingleFactor",
#                                     "softwareOath,federatedSingleFactor",
#                                     "hardwareOath,federatedSingleFactor",
#                                     "sms,federatedSingleFactor",
#                                     "voice,federatedSingleFactor"                               
#                                 ]
# }

# MultifactorAuthentication[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     MultifactorAuthenticationConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.1v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : MultifactorAuthentication,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(MultifactorAuthentication) > 0
# }


# #
# # MS.Entra.2.2v1 
# #--
# default PasswordlessMFAConditionsMatch(_) := false
# PasswordlessMFAConditionsMatch(Policy) := true if {
#     Policy.DisplayName == "Passwordless MFA"
#     Policy.Description == "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator"
#     Policy.AllowedCombinations == [
#                                     "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor",
#                                     "deviceBasedPush"                               
#                                 ]
# }

# PasswordlessMFA[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     PasswordlessMFAConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.2v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : PasswordlessMFA,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(PasswordlessMFA) > 0
# }
# #--


# #
# # MS.Entra.2.3v1
# #--
# default PhishingResistantMFAConditionsMatch(_) := false
# PhishingResistantMFAConditionsMatch(Policy) := true if {
#     Policy.DisplayName == "Phishing-resistant MFA"
#     Policy.Description == "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key"
#     Policy.AllowedCombinations == [
#                                     "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor"                          
#                                 ]
# }

# PhishingResistantMFA[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     PhishingResistantMFAConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.3v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : PhishingResistantMFA,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(PhishingResistantMFA) > 0
# }
# #--

#--
############
# MS.Entra.3 #
############

#
# MS.Entra.3.1v1
#--


# tests[{
#     "PolicyId" : "MS.Entra.3.1v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyIdentitySecurityDefaultEnforcementPolicy"],
#     "ActualValue" : Policy.IsEnabled,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Policy := input.security_defaults[_]
#     Status := Policy.IsEnabled == false
#     Detail := "Requirement not met: Security Defaults must be disabled"
# }
# #--

# #--
# ############
# # MS.Entra.1 #
# ############

# #
# # MS.Entra.1.1v1
# #--
# tests[{
#     "PolicyId" : "MS.Entra.1.1v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaGroupLifecyclePolicy"],
#     "ActualValue" : [Policy.ManagedGroupTypes, Policy.GroupLifetimeInDays, Policy.AlternateNotificationEmails],
#     "ReportDetails" : ReportDetailsBoolean(Status   ),
#     "RequirementMet" : Status
# }] {
    

#     Policy := input.group_lifecycle_policy[_]
#     Conditions := [Policy.ManagedGroupTypes == "All", Policy.GroupLifetimeInDays == 180, Policy.AlternateNotificationEmails == "Office365_Group_Expiration@agency.gov.au"]
#     Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    
# }
# #--

# #
# # MS.Entra.1.2v1
# #--
# default CustomBlockedWordsListMatch(_) := false
# CustomBlockedWordsListMatch(Policy) := true if {
#     Policy.Name == "CustomBlockedWordsList"  
#     Policy.Value == "HR,Exec,SOC,Minister"
# }

# CustomBlockedWordsList[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     CustomBlockedWordsListMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.2v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : CustomBlockedWordsList,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(CustomBlockedWordsList) > 0
#     Detail := "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
# }
# #--

# #
# # MS.Entra.1.3v1
# #--
# default AllowGuestsToAccessGroupsMatch(_) := false
# AllowGuestsToAccessGroupsMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToAccessGroups"  
#     Policy.Value == "False"
# }
# AllowGuestsToAccessGroupsMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToAccessGroups"  
#     Policy.Value == "false"
# }

# AllowGuestsToAccessGroups[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowGuestsToAccessGroupsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.3v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowGuestsToAccessGroups,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowGuestsToAccessGroups) > 0
#     Detail := "Requirement not met: 'AllowGuestsToAccessGroups' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.4v1
# #--
# default AllowGuestsToBeGroupOwnerMatch(_) := false
# AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToBeGroupOwner"  
#     Policy.Value == "false"
# }
# AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToBeGroupOwner"  
#     Policy.Value == "False"
# }

# AllowGuestsToBeGroupOwner[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowGuestsToBeGroupOwnerMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.4v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowGuestsToBeGroupOwner,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowGuestsToBeGroupOwner) > 0
#     Detail := "Requirement not met: 'AllowGuestsToBeGroupOwner' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.5v1
# #--
# default AllowToAddGuestsMatch(_) := false
# AllowToAddGuestsMatch(Policy) := true if {
#     Policy.Name == "AllowToAddGuests"  
#     Policy.Value == "false"
# }
# AllowToAddGuestsMatch(Policy) := true if {
#     Policy.Name == "AllowToAddGuests"  
#     Policy.Value == "False"
# }

# AllowToAddGuests[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowToAddGuestsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.5v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowToAddGuests,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowToAddGuests) > 0
#     Detail := "Requirement not met: 'AllowToAddGuests' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.6v1
# #--
# default EnableGroupCreationMatch(_) := false
# EnableGroupCreationMatch(Policy) := true if {
#     Policy.Name == "EnableGroupCreation"  
#     Policy.Value == "false"
# }
# EnableGroupCreationMatch(Policy) := true if {
#     Policy.Name == "EnableGroupCreation"  
#     Policy.Value == "False"
# }

# EnableGroupCreation[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     EnableGroupCreationMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.6v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : EnableGroupCreation,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(EnableGroupCreation) > 0
#     Detail := "Requirement not met: 'EnableGroupCreation' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.7v1
# #--
# default EnableMIPLabelsMatch(_) := false
# EnableMIPLabelsMatch(Policy) := true if {
#     Policy.Name == "EnableMIPLabels"  
#     Policy.Value == "true"
# }
# EnableMIPLabelsMatch(Policy) := true if {
#     Policy.Name == "EnableMIPLabels"  
#     Policy.Value == "True"
# }

# EnableMIPLabels[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     EnableMIPLabelsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.7v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : EnableMIPLabels,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(EnableMIPLabels) > 0
#     Detail := "Requirement not met: 'EnableMIPLabels' needs to be set to true"
# }
# #--


############
# MS.Entra.6 #
############

#
# MS.Entra.6.1v1
#--


default InboundTrustMatch(_) := false
InboundTrustMatch(Policy) := true if {
    Policy.InboundTrust ==  {
                             "IsCompliantDeviceAccepted":  false,
                             "IsHybridAzureAdJoinedDeviceAccepted":  false,
                             "IsMfaAccepted":  false
                            }
}

InboundTrust[Policy.InboundTrust] {
    Policy := input.cross_tenant_access_policy[_]

    

    # Match all simple conditions
    InboundTrustMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.6.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyCrossTenantAccessPolicyDefault"],
    "ActualValue" : InboundTrust,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(InboundTrust) > 0
    Details := "Requirement not met: 'IsCompliantDeviceAccepted', 'IsHybridAzureAdJoinedDeviceAccepted' and 'IsMfaAccepted' must be set to false"
    
}
#--

tests[{
    "PolicyId" : "MS.Entra.7.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : [Policy.IsEnabled, Policy.Type, Policy.Value],
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.SignInFrequency
    Conditions := [Policy.IsEnabled == true, Policy.Type == "hours", Policy.Value == 4]
    Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    Incorrect := 3 - count([Condition | Condition = Conditions[_]; Condition == true]) 
    Details := concat(format_int(Incorrect, 10), ["Requirement not met: ", " AdminSignInFrequency - SignInFrequency policies configured incorrectly"])
    
}
#--

#
# MS.Entra.7.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: AdminSignInFrequency - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.7.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.7.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions
    Status := Policy.ClientAppTypes == ["browser", "mobileAppsAndDesktopClients", "other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.7.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.7.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 

}



#
# MS.Entra.7.10v1
#--

default AdminSigninIncludeRolesMatch(_) := false
AdminSigninIncludeRolesMatch(Policy) := true if {
    ContainsApplicationAdministrator := contains(Policy.IncludeRoles, ApplicationAdministrator)
    ContainsApplicationDeveloper := contains(Policy.IncludeRoles, ApplicationDeveloper)
    ContainsAttackPayloadAuthor := contains(Policy.IncludeRoles, AttackPayloadAuthor)
    ContainsAttackSimulationAdministrator := contains(Policy.IncludeRoles, AttackSimulationAdministrator)
    ContainsAttributeDefinitionAdministrator := contains(Policy.IncludeRoles, AttributeDefinitionAdministrator)
    ContainsAttributeAssignmentReader := contains(Policy.IncludeRoles, AttributeAssignmentReader)
    ContainsAttributeAssignmentAdministrator := contains(Policy.IncludeRoles, AttributeAssignmentAdministrator)
    ContainsReportsReader := contains(Policy.IncludeRoles, ReportsReader)
    ContainsOrganizationalMessagesWriter := contains(Policy.IncludeRoles, OrganizationalMessagesWriter)
    ContainsSharePointAdministrator := contains(Policy.IncludeRoles, SharePointAdministrator)
    ContainsYammerAdministrator := contains(Policy.IncludeRoles, YammerAdministrator)
    ContainsWindowsUpdateDeploymentAdministrator := contains(Policy.IncludeRoles, WindowsUpdateDeploymentAdministrator)
    ContainsWindows365Administrator := contains(Policy.IncludeRoles, Windows365Administrator)
    ContainsVivaGoalsAdministrator := contains(Policy.IncludeRoles, VivaGoalsAdministrator)
    ContainsVirtualVisitsAdministrator := contains(Policy.IncludeRoles, VirtualVisitsAdministrator)
    ContainsUserAdministrator := contains(Policy.IncludeRoles, UserAdministrator)
    ContainsUsageSummaryReportsReader := contains(Policy.IncludeRoles, UsageSummaryReportsReader)
    ContainsTenantCreator := contains(Policy.IncludeRoles, TenantCreator)
    ContainsTeamsDevicesAdministrator := contains(Policy.IncludeRoles, TeamsDevicesAdministrator)
    ContainsTeamsCommunicationsSupportSpecialist := contains(Policy.IncludeRoles, TeamsCommunicationsSupportSpecialist)
    ContainsTeamsCommunicationsSupportEngineer := contains(Policy.IncludeRoles, TeamsCommunicationsSupportEngineer)
    ContainsTeamsCommunicationsAdministrator := contains(Policy.IncludeRoles, TeamsCommunicationsAdministrator)
    ContainsTeamsAdministrator := contains(Policy.IncludeRoles, TeamsAdministrator)
    ContainsSkypeforBusinessAdministrator := contains(Policy.IncludeRoles, SkypeforBusinessAdministrator)
    ContainsServiceSupportAdministrator := contains(Policy.IncludeRoles, ServiceSupportAdministrator)
    ContainsSecurityReader := contains(Policy.IncludeRoles, SecurityReader)
    ContainsSecurityAdministrator := contains(Policy.IncludeRoles, SecurityAdministrator)
    ContainsSecurityOperator := contains(Policy.IncludeRoles, SecurityOperator)
    ContainsSearchEditor := contains(Policy.IncludeRoles, SearchEditor)
    ContainsSearchAdministrator := contains(Policy.IncludeRoles, SearchAdministrator)
    ContainsPrivilegedRoleAdministrator := contains(Policy.IncludeRoles, PrivilegedRoleAdministrator)
    ContainsPrivilegedAuthenticationAdministrator := contains(Policy.IncludeRoles, PrivilegedAuthenticationAdministrator)
    ContainsPrinterTechnician := contains(Policy.IncludeRoles, PrinterTechnician)
    ContainsPrinterAdministrator := contains(Policy.IncludeRoles, PrinterAdministrator)
    ContainsPowerPlatformAdministrator := contains(Policy.IncludeRoles, PowerPlatformAdministrator)
    ContainsFabricAdministrator := contains(Policy.IncludeRoles, FabricAdministrator)
    ContainsPermissionsManagementAdministrator := contains(Policy.IncludeRoles, PermissionsManagementAdministrator)
    ContainsPasswordAdministrator := contains(Policy.IncludeRoles, PasswordAdministrator)
    ContainsOfficeAppsAdministrator := contains(Policy.IncludeRoles, OfficeAppsAdministrator)
    ContainsNetworkAdministrator := contains(Policy.IncludeRoles, NetworkAdministrator)
    ContainsMicrosoftHardwareWarrantySpecialist := contains(Policy.IncludeRoles, MicrosoftHardwareWarrantySpecialist)
    ContainsMicrosoftHardwareWarrantyAdministrator := contains(Policy.IncludeRoles, MicrosoftHardwareWarrantyAdministrator)
    ContainsMessageCenterReader := contains(Policy.IncludeRoles, MessageCenterReader)
    ContainsMessageCenterPrivacyReader := contains(Policy.IncludeRoles, MessageCenterPrivacyReader)
    ContainsLifecycleWorkflowsAdministrator := contains(Policy.IncludeRoles, LifecycleWorkflowsAdministrator)
    ContainsLicenseAdministrator := contains(Policy.IncludeRoles, LicenseAdministrator)
    ContainsKnowledgeManager := contains(Policy.IncludeRoles, KnowledgeManager)
    ContainsKnowledgeAdministrator := contains(Policy.IncludeRoles, KnowledgeAdministrator)
    ContainsKaizalaAdministrator := contains(Policy.IncludeRoles, KaizalaAdministrator)
    ContainsIntuneAdministrator := contains(Policy.IncludeRoles, IntuneAdministrator)
    ContainsInsightsBusinessLeader := contains(Policy.IncludeRoles, InsightsBusinessLeader)
    ContainsInsightsAnalyst := contains(Policy.IncludeRoles, InsightsAnalyst)
    ContainsInsightsAdministrator := contains(Policy.IncludeRoles, InsightsAdministrator)
    ContainsIdentityGovernanceAdministrator := contains(Policy.IncludeRoles, IdentityGovernanceAdministrator)
    ContainsHybridIdentityAdministrator := contains(Policy.IncludeRoles, HybridIdentityAdministrator)
    ContainsHelpdeskAdministrator := contains(Policy.IncludeRoles, HelpdeskAdministrator)
    ContainsGuestInviter := contains(Policy.IncludeRoles, GuestInviter)
    ContainsGroupsAdministrator := contains(Policy.IncludeRoles, GroupsAdministrator)
    ContainsGlobalReader := contains(Policy.IncludeRoles, GlobalReader)
    ContainsGlobalAdministrator := contains(Policy.IncludeRoles, GlobalAdministrator)
    ContainsExternalIdentityProviderAdministrator := contains(Policy.IncludeRoles, ExternalIdentityProviderAdministrator)
    ContainsExternalIDUserFlowAttributeAdministrator := contains(Policy.IncludeRoles, ExternalIDUserFlowAttributeAdministrator)
    ContainsExternalIDUserFlowAdministrator := contains(Policy.IncludeRoles, ExternalIDUserFlowAdministrator)
    ContainsExchangeRecipientAdministrator := contains(Policy.IncludeRoles, ExchangeRecipientAdministrator)
    ContainsExchangeAdministrator := contains(Policy.IncludeRoles, ExchangeAdministrator)
    ContainsEdgeAdministrator := contains(Policy.IncludeRoles, EdgeAdministrator)
    ContainsDynamics365Administrator := contains(Policy.IncludeRoles, Dynamics365Administrator)
    ContainsDomainNameAdministrator := contains(Policy.IncludeRoles, DomainNameAdministrator)
    ContainsDirectoryWriters := contains(Policy.IncludeRoles, DirectoryWriters)
    ContainsDirectorySynchronizationAccounts := contains(Policy.IncludeRoles, DirectorySynchronizationAccounts)
    ContainsDirectoryReaders := contains(Policy.IncludeRoles, DirectoryReaders)
    ContainsDesktopAnalyticsAdministrator := contains(Policy.IncludeRoles, DesktopAnalyticsAdministrator)
    ContainsCustomerLockBoxAccessApprover := contains(Policy.IncludeRoles, CustomerLockBoxAccessApprover)
    ContainsConditionalAccessAdministrator := contains(Policy.IncludeRoles, ConditionalAccessAdministrator)
    ContainsComplianceDataAdministrator := contains(Policy.IncludeRoles, ComplianceDataAdministrator)
    ContainsComplianceAdministrator := contains(Policy.IncludeRoles, ComplianceAdministrator)
    ContainsCloudDeviceAdministrator := contains(Policy.IncludeRoles, CloudDeviceAdministrator)
    ContainsCloudApplicationAdministrator := contains(Policy.IncludeRoles, CloudApplicationAdministrator)
    ContainsCloudAppSecurityAdministrator := contains(Policy.IncludeRoles, CloudAppSecurityAdministrator)
    ContainsBillingAdministrator := contains(Policy.IncludeRoles, BillingAdministrator)
    ContainsB2CIEFPolicyAdministrator := contains(Policy.IncludeRoles, B2CIEFPolicyAdministrator)
    ContainsAzureInformationProtectionAdministrator := contains(Policy.IncludeRoles, AzureInformationProtectionAdministrator)
    ContainsB2CIEFKeysetAdministrator := contains(Policy.IncludeRoles, B2CIEFKeysetAdministrator)
    ContainsAzureDevOpsAdministrator := contains(Policy.IncludeRoles, AzureDevOpsAdministrator)
    ContainsAuthenticationPolicyAdministrator := contains(Policy.IncludeRoles, AuthenticationPolicyAdministrator)
    ContainsAuthenticationAdministrator := contains(Policy.IncludeRoles, AuthenticationAdministrator)
    ContainsAttributeDefinitionReader := contains(Policy.IncludeRoles, AttributeDefinitionReader)
}
AdminSigninIncludeRoles[Policy.IncludeRoles] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Users

    

    # Match all simple conditions
    AdminSigninIncludeRolesMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.7.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : AdminSigninIncludeRoles,
    "ReportDetails" : ReportDetailsString(Status, Details), 
    "RequirementMet" : Status
}] {
    Status := count(AdminSigninIncludeRoles) > 0

    Details := "Requirement not met: IncludeRoles must be configured correctly" 

}
#--

#
# MS.Entra.7.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}


#--
# ############
# # MS.Entra.8 #
# ############

#
# MS.Entra.8.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: CountriesNotAllowed - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.8.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CountriesNotAllowed - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.8.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.8.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions
    Status := Policy.ClientAppTypes == "all"
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.8.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.8.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeLocations,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Locations
    Status := Policy.IncludeLocations == "All"
    Details := "Requirement not met: IncludeLocations must be set to 'All'" 

}
#--

#
# MS.Entra.8.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}
#--


#
# MS.Entra.8.11v1
#--
tests[{
    "PolicyId" : "MS.Entra.8.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}

#
# MS.Entra.8.12v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.12v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 

}
#--

#
# MS.Entra.8.13v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.13v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeLocations,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Locations
    Status := Policy.ExcludeLocations == "1ea33f82-a850-412b-937b-e3cdea4b9dd7"
    Details := "Requirement not met: ExcludeLocations must be set to 'Allowed Countries'/'1ea33f82-a850-412b-937b-e3cdea4b9dd7'" 

}
#--
    

# ############
# # MS.Entra.9 #
# ############

#
# MS.Entra.9.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessBlock - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.9.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessBlock - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.9.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.9.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","browser","mobileAppsAndDesktopClients","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.9.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.9.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions.Applications
    Status := Policy.ExcludeApplications == "Office365"
    Details := "Requirement not met: ExcludeApplications must be set to 'Office365'" 

}
#--

#
# MS.Entra.9.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.9.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabled'" 
}

############
# MS.Entra.10 #
############

#
# MS.Entra.10.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.10.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.10.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.10.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.10.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions.Applications
    Status := Policy.IncludeApplications == "Office365"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.10.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludePlatforms,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions.Platforms
    Status := Policy.IncludePlatforms == "windows"
    Details := "Requirement not met: IncludePlatforms must be set to 'windows'" 

}
#--

#
# MS.Entra.10.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.10.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 
}


############
# MS.Entra.11 #
############
#
# MS.Entra.11.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.11.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.11.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.11.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.11.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","browser","mobileAppsAndDesktopClients", "other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.11.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be configured correctly" 

}
#--

############
# MS.Entra.12 #
############

#
# MS.Entra.12.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.12.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.12.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.12.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.12.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.12.9v1
#--

tests[{
    "PolicyId" : "MS.Entra.12.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}
#--

#
# MS.Entra.12.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.12.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}


############
# MS.Entra.13 #
############

#
# MS.Entra.13.1v1 
#--


tests[{
    "PolicyId" : "MS.Entra.13.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.13.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.13.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.13.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions
    Status := Policy.ClientAppTypes == "all"
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.13.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions.Applications
    Status := Policy.IncludeApplications == "None"
    Details := "Requirement not met: IncludeApplications must be set to 'None'" 

}

#
# MS.Entra.13.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeRoles,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions.Users
    Status := Policy.ExcludeRoles == GlobalAdministrator
    Details := "Requirement not met: ExcludeRoles must be set to Global Administrator" 

}
#
# MS.Entra.13.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.13.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}



############
# MS.Entra.14 #
############

#
# MS.Entra.14.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details :="Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'"
    
}
#--

#
# MS.Entra.14.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.14.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.14.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.14.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.14.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}

#
# MS.Entra.14.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : [Policy.IsEnabled, Policy.Type, Policy.Value],
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.SignInFrequency
    Conditions := [Policy.IsEnabled == true, Policy.Type == "hours", Policy.Value == 12]
    Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    Incorrect := 3 - count([Condition | Condition = Conditions[_]; Condition == true]) 
    Details := concat(format_int(Incorrect, 10), ["Requirement not met: ", " SessionSignInFrequency - SignInFrequency policies configured incorrectly"])
    
}

#
# MS.Entra.14.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}

############
# MS.Entra.15 #
############

#
# MS.Entra.15.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.15.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.15.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups needs to be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 
    
}
#--

#
# MS.Entra.15.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.15.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.15.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.15.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.TermsOfUse,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.GrantControls
    Status := Policy.TermsOfUse == ["00361d63-8e1d-4f43-ad68-513fcddfdd20"]
    Details := "Requirement not met: TermsOfUse must be set to 'Acceptable Use Policy'/'00361d63-8e1d-4f43-ad68-513fcddfdd20'" 
}

#
# MS.Entra.15.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}