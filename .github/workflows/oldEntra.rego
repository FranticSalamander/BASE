
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

