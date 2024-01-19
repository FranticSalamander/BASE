package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.policy.utils.IsEmptyContainer
import data.policy.utils.Contains
import data.policy.utils.Count
import data.report.utils.ReportDetailsString

#############################################################################
# The report formatting functions below are generic and used throughout Entra #
#############################################################################

Description(String1, String2, String3) := trim(concat(" ", [String1, String2, String3]), " ")

ReportDetailsArray(Array, String) := Description(Format(Array), String, "")

# Set to the maximum number of array items to be
# printed in the report details section
ReportArrayMaxCount := 20

ReportFullDetailsArray(Array, String) := Details {
    count(Array) == 0
    Details := ReportDetailsArray(Array, String)
}

ReportFullDetailsArray(Array, String) := Details {
    count(Array) > 0
    count(Array) <= ReportArrayMaxCount
    Details := Description(Format(Array), concat(":<br/>", [String, concat(", ", Array)]), "")
}

ReportFullDetailsArray(Array, String) := Details {
    count(Array) > ReportArrayMaxCount
    List := [ x | x := Array[_] ]

    TruncationWarning := "...<br/>Note: The list of matching items has been truncated.  Full details are available in the JSON results."
    TruncatedList := concat(", ", array.slice(List, 0, ReportArrayMaxCount))
    Details := Description(Format(Array), concat(":<br/>", [String, TruncatedList]), TruncationWarning)
}

CapLink := "<a href='#caps'>View all CA policies</a>."

##############################################################################################################
# The report formatting functions below are for policies that check the required Microsoft Entra ID P2 license #
##############################################################################################################

Aad2P2Licenses[ServicePlan.ServicePlanId] {
    ServicePlan = input.service_plans[_]
    ServicePlan.ServicePlanName == "Entra_PREMIUM_P2"
}

P2WarningString := "**NOTE: Your tenant does not have a Microsoft Entra ID P2 license, which is required for this feature**"

ReportDetailsArrayLicenseWarningCap(Array, String) := Description if {
  count(Aad2P2Licenses) > 0
  Description :=  concat(". ", [ReportFullDetailsArray(Array, String), CapLink])
}

ReportDetailsArrayLicenseWarningCap(_, _) := Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsArrayLicenseWarning(Array, String) := Description if {
  count(Aad2P2Licenses) > 0
  Description :=  ReportFullDetailsArray(Array, String)
}

ReportDetailsArrayLicenseWarning(_, _) := Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsBooleanLicenseWarning(Status) := Description if {
    count(Aad2P2Licenses) > 0
    Status == true
    Description := "Requirement met"
}

ReportDetailsBooleanLicenseWarning(Status) := Description if {
    count(Aad2P2Licenses) > 0
    Status == false
    Description := "Requirement not met"
}

ReportDetailsBooleanLicenseWarning(_) := Description if {
    count(Aad2P2Licenses) == 0
    Description := P2WarningString
}

##########################################
# User/Group Exclusion support functions #
##########################################

default UserExclusionsFullyExempt(_, _) := false
UserExclusionsFullyExempt(Policy, PolicyID) := true if {
    # Returns true when all user exclusions present in the conditional
    # access policy are exempted in matching config variable for the
    # baseline policy item.  Undefined if no exclusions AND no exemptions.
    ExemptedUsers := input.scuba_config.Aad[PolicyID].CapExclusions.Users
    ExcludedUsers := { x | x := Policy.Conditions.Users.ExcludeUsers[_] }
    AllowedExcludedUsers := { y | y := ExemptedUsers[_] }
    count(ExcludedUsers - AllowedExcludedUsers) == 0
}

UserExclusionsFullyExempt(Policy, PolicyID) := true if {
    # Returns true when user inputs are not defined or user exclusion lists are empty
    count({ x | x := Policy.Conditions.Users.ExcludeUsers[_] }) == 0
    count({ y | y := input.scuba_config.Aad[PolicyID].CapExclusions.Users }) == 0
}

default GroupExclusionsFullyExempt(_, _) := false
GroupExclusionsFullyExempt(Policy, PolicyID) := true if {
    # Returns true when all group exclusions present in the conditional
    # access policy are exempted in matching config variable for the
    # baseline policy item.  Undefined if no exclusions AND no exemptions.
    ExemptedGroups := input.scuba_config.Aad[PolicyID].CapExclusions.Groups
    ExcludedGroups := { x | x := Policy.Conditions.Users.ExcludeGroups[_] }
    AllowedExcludedGroups := { y | y:= ExemptedGroups[_] }
    count(ExcludedGroups - AllowedExcludedGroups) == 0
}

GroupExclusionsFullyExempt(Policy, PolicyID) := true if {
    # Returns true when user inputs are not defined or group exclusion lists are empty
    count({ x | x := Policy.Conditions.Users.ExcludeGroups[_] }) == 0
    count({ y | y := input.scuba_config.Aad[PolicyID].CapExclusions.Groups }) == 0
}


#--
############
# MS.Entra.1 #
############

#
# MS.Entra.1.1v1
#--
tests[{
    "PolicyId" : "MS.Entra.1.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaGroupLifecyclePolicy"],
    "ActualValue" : [Policy.ManagedGroupTypes, Policy.GroupLifetimeInDays, Policy.AlternateNotificationEmails],
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    

    Policy := input.group_lifecycle_policy[_]
    Conditions := [Policy.ManagedGroupTypes == "All", Policy.GroupLifetimeInDays == 180, Policy.AlternateNotificationEmails == "Office365_Group_Expiration@agency.gov.au"]
    Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    
}
#--

#
# MS.Entra.1.2v1
#--
default CustomBlockedWordsListMatch(_) := false
CustomBlockedWordsListMatch(Policy) := true if {
    Policy.Name == "CustomBlockedWordsList"  
    Policy.Value == "HR,Exec,SOC,Minister"
}

CustomBlockedWordsList[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    CustomBlockedWordsListMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : CustomBlockedWordsList,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(CustomBlockedWordsList) > 0
    Detail := "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
}
#--

#
# MS.Entra.1.3v1
#--
default AllowGuestsToAccessGroupsMatch(_) := false
AllowGuestsToAccessGroupsMatch(Policy) := true if {
    Policy.Name == "AllowGuestsToAccessGroups"  
    Policy.Value == "False"
}
AllowGuestsToAccessGroupsMatch(Policy) := true if {
    Policy.Name == "AllowGuestsToAccessGroups"  
    Policy.Value == "false"
}

AllowGuestsToAccessGroups[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    AllowGuestsToAccessGroupsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : AllowGuestsToAccessGroups,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(AllowGuestsToAccessGroups) > 0
    Detail := "Requirement not met: 'AllowGuestsToAccessGroups' needs to be set to false"
}
#--

#
# MS.Entra.1.4v1
#--
default AllowGuestsToBeGroupOwnerMatch(_) := false
AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
    Policy.Name == "AllowGuestsToBeGroupOwner"  
    Policy.Value == "false"
}
AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
    Policy.Name == "AllowGuestsToBeGroupOwner"  
    Policy.Value == "False"
}

AllowGuestsToBeGroupOwner[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    AllowGuestsToBeGroupOwnerMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : AllowGuestsToBeGroupOwner,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(AllowGuestsToBeGroupOwner) > 0
    Detail := "Requirement not met: 'AllowGuestsToBeGroupOwner' needs to be set to false"
}
#--

#
# MS.Entra.1.5v1
#--
default AllowToAddGuestsMatch(_) := false
AllowToAddGuestsMatch(Policy) := true if {
    Policy.Name == "AllowToAddGuests"  
    Policy.Value == "false"
}
AllowToAddGuestsMatch(Policy) := true if {
    Policy.Name == "AllowToAddGuests"  
    Policy.Value == "False"
}

AllowToAddGuests[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    AllowToAddGuestsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : AllowToAddGuests,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(AllowToAddGuests) > 0
    Detail := "Requirement not met: 'AllowToAddGuests' needs to be set to false"
}
#--

#
# MS.Entra.1.6v1
#--
default EnableGroupCreationMatch(_) := false
EnableGroupCreationMatch(Policy) := true if {
    Policy.Name == "EnableGroupCreation"  
    Policy.Value == "false"
}
EnableGroupCreationMatch(Policy) := true if {
    Policy.Name == "EnableGroupCreation"  
    Policy.Value == "False"
}

EnableGroupCreation[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    EnableGroupCreationMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : EnableGroupCreation,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(EnableGroupCreation) > 0
    Detail := "Requirement not met: 'EnableGroupCreation' needs to be set to false"
}
#--

#
# MS.Entra.1.7v1
#--
default EnableMIPLabelsMatch(_) := false
EnableMIPLabelsMatch(Policy) := true if {
    Policy.Name == "EnableMIPLabels"  
    Policy.Value == "true"
}
EnableMIPLabelsMatch(Policy) := true if {
    Policy.Name == "EnableMIPLabels"  
    Policy.Value == "True"
}

EnableMIPLabels[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    EnableMIPLabelsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : EnableMIPLabels,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(EnableMIPLabels) > 0
    Detail := "Requirement not met: 'EnableMIPLabels' needs to be set to true"
}
#--




#--
############
# MS.Entra.2 #
############


#
# MS.Entra.2.1v1 #This test layout works when there are multiple settings using the same name
#--
default MultifactorAuthenticationConditionsMatch(_) := false
MultifactorAuthenticationConditionsMatch(Policy) := true if {
    Policy.DisplayName =="Multifactor authentication"
    Policy.Description == "Combinations of methods that satisfy strong authentication, such as a password + SMS"
    Policy.AllowedCombinations == [
                                     "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"                               
                                ]
}

MultifactorAuthentication[Policy.DisplayName] {
    Policy := input.authentication_strength_policy[_]

    # Match all simple conditions
    MultifactorAuthenticationConditionsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.2.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
    "ActualValue" : MultifactorAuthentication,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(MultifactorAuthentication) > 0
}


#
# MS.Entra.2.2v1 
#--
default PasswordlessMFAConditionsMatch(_) := false
PasswordlessMFAConditionsMatch(Policy) := true if {
    Policy.DisplayName == "Passwordless MFA"
    Policy.Description == "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator"
    Policy.AllowedCombinations == [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush"                               
                                ]
}

PasswordlessMFA[Policy.DisplayName] {
    Policy := input.authentication_strength_policy[_]

    # Match all simple conditions
    PasswordlessMFAConditionsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.2.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
    "ActualValue" : PasswordlessMFA,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(PasswordlessMFA) > 0
}
#--


#
# MS.Entra.2.3v1
#--
default PhishingResistantMFAConditionsMatch(_) := false
PhishingResistantMFAConditionsMatch(Policy) := true if {
    Policy.DisplayName == "Phishing-resistant MFA"
    Policy.Description == "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key"
    Policy.AllowedCombinations == [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor"                          
                                ]
}

PhishingResistantMFA[Policy.DisplayName] {
    Policy := input.authentication_strength_policy[_]

    # Match all simple conditions
    PhishingResistantMFAConditionsMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.2.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
    "ActualValue" : PhishingResistantMFA,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(PhishingResistantMFA) > 0
}
#--

#--
############
# MS.Entra.3 #
############

#
# MS.Entra.3.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.3.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyIdentitySecurityDefaultEnforcementPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.security_defaults[_]
    Status := Policy.IsEnabled == false
    Detail := "Requirement not met: Security Defaults must be disabled"
}
#--

#--
############
# MS.Entra.4 #
############

#
# MS.Entra.4.1v1
#--


default BreakGlassUser1Match(_) := false
BreakGlassUser1Match(Policy) := true if {
    Policy.DisplayName == "Break Glass"  
    Policy.PasswordPolicies == null
    Policy.UsageLocation == "AU"
    Policy.UserType == "Member"
    startswith(Policy.UserPrincipalName, "break.glass_priv1")
   
}

BreakGlassUser1[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1Match(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1) == 1
    Details := "Requirement not met: Break Glass User Account 1 is not configured correctly"
    
}
#--

#
# MS.Entra.4.2v1
#--


default BreakGlassUser2Match(_) := false
BreakGlassUser2Match(Policy) := true if {
    Policy.DisplayName == "Break Glass"  
    Policy.PasswordPolicies == null
    Policy.UsageLocation == "AU"
    Policy.UserType == "Member"
    startswith(Policy.UserPrincipalName, "break.glass_priv2")
   
}

BreakGlassUser2[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2Match(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2) == 1
    Details := "Requirement not met: Break Glass User Account 2 is not configured correctly"
    
}
#--

############
# MS.Entra.5 #
############


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