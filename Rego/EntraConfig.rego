package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.policy.utils.IsEmptyContainer
import data.policy.utils.Contains
import data.policy.utils.Count

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
    Policy := input.group_naming_policy[_]

    # Match all simple conditions
    CustomBlockedWordsListMatch(Policy)
}

tests[{
    "PolicyId" : "MS.Entra.1.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : CustomBlockedWordsList,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(CustomBlockedWordsList) > 0
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
    "Commandlet" : ["Get--MgBetaPolicyAuthenticationStrengthPolicy"],
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
    "Commandlet" : ["Get--MgBetaPolicyAuthenticationStrengthPolicy"],
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

