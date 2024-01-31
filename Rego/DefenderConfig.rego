package defender
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean
import data.defender.utils.SensitiveAccounts
import data.defender.utils.SensitiveAccountsConfig
import data.defender.utils.SensitiveAccountsSetting
import data.defender.utils.ImpersonationProtection
import data.defender.utils.ImpersonationProtectionConfig

## Report details menu
#
# NOTE: Use report.utils package for common report formatting functions.
#
# If you simply want a boolean "Requirement met" / "Requirement not met"
# just call ReportDetailsBoolean(Status) and leave it at that.
#
# If you want to customize the error message, wrap the ReportDetails call
# inside CustomizeError, like so:
# CustomizeError(ReportDetailsBoolean(Status), "Custom error message")
#
# If you want to customize the error message with details about an array,
# generate the custom error message using GenerateArrayString, for example:
# CustomizeError(ReportDetailsBoolean(Status), GenerateArrayString(BadPolicies, "bad policies found:"))
#
# If the setting in question requires a defender license,
# wrap the details string inside ApplyLicenseWarning, like so:
# ApplyLicenseWarning(ReportDetailsBoolean(Status))
#
# These functions can be nested. For example:
# ApplyLicenseWarning(CustomizeError(ReportDetailsBoolean(Status), "Custom error message"))
#
##

GenerateArrayString(Array, CustomString) := Output if {
    # Example usage and output:
    # GenerateArrayString([1,2], "numbers found:") ->
    # 2 numbers found: 1, 2
    Length := format_int(count(Array), 10)
    ArrayString := concat(", ", Array)
    Output := trim(concat(" ", [Length, concat(" ", [CustomString, ArrayString])]), " ")
}

CustomizeError(Message, CustomString) := Message if {
    # If the message reports success, don't apply the custom
    # error message
    Message == ReportDetailsBoolean(true)
}

CustomizeError(Message, CustomString) := CustomString if {
    # If the message does not report success, apply the custom
    # error message
    Message != ReportDetailsBoolean(true)
}

ApplyLicenseWarning(Message) := Message if {
    # If a defender license is present, don't apply the warning
    # and leave the message unchanged
    input.defender_license == true
}

ApplyLicenseWarning(Message) := concat("", [ReportDetailsBoolean(false), LicenseWarning]) if {
    # If a defender license is not present, assume failure and
    # replace the message with the warning
    input.defender_license == false
    LicenseWarning := " **NOTE: Either you do not have sufficient permissions or your tenant does not have a license for Microsoft Defender for Office 365 Plan 1, which is required for this feature.**"
}


#
# MS.DEFENDER.1.1v1
#--

ReportDetails1_1(Standard, Strict) := "Requirement met" if {
    Standard == true
    Strict == true
}
ReportDetails1_1(Standard, Strict) := "Standard preset policy is disabled" if {
    Standard == false
    Strict == true
}
ReportDetails1_1(Standard, Strict) := "Strict preset policy is disabled" if {
    Standard == true
    Strict == false
}
ReportDetails1_1(Standard, Strict) := "Standard and Strict preset policies are both disabled" if {
    Standard == false
    Strict == false
}

tests[{
    "PolicyId" : "MS.DEFENDER.1.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-EOPProtectionPolicyRule", "Get-ATPProtectionPolicyRule"],
    "ActualValue" : {"StandardPresetState": IsStandardEnabled, "StrictPresetState": IsStrictEnabled},
    "ReportDetails" : ReportDetails1_1(IsStandardEnabled, IsStrictEnabled),
    "RequirementMet" : Status
}] {
    # For this one you need to check both:
    # - Get-EOPProtectionPolicyRule
    # - Get-ATPProtectionPolicyRule
    #
    # This is because there isn't an easy way to check if the toggle is on
    # the main "Preset security policies" page is or set not. It is
    # entirely possible for the standard/strict policies to be enabled
    # but for one of the above commands to not reflect it.
    #
    # For example, if we enable the standard policy but only add users to
    # Exchange online protection, Get-EOPProtectionPolicyRule will report
    # the standard policy as enabled, but the standard policy won't even
    # be included in the output of Get-ATPProtectionPolicyRule, and vice
    # versa.
    #
    # TLDR: If at least one of the commandlets reports the policy as
    # enabled, then the policy is enabled; if the policy is missing in
    # the output of one, you need to check the other before you can
    # conclude that it is disabled.

    EOPPolicies := input.protection_policy_rules
    IsStandardEOPEnabled := count([Policy | Policy = EOPPolicies[_];
        Policy.Identity == "Standard Preset Security Policy";
        Policy.State == "Enabled"]) > 0
    IsStrictEOPEnabled := count([Policy | Policy = EOPPolicies[_];
        Policy.Identity == "Strict Preset Security Policy";
        Policy.State == "Enabled"]) > 0

    ATPPolicies := input.atp_policy_rules
    IsStandardATPEnabled := count([Policy | Policy = ATPPolicies[_];
        Policy.Identity == "Standard Preset Security Policy";
        Policy.State == "Enabled"]) > 0
    IsStrictATPEnabled := count([Policy | Policy = ATPPolicies[_];
        Policy.Identity == "Strict Preset Security Policy";
        Policy.State == "Enabled"]) > 0

    StandardConditions := [IsStandardEOPEnabled, IsStandardATPEnabled]
    IsStandardEnabled := count([Condition | Condition = StandardConditions[_]; Condition == true]) > 0

    StrictConditions := [IsStrictEOPEnabled, IsStrictATPEnabled]
    IsStrictEnabled := count([Condition | Condition = StrictConditions[_]; Condition == true]) > 0

    Conditions := [IsStandardEnabled, IsStrictEnabled]
    Status := count([Condition | Condition = Conditions[_]; Condition == false]) == 0
}
#--
