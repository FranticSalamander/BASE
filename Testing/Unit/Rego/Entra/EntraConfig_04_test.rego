package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.4.1v1
#--
test_BreakGlassUser1_Correct_V1 if {
    PolicyId := "MS.Entra.4.1v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : null,
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv1@sdablueprinthybriddev.onmicrosoft.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser1_Correct_V2 if {
    PolicyId := "MS.Entra.4.1v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : null,
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv1@generic.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}



test_BreakGlassUser1_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.1v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : "PasswordNeverExpires",
                "Roles" : "Global Administrator",
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv2@sdablueprinthybriddev.onmicrosoft.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: Break Glass User Account 1 is not configured correctly"
}

#
# MS.Entra.4.2v1
#--
test_BreakGlassUser2_Correct_V1 if {
    PolicyId := "MS.Entra.4.2v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : null,
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv2@sdablueprinthybriddev.onmicrosoft.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser2_Correct_V2 if {
    PolicyId := "MS.Entra.4.2v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : null,
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv2@generic.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}



test_BreakGlassUser2_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.2v1"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "PasswordPolicies" : "PasswordNeverExpires",
                "Roles" : "Global Administrator",
                "UsageLocation" : "AU",
                "UserPrincipalName" : "break.glass_priv1@sdablueprinthybriddev.onmicrosoft.com",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: Break Glass User Account 2 is not configured correctly"
}
