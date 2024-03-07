package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.2.1v2
#--
test_SecurityDefaults_Correct if {
    PolicyId := "MS.Entra.2.1v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateApps": false
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_SecurityDefaults_Incorrect if {
    PolicyId := "MS.Entra.2.1v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateApps": true
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: Security Defaults must be disabled"
}
