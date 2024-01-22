package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.7.1v1
#--
test_AdminSignInFrequency_Correct if {
    PolicyId := "MS.Entra.7.1v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency": [
            {
                "SessionControls":  {
                            "SignInFrequency":  {
                                                    "IsEnabled":  true,
                                                    "Type":  "hours",
                                                    "Value":  4
                                                }
                        }
            }
        ]
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AdminSignInFrequency_Incorrect if {
    PolicyId := "MS.Entra.7.1v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency": [
            {
                "SessionControls":  {
                            "SignInFrequency":  {
                                                    "AuthenticationType":  "primaryAndSecondaryAuthentication",
                                                    "FrequencyInterval":  "timeBased",
                                                    "IsEnabled":  true,
                                                    "Type":  "hours",
                                                    "Value":  2
                                                }
                        },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 1 AdminSignInFrequency - SignInFrequency policies configured incorrectly"
}
