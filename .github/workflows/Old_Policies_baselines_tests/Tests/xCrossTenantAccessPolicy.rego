package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.6.1v1
#--
test_InboundTrust_Correct if {
    PolicyId := "MS.Entra.6.1v1"

    Output := tests with input as {
        "cross_tenant_access_policy": [
            {
                 "InboundTrust":  {
                             "IsCompliantDeviceAccepted":  false,
                             "IsHybridAzureAdJoinedDeviceAccepted":  false,
                             "IsMfaAccepted":  false
                         }
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_InboundTrust_Incorrect if {
    PolicyId := "MS.Entra.6.1v1"

    Output := tests with input as {
        "cross_tenant_access_policy": [
            {
                 "InboundTrust":  {
                             "IsCompliantDeviceAccepted":  true,
                             "IsHybridAzureAdJoinedDeviceAccepted":  false,
                             "IsMfaAccepted":  false
                         }
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'IsCompliantDeviceAccepted', 'IsHybridAzureAdJoinedDeviceAccepted' and 'IsMfaAccepted' must be set to false"
}
