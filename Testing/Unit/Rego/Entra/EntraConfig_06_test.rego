package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.6.1v2
#--
test_GroupLifetime_Correct if {
    PolicyId := "MS.Entra.6.1v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "GroupLifetimeInDays":  180
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupLifetime_Incorrect_V1 if {
    PolicyId := "MS.Entra.6.1v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "GroupLifetimeInDays":  179
            }
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Group lifetime (in days)</b> must be set to <b>180</b>"
}

test_GroupLifetime_Incorrect_V2 if {
    PolicyId := "MS.Entra.6.1v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                 "GroupLifetimeInDays":  181
            }     
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Group lifetime (in days)</b> must be set to <b>180</b>"
}
test_GroupLifetime_Incorrect_V3 if {
    PolicyId := "MS.Entra.6.1v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "GroupLifetimeInDays":  0
            }
            
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Group lifetime (in days)</b> must be set to <b>180</b>"
}
test_GroupLifetime_Incorrect_V4 if {
    PolicyId := "MS.Entra.6.1v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "GroupLifetimeInDays":  null
            }
            
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Group lifetime (in days)</b> must be set to <b>180</b>"
}

#
# MS.Entra.6.2v2
#--
test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.6.2v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}


#
# MS.Entra.6.3v2
#--
test_ManagedGroupTypes_Correct if {
    PolicyId := "MS.Entra.6.3v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "ManagedGroupTypes":  "All"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_ManagedGroupTypes_Incorrect_V1 if {
    PolicyId := "MS.Entra.6.3v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {    
                 "ManagedGroupTypes":  "al"
            }
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Enable expiration for these Microsoft 365 groups</b> must be set to <b>All</b>"
}

test_ManagedGroupTypes_Incorrect_V2 if {
    PolicyId := "MS.Entra.6.3v2"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                 "ManagedGroupTypes":  null
            }     
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Enable expiration for these Microsoft 365 groups</b> must be set to <b>All</b>"
}
