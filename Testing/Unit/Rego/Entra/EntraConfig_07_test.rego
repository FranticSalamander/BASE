package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.7.1v2
#--
test_GroupLifetime_Correct if {
    PolicyId := "MS.Entra.7.1v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "CustomBlockedWordsList",
                "Value": ""
            },
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupLifetime_Incorrect if {
    PolicyId := "MS.Entra.7.1v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "CustomBlockedWordsList",
                "Value": "Anything"
            },
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Block word list</b> must be set to <b>Not Configured</b>"
}


#
# MS.Entra.7.2v2
#--
test_GroupLifetime_Correct if {
    PolicyId := "MS.Entra.7.2v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "PrefixSuffixNamingRequirement",
                "Value": ""
            },
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupLifetime_Incorrect if {
    PolicyId := "MS.Entra.7.2v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "PrefixSuffixNamingRequirement",
                "Value": "anything"
            },
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"
}

#
# MS.Entra.7.3v2
#--
test_GroupLifetime_Correct if {
    PolicyId := "MS.Entra.7.3v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "PrefixSuffixNamingRequirement",
                "Value": ""
            },
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupLifetime_Incorrect if {
    PolicyId := "MS.Entra.7.3v2"

    Output := tests with input as {
        "group_settings": [
            {
                "Name": "PrefixSuffixNamingRequirement",
                "Value": "anything"
            },
            
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Add suffix</b> must be set to <b>Not Configured</b>"
}
