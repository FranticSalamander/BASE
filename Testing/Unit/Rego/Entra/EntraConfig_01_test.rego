package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.1.1v1
#--
test_GroupExpiry_Correct if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : "All",
                "GroupLifetimeInDays" : 180,
                "AlternateNotificationEmails" : "Office365_Group_Expiration@agency.gov.au"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupExpiry_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : "Al",
                "GroupLifetimeInDays" : 180,
                "AlternateNotificationEmails" : "Office365_Group_Expiration@agency.gov.au"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_GroupExpiry_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : null,
                "GroupLifetimeInDays" : 180,
                "AlternateNotificationEmails" : "Office365_Group_Expiration@agency.gov.au"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_GroupExpiry_Incorrect_V3 if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : "All",
                "GroupLifetimeInDays" : 179,
                "AlternateNotificationEmails" : "Office365_Group_Expiration@agency.gov.au"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_GroupExpiry_Incorrect_V4 if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : "All",
                "GroupLifetimeInDays" : "180",
                "AlternateNotificationEmails" : "Office365_Group_Expiration@agency.gov.au"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_GroupExpiry_Incorrect_V5 if {
    PolicyId := "MS.Entra.1.1v1"

    Output := tests with input as {
        "group_lifecycle_policy": [
            {
                "ManagedGroupTypes" : "All",
                "GroupLifetimeInDays" : 180,
                "AlternateNotificationEmails" : 6
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}