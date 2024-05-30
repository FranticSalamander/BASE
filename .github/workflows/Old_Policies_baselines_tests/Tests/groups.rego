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

#
# MS.Entra.1.2v1
#--
test_CustomBlockedWordsList_Correct if {
    PolicyId := "MS.Entra.1.2v1"

    Output := tests with input as {
        "group_settings": [
            {
                "Name" : "CustomBlockedWordsList",
                "Value" : "HR,Exec,SOC,Minister"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_CustomBlockedWordsList_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.2v1"

    Output := tests with input as {
        "group_settings": [
            {
                "Name" : "CustomBlokedWordsList",
                "Value" : "HR,Exec,SOC,Minister"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
}

test_CustomBlockedWordsList_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.2v1"

    Output := tests with input as {
        "group_settings": [
            {
                "Name" : "AllowGuestsToBeGroupOwner",
                "Value" : "HR,Exec,SOC,Minister"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
}

test_CustomBlockedWordsList_Incorrect_V3 if {
    PolicyId := "MS.Entra.1.2v1"

    Output := tests with input as {
        "group_settings": [
            {
                "Name" : "",
                "Value" : ""
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
}

test_CustomBlockedWordsList_Incorrect_V4 if {
    PolicyId := "MS.Entra.1.2v1"

    Output := tests with input as {
        "group_settings": [
            {
               
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
}

#
# MS.Entra.1.3v1
#--
test_AllowGuestsToAccessGroups_Correct_V1 if {
    PolicyId := "MS.Entra.1.3v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToAccessGroups",
                "Value" : "False"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowGuestsToAccessGroups_Correct_V2 if {
    PolicyId := "MS.Entra.1.3v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToAccessGroups",
                "Value" : "false"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowGuestsToAccessGroups_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.3v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToAccessGroups",
                "Value" : "f"
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowGuestsToAccessGroups' needs to be set to false"
}

test_AllowGuestsToAccessGroups_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.3v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "",
                "Value" : ""
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowGuestsToAccessGroups' needs to be set to false"
}

#
# MS.Entra.1.4v1
#--
test_AllowGuestsToBeGroupOwner_Correct_V1 if {
    PolicyId := "MS.Entra.1.4v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToBeGroupOwner",
                "Value" : "False"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowGuestsToBeGroupOwner_Correct_V2 if {
    PolicyId := "MS.Entra.1.4v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToBeGroupOwner",
                "Value" : "false"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowGuestsToBeGroupOwner_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.4v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowGuestsToBeGroupOwner",
                "Value" : "f"
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowGuestsToBeGroupOwner' needs to be set to false"
}

test_AllowGuestsToBeGroupOwner_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.4v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "",
                "Value" : ""
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowGuestsToBeGroupOwner' needs to be set to false"
}

#
# MS.Entra.1.5v1
#--
test_AllowToAddGuests_Correct_V1 if {
    PolicyId := "MS.Entra.1.5v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowToAddGuests",
                "Value" : "False"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowToAddGuests_Correct_V2 if {
    PolicyId := "MS.Entra.1.5v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowToAddGuests",
                "Value" : "false"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowToAddGuests_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.5v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "AllowToAddGuests",
                "Value" : "f"
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowToAddGuests' needs to be set to false"
}

test_AllowToAddGuests_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.5v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "",
                "Value" : ""
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowToAddGuests' needs to be set to false"
}

#
# MS.Entra.1.6v1 #This setting may be configured incorrectly
#--
test_EnableGroupCreation_Correct_V1 if {
    PolicyId := "MS.Entra.1.6v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableGroupCreation",
                "Value" : "false"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_EnableGroupCreation_Correct_V2 if {
    PolicyId := "MS.Entra.1.6v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableGroupCreation",
                "Value" : "False"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_EnableGroupCreation_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.6v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableGroupCreation",
                "Value" : "f"
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'EnableGroupCreation' needs to be set to false"
}

test_EnableGroupCreation_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.6v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "",
                "Value" : ""
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'EnableGroupCreation' needs to be set to false"
}

#
# MS.Entra.1.7v1
#--
test_EnableMIPLabels_Correct_V1 if {
    PolicyId := "MS.Entra.1.7v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableMIPLabels",
                "Value" : "True"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_EnableMIPLabels_Correct_V2 if {
    PolicyId := "MS.Entra.1.7v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableMIPLabels",
                "Value" : "true"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_EnableMIPLabels_Incorrect_V1 if {
    PolicyId := "MS.Entra.1.7v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "EnableMIPLabels",
                "Value" : "f"
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'EnableMIPLabels' needs to be set to true"
}

test_EnableMIPLabels_Incorrect_V2 if {
    PolicyId := "MS.Entra.1.7v1"

    Output := tests with input as {
        "group_settings": [
             {
                "Name" : "",
                "Value" : ""
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'EnableMIPLabels' needs to be set to true"
}