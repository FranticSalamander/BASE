package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean



#
# MS.Entra.5.1v2
#--
test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.5.1v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}

#
# MS.Entra.5.2v2
#--
test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.5.2v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}


#
# MS.Entra.5.3v2
#--
test_AllowedToCreateSecurityGroups_Correct if {
    PolicyId := "MS.Entra.5.3v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateSecurityGroups": false
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowedToCreateSecurityGroups_Incorrect_V1 if {
    PolicyId := "MS.Entra.5.3v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateSecurityGroups": true
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create security groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}
test_AllowedToCreateSecurityGroups_Incorrect_V2 if {
    PolicyId := "MS.Entra.5.3v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateSecurityGroups": null
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create security groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}

#
# MS.Entra.5.4v2
#--
test_AllowedToCreateM365Groups_Correct_V1 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "EnableGroupCreation",
                    "Value": "false"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowedToCreateM365Groups_Correct_V1 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "EnableGroupCreation",
                    "Value": "False"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowedToCreateM365Groups_Incorrect_V1 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "EnableGroupCreation",
                    "Value": ""
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}
test_AllowedToCreateM365Groups_Incorrect_V2 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "EnableGroupCreation",
                    "Value": "true"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}
test_AllowedToCreateM365Groups_Incorrect_V3 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "EnableGroupCreation",
                    "Value": "True"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}
test_AllowedToCreateM365Groups_Incorrect_V4 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "AllowGuestsToBeGroupOwner",
                    "Value": "False"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}
test_AllowedToCreateM365Groups_Incorrect_V5 if {
    PolicyId := "MS.Entra.5.4v2"

    Output := tests with input as {
        "group_settings": [
                {
                    "Name": "AllowGuestsToBeGroupOwner",
                    "Value": "false"
                }
              
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"

}