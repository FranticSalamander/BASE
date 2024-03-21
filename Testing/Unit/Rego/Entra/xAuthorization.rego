package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.5.1v1
#--
test_AllowedToSignUpEmailBasedSubscriptions_Correct if {
    PolicyId := "MS.Entra.5.1v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowedToSignUpEmailBasedSubscriptions" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowedToSignUpEmailBasedSubscriptions_Incorrect if {
    PolicyId := "MS.Entra.5.1v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowedToSignUpEmailBasedSubscriptions" : false
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowedToSignUpEmailBasedSubscriptions' must be set to true"
}


#
# MS.Entra.5.2v1
#--
test_AllowedToUseSSPR_Correct if {
    PolicyId := "MS.Entra.5.2v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowedToUseSspr" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowedToUseSSPR_Incorrect if {
    PolicyId := "MS.Entra.5.2v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowedToUseSspr" : false
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowedToUseSSPR' must be set to true"
}

#
# MS.Entra.5.3v1
#--
test_AllowEmailVerifiedUsersToJoinOrganization_Correct if {
    PolicyId := "MS.Entra.5.3v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowEmailVerifiedUsersToJoinOrganization" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowEmailVerifiedUsersToJoinOrganization_Incorrect if {
    PolicyId := "MS.Entra.5.3v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowEmailVerifiedUsersToJoinOrganization" : false
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowEmailVerifiedUsersToJoinOrganization' must be set to true"
}

# MS.Entra.5.4v1
#--
test_AllowInvitesFrom_Correct if {
    PolicyId := "MS.Entra.5.4v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowInvitesFrom" : "none"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AllowInvitesFrom_Incorrect_V1 if {
    PolicyId := "MS.Entra.5.4v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowInvitesFrom" : ""
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowInvitesFrom' must be set to 'none'"
}

test_AllowInvitesFrom_Incorrect_V2 if {
    PolicyId := "MS.Entra.5.4v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "AllowInvitesFrom" : "no"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'AllowInvitesFrom' must be set to 'none'"
}

#
# MS.Entra.5.5v1
#--
test_BlockMsolPowerShell_Correct if {
    PolicyId := "MS.Entra.5.5v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "BlockMsolPowerShell" : false
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BlockMsolPowerShell_Incorrect if {
    PolicyId := "MS.Entra.5.5v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "BlockMsolPowerShell" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'BlockMsolPowerShell' must be set to false"
}

#
# MS.Entra.5.6v1
#--
test_DefaultUserRoleAllowedToCreateApps_Correct if {
    PolicyId := "MS.Entra.5.6v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "DefaultUserRolePermissions":  {
                                           "AllowedToCreateApps":  false,
                                           "AllowedToCreateSecurityGroups":  false,
                                           "AllowedToCreateTenants":  true,
                                           "AllowedToReadBitlockerKeysForOwnedDevice":  true,
                                           "AllowedToReadOtherUsers":  true
                                       },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_DefaultUserRoleAllowedToCreateApps_Incorrect if {
    PolicyId := "MS.Entra.5.6v1"

    Output := tests with input as {
        "authorisation_policy": [
            {
                "DefaultUserRolePermissions":  {
                                           "AllowedToCreateApps":  true
                }
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 'DefaultUserRolePermissions' must be configured correctly"
}

