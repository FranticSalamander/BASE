package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.2.1v2
#--
test_DefaultUserRolePermissionsAllowedToCreateApps_Correct if {
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

test_DefaultUserRolePermissionsAllowedToCreateApps_Incorrect_V1 if {
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
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User can register application</b> must be set to <b>No</b>"
}

test_DefaultUserRolePermissionsAllowedToCreateApps_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.1v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateApps": null
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User can register application</b> must be set to <b>No</b>"
}

#
# MS.Entra.2.2v2
#--
test_DefaultUserRolePermissionsAllowedToCreateTenants_Correct if {
    PolicyId := "MS.Entra.2.2v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateTenants": false
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_DefaultUserRolePermissionsAllowedToCreateTenants_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.2v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateTenants": true
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Restrict non-admin users from creating tenants</b> must be set to <b>Yes</b>"
}

test_DefaultUserRolePermissionsAllowedToCreateTenants_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.2v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "DefaultUserRolePermissions": {
                            "AllowedToCreateTenants": null
                },
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Restrict non-admin users from creating tenants</b> must be set to <b>Yes</b>"
}

#
# MS.Entra.2.3v2
#--
test_DefaultUserRolePermissionsAllowedToCreateSecurityGroups_Correct if {
    PolicyId := "MS.Entra.2.3v2"

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

test_DefaultUserRolePermissionsAllowedToCreateSecurityGroups_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.3v2"

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
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create security groups</b> must be set to <b>No</b>"

}
test_DefaultUserRolePermissionsAllowedToCreateSecurityGroups_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.3v2"

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
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Users can create security groups</b> must be set to <b>No</b>"

}

#
# MS.Entra.2.4v2
#--
test_GuestUserRoleId_Correct if {
    PolicyId := "MS.Entra.2.4v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "GuestUserRoleId" : "2af84b1e-32c8-42b7-82bc-daa82404023b" 
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GuestUserRoleId_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.4v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "GuestUserRoleId" : "2af84b1e-2c8-42b7-82bc-daa82404023b" 
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Guest user access restrictions</b> must be set to <b>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</b>"

}
test_GuestUserRoleId_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.4v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "GuestUserRoleId" : null 

            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Guest user access restrictions</b> must be set to <b>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</b>"

}

test_GuestUserRoleId_Incorrect_V3 if {
    PolicyId := "MS.Entra.2.4v2"

    Output := tests with input as {
        "user_settings_default_permissions": [
            {
                "GuestUserRoleId" : "" 

            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Guest user access restrictions</b> must be set to <b>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</b>"

}