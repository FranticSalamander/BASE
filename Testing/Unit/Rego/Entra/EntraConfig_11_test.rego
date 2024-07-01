package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.11.1v1
#--
test_UserApplicationConsentSettings_Correct if {
    PolicyId := "MS.Entra.11.1v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_UserApplicationConsentSettings_Incorrect_V1 if {
    PolicyId := "MS.Entra.11.1v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForSelf.microsoft-user-default-low",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether users are allowed to consent for applications to access your organization's data.</b> must be set to <b>Do not allow user consent</b>"
}

test_UserApplicationConsentSettings_Incorrect_V2 if {
    PolicyId := "MS.Entra.11.1v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether users are allowed to consent for applications to access your organization's data.</b> must be set to <b>Do not allow user consent</b>"
}

test_UserApplicationConsentSettings_Incorrect_V3 if {
    PolicyId := "MS.Entra.11.1v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForSelf.microsoft-user-default-low",
                "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",                
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether users are allowed to consent for applications to access your organization's data.</b> must be set to <b>Do not allow user consent</b>"
}

#
# MS.Entra.11.2v1
#--
test_GroupApplicationConsentPermision_Correct if {
    PolicyId := "MS.Entra.11.2v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GroupApplicationConsentPermision_Incorrect_V1 if {
    PolicyId := "MS.Entra.11.2v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForOwnedResource.microsoft-pre-approval-apps-for-group",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether group owners are allowed to consent for applications to access your organization's data for the groups they own</b> must be set to <b>Do not allow group owner consent</b>"
}

test_GroupApplicationConsentPermision_Incorrect_V2 if {
    PolicyId := "MS.Entra.11.2v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForOwnedResource.microsoft-all-application-permissions-for-group",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether group owners are allowed to consent for applications to access your organization's data for the groups they own</b> must be set to <b>Do not allow group owner consent</b>"
}

test_GroupApplicationConsentPermision_Incorrect_V3 if {
    PolicyId := "MS.Entra.11.2v1"

    Output := tests with input as {
        "user_settings_default_permissions" : [
            {
                "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [
                "ManagePermissionGrantsForOwnedResource.microsoft-pre-approval-apps-for-group",
                "ManagePermissionGrantsForOwnedResource.microsoft-all-application-permissions-for-group",                
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat",
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
                ]
            }
        ]
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Configure whether group owners are allowed to consent for applications to access your organization's data for the groups they own</b> must be set to <b>Do not allow group owner consent</b>"
}