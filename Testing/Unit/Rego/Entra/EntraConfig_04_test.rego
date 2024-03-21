package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.4.1v2
#--
test_BreakGlassUser1DisplayName_Correct if {
    PolicyId := "MS.Entra.4.1v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 1",
                
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}





test_BreakGlassUser1DisplayName_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.1v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 1</b> --- <b>IF THIS IS NOT CORRECT 4.2, 4.3 & 4.4 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser1DisplayName_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.1v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 1</b> --- <b>IF THIS IS NOT CORRECT 4.2, 4.3 & 4.4 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}


#
# MS.Entra.4.2v2
#--
test_BreakGlassUser1UserType_Correct if {
    PolicyId := "MS.Entra.4.2v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 1",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser1UserType_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.2v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UserType" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser1UserType_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.2v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.3v2
#--
test_BreakGlassUser1AccountEnabled_Correct if {
    PolicyId := "MS.Entra.4.3v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 1",
                "AccountEnabled" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser1AccountEnabled_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.3v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "AccountEnabled" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails =="Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser1AccountEnabled_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.3v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "AccountEnabled" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.4v2
#--
test_BreakGlassUser1UsageLocation_Correct if {
    PolicyId := "MS.Entra.4.4v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 1",
                "UsageLocation" : "AU"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser1UsageLocation_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.4v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UsageLocation" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails =="Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser1UsageLocation_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.4v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UsageLocation" : "AU"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.7v2
#--


test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.4.5v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}

#
# MS.Entra.4.6v2
#--


test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.4.6v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}


#
# MS.Entra.4.7v2
#--
test_BreakGlassUser2DisplayName_Correct if {
    PolicyId := "MS.Entra.4.7v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 2",
                
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}





test_BreakGlassUser2DisplayName_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.7v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 2</b> --- <b>IF THIS IS NOT CORRECT 4.8, 4.9 & 4.10 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser2DisplayName_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.7v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 2</b> --- <b>IF THIS IS NOT CORRECT 4.8, 4.9 & 4.10 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}


#
# MS.Entra.4.8v2
#--
test_BreakGlassUser2UserType_Correct if {
    PolicyId := "MS.Entra.4.8v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 2",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser2UserType_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.8v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UserType" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser2UserType_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.8v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UserType" : "Member"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.9v2
#--
test_BreakGlassUser2AccountEnabled_Correct if {
    PolicyId := "MS.Entra.4.9v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 2",
                "AccountEnabled" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_BreakGlassUser2AccountEnabled_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.9v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "AccountEnabled" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails =="Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser2AccountEnabled_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.9v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "AccountEnabled" : true
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.10v2
#--
test_BreakGlassUser2UsageLocation_Correct if {
    PolicyId := "MS.Entra.4.10v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "BreakGlass 2",
                "UsageLocation" : "AU"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}


test_BreakGlassUser2UsageLocation_Incorrect_V1 if {
    PolicyId := "MS.Entra.4.10v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UsageLocation" : null
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails =="Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

test_BreakGlassUser2UsageLocation_Incorrect_V2 if {
    PolicyId := "MS.Entra.4.10v2"

    Output := tests with input as {
        "user": [
            {
                "DisplayName" : "Break Glass",
                "UsageLocation" : "AU"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."
}

#
# MS.Entra.4.11v2
#--


test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.4.11v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}

#
# MS.Entra.4.12v2
#--


test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.4.12v2"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}