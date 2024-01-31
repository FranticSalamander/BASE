################
# Teams Baseline
################

#--
# Reference: Secure Baseline file, teams.md
#--
# This file implements controls/policies documented in the secure baseline.  The tests.PolicyId
# (e.g., MS.TEAMS.1.1v1) aligns this files to the secure baseline control.
package teams
import future.keywords
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.report.utils.Description

ReportDetailsArray(Status, Array, String1) := Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsArray(Status, Array, String1) := Detail if {
	Status == false
	String2 := concat(", ", Array)
    Detail := Description(Format(Array), String1, String2)
}

AllowUserPinings[Policy.Identity] {
	Policy := input.app_setup_policy[_]
	Policy.AllowUserPining == true
}

tests[{
	"PolicyId" : "MS.TEAMS.0.0v1",
	"Criticality" : "Should",
	"Commandlet" : ["Get-CsTeamsMeetingPolicy"],
	"ActualValue" : Policies,
	"ReportDetails" : ReportDetailsArray(Status, Policies, String),
	"RequirementMet" : Status
}] {
	Policies := AllowUserPinings
	String := "meeting policy(ies) found that allows external control:"
	Status := count(Policies) == 0
}
