package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.12.1v1"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}

test_NotImplemented_Correct if {
    PolicyId := "MS.Entra.12.2v1"

    Output := tests with input as { }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == NotCheckedDetails(PolicyId)
}
