package powerplatform
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.report.utils.Description
import data.report.utils.ReportDetailsString

ReportDetailsArray(Status, Array, String1) :=  Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsArray(Status, Array, String1) := Detail if {
	Status == false
    String2 := concat(", ", Array)
    Detail := Description(Format(Array), String1, String2)
}

