package exo
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.DefenderMirrorDetails
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.report.utils.Description
import data.report.utils.ReportDetailsString

ReportDetailsArray(Status, Array1, Array2) := Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsArray(Status, Array1, Array2) := Detail if {
	Status == false
    Fraction := concat(" of ", [Format(Array1), Format(Array2)])
	String := concat(", ", Array1)
    Detail := Description(Fraction, "agency domain(s) found in violation:", String)
}

# this should be allowed https://github.com/StyraInc/regal/issues/415
# regal ignore:prefer-set-or-object-rule
AllDomains := {Domain.domain | Domain := input.spf_records[_]}

