   package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.Format
import data.report.utils.ReportDetailsBoolean
import data.policy.utils.IsEmptyContainer
import data.policy.utils.Contains
import data.policy.utils.Count
import data.report.utils.ReportDetailsString

#############################################################################
# The report formatting functions below are generic and used throughout Entra #
#############################################################################

Description(String1, String2, String3) := trim(concat(" ", [String1, String2, String3]), " ")

ReportDetailsArray(Array, String) := Description(Format(Array), String, "")

# Set to the maximum number of array items to be
# printed in the report details section
ReportArrayMaxCount := 20

ReportFullDetailsArray(Array, String) := Details {
    count(Array) == 0
    Details := ReportDetailsArray(Array, String)
}

ReportFullDetailsArray(Array, String) := Details {
    count(Array) > 0
    count(Array) <= ReportArrayMaxCount
    Details := Description(Format(Array), concat(":<br/>", [String, concat(", ", Array)]), "")
}

ReportFullDetailsArray(Array, String) := Details {
    count(Array) > ReportArrayMaxCount
    List := [ x | x := Array[_] ]

    TruncationWarning := "...<br/>Note: The list of matching items has been truncated.  Full details are available in the JSON results."
    TruncatedList := concat(", ", array.slice(List, 0, ReportArrayMaxCount))
    Details := Description(Format(Array), concat(":<br/>", [String, TruncatedList]), TruncationWarning)
}

CapLink := "<a href='#caps'>View all CA policies</a>."




##############################################################################################################
# The report formatting functions below are for policies that check the required Microsoft Entra ID P2 license #
##############################################################################################################

Aad2P2Licenses[ServicePlan.ServicePlanId] {
    ServicePlan = input.service_plans[_]
    ServicePlan.ServicePlanName == "Entra_PREMIUM_P2"
}

P2WarningString := "**NOTE: Your tenant does not have a Microsoft Entra ID P2 license, which is required for this feature**"

ReportDetailsArrayLicenseWarningCap(Array, String) := Description if {
  count(Aad2P2Licenses) > 0
  Description :=  concat(". ", [ReportFullDetailsArray(Array, String), CapLink])
}

ReportDetailsArrayLicenseWarningCap(_, _) := Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsArrayLicenseWarning(Array, String) := Description if {
  count(Aad2P2Licenses) > 0
  Description :=  ReportFullDetailsArray(Array, String)
}

ReportDetailsArrayLicenseWarning(_, _) := Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsBooleanLicenseWarning(Status) := Description if {
    count(Aad2P2Licenses) > 0
    Status == true
    Description := "Requirement met"
}

ReportDetailsBooleanLicenseWarning(Status) := Description if {
    count(Aad2P2Licenses) > 0
    Status == false
    Description := "Requirement not met"
}

ReportDetailsBooleanLicenseWarning(_) := Description if {
    count(Aad2P2Licenses) == 0
    Description := P2WarningString
}

#################
# EntraID roles #
#################


ApplicationAdministrator := "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
ApplicationDeveloper := "cf1c38e5-3621-4004-a7cb-879624dced7c"
AttackPayloadAuthor := "9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f"
AttackSimulationAdministrator := "c430b396-e693-46cc-96f3-db01bf8bb62a"
AttributeAssignmentAdministrator := "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d"
AttributeAssignmentReader := "ffd52fa5-98dc-465c-991d-fc073eb59f8f"
AttributeDefinitionAdministrator := "8424c6f0-a189-499e-bbd0-26c1753c96d4"
AttributeDefinitionReader := "1d336d2c-4ae8-42ef-9711-b3604ce3fc2c"
AttributeLogAdministrator := "5b784334-f94b-471a-a387-e7219fc49ca2"
AttributeLogReader := "9c99539d-8186-4804-835f-fd51ef9e2dcd"
AuthenticationAdministrator := "c4e39bd9-1100-46d3-8c65-fb160da0071f"
AuthenticationPolicyAdministrator := "0526716b-113d-4c15-b2c8-68e3c22b9f80"
AzureDevOpsAdministrator := "e3973bdf-4987-49ae-837a-ba8e231c7286"
AzureInformationProtectionAdministrator := "7495fdc4-34c4-4d15-a289-98788ce399fd"
B2CIEFKeysetAdministrator := "aaf43236-0c0d-4d5f-883a-6955382ac081"
B2CIEFPolicyAdministrator := "3edaf663-341e-4475-9f94-5c398ef6c070"
BillingAdministrator := "b0f54661-2d74-4c50-afa3-1ec803f12efe"
CloudAppSecurityAdministrator := "892c5842-a9a6-463a-8041-72aa08ca3cf6"
CloudApplicationAdministrator := "158c047a-c907-4556-b7ef-446551a6b5f7"
CloudDeviceAdministrator := "7698a772-787b-4ac8-901f-60d6b08affd2"
ComplianceAdministrator := "17315797-102d-40b4-93e0-432062caca18"
ComplianceDataAdministrator := "e6d1a23a-da11-4be4-9570-befc86d067a7"
ConditionalAccessAdministrator := "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
CustomerLockBoxAccessApprover := "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91"
DesktopAnalyticsAdministrator := "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4"
DirectoryReaders := "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
DirectorySynchronizationAccounts := "d29b2b05-8046-44ba-8758-1e26182fcf32"
DirectoryWriters := "9360feb5-f418-4baa-8175-e2a00bac4301"
DomainNameAdministrator := "8329153b-31d0-4727-b945-745eb3bc5f31"
Dynamics365Administrator := "44367163-eba1-44c3-98af-f5787879f96a"
EdgeAdministrator := "3f1acade-1e04-4fbc-9b69-f0302cd84aef"
ExchangeAdministrator := "29232cdf-9323-42fd-ade2-1d097af3e4de"
ExchangeRecipientAdministrator := "31392ffb-586c-42d1-9346-e59415a2cc4e"
ExternalIDUserFlowAdministrator := "6e591065-9bad-43ed-90f3-e9424366d2f0"
ExternalIDUserFlowAttributeAdministrator := "0f971eea-41eb-4569-a71e-57bb8a3eff1e"
ExternalIdentityProviderAdministrator := "be2f45a1-457d-42af-a067-6ec1fa63bc45"
FabricAdministrator := "a9ea8996-122f-4c74-9520-8edcd192826c"
GlobalAdministrator := "62e90394-69f5-4237-9190-012177145e10"
GlobalReader := "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
GlobalSecureAccessAdministrator := "ac434307-12b9-4fa1-a708-88bf58caabc1"
GroupsAdministrator := "fdd7a751-b60b-444a-984c-02652fe8fa1c"
GuestInviter := "95e79109-95c0-4d8e-aee3-d01accf2d47b"
HelpdeskAdministrator := "729827e3-9c14-49f7-bb1b-9608f156bbb8"
HybridIdentityAdministrator := "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
IdentityGovernanceAdministrator := "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e"
InsightsAdministrator := "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c"
InsightsAnalyst := "25df335f-86eb-4119-b717-0ff02de207e9"
InsightsBusinessLeader := "31e939ad-9672-4796-9c2e-873181342d2d"
IntuneAdministrator := "3a2c62db-5318-420d-8d74-23affee5d9d5"
KaizalaAdministrator := "74ef975b-6605-40af-a5d2-b9539d836353"
KnowledgeAdministrator := "b5a8dcf3-09d5-43a9-a639-8e29ef291470"
KnowledgeManager := "744ec460-397e-42ad-a462-8b3f9747a02c"
LicenseAdministrator := "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
LifecycleWorkflowsAdministrator := "59d46f88-662b-457b-bceb-5c3809e5908f"
MessageCenterPrivacyReader := "ac16e43d-7b2d-40e0-ac05-243ff356ab5b"
MessageCenterReader := "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b"
Microsoft365MigrationAdministrator := "8c8b803f-96e1-4129-9349-20738d9f9652"
MicrosoftEntraJoinedDeviceLocalAdministrator := "9f06204d-73c1-4d4c-880a-6edb90606fd8"
MicrosoftHardwareWarrantyAdministrator := "1501b917-7653-4ff9-a4b5-203eaf33784f"
MicrosoftHardwareWarrantySpecialist := "281fe777-fb20-4fbb-b7a3-ccebce5b0d96"
ModernCommerceAdministrator := "d24aef57-1500-4070-84db-2666f29cf966"
NetworkAdministrator := "d37c8bed-0711-4417-ba38-b4abe66ce4c2"
OfficeAppsAdministrator := "2b745bdf-0803-4d80-aa65-822c4493daac"
OrganizationalMessagesWriter := "507f53e4-4e52-4077-abd3-d2e1558b6ea2"
PartnerTier1Support := "4ba39ca4-527c-499a-b93d-d9b492c50246"
PartnerTier2Support := "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"
PasswordAdministrator := "966707d0-3269-4727-9be2-8c3a10f19b9d"
PermissionsManagementAdministrator := "af78dc32-cf4d-46f9-ba4e-4428526346b5"
PowerPlatformAdministrator := "11648597-926c-4cf3-9c36-bcebb0ba8dcc"
PrinterAdministrator := "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f"
PrinterTechnician := "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477"
PrivilegedAuthenticationAdministrator := "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
PrivilegedRoleAdministrator := "e8611ab8-c189-46e8-94e1-60213ab1f814"
ReportsReader := "4a5d8f65-41da-4de4-8968-e035b65339cf"
SearchAdministrator := "0964bb5e-9bdb-4d7b-ac29-58e794862a40"
SearchEditor := "8835291a-918c-4fd7-a9ce-faa49f0cf7d9"
SecurityAdministrator := "194ae4cb-b126-40b2-bd5b-6091b380977d"
SecurityOperator := "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"
SecurityReader := "5d6b6bb7-de71-4623-b4af-96380a352509"
ServiceSupportAdministrator := "f023fd81-a637-4b56-95fd-791ac0226033"
SharePointAdministrator := "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
SkypeforBusinessAdministrator := "75941009-915a-4869-abe7-691bff18279e"
TeamsAdministrator := "69091246-20e8-4a56-aa4d-066075b2a7a8"
TeamsCommunicationsAdministrator := "baf37b3a-610e-45da-9e62-d9d1e5e8914b"
TeamsCommunicationsSupportEngineer := "f70938a0-fc10-4177-9e90-2178f8765737"
TeamsCommunicationsSupportSpecialist := "fcf91098-03e3-41a9-b5ba-6f0ec8188a12"
TeamsDevicesAdministrator := "3d762c5a-1b6c-493f-843e-55a3b42923d4"
TenantCreator := "112ca1a2-15ad-4102-995e-45b0bc479a6a"
UsageSummaryReportsReader := "75934031-6c7e-415a-99d7-48dbd49e875e"
UserAdministrator := "fe930be7-5e62-47db-91af-98c3a49a38b1"
VirtualVisitsAdministrator := "e300d9e7-4a2b-4295-9eff-f1c78b36cc98"
VivaGoalsAdministrator := "92b086b3-e367-4ef2-b869-1de128fb986e"
VivaPulseAdministrator := "87761b17-1ed2-4af3-9acd-92a150038160"
Windows365Administrator := "11451d60-acb2-45eb-a7d6-43d0f0125c13"
WindowsUpdateDeploymentAdministrator := "32696413-001a-46ae-978c-ce0f6b3620d2"
YammerAdministrator := "810a2642-a034-447f-a5e8-41beaa378541"

#--
############
# MS.Entra.1 #
############

#
# MS.Entra.1.1v2
#--
# At this time we are unable to test for this because it will be different for every organisation
tests[{
    "PolicyId" : "MS.Entra.1.1v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.1v2"
    true

}
#--

#
# MS.Entra.1.2v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.1.2v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.2v2"
    true

}
#--

#
# MS.Entra.1.3v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.1.3v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.3v2"
    true

}
#--

#
# MS.Entra.1.4v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.1.4v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.4v2"
    true

}
#--

#
# MS.Entra.1.5v2
#--
# At this time we are unable to test for this because it will be unique to each tenant
tests[{
    "PolicyId" : "MS.Entra.1.5v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.5v2"
    true

}
#--

#
# MS.Entra.1.6v2
#--
# At this time we are unable to test for this because it will be different for every organisation
tests[{
    "PolicyId" : "MS.Entra.1.6v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.6v2"
    true

}
#--

#
# MS.Entra.1.7v2
#--
# At this time we are unable to test for this because it will be different for every organisation
tests[{
    "PolicyId" : "MS.Entra.1.7v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.7v2"
    true

}
#--

#
# MS.Entra.1.8v2
#--
# At this time we are unable to test for this because it will be different for every organisation
tests[{
    "PolicyId" : "MS.Entra.1.8v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.8v2"
    true

}
#--

#
# MS.Entra.1.9v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.1.9v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.1.9v2"
    true

}
#--



# #--
# ############
# # MS.Entra.1 #
# ############

# #
# # MS.Entra.1.1v1
# #--
# tests[{
#     "PolicyId" : "MS.Entra.1.1v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaGroupLifecyclePolicy"],
#     "ActualValue" : [Policy.ManagedGroupTypes, Policy.GroupLifetimeInDays, Policy.AlternateNotificationEmails],
#     "ReportDetails" : ReportDetailsBoolean(Status   ),
#     "RequirementMet" : Status
# }] {
    

#     Policy := input.group_lifecycle_policy[_]
#     Conditions := [Policy.ManagedGroupTypes == "All", Policy.GroupLifetimeInDays == 180, Policy.AlternateNotificationEmails == "Office365_Group_Expiration@agency.gov.au"]
#     Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    
# }
# #--

# #
# # MS.Entra.1.2v1
# #--
# default CustomBlockedWordsListMatch(_) := false
# CustomBlockedWordsListMatch(Policy) := true if {
#     Policy.Name == "CustomBlockedWordsList"  
#     Policy.Value == "HR,Exec,SOC,Minister"
# }

# CustomBlockedWordsList[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     CustomBlockedWordsListMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.2v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : CustomBlockedWordsList,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(CustomBlockedWordsList) > 0
#     Detail := "Requirement not met: 'CustomBlockedWordsList' needs to be set to 'HR,Exec,SOC,Minister'"
# }
# #--

# #
# # MS.Entra.1.3v1
# #--
# default AllowGuestsToAccessGroupsMatch(_) := false
# AllowGuestsToAccessGroupsMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToAccessGroups"  
#     Policy.Value == "False"
# }
# AllowGuestsToAccessGroupsMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToAccessGroups"  
#     Policy.Value == "false"
# }

# AllowGuestsToAccessGroups[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowGuestsToAccessGroupsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.3v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowGuestsToAccessGroups,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowGuestsToAccessGroups) > 0
#     Detail := "Requirement not met: 'AllowGuestsToAccessGroups' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.4v1
# #--
# default AllowGuestsToBeGroupOwnerMatch(_) := false
# AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToBeGroupOwner"  
#     Policy.Value == "false"
# }
# AllowGuestsToBeGroupOwnerMatch(Policy) := true if {
#     Policy.Name == "AllowGuestsToBeGroupOwner"  
#     Policy.Value == "False"
# }

# AllowGuestsToBeGroupOwner[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowGuestsToBeGroupOwnerMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.4v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowGuestsToBeGroupOwner,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowGuestsToBeGroupOwner) > 0
#     Detail := "Requirement not met: 'AllowGuestsToBeGroupOwner' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.5v1
# #--
# default AllowToAddGuestsMatch(_) := false
# AllowToAddGuestsMatch(Policy) := true if {
#     Policy.Name == "AllowToAddGuests"  
#     Policy.Value == "false"
# }
# AllowToAddGuestsMatch(Policy) := true if {
#     Policy.Name == "AllowToAddGuests"  
#     Policy.Value == "False"
# }

# AllowToAddGuests[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     AllowToAddGuestsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.5v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : AllowToAddGuests,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(AllowToAddGuests) > 0
#     Detail := "Requirement not met: 'AllowToAddGuests' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.6v1
# #--
# default EnableGroupCreationMatch(_) := false
# EnableGroupCreationMatch(Policy) := true if {
#     Policy.Name == "EnableGroupCreation"  
#     Policy.Value == "false"
# }
# EnableGroupCreationMatch(Policy) := true if {
#     Policy.Name == "EnableGroupCreation"  
#     Policy.Value == "False"
# }

# EnableGroupCreation[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     EnableGroupCreationMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.6v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : EnableGroupCreation,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(EnableGroupCreation) > 0
#     Detail := "Requirement not met: 'EnableGroupCreation' needs to be set to false"
# }
# #--

# #
# # MS.Entra.1.7v1
# #--
# default EnableMIPLabelsMatch(_) := false
# EnableMIPLabelsMatch(Policy) := true if {
#     Policy.Name == "EnableMIPLabels"  
#     Policy.Value == "true"
# }
# EnableMIPLabelsMatch(Policy) := true if {
#     Policy.Name == "EnableMIPLabels"  
#     Policy.Value == "True"
# }

# EnableMIPLabels[Policy.Name] {
#     Policy := input.group_settings[_]

#     # Match all simple conditions
#     EnableMIPLabelsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.1.7v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaDirectorySetting"],
#     "ActualValue" : EnableMIPLabels,
#     "ReportDetails" : ReportDetailsString(Status, Detail),
#     "RequirementMet" : Status
# }] {
#     Status := count(EnableMIPLabels) > 0
#     Detail := "Requirement not met: 'EnableMIPLabels' needs to be set to true"
# }
# #--



#--
############
# MS.Entra.2 #
############

#
# MS.Entra.2.1v2
#--


tests[{
    "PolicyId" : "MS.Entra.2.1v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.DefaultUserRolePermissions.AllowedToCreateApps,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.DefaultUserRolePermissions.AllowedToCreateApps == false 
    Detail := "Requirement not met: <b>User can register application</b> must be set to <b>No</b>"
}
#--

#
# MS.Entra.2.2v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.2v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.DefaultUserRolePermissions.AllowedToCreateTenants,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.DefaultUserRolePermissions.AllowedToCreateTenants == false 
    Detail := "Requirement not met: <b>Restrict non-admin users from creating tenants</b> must be set to <b>Yes</b>"
}
#--

#
# MS.Entra.2.3v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.3v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups == false 
    Detail := "Requirement not met: <b>Users can create security groups</b> must be set to <b>No</b>"
}
#--

#
# MS.Entra.2.4v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.4v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.GuestUserRoleId,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.GuestUserRoleId == "2af84b1e-32c8-42b7-82bc-daa82404023b" 
    Detail := "Requirement not met: <b>Guest user access restrictions</b> must be set to <b>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</b>"
}
#--

#
# MS.Entra.2.5v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.5v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.5v2"
    true

}
#--

#
# MS.Entra.2.6v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.6v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.6v2"
    true

}
#--

#
# MS.Entra.2.7v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.7v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.7v2"
    true

}
#--

#
# MS.Entra.2.8v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.8v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.GuestUserRoleId,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.GuestUserRoleId == "2af84b1e-32c8-42b7-82bc-daa82404023b" 
    Detail := "Requirement not met: <b>Guest user access restrictions</b> must be set to <b>Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)</b>"
}
#--

#
# MS.Entra.2.9v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.9v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowInvitesFrom,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.AllowInvitesFrom == "none"
    Detail := "Requirement not met: <b>Guest invite restrictions</b> must be set to <b>No one in the organization can invite guest users including admins (most restrictive)</b>"
}
#--

#
# MS.Entra.2.10v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.10v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthenticationFlowPolicy"],
    "ActualValue" : Policy.SelfServiceSignUp.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.authentication_flow_policy[_]
    Status := Policy.SelfServiceSignUp.IsEnabled == false
    Detail := "Requirement not met: <b>Enable guest self-service sign up via user flows</b> must be set to <b>No</b>"
}
#--

#
# MS.Entra.2.11v2
#--

tests[{
    "PolicyId" : "MS.Entra.2.11v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.SelfServiceSignUp.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.external_identity_policy[_]
    Status := Policy.AllowExternalIdentitiesToLeave == true
    Detail := "Requirement not met: <b>Allow external users to remove themselves from your organization (recommended)</b> must be set to <b>Yes</b>"
}
#--

#
# MS.Entra.2.12v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.12v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.12v2"
    true

}
#--

#
# MS.Entra.2.13v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.13v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.13v2"
    true

}
#--

#
# MS.Entra.2.14v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.2.14v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.2.14v2"
    true

}
#--

# #--
# ############
# # MS.Entra.2 #
# ############


# #
# # MS.Entra.2.1v1 #This test layout works when there are multiple settings using the same name
# #--
# default MultifactorAuthenticationConditionsMatch(_) := false
# MultifactorAuthenticationConditionsMatch(Policy) := true if {
#     Policy.DisplayName =="Multifactor authentication"
#     Policy.Description == "Combinations of methods that satisfy strong authentication, such as a password + SMS"
#     Policy.AllowedCombinations == [
#                                      "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor",
#                                     "deviceBasedPush",
#                                     "temporaryAccessPassOneTime",
#                                     "temporaryAccessPassMultiUse",
#                                     "password,microsoftAuthenticatorPush",
#                                     "password,softwareOath",
#                                     "password,hardwareOath",
#                                     "password,sms",
#                                     "password,voice",
#                                     "federatedMultiFactor",
#                                     "microsoftAuthenticatorPush,federatedSingleFactor",
#                                     "softwareOath,federatedSingleFactor",
#                                     "hardwareOath,federatedSingleFactor",
#                                     "sms,federatedSingleFactor",
#                                     "voice,federatedSingleFactor"                               
#                                 ]
# }

# MultifactorAuthentication[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     MultifactorAuthenticationConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.1v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : MultifactorAuthentication,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(MultifactorAuthentication) > 0
# }


# #
# # MS.Entra.2.2v1 
# #--
# default PasswordlessMFAConditionsMatch(_) := false
# PasswordlessMFAConditionsMatch(Policy) := true if {
#     Policy.DisplayName == "Passwordless MFA"
#     Policy.Description == "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator"
#     Policy.AllowedCombinations == [
#                                     "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor",
#                                     "deviceBasedPush"                               
#                                 ]
# }

# PasswordlessMFA[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     PasswordlessMFAConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.2v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : PasswordlessMFA,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(PasswordlessMFA) > 0
# }
# #--


# #
# # MS.Entra.2.3v1
# #--
# default PhishingResistantMFAConditionsMatch(_) := false
# PhishingResistantMFAConditionsMatch(Policy) := true if {
#     Policy.DisplayName == "Phishing-resistant MFA"
#     Policy.Description == "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key"
#     Policy.AllowedCombinations == [
#                                     "windowsHelloForBusiness",
#                                     "fido2",
#                                     "x509CertificateMultiFactor"                          
#                                 ]
# }

# PhishingResistantMFA[Policy.DisplayName] {
#     Policy := input.authentication_strength_policy[_]

#     # Match all simple conditions
#     PhishingResistantMFAConditionsMatch(Policy)
# }

# tests[{
#     "PolicyId" : "MS.Entra.2.3v1",
#     "Criticality" : "Shall",
#     "Commandlet" : ["Get-MgBetaPolicyAuthenticationStrengthPolicy"],
#     "ActualValue" : PhishingResistantMFA,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := count(PhishingResistantMFA) > 0
# }
# #--

#--
############
# MS.Entra.3 #
############

#
# MS.Entra.3.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.3.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyIdentitySecurityDefaultEnforcementPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.security_defaults[_]
    Status := Policy.IsEnabled == false
    Detail := "Requirement not met: Security Defaults must be disabled"
}
#--

#--
############
# MS.Entra.4 #
############

#
# MS.Entra.4.1v1
#--


default BreakGlassUser1Match(_) := false
BreakGlassUser1Match(Policy) := true if {
    Policy.DisplayName == "Break Glass"  
    Policy.PasswordPolicies == null
    Policy.UsageLocation == "AU"
    Policy.UserType == "Member"
    startswith(Policy.UserPrincipalName, "break.glass_priv1")
   
}

BreakGlassUser1[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1Match(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1) == 1
    Details := "Requirement not met: Break Glass User Account 1 is not configured correctly"
    
}
#--

#
# MS.Entra.4.2v1
#--


default BreakGlassUser2Match(_) := false
BreakGlassUser2Match(Policy) := true if {
    Policy.DisplayName == "Break Glass"  
    Policy.PasswordPolicies == null
    Policy.UsageLocation == "AU"
    Policy.UserType == "Member"
    startswith(Policy.UserPrincipalName, "break.glass_priv2")
   
}

BreakGlassUser2[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2Match(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2) == 1
    Details := "Requirement not met: Break Glass User Account 2 is not configured correctly"
    
}
#--

############
# MS.Entra.5 #
############


#
# MS.Entra.5.1v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowedToSignUpEmailBasedSubscriptions,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowedToSignUpEmailBasedSubscriptions == true
    Details := "Requirement not met: 'AllowedToSignUpEmailBasedSubscriptions' must be set to true"
    
}
#--

#
# MS.Entra.5.2v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowedToUseSspr,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowedToUseSspr == true
    Details := "Requirement not met: 'AllowedToUseSSPR' must be set to true"
    
}
#--

#
# MS.Entra.5.3v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowEmailVerifiedUsersToJoinOrganization,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowEmailVerifiedUsersToJoinOrganization == true
    Details := "Requirement not met: 'AllowEmailVerifiedUsersToJoinOrganization' must be set to true"
    
}
#--

#
# MS.Entra.5.4v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.AllowInvitesFrom,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.AllowInvitesFrom == "none"
    Details := "Requirement not met: 'AllowInvitesFrom' must be set to 'none'"
    
}
#--

#
# MS.Entra.5.5v1
#--

tests[{
    "PolicyId" : "MS.Entra.5.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.BlockMsolPowerShell,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Policy := input.authorisation_policy[_]
    Status := Policy.BlockMsolPowerShell == false
    Details := "Requirement not met: 'BlockMsolPowerShell' must be set to false"
    
}
#--

#
# MS.Entra.5.6v1
#--


default DefaultUserRolePermissionsMatch(_) := false
DefaultUserRolePermissionsMatch(Policy) := true if {
    Policy.DefaultUserRolePermissions == {
                                           "AllowedToCreateApps":  false,
                                           "AllowedToCreateSecurityGroups":  false,
                                           "AllowedToCreateTenants":  true,
                                           "AllowedToReadBitlockerKeysForOwnedDevice":  true,
                                           "AllowedToReadOtherUsers":  true
                                         }
}

DefaultUserRolePermissions[Policy.DefaultUserRolePermissions] {
    Policy := input.authorisation_policy[_]

    

    # Match all simple conditions
    DefaultUserRolePermissionsMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.5.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : DefaultUserRolePermissions,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(DefaultUserRolePermissions) > 0
    Details := "Requirement not met: 'DefaultUserRolePermissions' must be configured correctly"
    
}
#--

############
# MS.Entra.6 #
############

#
# MS.Entra.6.1v1
#--


default InboundTrustMatch(_) := false
InboundTrustMatch(Policy) := true if {
    Policy.InboundTrust ==  {
                             "IsCompliantDeviceAccepted":  false,
                             "IsHybridAzureAdJoinedDeviceAccepted":  false,
                             "IsMfaAccepted":  false
                            }
}

InboundTrust[Policy.InboundTrust] {
    Policy := input.cross_tenant_access_policy[_]

    

    # Match all simple conditions
    InboundTrustMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.6.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyCrossTenantAccessPolicyDefault"],
    "ActualValue" : InboundTrust,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(InboundTrust) > 0
    Details := "Requirement not met: 'IsCompliantDeviceAccepted', 'IsHybridAzureAdJoinedDeviceAccepted' and 'IsMfaAccepted' must be set to false"
    
}
#--

############
# MS.Entra.7 #
############

#
# MS.Entra.7.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : [Policy.IsEnabled, Policy.Type, Policy.Value],
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.SignInFrequency
    Conditions := [Policy.IsEnabled == true, Policy.Type == "hours", Policy.Value == 4]
    Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    Incorrect := 3 - count([Condition | Condition = Conditions[_]; Condition == true]) 
    Details := concat(format_int(Incorrect, 10), ["Requirement not met: ", " AdminSignInFrequency - SignInFrequency policies configured incorrectly"])
    
}
#--

#
# MS.Entra.7.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: AdminSignInFrequency - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.7.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.7.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.7.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions
    Status := Policy.ClientAppTypes == ["browser", "mobileAppsAndDesktopClients", "other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.7.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.7.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 

}
#--

#
# MS.Entra.7.10v1
#--

default AdminSigninIncludeRolesMatch(_) := false
AdminSigninIncludeRolesMatch(Policy) := true if {
    ContainsApplicationAdministrator := contains(Policy.IncludeRoles, ApplicationAdministrator)
    ContainsApplicationDeveloper := contains(Policy.IncludeRoles, ApplicationDeveloper)
    ContainsAttackPayloadAuthor := contains(Policy.IncludeRoles, AttackPayloadAuthor)
    ContainsAttackSimulationAdministrator := contains(Policy.IncludeRoles, AttackSimulationAdministrator)
    ContainsAttributeDefinitionAdministrator := contains(Policy.IncludeRoles, AttributeDefinitionAdministrator)
    ContainsAttributeAssignmentReader := contains(Policy.IncludeRoles, AttributeAssignmentReader)
    ContainsAttributeAssignmentAdministrator := contains(Policy.IncludeRoles, AttributeAssignmentAdministrator)
    ContainsReportsReader := contains(Policy.IncludeRoles, ReportsReader)
    ContainsOrganizationalMessagesWriter := contains(Policy.IncludeRoles, OrganizationalMessagesWriter)
    ContainsSharePointAdministrator := contains(Policy.IncludeRoles, SharePointAdministrator)
    ContainsYammerAdministrator := contains(Policy.IncludeRoles, YammerAdministrator)
    ContainsWindowsUpdateDeploymentAdministrator := contains(Policy.IncludeRoles, WindowsUpdateDeploymentAdministrator)
    ContainsWindows365Administrator := contains(Policy.IncludeRoles, Windows365Administrator)
    ContainsVivaGoalsAdministrator := contains(Policy.IncludeRoles, VivaGoalsAdministrator)
    ContainsVirtualVisitsAdministrator := contains(Policy.IncludeRoles, VirtualVisitsAdministrator)
    ContainsUserAdministrator := contains(Policy.IncludeRoles, UserAdministrator)
    ContainsUsageSummaryReportsReader := contains(Policy.IncludeRoles, UsageSummaryReportsReader)
    ContainsTenantCreator := contains(Policy.IncludeRoles, TenantCreator)
    ContainsTeamsDevicesAdministrator := contains(Policy.IncludeRoles, TeamsDevicesAdministrator)
    ContainsTeamsCommunicationsSupportSpecialist := contains(Policy.IncludeRoles, TeamsCommunicationsSupportSpecialist)
    ContainsTeamsCommunicationsSupportEngineer := contains(Policy.IncludeRoles, TeamsCommunicationsSupportEngineer)
    ContainsTeamsCommunicationsAdministrator := contains(Policy.IncludeRoles, TeamsCommunicationsAdministrator)
    ContainsTeamsAdministrator := contains(Policy.IncludeRoles, TeamsAdministrator)
    ContainsSkypeforBusinessAdministrator := contains(Policy.IncludeRoles, SkypeforBusinessAdministrator)
    ContainsServiceSupportAdministrator := contains(Policy.IncludeRoles, ServiceSupportAdministrator)
    ContainsSecurityReader := contains(Policy.IncludeRoles, SecurityReader)
    ContainsSecurityAdministrator := contains(Policy.IncludeRoles, SecurityAdministrator)
    ContainsSecurityOperator := contains(Policy.IncludeRoles, SecurityOperator)
    ContainsSearchEditor := contains(Policy.IncludeRoles, SearchEditor)
    ContainsSearchAdministrator := contains(Policy.IncludeRoles, SearchAdministrator)
    ContainsPrivilegedRoleAdministrator := contains(Policy.IncludeRoles, PrivilegedRoleAdministrator)
    ContainsPrivilegedAuthenticationAdministrator := contains(Policy.IncludeRoles, PrivilegedAuthenticationAdministrator)
    ContainsPrinterTechnician := contains(Policy.IncludeRoles, PrinterTechnician)
    ContainsPrinterAdministrator := contains(Policy.IncludeRoles, PrinterAdministrator)
    ContainsPowerPlatformAdministrator := contains(Policy.IncludeRoles, PowerPlatformAdministrator)
    ContainsFabricAdministrator := contains(Policy.IncludeRoles, FabricAdministrator)
    ContainsPermissionsManagementAdministrator := contains(Policy.IncludeRoles, PermissionsManagementAdministrator)
    ContainsPasswordAdministrator := contains(Policy.IncludeRoles, PasswordAdministrator)
    ContainsOfficeAppsAdministrator := contains(Policy.IncludeRoles, OfficeAppsAdministrator)
    ContainsNetworkAdministrator := contains(Policy.IncludeRoles, NetworkAdministrator)
    ContainsMicrosoftHardwareWarrantySpecialist := contains(Policy.IncludeRoles, MicrosoftHardwareWarrantySpecialist)
    ContainsMicrosoftHardwareWarrantyAdministrator := contains(Policy.IncludeRoles, MicrosoftHardwareWarrantyAdministrator)
    ContainsMessageCenterReader := contains(Policy.IncludeRoles, MessageCenterReader)
    ContainsMessageCenterPrivacyReader := contains(Policy.IncludeRoles, MessageCenterPrivacyReader)
    ContainsLifecycleWorkflowsAdministrator := contains(Policy.IncludeRoles, LifecycleWorkflowsAdministrator)
    ContainsLicenseAdministrator := contains(Policy.IncludeRoles, LicenseAdministrator)
    ContainsKnowledgeManager := contains(Policy.IncludeRoles, KnowledgeManager)
    ContainsKnowledgeAdministrator := contains(Policy.IncludeRoles, KnowledgeAdministrator)
    ContainsKaizalaAdministrator := contains(Policy.IncludeRoles, KaizalaAdministrator)
    ContainsIntuneAdministrator := contains(Policy.IncludeRoles, IntuneAdministrator)
    ContainsInsightsBusinessLeader := contains(Policy.IncludeRoles, InsightsBusinessLeader)
    ContainsInsightsAnalyst := contains(Policy.IncludeRoles, InsightsAnalyst)
    ContainsInsightsAdministrator := contains(Policy.IncludeRoles, InsightsAdministrator)
    ContainsIdentityGovernanceAdministrator := contains(Policy.IncludeRoles, IdentityGovernanceAdministrator)
    ContainsHybridIdentityAdministrator := contains(Policy.IncludeRoles, HybridIdentityAdministrator)
    ContainsHelpdeskAdministrator := contains(Policy.IncludeRoles, HelpdeskAdministrator)
    ContainsGuestInviter := contains(Policy.IncludeRoles, GuestInviter)
    ContainsGroupsAdministrator := contains(Policy.IncludeRoles, GroupsAdministrator)
    ContainsGlobalReader := contains(Policy.IncludeRoles, GlobalReader)
    ContainsGlobalAdministrator := contains(Policy.IncludeRoles, GlobalAdministrator)
    ContainsExternalIdentityProviderAdministrator := contains(Policy.IncludeRoles, ExternalIdentityProviderAdministrator)
    ContainsExternalIDUserFlowAttributeAdministrator := contains(Policy.IncludeRoles, ExternalIDUserFlowAttributeAdministrator)
    ContainsExternalIDUserFlowAdministrator := contains(Policy.IncludeRoles, ExternalIDUserFlowAdministrator)
    ContainsExchangeRecipientAdministrator := contains(Policy.IncludeRoles, ExchangeRecipientAdministrator)
    ContainsExchangeAdministrator := contains(Policy.IncludeRoles, ExchangeAdministrator)
    ContainsEdgeAdministrator := contains(Policy.IncludeRoles, EdgeAdministrator)
    ContainsDynamics365Administrator := contains(Policy.IncludeRoles, Dynamics365Administrator)
    ContainsDomainNameAdministrator := contains(Policy.IncludeRoles, DomainNameAdministrator)
    ContainsDirectoryWriters := contains(Policy.IncludeRoles, DirectoryWriters)
    ContainsDirectorySynchronizationAccounts := contains(Policy.IncludeRoles, DirectorySynchronizationAccounts)
    ContainsDirectoryReaders := contains(Policy.IncludeRoles, DirectoryReaders)
    ContainsDesktopAnalyticsAdministrator := contains(Policy.IncludeRoles, DesktopAnalyticsAdministrator)
    ContainsCustomerLockBoxAccessApprover := contains(Policy.IncludeRoles, CustomerLockBoxAccessApprover)
    ContainsConditionalAccessAdministrator := contains(Policy.IncludeRoles, ConditionalAccessAdministrator)
    ContainsComplianceDataAdministrator := contains(Policy.IncludeRoles, ComplianceDataAdministrator)
    ContainsComplianceAdministrator := contains(Policy.IncludeRoles, ComplianceAdministrator)
    ContainsCloudDeviceAdministrator := contains(Policy.IncludeRoles, CloudDeviceAdministrator)
    ContainsCloudApplicationAdministrator := contains(Policy.IncludeRoles, CloudApplicationAdministrator)
    ContainsCloudAppSecurityAdministrator := contains(Policy.IncludeRoles, CloudAppSecurityAdministrator)
    ContainsBillingAdministrator := contains(Policy.IncludeRoles, BillingAdministrator)
    ContainsB2CIEFPolicyAdministrator := contains(Policy.IncludeRoles, B2CIEFPolicyAdministrator)
    ContainsAzureInformationProtectionAdministrator := contains(Policy.IncludeRoles, AzureInformationProtectionAdministrator)
    ContainsB2CIEFKeysetAdministrator := contains(Policy.IncludeRoles, B2CIEFKeysetAdministrator)
    ContainsAzureDevOpsAdministrator := contains(Policy.IncludeRoles, AzureDevOpsAdministrator)
    ContainsAuthenticationPolicyAdministrator := contains(Policy.IncludeRoles, AuthenticationPolicyAdministrator)
    ContainsAuthenticationAdministrator := contains(Policy.IncludeRoles, AuthenticationAdministrator)
    ContainsAttributeDefinitionReader := contains(Policy.IncludeRoles, AttributeDefinitionReader)
}
AdminSigninIncludeRoles[Policy.IncludeRoles] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency.Conditions.Users

    

    # Match all simple conditions
    AdminSigninIncludeRolesMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.7.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : AdminSigninIncludeRoles,
    "ReportDetails" : ReportDetailsString(Status, Details), 
    "RequirementMet" : Status
}] {
    Status := count(AdminSigninIncludeRoles) > 0

    Details := "Requirement not met: IncludeRoles must be configured correctly" 

}
#--

#
# MS.Entra.7.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.7.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_admin_sign_in_frequency
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}

# ############
# # MS.Entra.8 #
# ############

#
# MS.Entra.8.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: CountriesNotAllowed - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.8.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CountriesNotAllowed - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.8.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.8.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.8.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions
    Status := Policy.ClientAppTypes == "all"
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.8.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.8.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeLocations,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Locations
    Status := Policy.IncludeLocations == "All"
    Details := "Requirement not met: IncludeLocations must be set to 'All'" 

}
#--

#
# MS.Entra.8.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}
#--


#
# MS.Entra.8.11v1
#--
tests[{
    "PolicyId" : "MS.Entra.8.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}

#
# MS.Entra.8.12v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.12v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 

}
#--

#
# MS.Entra.8.13v1
#--


tests[{
    "PolicyId" : "MS.Entra.8.13v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeLocations,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_countries_not_allowed.Conditions.Locations
    Status := Policy.ExcludeLocations == "1ea33f82-a850-412b-937b-e3cdea4b9dd7"
    Details := "Requirement not met: ExcludeLocations must be set to 'Allowed Countries'/'1ea33f82-a850-412b-937b-e3cdea4b9dd7'" 

}
#--
    

# ############
# # MS.Entra.9 #
# ############

#
# MS.Entra.9.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessBlock - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.9.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessBlock - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.9.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.9.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.9.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","browser","mobileAppsAndDesktopClients","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.9.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.9.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.9.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block.Conditions.Applications
    Status := Policy.ExcludeApplications == "Office365"
    Details := "Requirement not met: ExcludeApplications must be set to 'Office365'" 

}
#--

#
# MS.Entra.9.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.9.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_block
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabled'" 
}

############
# MS.Entra.10 #
############

#
# MS.Entra.10.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.10.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.10.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.10.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.10.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.10.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions.Applications
    Status := Policy.IncludeApplications == "Office365"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.10.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.10.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludePlatforms,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant.Conditions.Platforms
    Status := Policy.IncludePlatforms == "windows"
    Details := "Requirement not met: IncludePlatforms must be set to 'windows'" 

}
#--

#
# MS.Entra.10.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.10.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_guest_access_grant
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 
}


############
# MS.Entra.11 #
############
#
# MS.Entra.11.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.11.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.11.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.11.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.11.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","browser","mobileAppsAndDesktopClients", "other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.11.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.11.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_high_risk_sign_ins_grant.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups must be configured correctly" 

}
#--

############
# MS.Entra.12 #
############

#
# MS.Entra.12.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.12.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.12.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.12.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.GrantControls
    Status := Policy.BuiltInControls == ["block"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'block'" 
    
}
#--

#
# MS.Entra.12.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions
    Status := Policy.ClientAppTypes == ["exchangeActiveSync","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.12.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.12.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}
#--

#
# MS.Entra.12.9v1
#--

tests[{
    "PolicyId" : "MS.Entra.12.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}
#--

#
# MS.Entra.12.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.12.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_legacy_auth_block
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}


############
# MS.Entra.13 #
############

#
# MS.Entra.13.1v1 
#--


tests[{
    "PolicyId" : "MS.Entra.13.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: GuestAccessGrant - SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.13.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: GuestAccessGrant - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.13.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.13.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.13.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions
    Status := Policy.ClientAppTypes == "all"
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.13.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions.Applications
    Status := Policy.IncludeApplications == "None"
    Details := "Requirement not met: IncludeApplications must be set to 'None'" 

}

#
# MS.Entra.13.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.13.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeRoles,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access.Conditions.Users
    Status := Policy.ExcludeRoles == GlobalAdministrator
    Details := "Requirement not met: ExcludeRoles must be set to Global Administrator" 

}
#
# MS.Entra.13.10v1
#--

tests[{
    "PolicyId" : "MS.Entra.13.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_mfa_guest_b2b_access
    Status := Policy.State == "enabled"
    Details := "Requirement not met: State must be set to 'enabled'" 
}



############
# MS.Entra.14 #
############

#
# MS.Entra.14.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details :="Requirement not met: ExcludeGroups must be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'"
    
}
#--

#
# MS.Entra.14.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.14.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.14.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.BuiltInControls,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.GrantControls
    Status := Policy.BuiltInControls == ["mfa"]
    Details := "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'" 
    
}
#--

#
# MS.Entra.14.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients","other"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.14.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.14.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeUsers must be set to 'All'" 

}

#
# MS.Entra.14.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : [Policy.IsEnabled, Policy.Type, Policy.Value],
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency.SessionControls.SignInFrequency
    Conditions := [Policy.IsEnabled == true, Policy.Type == "hours", Policy.Value == 12]
    Status := count([Condition | Condition = Conditions[_]; Condition == true]) == 3
    Incorrect := 3 - count([Condition | Condition = Conditions[_]; Condition == true]) 
    Details := concat(format_int(Incorrect, 10), ["Requirement not met: ", " SessionSignInFrequency - SignInFrequency policies configured incorrectly"])
    
}

#
# MS.Entra.14.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.14.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_session_sign_in_frequency
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}

############
# MS.Entra.15 #
############

#
# MS.Entra.15.1v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.SignInFrequency
    Status := Policy.IsEnabled == true
    Details :="Requirement not met: SignInFrequency 'IsEnabled' must be set to false"
    
}
#--

#
# MS.Entra.15.2v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.ApplicationEnforcedRestrictions
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.3v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.CloudAppSecurity
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.4v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.SessionControls.PersistentBrowser
    Status := Policy.IsEnabled == false
    Details := "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
    
}
#--

#
# MS.Entra.15.5v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.5v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.Operator,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.GrantControls
    Status := Policy.Operator == "OR"
    Details := "Requirement not met: GrantControls Operator must be 'OR'" 
    
}
#--

#
# MS.Entra.15.6v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.6v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ExcludeGroups,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Users
    Status := Policy.ExcludeGroups == "a2b89a91-d113-4d94-9d17-08875130ecc1"
    Details := "Requirement not met: ExcludeGroups needs to be set to 'grp-Conditional_Access_Exclude'/'a2b89a91-d113-4d94-9d17-08875130ecc1'" 
    
}
#--

#
# MS.Entra.15.7v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.7v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.ClientAppTypes,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions
    Status := Policy.ClientAppTypes == ["browser","mobileAppsAndDesktopClients"]
    Details := "Requirement not met: ClientAppTypes must be configured correctly" 

}
#--

#
# MS.Entra.15.8v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.8v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeApplications,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Applications
    Status := Policy.IncludeApplications == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.15.9v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.9v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.IncludeUsers,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.Conditions.Users
    Status := Policy.IncludeUsers == "All"
    Details := "Requirement not met: IncludeApplications must be set to 'All'" 

}

#
# MS.Entra.15.10v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.10v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.TermsOfUse,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant.GrantControls
    Status := Policy.TermsOfUse == ["00361d63-8e1d-4f43-ad68-513fcddfdd20"]
    Details := "Requirement not met: TermsOfUse must be set to 'Acceptable Use Policy'/'00361d63-8e1d-4f43-ad68-513fcddfdd20'" 
}

#
# MS.Entra.15.11v1
#--


tests[{
    "PolicyId" : "MS.Entra.15.11v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaIdentityConditionalAccessPolicy"],
    "ActualValue" : Policy.State,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    Policy := input.conditional_access_policy_terms_of_use_grant
    Status := Policy.State == "enabledForReportingButNotEnforced"
    Details := "Requirement not met: State must be set to 'enabledForReportingButNotEnforced'" 

    
}