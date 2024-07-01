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
    "Commandlet" : ["Get-MgBetaPolicyExternalIdentityPolicy"],
    "ActualValue" : Policy.AllowExternalIdentitiesToLeave,
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



#--
############
# MS.Entra.4 #
############

#
# MS.Entra.4.1v2
#--


default BreakGlassUser1DisplayNameMatch(_) := false
BreakGlassUser1DisplayNameMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 1"  
   
}

BreakGlassUser1DisplayName[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1DisplayNameMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.1v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1DisplayName,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1DisplayName) == 1
    Details := "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 1</b> --- <b>IF THIS IS NOT CORRECT 4.2, 4.3 & 4.4 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.2v2
#--

default BreakGlassUser1UserTypeMatch(_) := false
BreakGlassUser1UserTypeMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 1" 
    Policy.UserType == "Member"
}

BreakGlassUser1UserType[Policy.UserType] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1UserTypeMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.2v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1UserType,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1UserType) == 1
    Details := "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.3v2
#--

default BreakGlassUser1AccountEnabledMatch(_) := false
BreakGlassUser1AccountEnabledMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 1" 
    Policy.AccountEnabled == true
}

BreakGlassUser1AccountEnabled[Policy.AccountEnabled] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1AccountEnabledMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.3v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1AccountEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1AccountEnabled) == 1
    Details := "Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}

#
# MS.Entra.4.4v2
#--

default BreakGlassUser1UsageLocationMatch(_) := false
BreakGlassUser1UsageLocationMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 1" 
    Policy.UsageLocation == "AU"
}

BreakGlassUser1UsageLocation[Policy.UsageLocation] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser1UsageLocationMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.4v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser1UsageLocation,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser1UsageLocation) == 1
    Details := "Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 1</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.5v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.4.5v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.4.5v2"
    true

}
#--

#
# MS.Entra.4.6v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.4.6v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.4.6v2"
    true

}
#--

#
# MS.Entra.4.7v2
#--


default BreakGlassUser2DisplayNameMatch(_) := false
BreakGlassUser2DisplayNameMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 2"  
   
}

BreakGlassUser2DisplayName[Policy.DisplayName] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2DisplayNameMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.7v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2DisplayName,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2DisplayName) == 1
    Details := "Requirement not met: <b>Display name</b> must be set to <b>BreakGlass 2</b> --- <b>IF THIS IS NOT CORRECT 4.8, 4.9 & 4.10 WILL FAIL</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.8v2
#--

default BreakGlassUser2UserTypeMatch(_) := false
BreakGlassUser2UserTypeMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 2" 
    Policy.UserType == "Member"
}

BreakGlassUser2UserType[Policy.UserType] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2UserTypeMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.8v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2UserType,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2UserType) == 1
    Details := "Requirement not met: <b>User type</b> must be set to <b>Member</b>. \n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.9v2
#--

default BreakGlassUser2AccountEnabledMatch(_) := false
BreakGlassUser2AccountEnabledMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 2" 
    Policy.AccountEnabled == true
}

BreakGlassUser2AccountEnabled[Policy.AccountEnabled] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2AccountEnabledMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.9v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2AccountEnabled,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2AccountEnabled) == 1
    Details := "Requirement not met: <b>Account enabled</b> must be checked.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}

default BreakGlassUser2UsageLocationMatch(_) := false
BreakGlassUser2UsageLocationMatch(Policy) := true if {
    Policy.DisplayName == "BreakGlass 2" 
    Policy.UsageLocation == "AU"
}

BreakGlassUser2UsageLocation[Policy.UsageLocation] {
    Policy := input.user[_]

    # Match all simple conditions
    BreakGlassUser2UsageLocationMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.4.10v2",
    "Criticality" : "Should",
    "Commandlet" : ["Get-MgBetaUser"],
    "ActualValue" : BreakGlassUser2UsageLocation,
    "ReportDetails" : ReportDetailsString(Status, Details),
    "RequirementMet" : Status
}] {
    
    Status := count(BreakGlassUser2UsageLocation) == 1
    Details := "Requirement not met: <b>Usage location</b> must be set to <b>Australia</b>.\n\nThis test can only run correctly if the <b>Display name</b> is set to <b>BreakGlass 2</b>, however, a different <b>Display name</b> is permisable as long as it is not shared with any other user."

}
#--

#
# MS.Entra.4.11v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.4.11v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.4.11v2"
    true

}
#--

#
# MS.Entra.4.12v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.4.12v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.4.12v2"
    true

}
#--


############
# MS.Entra.5 #
############


#
# MS.Entra.5.1v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.5.1v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.5.1v2"
    true

}
#--

#
# MS.Entra.5.2v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.5.2v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.5.2v2"
    true

}
#--

#
# MS.Entra.5.3v2
#--

tests[{
    "PolicyId" : "MS.Entra.5.3v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Policy := input.user_settings_default_permissions[_]
    Status := Policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups == false 
    Detail := "Requirement not met: <b>Users can create security groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"
}
#--

#
# MS.Entra.5.4v2
#--

default UserCanCreateM365GroupsMatch(_) := false
UserCanCreateM365GroupsMatch(Policy) := true if {
    Policy.Name == "EnableGroupCreation"
    Policy.Value == "False" 
}
UserCanCreateM365GroupsMatch(Policy) := true if {
    Policy.Name == "EnableGroupCreation"
    Policy.Value == "false" 
}

UserCanCreateM365Groups[Policy.Name] {
    Policy := input.group_settings[_]

    # Match all simple conditions
    UserCanCreateM365GroupsMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.5.4v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : UserCanCreateM365Groups,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    Status := count(UserCanCreateM365Groups) > 0
    Detail := "Requirement not met: <b>Users can create M365 groups in Azure portals, API or PowerShell</b> must be set to <b>No</b>"
}
#--

#--
############
# MS.Entra.6 #
############

#
# MS.Entra.6.1v2
#--
tests[{
    "PolicyId" : "MS.Entra.6.1v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaGroupLifecyclePolicy"],
    "ActualValue" : Policy.GroupLifetimeInDays,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    

    Policy := input.group_lifecycle_policy[_]
    Status := Policy.GroupLifetimeInDays == 180
    Detail := "Requirement not met: <b>Group lifetime (in days)</b> must be set to <b>180</b>"

    
}
#--


#
# MS.Entra.6.2v2
#--
# At this time we are unable to test for this because it will be different for every setup
tests[{
    "PolicyId" : "MS.Entra.6.2v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.6.2v2"
    true

}
#--

#
# MS.Entra.6.3v2
#--
tests[{
    "PolicyId" : "MS.Entra.6.3v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaGroupLifecyclePolicy"],
    "ActualValue" : Policy.ManagedGroupTypes,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    

    Policy := input.group_lifecycle_policy[_]
    Status := Policy.ManagedGroupTypes == "All"
    Detail := "Requirement not met: <b>Enable expiration for these Microsoft 365 groups</b> must be set to <b>All</b>"

    
}
#--


############
# MS.Entra.7 #
############

#
# MS.Entra.7.1v2
#--
default CustomBlockedWordListMatch(_) := false
CustomBlockedWordListMatch(Policy) := true if {
    Policy.Name == "CustomBlockedWordsList"
    Policy.Value == "" 
}

CustomBlockedWordList[Policy.Name] {
    Policy := input.group_settings[_]
    # Match all simple conditions
    CustomBlockedWordListMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.7.1v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : CustomBlockedWordList,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    

    Status := count(CustomBlockedWordList) > 0
    Detail := "Requirement not met: <b>Block word list</b> must be set to <b>Not Configured</b>"

    
}
#--

#
# MS.Entra.7.2v2
#--
default PrefixSuffixNamingRequirementMatch(_) := false
PrefixSuffixNamingRequirementMatch(Policy) := true if {
    Policy.Name == "PrefixSuffixNamingRequirement"
    Policy.Value == "" 
}

PrefixSuffixNamingRequirement[Policy.Name] {
    Policy := input.group_settings[_]
    # Match all simple conditions
    PrefixSuffixNamingRequirementMatch(Policy)

}

tests[{
    "PolicyId" : "MS.Entra.7.2v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : PrefixSuffixNamingRequirement,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    

    Status := count(PrefixSuffixNamingRequirement) > 0
    Detail := "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"

    
}
#--

#
# MS.Entra.7.3v2
#--

tests[{
    "PolicyId" : "MS.Entra.7.3v2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaDirectorySetting"],
    "ActualValue" : PrefixSuffixNamingRequirement,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    

    Status := count(PrefixSuffixNamingRequirement) > 0
    Detail := "Requirement not met: <b>Add suffix</b> must be set to <b>Not Configured</b>"

    
}
#--

# ############
# # MS.Entra.8 #
# ############
# ##Devices | Device Settings | Microsoft Entra join and registration settings

#--
# THIS PIECE OF CODE IS NOT NEEDED IN THIS CASE AND IS NOW REPLACED BY THE CODE IN 1297
# default multiFactorAuthConfigurationMatch(_) := false
# multiFactorAuthConfigurationMatch(Policy) := true if {
#     Policy.MultiFactorAuthConfiguration == "required"
# }

# userDeviceQuota( ) := true
# userDeviceQuota(Policy) := true if {
#     Policy.Name == "userDeviceQuota"
#     Policy.Value == "2147483647" 

# }

# azureADRegistration( ) := true
# azureADRegistration(Policy) := true if {
#     Policy.Name == "azureADRegistration"
#     Policy.Value == "true" 

# }

# azureADJoin( ) := true
# azureADJoin(Policy) := true if {
#     Policy.Name == "azureADJoin"
#     Policy.Value == "true" 

# }

# localAdminPassword( ) := true
# localAdminPassword(Policy) := true if {
#     Policy.Name == "localAdminPassword"
#     Policy.Value == "true" 

# }


# THIS PIECE OF CODE IS NOT NEEDED IN THIS CASE AND IS NOW REPLACED BY THE CODE IN 1296
# multiFactorAuthConfiguration[Policy.Name] {
#     Policy := input.Device_Registration_Policy[_]
#     #Match all simple conditions
#     multiFactorAuthConfigurationMatch(Policy)
# }

# MS.Entra.8.1v1
tests[{
    "PolicyId" : "MS.Entra.8.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyDeviceRegistrationPolicy"],
    "ActualValue" : Policy.MultiFactorAuthConfiguration,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Device_Registration_Policy[_]
    Status := Policy.MultiFactorAuthConfiguration == "required"
    Detail := "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"

}

# MS.Entra.8.2v1
tests[{
    "PolicyId" : "MS.Entra.8.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyDeviceRegistrationPolicy"],
    "ActualValue" : Policy.UserDeviceQuota,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Device_Registration_Policy[_]
    Status := Policy.UserDeviceQuota == 2147483647
    Detail := "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"
   
}


# MS.Entra.8.3v1
tests[{
    "PolicyId" : "MS.Entra.8.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyDeviceRegistrationPolicy"],
    "ActualValue" : Policy.LocalAdminPassword.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Device_Registration_Policy[_]
    Status := Policy.LocalAdminPassword.IsEnabled == true
    Detail := "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"
   
}


# MS.Entra.8.4v1
tests[{
    "PolicyId" : "MS.Entra.8.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyDeviceRegistrationPolicy"],
    "ActualValue" : Policy.AzureAdRegistration,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Device_Registration_Policy[_]
    Status := Policy.AzureAdRegistration == "true"
    Detail := "Requirement not met: <b>Add prefix</b> must be set to <b>Not Configured</b>"
   
}



#--


############
# MS.Entra.9 #
############
#Devices | Enterprise state roaming

#
# MS.Entra.9.1v2
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.9.1v2",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.9.1v2"
    true

}
#--

############
# MS.Entra.10 #
############
#Applications | Enterprise Applications | Consent and Permissions | Admin consent requests

# MS.Entra.10.1v1
tests[{
    "PolicyId" : "MS.Entra.10.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAdminConsentRequestPolicy"],
    "ActualValue" : Policy.IsEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Admin_Consent_Request_Policy[_]
    Status := Policy.IsEnabled == "false"
    Detail := "Requirement not met: <b>Request admin consent to apps they are unable to consent to.</b> must be set to <b>No</b>"

}

# MS.Entra.10.2v1
tests[{
    "PolicyId" : "MS.Entra.10.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAdminConsentRequestPolicy"],
    "ActualValue" : Policy.NotifyReviewers,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Admin_Consent_Request_Policy[_]
    Status := Policy.NotifyReviewers == "true"
    Detail := "Requirement not met: <b>Receive email notifications for requests.</b> must be set to <b>Yes</b>"
   
}


# MS.Entra.10.3v1
tests[{
    "PolicyId" : "MS.Entra.10.3v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAdminConsentRequestPolicy"],
    "ActualValue" : Policy.RemindersEnabled,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Admin_Consent_Request_Policy[_]
    Status := Policy.RemindersEnabled == "true"
    Detail := "Requirement not met: <bRequest expiration reminders.</b> must be set to <b>Yes</b>"
   
}


# MS.Entra.10.4v1
tests[{
    "PolicyId" : "MS.Entra.10.4v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAdminConsentRequestPolicy"],
    "ActualValue" : Policy.RequestDurationInDays,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.Admin_Consent_Request_Policy[_]
    Status := Policy.RequestDurationInDays == "30"
    Detail := "Requirement not met: <b>Consent request expires after (days).</b> must be set to <b>30 days</b>"
         
}
#--


############
# MS.Entra.11 #
############
#Applications | Enterprise applications | consent and permissions | User consent settings

#
# MS.Entra.11.1v1
#--
tests[{
    "PolicyId" : "MS.Entra.11.1v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.user_settings_default_permissions[_]
    Conditions := [contains(concat(",",Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole), "ManagePermissionGrantsForSelf.microsoft-user-default-low"), contains(concat(",",Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole), "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")]
    Status := count([Condition | Condition = Conditions[_]; Condition == false]) == 2
    Detail := "Requirement not met: <b>Configure whether users are allowed to consent for applications to access your organization's data.</b> must be set to <b>Do not allow user consent</b>"

    
}
#--

# This Setting is now managed from teams instead of Entra so test 11.2v1 may be depreciated
#
# MS.Entra.11.2v1
#--
tests[{
    "PolicyId" : "MS.Entra.11.2v1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-MgBetaPolicyAuthorizationPolicy"],
    "ActualValue" : Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole,
    "ReportDetails" : ReportDetailsString(Status, Detail),
    "RequirementMet" : Status
}] {
    
    Policy := input.user_settings_default_permissions[_]
    Conditions := [contains(concat(",",Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole), "ManagePermissionGrantsForOwnedResource.microsoft-pre-approval-apps-for-group"), contains(concat(",",Policy.PermissionGrantPolicyIdsAssignedToDefaultUserRole), "ManagePermissionGrantsForOwnedResource.microsoft-all-application-permissions-for-group")]
    Status := count([Condition | Condition = Conditions[_]; Condition == false]) == 2
    Detail := "Requirement not met: <b>Configure whether group owners are allowed to consent for applications to access your organization's data for the groups they own</b> must be set to <b>Do not allow group owner consent</b>"

    
}
#--

############
# MS.Entra.12 #
############
#Applications | Enterprise applications | User settings

#
# MS.Entra.12.1v1
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.12.1v1",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.12.1v1"
    true

}
#--

#
# MS.Entra.12.2v1
#--
# At this time we are unable to test for X because of Y
tests[{
    "PolicyId" : "MS.Entra.12.2v1",
    "Criticality" : "Shall/Not-Implemented",
    "Commandlet" : [],
    "ActualValue" : [],
    "ReportDetails" : NotCheckedDetails(PolicyId),
    "RequirementMet" : false
}] {
    
    PolicyId := "MS.Entra.12.2v1"
    true

}
#--