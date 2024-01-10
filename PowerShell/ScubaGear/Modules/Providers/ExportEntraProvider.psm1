function Export-EntraProvider {
    <#
    .Description
    Gets the Entra Id (Entra) settings that are relevant
    to the SCuBA Entra baselines using a subset of the modules under the
    overall Microsoft Graph PowerShell Module
    .Functionality
    Internal
    #>

    Import-Module $PSScriptRoot/ProviderHelpers/CommandTracker.psm1
    $Tracker = Get-CommandTracker

    # The below cmdlet covers the following baselines
    # - 1.1

    $GroupLifecyclePolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaGroupLifecyclePolicy"))
    #$RoleSettingPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPrivilegedAccessResourceRoleSetting"))

    $SuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $UnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # Each policy to JSON
    $GroupLifecyclePolicy | Out-File -FilePath .\configs-json\entratest\group_lifecycle_policy_config.json
    #$RoleSettingPolicy | Out-File -FilePath .\configs-json\entratest\role_setting_policy_config.json

    # Note the spacing and the last comma in the json is important
    $json = @"
    "group_lifecycle_policies" : $GroupLifecyclePolicy,
    "aad_successful_commands": $SuccessfulCommands,
    "aad_unsuccessful_commands": $UnSuccessfulCommands,
"@

    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")

    $json
}