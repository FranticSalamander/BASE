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
    $GroupNamingTemp = @($Tracker.TryCommand("Get-MgBetaDirectorySetting")) | ? { $_.DisplayName -eq "Group.Unified"} 
    $GroupNamingPolicy = ConvertTo-Json $GroupNamingTemp.Values
   # $GroupSettings = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaGroupSetting"))
    $NamedLocationsPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessNamedLocation"))
    $AuthenticationStrengthPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationStrengthPolicy"))



    $SuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $UnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # Each policy to JSON 
    # Useful for Checking what the commands are spitting out
    $GroupLifecyclePolicy | Out-File -FilePath .\configs-json\entratest\group_lifecycle_policy_config.json
    $GroupNamingPolicy | Out-File -FilePath .\configs-json\entratest\group_naming_policy_config.json
    #$GroupSettings | Out-File -FilePath .\configs-json\entratest\group_settings.json
    $NamedLocationsPolicy | Out-File -FilePath .\configs-json\entratest\named_locations_policy.json
    $AuthenticationStrengthPolicy | Out-File -FilePath .\configs-json\entratest\authentication_strength_policy.json



    # Note the spacing and the last comma in the json is important
    $json = @"
    "group_lifecycle_policy" : $GroupLifecyclePolicy,
    "group_naming_policy" : $GroupNamingPolicy,
    "named_locations_policy" : $NamedLocationsPolicy,
    "authentication_strength_policy" : $AuthenticationStrengthPolicy,
    "aad_successful_commands": $SuccessfulCommands,
    "aad_unsuccessful_commands": $UnSuccessfulCommands,
"@

    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")

    $json
}