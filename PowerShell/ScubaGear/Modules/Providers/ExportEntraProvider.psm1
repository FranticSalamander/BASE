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
    $GroupSettingsTemp = @($Tracker.TryCommand("Get-MgBetaDirectorySetting")) | ? { $_.DisplayName -eq "Group.Unified"} 
    $GroupSettings = ConvertTo-Json $GroupSettingsTemp.Values
    #
   # $GroupSettings = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaGroupSetting"))
    #$NamedLocationsPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-countryNamedLocation"))
    $AuthenticationStrengthPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationStrengthPolicy"))
    $SecurityDefaults = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyIdentitySecurityDefaultEnforcementPolicy"))
    $User = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaUser"))
    $AuthenticationMethodsPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationMethodPolicy"))
    $AuthorisationPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthorizationPolicy"))
    $CrossTenantAccessPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyCrossTenantAccessPolicyDefault"))
   # $AuthenticationMethodsPolicyMicrosoftAuthenticator = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaUserAuthenticationMicrosoftAuthenticatorMethod"))


    $SuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $UnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # Each policy to JSON 
    # Useful for Checking what the commands are spitting out
    $GroupLifecyclePolicy | Out-File -FilePath .\configs-json\entratest\group_lifecycle_policy_config.json
    $GroupSettings | Out-File -FilePath .\configs-json\entratest\group_settings_config.json
    #$GroupSettings | Out-File -FilePath .\configs-json\entratest\group_settings.json
   # $NamedLocationsPolicy | Out-File -FilePath .\configs-json\entratest\named_locations_policy.json
    $AuthenticationStrengthPolicy | Out-File -FilePath .\configs-json\entratest\authentication_strength_policy.json
    $SecurityDefaults | Out-File -FilePath .\configs-json\entratest\security_defaults_policy.json
    $User | Out-File -FilePath .\configs-json\entratest\user.json
    $AuthenticationMethodsPolicy | Out-File -FilePath .\configs-json\entratest\authentication_method_policy.json
    $AuthorisationPolicy | Out-File -FilePath .\configs-json\entratest\authorisation_policy.json
    $CrossTenantAccessPolicy | Out-File -FilePath .\configs-json\entratest\cross_tenant_access_policy.json
   # $AuthenticationMethodsPolicyMicrosoftAuthenticator | Out-File -FilePath .\configs-json\entratest\authentication_method_policy_Microsoft_Authenticator.json

    
    # Note the spacing and the last comma in the json is important
    $json = @"
    "group_lifecycle_policy" : $GroupLifecyclePolicy,
    "group_settings" : $GroupSettings,
    "authentication_strength_policy" : $AuthenticationStrengthPolicy,
    "security_defaults" : $SecurityDefaults,
    "user" : $User,
    "authorisation_policy" : $AuthorisationPolicy,
    "cross_tenant_access_policy" : $CrossTenantAccessPolicy,
    "aad_successful_commands": $SuccessfulCommands,
    "aad_unsuccessful_commands": $UnSuccessfulCommands,
"@

    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")

    $json
}