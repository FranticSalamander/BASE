function Export-EntraProvider {
    <#
    .Description
    Gets the Entra Id (Entra) settings that are relevant
    to the BASE Entra baselines using a subset of the modules under the
    overall Microsoft Graph PowerShell Module
    .Functionality
    Internal
    #>

    Import-Module $PSScriptRoot/ProviderHelpers/CommandTracker.psm1
    $Tracker = Get-CommandTracker

   

    # The below cmdlet covers the following baselines
    # - 1.1
    #Could possibly check some for not NULL 
     #$Properties = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaOrganization"))
     #$Properties | Out-File -FilePath .\configs-json\test.json

    $GroupLifecyclePolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaGroupLifecyclePolicy"))
    $GroupSettingsTemp = @($Tracker.TryCommand("Get-MgBetaDirectorySetting")) | ? { $_.DisplayName -eq "Group.Unified"} 
    $GroupSettings = ConvertTo-Json $GroupSettingsTemp.Values
    #
   # $GroupSettings = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaGroupSetting"))
    #$NamedLocationsPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-countryNamedLocation"))
    $AuthenticationStrengthPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationStrengthPolicy"))
    $SecurityDefaults = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyIdentitySecurityDefaultEnforcementPolicy"))
    $User = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaUser"))
   # $AuthenticationMethodsPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationMethodPolicy"))
    $AuthorisationPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyAuthorizationPolicy"))
    $CrossTenantAccessPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaPolicyCrossTenantAccessPolicyDefault"))

    $AuthenticationMethodsPolicyTEMP = @($Tracker.TryCommand("Get-MgBetaPolicyAuthenticationMethodPolicy"))  | ? { $_.Id -eq "authenticationMethodsPolicy"}
    $AuthenticationMethodsPolicy = ConvertTo-Json $AuthenticationMethodsPolicyTEMP

    $ConditiontalAccessPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy"))
    $ConditiontalAccessPolicyAdminSignInFrequencyTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "f14f88d7-2665-4ce6-b89b-125b11588383"}
    $ConditiontalAccessPolicyAdminSignInFrequency = ConvertTo-Json $ConditiontalAccessPolicyAdminSignInFrequencyTEMP
    $ConditiontalAccessPolicyCountriesNotAllowedTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "1e07844e-825d-4e30-824a-3cb0f34cdd2a"}
    $ConditiontalAccessPolicyCountriesNotAllowed = ConvertTo-Json $ConditiontalAccessPolicyCountriesNotAllowedTEMP
    $ConditiontalAccessPolicyGuestAccessBlockTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "efd4b3c6-e78d-49ad-ac6a-ca0436576317"}
    $ConditiontalAccessPolicyGuestAccessBlock = ConvertTo-Json $ConditiontalAccessPolicyGuestAccessBlockTEMP
    $ConditiontalAccessPolicyGuestAccessGrantTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "d015040f-99fd-4e7c-abc1-35f5e5a9c728"}
    $ConditiontalAccessPolicyGuestAccessGrant = ConvertTo-Json $ConditiontalAccessPolicyGuestAccessGrantTEMP
    $ConditiontalAccessPolicyHighRiskSignInsGrantTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "4f73b5d4-020e-4631-af22-d6ddd914d1bc"}
    $ConditiontalAccessPolicyHighRiskSignInsGrant = ConvertTo-Json $ConditiontalAccessPolicyHighRiskSignInsGrantTEMP
    $ConditiontalAccessPolicyLegacyAuthBlockTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "03cd82f7-61dc-4b79-ba6f-825733e38286"}
    $ConditiontalAccessPolicyLegacyAuthBlock = ConvertTo-Json $ConditiontalAccessPolicyLegacyAuthBlockTEMP
    $ConditiontalAccessPolicyMFAGuestB2BAccessTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "91d98558-e2ce-4a20-bd95-c08f22fc6d22"}
    $ConditiontalAccessPolicyMFAGuestB2BAccess = ConvertTo-Json $ConditiontalAccessPolicyMFAGuestB2BAccessTEMP
    $ConditiontalAccessPolicySessionSignInFrequencyTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "07d16e09-b8f2-46e9-9b90-71d85ce589b3"}
    $ConditiontalAccessPolicySessionSignInFrequency = ConvertTo-Json $ConditiontalAccessPolicySessionSignInFrequencyTEMP
    $ConditiontalAccessPolicyTermsOfUseGrantTEMP =  @($Tracker.TryCommand("Get-MgBetaIdentityConditionalAccessPolicy")) | ? { $_.Id -eq "485b13ff-9f66-4954-b74e-da7b8f2e243e"}
    $ConditiontalAccessPolicyTermsOfUseGrant = ConvertTo-Json $ConditiontalAccessPolicyTermsOfUseGrantTEMP
    $SuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $UnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # Each policy to JSON 
    # Useful for Checking what the commands are spitting out
#     $GroupLifecyclePolicy | Out-File -FilePath .\configs-json\entratest\group_lifecycle_policy_config.json
#     $GroupSettings | Out-File -FilePath .\configs-json\entratest\group_settings_config.json
#     #$GroupSettings | Out-File -FilePath .\configs-json\entratest\group_settings.json
#    # $NamedLocationsPolicy | Out-File -FilePath .\configs-json\entratest\named_locations_policy.json
#     $AuthenticationStrengthPolicy | Out-File -FilePath .\configs-json\entratest\authentication_strength_policy.json
#     $SecurityDefaults | Out-File -FilePath .\configs-json\entratest\security_defaults_policy.json
#     $User | Out-File -FilePath .\configs-json\entratest\user.json
#     $AuthenticationMethodsPolicy | Out-File -FilePath .\configs-json\entratest\authentication_method_policy.json
#     $AuthorisationPolicy | Out-File -FilePath .\configs-json\entratest\authorisation_policy.json
#     $CrossTenantAccessPolicy | Out-File -FilePath .\configs-json\entratest\cross_tenant_access_policy.json
#     $ConditiontalAccessPolicy | Out-File -FilePath .\configs-json\entratest\conditional_access_policy.json
#     $ConditiontalAccessPolicyAdminSignInFrequency | Out-File -FilePath .\configs-json\entratest\conditional_access_policy_admin_sign_in_frequency.json
#     $ConditiontalAccessPolicyCountriesNotAllowed | Out-File -FilePath .\configs-json\entratest\conditional_access_policy_countries_not_allowed.json


    #$AuthenticationMethodsPolicyMicrosoftAuthenticator | Out-File -FilePath .\configs-json\entratest\authentication_method_policy_Microsoft_Authenticator.json

    
    # Note the spacing and the last comma in the json is important
    $json = @"
    "group_lifecycle_policy" : $GroupLifecyclePolicy,
    "group_settings" : $GroupSettings,
    "authentication_strength_policy" : $AuthenticationStrengthPolicy,
    "security_defaults" : $SecurityDefaults,
    "user" : $User,
    "authorisation_policy" : $AuthorisationPolicy,
    "cross_tenant_access_policy" : $CrossTenantAccessPolicy,
    "conditional_access_policy_admin_sign_in_frequency" : $ConditiontalAccessPolicyAdminSignInFrequency,
    "conditional_access_policy_countries_not_allowed" : $ConditiontalAccessPolicyCountriesNotAllowed,
    "conditional_access_policy_guest_access_block" : $ConditiontalAccessPolicyGuestAccessBlock,
    "conditional_access_policy_guest_access_grant" : $ConditiontalAccessPolicyGuestAccessGrant,
    "conditional_access_policy_high_risk_sign_ins_grant" : $ConditiontalAccessPolicyHighRiskSignInsGrant,
    "conditional_access_policy_legacy_auth_block" : $ConditiontalAccessPolicyLegacyAuthBlock,
    "conditional_access_policy_mfa_guest_b2b_access" : $ConditiontalAccessPolicyMFAGuestB2BAccess,
    "conditional_access_policy_session_sign_in_frequency" : $ConditiontalAccessPolicySessionSignInFrequency,
    "conditional_access_policy_terms_of_use_grant" : $ConditiontalAccessPolicyTermsOfUseGrant,
    "aad_successful_commands": $SuccessfulCommands,
    "aad_unsuccessful_commands": $UnSuccessfulCommands,
"@

    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")

    $json
}

