function Export-TeamsProvider {
    <#
    .Description
    Gets the Teams settings that are relevant
    to the SCuBA Teams baselines using the Teams PowerShell Module
    .Functionality
    Internal
    #>
    [CmdletBinding()]

    $HelperFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "ProviderHelpers"
    Import-Module (Join-Path -Path $HelperFolderPath -ChildPath "CommandTracker.psm1")
    $Tracker = Get-CommandTracker

    $TenantInfo = ConvertTo-Json @($Tracker.TryCommand("Get-CsTenant"))

    #needs to be here to pass test
    $MeetingPolicies = ConvertTo-Json @($Tracker.TryCommand("Get-CsTeamsMeetingPolicy"))
    $FedConfig = ConvertTo-Json @($Tracker.TryCommand("Get-CsTenantFederationConfiguration"))
    $ClientConfig = ConvertTo-Json @($Tracker.TryCommand("Get-CsTeamsClientConfiguration"))
    $AppPolicies = ConvertTo-Json @($Tracker.TryCommand("Get-CsTeamsAppPermissionPolicy"))
    $BroadcastPolicies = ConvertTo-Json @($Tracker.TryCommand("Get-CsTeamsMeetingBroadcastPolicy"))

    $Bonus = ConvertTo-Json @($Tracker.TryCommand("Get-CsTeamsAppSetupPolicy"))
    $Bonus | Out-File -FilePath .\configs-json\teams\teams_app_setup_policies_config.json

   

    #Output Configs in Json

    $MeetingPolicies | Out-File -FilePath .\configs-json\teams\blueprint\teams_meeting_policies_config.json
    $FedConfig | Out-File -FilePath .\configs-json\teams\blueprint\teams_Fed_config.json
    $ClientConfig | Out-File -FilePath .\configs-json\teams\blueprint\teams_client_config.json
    $AppPolicies | Out-File -FilePath .\configs-json\teams\blueprint\teams_app_policies_config.json
    $BroadcastPolicies | Out-File -FilePath .\configs-json\teams\blueprint\teams_Broadcast_policies_config.json


    #Use JSONs as input

    # $MeetingPolicies = Get-Content -Path .\configs-json\teams\teams_meeting_policies_config.json -Raw
    # $FedConfig = Get-Content -Path .\configs-json\teams\teams_Fed_config.json -Raw
    # $ClientConfig = Get-Content -Path .\configs-json\teams\teams_client_config.json -Raw
    # $AppPolicies = Get-Content -Path .\configs-json\teams\teams_app_policies_config.json -Raw
    # $BroadcastPolicies = Get-Content -Path .\configs-json\teams\teams_broadcast_policies_config.json -Raw





    $TeamsSuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $TeamsUnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # Note the spacing and the last comma in the json is important
    $json = @"
    "teams_tenant_info": $TenantInfo,
    "meeting_policies": $MeetingPolicies,
    "federation_configuration": $FedConfig,
    "client_configuration": $ClientConfig,
    "app_policies": $AppPolicies,
    "broadcast_policies": $BroadcastPolicies,
    "teams_successful_commands": $TeamsSuccessfulCommands,
    "teams_unsuccessful_commands": $TeamsUnSuccessfulCommands,
"@

    #$json | Out-File -FilePath .\configs-json\teams_config.json

    #$json = Get-Content -Path .\configs-json\teams_config.json -Raw
    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")

    #Outputs the JSON as a file
    
   # $json = ConvertTo-Json @($json)
    $json
    
}

function Get-TeamsTenantDetail {
    <#
    .Description
    Gets the M365 tenant details using the Teams PowerShell Module
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment
    )
    # Need to explicitly clear or convert these values to strings, otherwise
    # these fields contain values Rego can't parse.
    try {
        $TenantInfo = Get-CsTenant -ErrorAction "Stop"

        $VerifiedDomains = $TenantInfo.VerifiedDomains
        $TenantDomain = "Teams: Domain Unretrievable"
        $TLD = ".com"
        if (($M365Environment -eq "gcchigh") -or ($M365Environment -eq "dod")) {
            $TLD = ".us"
        }
        foreach ($Domain in $VerifiedDomains.GetEnumerator()) {
            $Name = $Domain.Name
            $Status = $Domain.Status
            $DomainChecker = $Name.EndsWith(".onmicrosoft$($TLD)") -and !$Name.EndsWith(".mail.onmicrosoft$($TLD)") -and $Status -eq "Enabled"
            if ($DomainChecker) {
                $TenantDomain = $Name
            }
        }

        $TeamsTenantInfo = @{
            "DisplayName" = $TenantInfo.DisplayName;
            "DomainName" = $TenantDomain;
            "TenantId" = $TenantInfo.TenantId;
            "TeamsAdditionalData" = $TenantInfo;
        }
        $TeamsTenantInfo = ConvertTo-Json @($TeamsTenantInfo) -Depth 4
        
        #created the test json tenant info
        #$TeamsTenantInfo | Out-File -FilePath .\configs-json\teams_tenant_info.json

        #Gets the tenant info from the test json    
        #$TeamsTenantInfo = Get-Content -Path .\configs-json\teams_tenant_info.json -Raw

        $TeamsTenantInfo
    }
    catch {
        Write-Warning "Error retrieving Tenant details using Get-TeamsTenantDetail $($_)"
        $TeamsTenantInfo = @{
            "DisplayName" = "Error retrieving Display name";
            "DomainName" = "Error retrieving Domain name";
            "TenantId" = "Error retrieving Tenant ID";
            "TeamsAdditionalData" = "Error retrieving additional data";
        }
        $TeamsTenantInfo = ConvertTo-Json @($TeamsTenantInfo) -Depth 4
        #$TeamsTenantInfo | Out-File -FilePath .\configs-json\teams_tenant_info.json

        $TeamsTenantInfo
    }
}
