function Export-DefenderProvider {
    <#
    .Description
    Gets the Microsoft 365 Defender settings that are relevant
    to the BASE Microsft 365 Defender baselines using the EXO PowerShell Module
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $ServicePrincipalParams
    )
    $ParentPath = Split-Path $PSScriptRoot -Parent
    $ConnectionFolderPath = Join-Path -Path $ParentPath -ChildPath "Connection"
    Import-Module (Join-Path -Path $ConnectionFolderPath -ChildPath "ConnectHelpers.psm1")

    $HelperFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "ProviderHelpers"
    Import-Module (Join-Path -Path $HelperFolderPath -ChildPath "CommandTracker.psm1")
    $Tracker = Get-CommandTracker

    # Manually importing the module name here to bypass cmdlet name conflicts
    # There are conflicting PowerShell Cmdlet names in EXO and Power Platform
    Import-Module ExchangeOnlineManagement

    # Sign in for the Defender Provider if not connected
    $ExchangeConnected = Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue
    if(-not $ExchangeConnected) {
        try {
            $EXOHelperParams = @{
                M365Environment = $M365Environment;
            }
            if ($ServicePrincipalParams) {
                $EXOHelperParams += @{ServicePrincipalParams = $ServicePrincipalParams}
            }
            Connect-EXOHelper @ServicePrincipalParams;
        }
        catch {
            Write-Error "Error connecting to ExchangeOnline. $($_)"
        }
    }

    # Regular Exchange i.e non IPPSSession cmdlets
    $AdminAuditLogConfig = ConvertTo-Json @($Tracker.TryCommand("Get-AdminAuditLogConfig"))
    $ProtectionPolicyRule = ConvertTo-Json @($Tracker.TryCommand("Get-EOPProtectionPolicyRule"))
    $AntiPhishPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-AntiPhishPolicy"))

    # Test if Defender specific commands are available. If the tenant does
    # not have a defender license (plan 1 or plan 2), the following
    # commandlets will fail with "The term [Cmdlet name] is not recognized
    # as the name of a cmdlet, function, script file, or operable program,"
    # so we can test for this using Get-Command.
    if (Get-Command Get-AtpPolicyForO365 -ErrorAction SilentlyContinue) {
        $ATPPolicy = ConvertTo-Json @($Tracker.TryCommand("Get-AtpPolicyForO365"))
        $ATPProtectionPolicyRule = ConvertTo-Json @($Tracker.TryCommand("Get-ATPProtectionPolicyRule"))
        $DefenderLicense = ConvertTo-Json $true
    }
    else {
        # The tenant can't make use of the defender commands
        Write-Warning "Defender for Office 365 license not available in tenant. Omitting the following commands: Get-AtpPolicyForO365, Get-ATPProtectionPolicyRule."
        $ATPPolicy = ConvertTo-Json @()
        $ATPProtectionPolicyRule = ConvertTo-Json @()
        $DefenderLicense = ConvertTo-Json $false

        # While it is counter-intuitive to add this both to SuccessfulCommands
        # and UnSuccessfulCommands, this is a unique error case that is
        # handled within the Rego.
        $Tracker.AddSuccessfulCommand("Get-AtpPolicyForO365")
        $Tracker.AddUnSuccessfulCommand("Get-AtpPolicyForO365")
        $Tracker.AddSuccessfulCommand("Get-ATPProtectionPolicyRule")
        $Tracker.AddUnSuccessfulCommand("Get-ATPProtectionPolicyRule")
    }

    # Connect to Security & Compliance
    $IPPSConnected = $false
    try {
        $DefenderHelperParams = @{
            M365Environment = $M365Environment;
        }

        if ($ServicePrincipalParams) {
            $DefenderHelperParams += @{ServicePrincipalParams = $ServicePrincipalParams}
        }
        Connect-DefenderHelper @DefenderHelperParams
        $IPPSConnected = $true
    }
    catch {
        Write-Error "Error running Connect-IPPSSession. $($_)"
        Write-Warning "Omitting the following commands: Get-DlpCompliancePolicy, Get-DlpComplianceRule, and Get-ProtectionAlert."
        $Tracker.AddUnSuccessfulCommand("Get-DlpCompliancePolicy")
        $Tracker.AddUnSuccessfulCommand("Get-DlpComplianceRule")
        $Tracker.AddUnSuccessfulCommand("Get-ProtectionAlert")
    }
    if ($IPPSConnected) {
        $DLPCompliancePolicy = ConvertTo-Json @($Tracker.TryCommand("Get-DlpCompliancePolicy"))
        $ProtectionAlert = ConvertTo-Json @($Tracker.TryCommand("Get-ProtectionAlert"))
        $DLPComplianceRules = @($Tracker.TryCommand("Get-DlpComplianceRule"))

        # Powershell is inconsistent with how it saves lists to json.
        # This loop ensures that the format of ContentContainsSensitiveInformation
        # will *always* be a list.

        foreach($Rule in $DLPComplianceRules) {
            if ($Rule.Count -gt 0) {
                $Rule.ContentContainsSensitiveInformation = @($Rule.ContentContainsSensitiveInformation)
            }
        }

        # We need to specify the depth because the data contains some
        # nested tables.
        $DLPComplianceRules = ConvertTo-Json -Depth 3 $DLPComplianceRules
    }
    else {
        $DLPCompliancePolicy = ConvertTo-Json @()
        $DLPComplianceRules = ConvertTo-Json @()
        $ProtectionAlert = ConvertTo-Json @()
        $DLPComplianceRules = ConvertTo-Json @()
    }

    $SuccessfulCommands = ConvertTo-Json @($Tracker.GetSuccessfulCommands())
    $UnSuccessfulCommands = ConvertTo-Json @($Tracker.GetUnSuccessfulCommands())

    # $ProtectionPolicyRule | Out-File -FilePath .\configs-json\defender\protection_policy_rules_config.json
    # $ATPPolicy | Out-File -FilePath .\configs-json\defender\atp_policy_rules_config.json
    # $DLPCompliancePolicy | Out-File -FilePath .\configs-json\defender\dlp_compliance_policies_config.json
    # $DLPComplianceRules | Out-File -FilePath .\configs-json\defender\dlp_compliance_rules_config.json
    # $AntiPhishPolicy | Out-File -FilePath .\configs-json\defender\anti_phish_policies_config.json
    # $ProtectionAlert | Out-File -FilePath .\configs-json\defender\protection_alerts_config.json
    # $AdminAuditLogConfig | Out-File -FilePath .\configs-json\defender\admin_audit_log_config.json
    # $ATPPolicy | Out-File -FilePath .\configs-json\defender\atp_policy_for_o365_config.json
    # $DefenderLicense | Out-File -FilePath .\configs-json\defender\defender_license_config.json


 

    # $ProtectionPolicyRule = Get-Content -Path .\configs-json\defender\protection_policy_rules_config.json -Raw
    # $ATPPolicy  = Get-Content -Path .\configs-json\defender\atp_policy_rules_config.json -Raw
    # $DLPCompliancePolicy = Get-Content -Path .\configs-json\defender\dlp_compliance_policies_config.json -Raw
    # $DLPComplianceRules = Get-Content -Path .\configs-json\defender\dlp_compliance_rules_config.json -Raw
    # $AntiPhishPolicy = Get-Content -Path .\configs-json\defender\anti_phish_policies_config.json -Raw
    # $ProtectionAlert = Get-Content -Path .\configs-json\defender\protection_alerts_config.json -Raw
    # $AdminAuditLogConfig = Get-Content -Path .\configs-json\defender\admin_audit_log_config.json -Raw
    # $ATPPolicy = Get-Content -Path .\configs-json\defender\atp_policy_for_o365_config.json -Raw
    # $DefenderLicense = Get-Content -Path .\configs-json\defender\defender_license_config.json -Raw

    # Note the spacing and the last comma in the json is important
    $json = @"
    "defender_license": $DefenderLicense,
    "defender_successful_commands": $SuccessfulCommands,
    "defender_unsuccessful_commands": $UnSuccessfulCommands,
"@

    # We need to remove the backslash characters from the
    # json, otherwise rego gets mad.
    $json = $json.replace("\`"", "'")
    $json = $json.replace("\", "")
    $json
}
