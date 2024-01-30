$ProviderPath = "../../../../../PowerShell/BASE/Modules/Providers"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "$($ProviderPath)/ExportEXOProvider.psm1") -Function Get-BASEDmarcRecords -Force

InModuleScope 'ExportEXOProvider' {
    Describe -Tag 'ExportEXOProvider' -Name "Get-BASEDmarcRecords" {
        It "TODO return DMARC records" {
            # Get-BASEDmarcRecords
            $true | Should -Be $true
        }
    }
}
AfterAll {
    Remove-Module ExportEXOProvider -Force -ErrorAction SilentlyContinue
}