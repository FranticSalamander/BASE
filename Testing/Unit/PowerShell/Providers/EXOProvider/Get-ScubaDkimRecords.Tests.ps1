$ProviderPath = "../../../../../PowerShell/BASE/Modules/Providers"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "$($ProviderPath)/ExportEXOProvider.psm1") -Function Get-BASEDkimRecords -Force

InModuleScope 'ExportEXOProvider' {
    Describe -Tag 'ExportEXOProvider' -Name "Get-BASEDkimRecords" {
        It "TODO handles a domain with DKIM" {
            # Get-BASEDkimRecords
            $true | Should -Be $true
        }

        It "TODO handles a domain without DKIM" {
            # Get-BASEDkimRecords
            $true | Should -Be $true

        }
    }
}
AfterAll {
    Remove-Module ExportEXOProvider -Force -ErrorAction SilentlyContinue
}