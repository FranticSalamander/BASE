$ProviderPath = "../../../../../PowerShell/BASE/Modules/Providers"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "$($ProviderPath)/ExportEXOProvider.psm1") -Function 'Get-BASESpfRecords' -Force

InModuleScope 'ExportEXOProvider' {
    Describe -Tag 'ExportEXOProvider' -Name "Get-BASESpfRecords" {
        It "TODO return SPF records" {
            # Get-BASESpfRecords
            $true | Should -Be $true
        }
    }
}
AfterAll {
    Remove-Module ExportEXOProvider -Force -ErrorAction SilentlyContinue
}