Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "../../../../PowerShell/BASE/Modules/Connection/Connection.psm1") -Function 'Disconnect-BASETenant' -Force

InModuleScope Connection {
    Describe -Tag 'Connection' -Name 'Disconnect-BASETenant' {
        BeforeAll {
            Mock Disconnect-MgGraph -MockWith {}
            Mock Disconnect-ExchangeOnline -MockWith {}
            Mock Disconnect-SPOService -MockWith {}
            Mock Disconnect-PnPOnline -MockWith {}
            Mock Remove-PowerAppsAccount -MockWith {}
            Mock Disconnect-MicrosoftTeams -MockWith {}
            Mock -CommandName Write-Progress {}
        }
        It 'Disconnects from Microsoft Graph' {
            Disconnect-BASETenant -ProductNames 'aad'
            Should -Invoke -CommandName Disconnect-MgGraph -Times 1 -Exactly
        }
        It 'Disconnects from Exchange Online' {
            Disconnect-BASETenant -ProductNames 'exo'
            Should -Invoke -CommandName Disconnect-ExchangeOnline -Times 1 -Exactly
        }
        It 'Disconnects from Defender (Exchange Online and Security & Compliance)' {
            {Disconnect-BASETenant -ProductNames 'defender'} | Should -Not -Throw
        }
        It 'Disconnects from Power Platform' {
            {Disconnect-BASETenant -ProductNames 'powerplatform'} | Should -Not -Throw
        }
        It 'Disconnects from SharePoint Online' {
            {Disconnect-BASETenant -ProductNames 'sharepoint'} | Should -Not -Throw
        }
        It 'Disconnects from Microsoft Teams' {
            {Disconnect-BASETenant -ProductNames 'sharepoint'} | Should -Not -Throw
        }
        It 'Disconnects from all products' {
            {Disconnect-BASETenant} | Should -Not -Throw
        }
    }
}

AfterAll {
    Remove-Module Connection -ErrorAction SilentlyContinue
}