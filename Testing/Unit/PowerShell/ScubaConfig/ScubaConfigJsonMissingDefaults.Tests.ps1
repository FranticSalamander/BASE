using module '..\..\..\..\PowerShell\BASE\Modules\BASEConfig\BASEConfig.psm1'

InModuleScope BASEConfig {
    Describe -tag "Utils" -name 'BASEConfigMissingDefaults' {
        Context 'General case'{
            It 'Get Instance without loading'{
               $Config1 = [BASEConfig]::GetInstance()
               $Config1 | Should -Not -BeNull
               $Config2 =  [BASEConfig]::GetInstance()

               $Config1 -eq $Config2 | Should -Be $true
            }
            It 'Load invalid path'{
                {[BASEConfig]::GetInstance().LoadConfig('Bad path name')}| Should -Throw -ExceptionType([System.IO.FileNotFoundException])
            }
        }
        context 'JSON Configuration' {
            BeforeAll {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'BASEConfigTestFile')]
                $BASEConfigTestFile = Join-Path -Path $PSScriptRoot -ChildPath config_test.json
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Result')]
                $Result = [BASEConfig]::GetInstance().LoadConfig($BASEConfigTestFile)
            }
            It 'Load valid config file'{
                $Result | Should -Be $true
            }
            It 'Valid string parameter'{
                [BASEConfig]::GetInstance().Configuration.M365Environment | Should -Be 'commercial'
            }
            It 'Valid array parameter'{
                [BASEConfig]::GetInstance().Configuration.ProductNames | Should -Contain 'aad'
            }
            It 'Valid boolean parameter'{
                [BASEConfig]::GetInstance().Configuration.DisconnectOnExit | Should -Be $false
            }
            It 'Valid object parameter'{
                [BASEConfig]::GetInstance().Configuration.AnObject.name | Should -Be 'MyObjectName'
            }
        }
    }
}