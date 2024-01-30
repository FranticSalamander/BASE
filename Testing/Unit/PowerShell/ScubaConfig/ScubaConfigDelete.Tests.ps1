using module '..\..\..\..\PowerShell\BASE\Modules\BASEConfig\BASEConfig.psm1'

InModuleScope BASEConfig {
    Describe -tag "Utils" -name 'BASEConfigDelete' {
        context 'Delete configuration' {
            BeforeEach{
                [BASEConfig]::ResetInstance()
            }
            It 'Valid config file'{
                $BASEConfigTestFile = Join-Path -Path $PSScriptRoot -ChildPath config_test.yaml
                $Result = [BASEConfig]::GetInstance().LoadConfig($BASEConfigTestFile)
                $Result | Should -Be $true
            }
            It '6 Product names'{
                [BASEConfig]::GetInstance().Configuration.ProductNames | Should -HaveCount 6 -Because "$([BASEConfig]::GetInstance().Configuration.ParameterNames)"
            }
            It 'Valid object parameter'{
                [BASEConfig]::GetInstance().Configuration.AnObject.name | Should -Be 'MyObjectName'
            }
            It 'Valid object parameter'{
                [BASEConfig]::GetInstance().Configuration.MissingObject.name | Should -BeNullOrEmpty
            }
            It 'A different valid config file'{
                $BASEConfigTestFile = Join-Path -Path $PSScriptRoot -ChildPath config_test_missing_defaults.json
                $Result = [BASEConfig]::GetInstance().LoadConfig($BASEConfigTestFile)
                $Result | Should -Be $true
            }
            It '1 Product names'{
                [BASEConfig]::GetInstance().Configuration.ProductNames | Should -HaveCount 1
            }
            It 'Valid object parameter'{
                [BASEConfig]::GetInstance().Configuration.AnObject.name | Should -BeNullOrEmpty
            }
            It 'Valid object parameter'{
                [BASEConfig]::GetInstance().Configuration.MissingObject.name | Should -Be 'MyMissingObjectName'
            }
        }
    }
}