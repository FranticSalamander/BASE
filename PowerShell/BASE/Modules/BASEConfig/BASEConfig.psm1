class BASEConfig {
    hidden static [BASEConfig]$_Instance = [BASEConfig]::new()
    hidden static [Boolean]$_IsLoaded = $false

    [Boolean]LoadConfig([System.IO.FileInfo]$Path){
        if (-Not (Test-Path -PathType Leaf $Path)){
            throw [System.IO.FileNotFoundException]"Failed to load: $Path"
        }
        elseif ($false -eq [BASEConfig]::_IsLoaded){
            $Content = Get-Content -Raw -Path $Path
            $this.Configuration = $Content | ConvertFrom-Yaml

            $this.SetParameterDefaults()
            [BASEConfig]::_IsLoaded = $true
        }

        return [BASEConfig]::_IsLoaded
    }

    hidden [void]ClearConfiguration(){
        Get-Member -InputObject ($this.Configuration) -Type properties |
          ForEach-Object { $this.Configuration.PSObject.Properties.Remove($_.name)}
    }

    hidden [Guid]$Uuid = [Guid]::NewGuid()
    hidden [Object]$Configuration

    hidden [void]SetParameterDefaults(){
        if (-Not $this.Configuration.ProductNames){
            $this.Configuration.ProductNames = "entra", "teams", "exo", "defender", "aad", "sharepoint", "powerplatform" | Sort-Object
        }
        else{
            $this.Configuration.ProductNames = $this.Configuration.ProductNames | Sort-Object
        }

        if (-Not $this.Configuration.M365Environment){
            $this.Configuration.M365Environment = 'commercial'
        }

        if (-Not $this.Configuration.OPAPath){
            $this.Configuration.OPAPath = (Join-Path -Path $PSScriptRoot -ChildPath "..\..\..")
        }

        if (-Not $this.Configuration.LogIn){
            $this.Configuration.LogIn = $true
        }

        if (-Not $this.Configuration.DisconnectOnExit){
            $this.Configuration.DisconnectOnExit = $false
        }

        if (-Not $this.Configuration.OutPath){
            $this.Configuration.OutPath = '.'
        }

        if (-Not $this.Configuration.OutFolderName){
            $this.Configuration.OutFolderName = "M365BaselineConformance"
        }

        if (-Not $this.Configuration.OutProviderFileName){
            $this.Configuration.OutProviderFileName = "ProviderSettingsExport"
        }

        if (-Not $this.Configuration.OutRegoFileName){
            $this.Configuration.OutFolderName = "TestResults"
        }

        if (-Not $this.Configuration.OutReportName){
            $this.Configuration.OutReportName = "BaselineReports"
        }

        return
    }

    hidden BASEConfig(){
    }

    static [void]ResetInstance(){
        if ([BASEConfig]::_IsLoaded){
            [BASEConfig]::_Instance.ClearConfiguration()
            [BASEConfig]::_IsLoaded = $false
        }

        return
    }

    static [BASEConfig]GetInstance(){
        return [BASEConfig]::_Instance
    }
}
