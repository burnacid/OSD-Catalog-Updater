# OSD Catalog Updater
This script allows you to create your own Catalog Updates for [OSD]([OSD PowerShell Module | OSD](https://osd.osdeploy.com/)) for Windows 10/11 and Windows Server. 

## Requirements
- OSD Powershell module needs to be installed locally
- A WSUS instance with the update metadata for the operating systems you like to create catalogs for
- Script cannot run on PowerShell Core 7. It requires Windows Powershell. (PowerShell Core cannot connect to WSUS)
- Requires to be ran as Administrator
## Syntax
```
.\Invoke-CatalogUpdates.ps1 [-WsusServer <String>] [-WsusPort <String>] [-SaveDirectory <String>] [-GridViewResults] [<CommonParameters>]
```
## Parameters
### -WsusServer

Specifies the address to the WSUS instance. When not set it defaults to the computer's name

```yaml
Type: System.String

Required: False
Position: Named
Default value: $env:computername
Accept pipeline input: False
Accept wildcard characters: False
```
### -WsusPort

Specfies the port on which WSUS is listening

```yaml
Type: System.String

Required: False
Position: Named
Default value: 8530
Accept pipeline input: False
Accept wildcard characters: False
```
### -SaveDirectory

Specifies the path where you like to save the resulting catalog files

```yaml
Type: System.String

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -GridViewResults

Indicates that you manually like to select possible updates via a gridview.

```yaml
Type: System.Management.Automation.SwitchParameter

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```