#Requires -RunAsAdministrator

function New-OSDCatalog {
    [CmdletBinding(DefaultParameterSetName = 'WSUS')]
    PARAM (
        #===================================================================================================
        #   Both Tabs
        #===================================================================================================
        [string]$WsusServer = $env:COMPUTERNAME,
        [string]$CatalogName,

        [ValidateSet('Internet', 'WSUS')]
        [string]$DownloadUri,
        [switch]$GridViewGetUpdates,
        [switch]$GridViewResults,
        [string]$SaveDirectory,
        [string]$WsusPort = '8530'
    )

    $Settings = Get-Content "$PSScriptRoot/settings.json" | ConvertFrom-Json

    # Load WSUS Assembly
    try {
        [Reflection.Assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration") | Out-Null
    }
    catch {
        Throw  "Unable to load WSUS assembly, do you have the WSUS Admin console installed?"
    }

    # Connect to WSUS instance
    try {
        Write-Verbose "Connecting to $($WsusServer) Port: $($WsusPort)" -Verbose
        $Wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer, $False, $WsusPort)  
    }
    catch {
        Throw ("Unable to connect to Server: {0} on port {1}" -f $WsusServer, $WsusPort)
    }

    foreach ($UpdateCategory in $Settings.Catalogs) {
        $CatalogName = $UpdateCategory
        Write-Verbose "OSDCatalog Name: $CatalogName" -Verbose

        # Get Update Catalogs
        $UpdateCategories = $null
        $UpdateCategories = $Wsus.GetUpdateCategories() | Where-Object { $_.Title -in $UpdateCategory }
        if ($null -eq $UpdateCategories) {
            Write-Warning "WSUS Update Category: Not Found . . . Exiting!"
            Return
        }

        # Set search scope
        $UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
        $UpdateScope.ApprovedStates = 'Any'
        $UpdateScope.UpdateTypes = 'All'
        $UpdateScope.TextIncludes = "$UpdateTextIncludes"
        $UpdateScope.TextNotIncludes = "$UpdateTextNotIncludes"
        if ($UpdateCategories) {
            $UpdateScope.Categories.AddRange($UpdateCategories)
        }
        $UpdateScope.IncludedInstallationStates = 'All'
        $UpdateScope.ExcludedInstallationStates = '0'

        # Get all updates in search scope
        $GetUpdates = $Wsus.GetUpdates($UpdateScope)

        # Filter Updates
        $GetUpdates = $GetUpdates | Where-Object { $_.IsDeclined -eq $false }
        $GetUpdates = $GetUpdates | Where-Object { $_.IsLatestRevision -eq $true }
        $GetUpdates = $GetUpdates | Where-Object { $_.IsSuperseded -eq $false }
        $GetUpdates = $GetUpdates | Where-Object { $_.LegacyName -notlike "*ARM64*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.LegacyName -notlike "*Partner*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.LegacyName -notlike "*PreRTM*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.LegacyName -notlike "*farm-deployment*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.Title -notlike "*ARM64*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.Title -notlike "*Beta*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.Title -notlike "*Insider Preview*" }
        $GetUpdates = $GetUpdates | Where-Object { $_.Title -notlike "*Preview of*" }

        # Feature Updates
        $GetUpdates = $GetUpdates | Where-Object { $_.UpdateClassificationTitle -ne 'Upgrades' }

        # Windows Malicious Software Removal Tool
        $GetUpdates = $GetUpdates | Where-Object { $_.KnowledgeBaseArticles -ne '890830' }

        $AllUpdates = @()

        foreach ($CategoryItem in $GetUpdates) {
            Write-Host "$($CategoryItem.KnowledgeBaseArticles) $($CategoryItem.CreationDate) $($CategoryItem.Title)" -ForegroundColor Gray

            $UpdateFile = @()
            $UpdateFile = Get-WsusUpdateFile -UpdateName $($CategoryItem.Title) | Select-Object -Property *

            # Filter files
            $UpdateFile = $UpdateFile | Where-Object { $_.Type -ne 'Express' }
            $UpdateFile = $UpdateFile | Where-Object { $_.Name -notlike "*ARM64*" }
            $UpdateFile = $UpdateFile | Where-Object { $_.Name -notlike "*.exe" }
            $UpdateFile = $UpdateFile | Where-Object { $_.Name -notlike "*.txt" }
            $UpdateFile = $UpdateFile | Where-Object { $_.Name -notlike "*.psf" }
            $UpdateFile = $UpdateFile | Where-Object { $_.Name -notlike "*.wim" }

            foreach ($Update in $UpdateFile) {
                $FileUri = $Update.OriginUri
                $OriginUri = $Update.OriginUri

                # Transform Catalog
                $UpdateOS = ''
                if ($Update.Title -like "*Windows 10*") {
                    $VersionInfo = Get-WindowsBuildFromUpdateTitle -Title $Update.Title
                    $UpdateOS = $VersionInfo.Windows
                    $CatalogName = "$($VersionInfo.Windows) $($VersionInfo.Build)"
                }elseif ($Update.Title -like "*Windows 11*") {
                    $VersionInfo = Get-WindowsBuildFromUpdateTitle -Title $Update.Title
                    $UpdateOS = $VersionInfo.Windows
                    $CatalogName = "$($VersionInfo.Windows) $($VersionInfo.Build)"
                }
                elseif ($CatalogName -like "Windows Server 2016*") { $UpdateOS = 'Windows Server' }
                elseif ($CatalogName -like "Windows Server 2019*") { $UpdateOS = 'Windows Server' }
                elseif ($CatalogName -like "Microsoft Server Operating System-*")
                { 
                    $CatalogName = $CatalogName -ireplace "Microsoft Server Operating System-", "Windows Server " 
                    $UpdateOS = 'Windows Server'
                }elseif( $catalogName -like "Windows Server*"){
                    $UpdateOS = 'Windows Server'
                }

                # Transform Update Arch
                $UpdateArch = ''
                if ($Update.Title -like "*32-Bit*") { $UpdateArch = 'x86' }
                elseif ($Update.Title -like "*64-Bit*") { $UpdateArch = 'x64' }
                elseif ($CategoryItem.LegacyName -like "*x86*") { $UpdateArch = 'x86' }
                elseif ($CategoryItem.LegacyName -like "*x64*") { $UpdateArch = 'x64' }
                elseif ($CategoryItem.LegacyName -like "*amd64*") { $UpdateArch = 'x64' }
                elseif ($Update.FileName -like "*x86*") { $UpdateArch = 'x86' }
                elseif ($Update.FileName -like "*x64*") { $UpdateArch = 'x64' }
                elseif ($Update.Title -like "*x86*") { $UpdateArch = 'x86' }
                elseif ($Update.Title -like "*x64*") { $UpdateArch = 'x64' }

                # Transform Update Build
                $UpdateBuild = ''
                if ($Update.Title -like "*Windows Server 2016*") { $UpdateBuild = '1607' }
                if ($Update.Title -like "*Windows Server 2019*") { $UpdateBuild = '1809' }
                if ($Update.Title -like "*Windows Server 2022*") { $UpdateBuild = '21H2' }
                if ($Update.Title -like "*Windows Server 2025*") { $UpdateBuild = '24H2' }
                if ($Update.Title -like "*1507*") { $UpdateBuild = '1507' }
                if ($Update.Title -like "*1511*") { $UpdateBuild = '1511' }
                if ($Update.Title -like "*1607*") { $UpdateBuild = '1607' }
                if ($Update.Title -like "*1703*") { $UpdateBuild = '1703' }
                if ($Update.Title -like "*1709*") { $UpdateBuild = '1709' }
                if ($Update.Title -like "*1803*") { $UpdateBuild = '1803' }
                if ($Update.Title -like "*1809*") { $UpdateBuild = '1809' }
                if ($Update.Title -like "*1903*") { $UpdateBuild = '1903' }
                if ($Update.Title -like "*1909*") { $UpdateBuild = '1909' }
                if ($Update.Title -like "*2004*") { $UpdateBuild = '2004' }
                if ($Update.Title -like "*20H2*") { $UpdateBuild = '20H2' }
                if ($Update.Title -like "*21H1*") { $UpdateBuild = '21H1' }
                if ($Update.Title -like "*21H2*") { $UpdateBuild = '21H2' }
                if ($Update.Title -like "*22H1*") { $UpdateBuild = '22H1' }
                if ($Update.Title -like "*22H2*") { $UpdateBuild = '22H2' }
                if ($Update.Title -like "*23H1*") { $UpdateBuild = '23H1' }
                if ($Update.Title -like "*23H2*") { $UpdateBuild = '23H2' }
                if ($Update.Title -like "*24H1*") { $UpdateBuild = '24H1' }
                if ($Update.Title -like "*24H2*") { $UpdateBuild = '24H2' }

                # Set default update builds
                if($UpdateBuild -eq ""){
                    $VersionInfo = Get-WindowsBuildFromUpdateTitle -Title $Update.Title
                    $UpdateBuild = $VersionInfo.Build
                }

                # Transform Update Group
                $UpdateGroup = ''
                if ($CategoryItem.LegacyName -like "*MRT*") { $UpdateGroup = 'MRT' }
                if ($CategoryItem.Description -like "ComponentUpdate*") { $UpdateGroup = 'ComponentDU' }
                if ($CategoryItem.LegacyName -like "*CriticalDU*") { $UpdateGroup = 'ComponentDU Critical' }
                if ($CategoryItem.LegacyName -like "*SafeOSDU*") { $UpdateGroup = 'ComponentDU SafeOS' }
                if ($CategoryItem.Description -like "SetupUpdate*") { $UpdateGroup = 'SetupDU' }
                if ($CategoryItem.LegacyName -like "*SetupDU*") { $UpdateGroup = 'SetupDU' }
                if ($CategoryItem.LegacyName -like "*ServicingStack*") { $UpdateGroup = 'SSU' }
                if ($Update.Title -like "*Adobe Flash Player*") { $UpdateGroup = 'AdobeSU' }
                if ($Update.Title -like "*Cumulative Update for Windows*") { $UpdateGroup = 'LCU' }
                if ($Update.Title -like "*Cumulative Update for Microsoft server*") { $UpdateGroup = 'LCU' }
                if ($Update.Title -like "*Cumulative Update for .NET*") { $UpdateGroup = 'DotNetCU' }

                if ($Update.KnowledgeBaseArticles -eq '3173427') { $UpdateGroup = 'SSU' }
                if ($Update.KnowledgeBaseArticles -eq '3173428') { $UpdateGroup = 'SSU' }

                # Escape characters
                # $Update.Title = $Update.Title -replace '\(', ''
                # $Update.Title = $Update.Title -replace '\)', ''
                $Update.Title = $Update.Title -replace '\[', ''
                $Update.Title = $Update.Title -replace ']', ''
                $Update.Title = $Update.Title -replace '\"', ''  #Quote
                $Update.Title = $Update.Title -replace '\\', ''
                $Update.Title = $Update.Title -replace '/', ''
                $Update.Title = $Update.Title -replace '\?', ''
                $Update.Title = $Update.Title -replace ',', ''
                $Update.Title = $Update.Title -replace ':', ''
                $Update.Title = $Update.Title -replace ';', ''
                $Update.Title = $Update.Title -replace '  ', ''  #Double Space

                if (!($UpdateGroup)) { if ($Update.Title -like "*.NET Framework*") { $UpdateGroup = 'DotNet' } }

                # Check if LCU file name is KB
                if($UpdateGroup -eq "LCU"){
                    if($Update.Name -notlike "*$([string]$CategoryItem.KnowledgeBaseArticles)*"){
                        Write-Verbose "Skipping $($Update.Name)"
                        continue
                    }
                }

                Write-Host "$($Update.Name) $($Update.LegacyName) " -ForegroundColor DarkGray
                $GUID = New-Guid
                $UpdateProperties = [PSCustomObject]@{
                    'Catalog'                            = $CatalogName;
                    'OSDVersion'                         = $OSDCatalogVersion;
                    'OSDStatus'                          = '';
                    'UpdateOS'                           = $UpdateOS;
                    'UpdateBuild'                        = $UpdateBuild;
                    'UpdateArch'                         = $UpdateArch;
                    'UpdateGroup'                        = $UpdateGroup;
                
                    'CreationDate'                       = [datetime]$CategoryItem.CreationDate;
                    'KBNumber'                           = [string]$CategoryItem.KnowledgeBaseArticles;
                    'FileKBNumber'                       = [string]$Update.KnowledgeBaseArticles;
                    'Title'                              = $Update.Title;
                    'UpdateId'                           = $CategoryItem.Id.UpdateId.Guid
                    'LegacyName'                         = $CategoryItem.LegacyName;
                    'Type'                               = [string]$Update.Type;
                    'FileName'                           = $Update.Name;
                    'Size'                               = $Update.TotalBytes;
                
                    'CompanyTitles'                      = [string]$CategoryItem.CompanyTitles;
                    'ProductFamilyTitles'                = [string]$CategoryItem.ProductFamilyTitles;
                    'Category'                           = [string]$CategoryItem.ProductTitles;
                    'UpdateClassificationTitle'          = $CategoryItem.UpdateClassificationTitle;
                    'MsrcSeverity'                       = [string]$CategoryItem.MsrcSeverity;
                    'SecurityBulletins'                  = [string]$CategoryItem.SecurityBulletins;
                    'UpdateType'                         = [string]$CategoryItem.UpdateType;
                    'PublicationState'                   = [string]$CategoryItem.PublicationState;
                    'HasLicenseAgreement'                = $CategoryItem.HasLicenseAgreement;
                    'RequiresLicenseAgreementAcceptance' = $CategoryItem.RequiresLicenseAgreementAcceptance;
                    'State'                              = [string]$CategoryItem.State;
                    'IsLatestRevision'                   = $CategoryItem.IsLatestRevision;
                    'HasEarlierRevision'                 = $CategoryItem.HasEarlierRevision;
                    'IsBeta'                             = $CategoryItem.IsBeta;
                    'HasStaleUpdateApprovals'            = $CategoryItem.HasStaleUpdateApprovals;
                    'IsApproved'                         = $CategoryItem.IsApproved;
                    'IsDeclined'                         = $CategoryItem.IsDeclined;
                    'HasSupersededUpdates'               = $CategoryItem.HasSupersededUpdates;
                    'IsSuperseded'                       = $CategoryItem.IsSuperseded;
                    'IsWsusInfrastructureUpdate'         = $CategoryItem.IsWsusInfrastructureUpdate;
                    'IsEditable'                         = $CategoryItem.IsEditable;
                    'UpdateSource'                       = [string]$CategoryItem.UpdateSource;
                    'AdditionalInformationUrls'          = [string]$CategoryItem.AdditionalInformationUrls;
                    'Description'                        = $CategoryItem.Description;
                    'ReleaseNotes'                       = $CategoryItem.ReleaseNotes;
                    
                    'FileUri'                            = $FileUri;
                    'OriginUri'                          = $OriginUri;
                    'Hash'                               = [string]$Update.Hash;
                    'AdditionalHash'                     = [string]$Update.AdditionalHash;
                    'OSDCore'                            = $OSDCore;
                    'OSDWinPE'                           = $OSDWinPE;
                    'OSDGuid'                            = $GUID;
                    'PartitionKey'                       = $CatalogName;
                    'RowKey'                             = $GUID;
                }
                $AllUpdates += $UpdateProperties
            }
        }

        $Catalogs = $AllUpdates | Select-Object 'Catalog' -Unique

        foreach($Catalog in $Catalogs.Catalog){
            $CatalogUpdates = $AllUpdates | Where-Object{$_.Catalog -eq $Catalog}
            
            # Sort
            $CatalogUpdates = $CatalogUpdates | Sort-Object OriginUri -Unique
            $CatalogUpdates = $CatalogUpdates | Sort-Object CreationDate, KBNumber, Title

            if ($GridViewResults) {
                $CatalogUpdates = $CatalogUpdates | Sort-Object CreationDate | Out-GridView -PassThru -Title 'Select OSDCatalog Results'
            }
            if ($SaveDirectory) {
                if($Catalog -like "Windows 11*"){
                    $LCU = $CatalogUpdates | Where-Object{$_.UpdateGroup -eq "LCU"}

                    $LCU | Export-Clixml -Path "$SaveDirectory\$($Catalog) LCU.xml" -Force
                    Write-Verbose "Results: Import-CliXml '$SaveDirectory\$($Catalog) LCU.xml' | Out-GridView" -Verbose

                    $NonLCU = $CatalogUpdates | Where-Object{$_.UpdateGroup -ne "LCU"}

                    $NonLCU | Export-Clixml -Path "$SaveDirectory\$($Catalog).xml" -Force
                    Write-Verbose "Results: Import-CliXml '$SaveDirectory\$($Catalog).xml' | Out-GridView" -Verbose
                }else{
                    $CatalogUpdates | Export-Clixml -Path "$SaveDirectory\$($Catalog).xml" -Force
                    Write-Verbose "Results: Import-CliXml '$SaveDirectory\$($Catalog).xml' | Out-GridView" -Verbose
                }
            }
        }
    }
}

function Get-WsusUpdateFile {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [string]$UpdateName
    )

    Write-Verbose "Using 'Update Name' set name"
    #Search for updates
    Write-Verbose "Searching for update/s"
    $patches = @($wsus.SearchUpdates($UpdateName))
    If ($patches -eq 0) {
        Write-Error "Update $update could not be found in WSUS!"
        Break
    }
    Else {
        $Items = $patches | ForEach-Object {
            $Patch = $_
            Write-Verbose ("Adding NoteProperty for {0}" -f $_.Title)                    
            $_.GetInstallableItems() | ForEach-Object {
                $itemdata = $_ | Add-Member -MemberType NoteProperty -Name KnowledgeBaseArticles -value $patch.KnowledgeBaseArticles -PassThru
                $itemdata | Add-Member -MemberType NoteProperty -Name Title -value $patch.Title -PassThru
            }
        }                
    }
    ForEach ($item in $items) {
        Write-Verbose ("Getting installable items on {0}" -f $item.Title)
        Try {
            $filedata = $item | Select-Object -Expand Files | Add-Member -MemberType NoteProperty -Name KnowledgeBaseArticles -value $item.KnowledgeBaseArticles -PassThru
            $filedata | Add-Member -MemberType NoteProperty -Name Title -value $item.Title -PassThru
        }
        Catch {
            Write-Warning ("{0}: {1}" -f $item.id.id, $_.Exception.Message)
        }
    }
}

function Get-WindowsBuildFromUpdateTitle ($Title){
    $DefaultBuilds = @{
        "Windows 11" = "21H2"
        "Windows 10" = "1909"
    }

    if($Title -notmatch 'Windows \d* (Version ){0,1}(\d{4}|\d{2}H\d)'){
        if($Title -notmatch 'Windows \d*'){
            return $False
        }
    }

    $WindowsVersion = ($Title | Select-String -Pattern 'Windows \d*' -AllMatches).Matches.Value
    $VersionString = ($Title | Select-String -Pattern "$WindowsVersion(,){0,1} (Version ){0,1}(\d{4}|\d{2}H\d)*" -AllMatches).Matches.Value
    $BuildVersion = $VersionString.Replace(",","").Replace($WindowsVersion,"").Replace("version", "").Replace("Version", "").Trim()

    if( $BuildVersion -eq ""){
        $BuildVersion = $DefaultBuilds.$WindowsVersion
    }

    return @{
        Windows = $WindowsVersion
        Build = $BuildVersion 
    }
}

# Get OSD Version
Import-Module OSD
$OSDModule = Get-Module OSD
$OSDCatalogVersion = $OSDModule.Version
$OSDLocation = $OSDModule.ModuleBase
$CatalogPath = "$OSDLocation\Catalogs\WSUSXML\Windows"

# Clear current temp catalogs
$CatalogFiles = Get-ChildItem "$PSScriptRoot\Catalogs\*.xml"
$CatalogFiles | Remove-Item

# Generate new catalog files
New-OSDCatalog -SaveDirectory "$PSScriptRoot\Catalogs"

$CatalogFiles = Get-ChildItem "$PSScriptRoot\Catalogs\*.xml"
Copy-Item -Path $CatalogFiles -Destination $CatalogPath -Force