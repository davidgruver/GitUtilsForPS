<#
.SYNOPSIS
    Collects normalized identity and Exchange evidence from a user-account forest.

.DESCRIPTION
    Queries one Active Directory user and produces a normalized evidence object
    containing identity, source-anchor, synchronization, and Exchange attributes.

    The collector is read-only. It does not modify Active Directory.

    Supported input identities include:
      - Distinguished name
      - ObjectGUID
      - sAMAccountName
      - UserPrincipalName

    The script can return the object to the pipeline, write JSON to disk, or both.

.NOTES
    Compatible with Windows PowerShell 5.1.

    Requires:
      - ActiveDirectory PowerShell module
      - Network access to a domain controller in the user-account forest

.EXAMPLE
    .\Collect-UserForest.ps1 `
        -Identity user1 `
        -Server userdc01.contoso.com

.EXAMPLE
    .\Collect-UserForest.ps1 `
        -Identity user1@contoso.com `
        -Server userdc01.contoso.com `
        -OutputPath .\Evidence\UserForest-user1.json `
        -PassThru

.EXAMPLE
    .\Collect-UserForest.ps1 `
        -Identity 'CN=User One,OU=Users,DC=contoso,DC=com' `
        -Server userdc01.contoso.com `
        -SyncExclusionAttribute adminDescription `
        -SyncExclusionValue ExcludeFromEntraSync `
        -OutputPath .\Evidence\UserForest-user1.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ForestRole = 'UserForest',

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SyncExclusionAttribute = 'adminDescription',

    [Parameter()]
    [string]$SyncExclusionValue = 'ExcludeFromEntraSync',

    [Parameter()]
    [ValidateSet(
        'Equals',
        'Contains',
        'StartsWith',
        'Regex',
        'Populated'
    )]
    [string]$SyncExclusionOperator = 'Equals',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateRange(3, 100)]
    [int]$JsonDepth = 12,

    [Parameter()]
    [switch]$IncludeRawAttributes,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

#region Utility functions

function Import-RequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Module -Name $Name)) {
        Import-Module -Name $Name -ErrorAction Stop
    }
}

function Convert-GuidToImmutableId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$Guid
    )

    return [Convert]::ToBase64String($Guid.ToByteArray())
}

function Convert-ByteArrayToGuid {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $bytes = [byte[]]$Value

    if ($bytes.Length -eq 0) {
        return $null
    }

    if ($bytes.Length -ne 16) {
        throw "Expected a 16-byte GUID value but received $($bytes.Length) bytes."
    }

    return [guid]::new($bytes)
}

function Convert-ByteArrayToImmutableId {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $bytes = [byte[]]$Value

    if ($bytes.Length -eq 0) {
        return $null
    }

    if ($bytes.Length -ne 16) {
        throw "Expected a 16-byte source anchor but received $($bytes.Length) bytes."
    }

    return [Convert]::ToBase64String($bytes)
}

function Convert-AdGuidAttribute {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [guid]) {
        if ($Value -eq [guid]::Empty) {
            return $null
        }

        return [guid]$Value
    }

    if ($Value -is [byte[]]) {
        if ($Value.Length -ne 16) {
            return $null
        }

        $guidValue = [guid]::new([byte[]]$Value)

        if ($guidValue -eq [guid]::Empty) {
            return $null
        }

        return $guidValue
    }

    $parsedGuid = [guid]::Empty

    if ([guid]::TryParse([string]$Value, [ref]$parsedGuid)) {
        if ($parsedGuid -eq [guid]::Empty) {
            return $null
        }

        return $parsedGuid
    }

    return $null
}

function Convert-SidToString {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
        return $Value.Value
    }

    if ($Value -is [byte[]]) {
        try {
            $sid = New-Object `
                System.Security.Principal.SecurityIdentifier `
                -ArgumentList $Value, 0

            return $sid.Value
        }
        catch {
            return $null
        }
    }

    $text = [string]$Value

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text
}

function Get-PrimarySmtpAddress {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$ProxyAddresses,

        [Parameter()]
        [AllowNull()]
        [string]$Mail
    )

    foreach ($address in @($ProxyAddresses)) {
        if ($null -eq $address) {
            continue
        }

        $text = [string]$address

        if ($text.StartsWith(
            'SMTP:',
            [System.StringComparison]::Ordinal
        )) {
            return $text.Substring(5)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Mail)) {
        return $Mail
    }

    return $null
}

function Convert-ToStringArray {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    return @(
        $Value |
            ForEach-Object {
                if ($null -ne $_) {
                    [string]$_
                }
            }
    )
}

function Test-SyncExclusion {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$AttributeValue,

        [Parameter(Mandatory)]
        [string]$ExpectedValue,

        [Parameter(Mandatory)]
        [ValidateSet(
            'Equals',
            'Contains',
            'StartsWith',
            'Regex',
            'Populated'
        )]
        [string]$Operator
    )

    $values = Convert-ToStringArray -Value $AttributeValue

    switch ($Operator) {
        'Equals' {
            return [bool](
                $values |
                    Where-Object {
                        $_.Equals(
                            $ExpectedValue,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            )
        }

        'Contains' {
            return [bool](
                $values |
                    Where-Object {
                        $_.IndexOf(
                            $ExpectedValue,
                            [System.StringComparison]::OrdinalIgnoreCase
                        ) -ge 0
                    }
            )
        }

        'StartsWith' {
            return [bool](
                $values |
                    Where-Object {
                        $_.StartsWith(
                            $ExpectedValue,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            )
        }

        'Regex' {
            return [bool](
                $values |
                    Where-Object {
                        $_ -match $ExpectedValue
                    }
            )
        }

        'Populated' {
            return [bool](
                $values |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        }
    }
}

function Convert-ValueForJson {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [byte[]]) {
        return [ordered]@{
            Type   = 'ByteArray'
            Length = $Value.Length
            Base64 = [Convert]::ToBase64String($Value)
            Hex    = (
                $Value |
                    ForEach-Object {
                        $_.ToString('X2')
                    }
            ) -join ''
        }
    }

    if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
        return $Value.Value
    }

    if ($Value -is [guid]) {
        return $Value.Guid
    }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o')
    }

    if (
        $Value -is [System.Collections.IEnumerable] -and
        -not ($Value -is [string])
    ) {
        return @(
            $Value |
                ForEach-Object {
                    Convert-ValueForJson -Value $_
                }
        )
    }

    return $Value
}

function Get-Sha256Hash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()

    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $hashBytes = $sha256.ComputeHash($bytes)

        return (
            $hashBytes |
                ForEach-Object {
                    $_.ToString('x2')
                }
        ) -join ''
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-AdUserByFlexibleIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string[]]$Properties,

        [Parameter()]
        [string]$SearchBase
    )

    try {
        return Get-ADUser `
            -Identity $Identity `
            -Server $Server `
            -Properties $Properties `
            -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Continue to attribute search.
    }
    catch {
        if (
            $_.Exception.Message -notmatch
            'Cannot find an object with identity'
        ) {
            throw
        }
    }

    $escapedIdentity = $Identity.Replace("'", "''")

    $filter = @"
SamAccountName -eq '$escapedIdentity' -or
UserPrincipalName -eq '$escapedIdentity' -or
mail -eq '$escapedIdentity'
"@

    $parameters = @{
        Filter      = $filter
        Server      = $Server
        Properties  = $Properties
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $parameters.SearchBase = $SearchBase
    }

    $matches = @(
        Get-ADUser @parameters
    )

    if ($matches.Count -eq 0) {
        throw "No user was found for identity '$Identity' on server '$Server'."
    }

    if ($matches.Count -gt 1) {
        $dns = $matches.DistinguishedName -join '; '

        throw (
            "Identity '$Identity' matched $($matches.Count) users. " +
            "Use a distinguished name or ObjectGUID. Matches: $dns"
        )
    }

    return $matches[0]
}

#endregion Utility functions

#region Collection

Import-RequiredModule -Name ActiveDirectory

$standardProperties = @(
    'CanonicalName'
    'DisplayName'
    'GivenName'
    'Surname'
    'EmployeeID'
    'EmployeeNumber'
    'Enabled'
    'SamAccountName'
    'UserPrincipalName'
    'objectGUID'
    'objectSid'
    'SIDHistory'
    'ms-DS-ConsistencyGuid'
    'msDS-ExternalDirectoryObjectId'
    'adminDescription'
    'mail'
    'proxyAddresses'
    'targetAddress'
    'legacyExchangeDN'
    'mailNickname'
    'msExchRecipientTypeDetails'
    'msExchRemoteRecipientType'
    'msExchMailboxGuid'
    'msExchArchiveGuid'
    'msExchDisabledArchiveGuid'
    'msExchMasterAccountSid'
    'msExchVersion'
    'extensionAttribute1'
    'extensionAttribute2'
    'extensionAttribute3'
    'extensionAttribute4'
    'extensionAttribute5'
    'extensionAttribute6'
    'extensionAttribute7'
    'extensionAttribute8'
    'extensionAttribute9'
    'extensionAttribute10'
    'extensionAttribute11'
    'extensionAttribute12'
    'extensionAttribute13'
    'extensionAttribute14'
    'extensionAttribute15'
    'whenCreated'
    'whenChanged'
    'uSNCreated'
    'uSNChanged'
)

$properties = @(
    $standardProperties
    $SyncExclusionAttribute
) |
    Sort-Object -Unique

$collectionStartedUtc = [datetime]::UtcNow

$user = Get-AdUserByFlexibleIdentity `
    -Identity $Identity `
    -Server $Server `
    -Properties $properties `
    -SearchBase $SearchBase

$collectionCompletedUtc = [datetime]::UtcNow

$objectGuid = [guid]$user.ObjectGUID
$objectGuidBase64 = Convert-GuidToImmutableId -Guid $objectGuid

$consistencyGuid = Convert-ByteArrayToGuid `
    -Value $user.'ms-DS-ConsistencyGuid'

$consistencyGuidBase64 = Convert-ByteArrayToImmutableId `
    -Value $user.'ms-DS-ConsistencyGuid'

$mailboxGuid = Convert-AdGuidAttribute `
    -Value $user.msExchMailboxGuid

$archiveGuid = Convert-AdGuidAttribute `
    -Value $user.msExchArchiveGuid

$disabledArchiveGuid = Convert-AdGuidAttribute `
    -Value $user.msExchDisabledArchiveGuid

$objectSid = Convert-SidToString -Value $user.ObjectSid
$masterAccountSid = Convert-SidToString `
    -Value $user.msExchMasterAccountSid

$sidHistory = @(
    $user.SIDHistory |
        ForEach-Object {
            Convert-SidToString -Value $_
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
)

$proxyAddresses = @(
    Convert-ToStringArray -Value $user.ProxyAddresses |
        Sort-Object -Unique
)

$primarySmtpAddress = Get-PrimarySmtpAddress `
    -ProxyAddresses $proxyAddresses `
    -Mail $user.Mail

$syncExclusionRawValue = $user.$SyncExclusionAttribute

$isExcludedFromSync = Test-SyncExclusion `
    -AttributeValue $syncExclusionRawValue `
    -ExpectedValue $SyncExclusionValue `
    -Operator $SyncExclusionOperator

$rawAttributes = $null

if ($IncludeRawAttributes) {
    $rawAttributes = [ordered]@{}

    foreach ($propertyName in $properties) {
        $rawAttributes[$propertyName] =
            Convert-ValueForJson -Value $user.$propertyName
    }
}

$normalizedObject = [ordered]@{
    SchemaVersion = '1.0'

    Collector = [ordered]@{
        Name                 = 'Collect-UserForest'
        Version              = '1.0.0'
        ComputerName         = $env:COMPUTERNAME
        UserName             = [Environment]::UserName
        ProcessId            = $PID
        PowerShellVersion    = $PSVersionTable.PSVersion.ToString()
        CollectionStartedUtc = $collectionStartedUtc.ToString('o')
        CollectionEndedUtc   = $collectionCompletedUtc.ToString('o')
        DurationMilliseconds = [math]::Round(
            (
                $collectionCompletedUtc -
                $collectionStartedUtc
            ).TotalMilliseconds
        )
    }

    Query = [ordered]@{
        Identity   = $Identity
        Server     = $Server
        SearchBase = $SearchBase
    }

    Source = [ordered]@{
        ForestRole       = $ForestRole
        DomainController = $Server
        DomainName       = $user.UserPrincipalName -replace '^.*@', ''
    }

    Identity = [ordered]@{
        DistinguishedName = $user.DistinguishedName
        CanonicalName     = $user.CanonicalName
        Name              = $user.Name
        DisplayName       = $user.DisplayName
        GivenName         = $user.GivenName
        Surname           = $user.Surname
        EmployeeId        = $user.EmployeeID
        EmployeeNumber    = $user.EmployeeNumber
        SamAccountName    = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        Enabled           = [bool]$user.Enabled
    }

    DirectoryIdentifiers = [ordered]@{
        ObjectGuid           = $objectGuid.Guid
        ObjectGuidBase64     = $objectGuidBase64
        ObjectSid            = $objectSid
        SidHistory           = $sidHistory
        ExternalDirectoryId  =
            $user.msDSExternalDirectoryObjectId
    }

    SourceAnchor = [ordered]@{
        AttributeName              = 'ms-DS-ConsistencyGuid'
        ConsistencyGuid            = if ($consistencyGuid) {
            $consistencyGuid.Guid
        }
        else {
            $null
        }
        ConsistencyGuidBase64      = $consistencyGuidBase64
        IsPopulated                = [bool]$consistencyGuid
        MatchesCurrentObjectGuid   = (
            -not [string]::IsNullOrWhiteSpace(
                $consistencyGuidBase64
            ) -and
            $consistencyGuidBase64 -eq $objectGuidBase64
        )
        CurrentObjectGuidCandidate = $objectGuidBase64
    }

    CrossForestRelationship = [ordered]@{
        ObjectSid        = $objectSid
        MasterAccountSid = $masterAccountSid
    }

    Synchronization = [ordered]@{
        ExclusionAttribute = $SyncExclusionAttribute
        ExclusionOperator  = $SyncExclusionOperator
        ExclusionValue     = $SyncExclusionValue
        AttributeValue     = Convert-ValueForJson `
            -Value $syncExclusionRawValue
        IsExcludedFromSync = $isExcludedFromSync
        InSyncScope        = -not $isExcludedFromSync
    }

    Mail = [ordered]@{
        Mail                 = $user.Mail
        MailNickname         = $user.MailNickname
        PrimarySmtpAddress   = $primarySmtpAddress
        ProxyAddresses       = $proxyAddresses
        TargetAddress        = $user.TargetAddress
        LegacyExchangeDn     = $user.LegacyExchangeDN

        MailboxGuid          = if ($mailboxGuid) {
            $mailboxGuid.Guid
        }
        else {
            $null
        }

        ArchiveGuid          = if ($archiveGuid) {
            $archiveGuid.Guid
        }
        else {
            $null
        }

        DisabledArchiveGuid  = if ($disabledArchiveGuid) {
            $disabledArchiveGuid.Guid
        }
        else {
            $null
        }

        RemoteRecipientType  = if (
            $null -ne $user.msExchRemoteRecipientType
        ) {
            [int64]$user.msExchRemoteRecipientType
        }
        else {
            $null
        }

        RecipientTypeDetails = if (
            $null -ne $user.msExchRecipientTypeDetails
        ) {
            [int64]$user.msExchRecipientTypeDetails
        }
        else {
            $null
        }

        ExchangeVersion      = if (
            $null -ne $user.msExchVersion
        ) {
            [int64]$user.msExchVersion
        }
        else {
            $null
        }
    }

    CustomAttributes = [ordered]@{
        ExtensionAttribute1  = $user.extensionAttribute1
        ExtensionAttribute2  = $user.extensionAttribute2
        ExtensionAttribute3  = $user.extensionAttribute3
        ExtensionAttribute4  = $user.extensionAttribute4
        ExtensionAttribute5  = $user.extensionAttribute5
        ExtensionAttribute6  = $user.extensionAttribute6
        ExtensionAttribute7  = $user.extensionAttribute7
        ExtensionAttribute8  = $user.extensionAttribute8
        ExtensionAttribute9  = $user.extensionAttribute9
        ExtensionAttribute10 = $user.extensionAttribute10
        ExtensionAttribute11 = $user.extensionAttribute11
        ExtensionAttribute12 = $user.extensionAttribute12
        ExtensionAttribute13 = $user.extensionAttribute13
        ExtensionAttribute14 = $user.extensionAttribute14
        ExtensionAttribute15 = $user.extensionAttribute15
    }

    ChangeTracking = [ordered]@{
        WhenCreated = if ($user.WhenCreated) {
            $user.WhenCreated.ToUniversalTime().ToString('o')
        }
        else {
            $null
        }

        WhenChanged = if ($user.WhenChanged) {
            $user.WhenChanged.ToUniversalTime().ToString('o')
        }
        else {
            $null
        }

        UsnCreated = if ($null -ne $user.uSNCreated) {
            [int64]$user.uSNCreated
        }
        else {
            $null
        }

        UsnChanged = if ($null -ne $user.uSNChanged) {
            [int64]$user.uSNChanged
        }
        else {
            $null
        }
    }

    RawAttributes = $rawAttributes
}

# Create the hash from the normalized evidence before adding the hash itself.
$hashInput = $normalizedObject |
    ConvertTo-Json -Depth $JsonDepth -Compress

$normalizedObject.EvidenceHash = Get-Sha256Hash -Text $hashInput

$result = [pscustomobject]$normalizedObject

#endregion Collection

#region Output

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $resolvedOutputPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($OutputPath)

    $outputDirectory = Split-Path `
        -Path $resolvedOutputPath `
        -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($outputDirectory) -and
        -not (Test-Path -LiteralPath $outputDirectory)
    ) {
        $null = New-Item `
            -ItemType Directory `
            -Path $outputDirectory `
            -Force
    }

    $json = $result |
        ConvertTo-Json -Depth $JsonDepth

    [System.IO.File]::WriteAllText(
        $resolvedOutputPath,
        $json,
        [System.Text.UTF8Encoding]::new($false)
    )
}

if ($PassThru -or [string]::IsNullOrWhiteSpace($OutputPath)) {
    $result
}

#endregion Output