# ============================================================================
#                           _                                    _   _                       _
#     /\                   | |                                  | | | |                     | |
#    /  \   _ __   ___  _ _  _   _ _ __ ___   ___  _   _ ___  | |_| | ___  _   _ _ __   __| |
#   / /\ \ | '_ \ / _ \| '_ \| | | | '_ ` _ \ / _ \| | | / __| |  _  |/ _ \| | | | '_ \ / _` |
#  / ____ \| | | | (_) | | | | |_| | | | | | | (_) | |_| \__ \ | | | | (_) | |_| | | | | (_| |
# /_/    \_\_| |_|\___/|_| |_|\__, |_| |_| |_|\___/ \__,_|___/ \_| |_/\___/ \__,_|_| |_|\__,_|
#                              __/ |
#                             |___/
#
#                    🎭 The BloodHound that leaves no trace 🎭
#
#---:::..     .:-.       ...   .:-..    :=.....:. .:..:.............:-::..              ........  .....:::::...
#--:::::..    .::.        ... .--:.    .:......:.-*=:+-:::.::::-=-:.---=-:...  .......  ............:..........
#--::..::...  .::.    ..   ...:-:.     ::...::-::##+*+::.:---+**+=--:--=--:.... .......................  ...:..
#--::...:......-:     ...   .:-:..   .--. ..::--###*=:-::+++##%%+--=-::--=+-..:     ..::..::::::... ......:::::
#--::..... ...:-:.    ....  .:-:..  .--.   .::.:%*=...:-=*#%@@@@%*+--===+#**=.::   .:::......:::..........:::::
#--::.....  ..-=:      ...   ..:..  :-.    .....-....:--*#%%#%*#%%%*===*###*+=:....::...   ....................
#-- - :...... ..-=:.     ....  .....  ::.     ....::::----=*####**#%%%*=*###*=*=:......  .. .     ....   ....   .
#-- - :.......  :=:..    ..........  :.  .  .----====--===+=++*#*####%*+####+++-::.........        ...   ....    
#-- - :.....::..:=:...............  :-   .:-===++++++++===++==+**#**##=*%###*+=::::::......         ...   ...    
#-- - :......-:.--::::::.......... .-.  :+*+====+*##*+=====+=+===***#*+%##%%#++--::::--....          ...   ...   
#-- - ::.....:-:-=:::---:........ .--.  #@@%%@%#**###**++++**===++=*#=*%#%%%%*#-------==.             ...  ...   
#--:::.....:--=-::-==--:........--.   :#%@%%%%%##%%*******#+=++==*+=##*%%%#+*=--====--:             .........  
#--::....:::-=+-::--=--:..   ..--.     *%%%#%%%#%##**#*+*+++-===+#=+#**#**=++-==-==-=--.             ..........
#--:....::---=+-:----::...   .:-.      *%%#%%%%###*******++++++=**=*#**#*+=*===+====--:-   .          .......::
#--:....:::-:-+-:-==-:::......--.  ....*%%%*#%#####****##*++++=*#+****#*==#+==+++=====--: ...          .......:
#-- - :....:::--+=--==---::::.:-=:.....:.*%%@%############**+++=*##*#**#*==##++==+=+++++=--.....          .....::
#-- = :....:::-=+=-----=-::.::==:....... *%@@@@#######%#*+***+++###*+***+*%#+++++++*+++++-=: ....         ......:
#----.....:::-+----------::==:.........:%%@@@@#######**+***++#%**++++*##*++*+++======++:-=. ..          .......
#--:-:.......-=--====----:-=: .... .... -@@@@@@%%%##%%*####*=#*+++*#%%#******++++++++*+:--=. ..     ...........
#--:-:.......==:-======-::=:. .......  ..-#@@@@@%%%%###%%##*+*++++%##*******++**++++*#*:-===: .................
#--::-:...:::=+:-=====---==:..............:=#%@@%@@%%%%%#%##******###******++*+++++****::=*=--..:..............
#=----:::::::=+--====---==-::.............=+++%@@%@%@%%%%##%#+++*#%###******+******#*+*-=+*++==-:..........::::
#==----::::::==----=-::-=::-:::..........:++++#%%%%@%#%#%#%%*++**#%********+++++**###**++#*****===:........::--
#=====---:::-+=--:--::-=-............. ..=+*+**%%@@@%%@##%%#++++*#******++++*++**###***++++*****++=:::::....:-=
#======--====+==------=+---::::::::::...-******+*###%@%%%%%#*++*##******++***+++***#*+++=+==**+**++::::......:-
#=========++++======+++=-=-------=-:----*###***+++*++%**##******###***********+++**++****++-:+#+***=:::::....:-
#=========+++*+=====++=----::.::==-:::=*#%#***++***+=*#*********##************+=-+##*+**++==-=++++*=----------=
#++++++++ = ++ * * += ====+=---==--:::--::..-#%##********#-+*#***++++#%###*******#*+=+*####**#***++=====*+=----======
#++++ * * ++ = =+*+=====+===+=====-:::::::::-+##*****###%-=+*#*++++*####********##*#%%#***+*+++***+=--:**++=------==
#**++++++======-=++======---==-::--::--=--*****##%@*==++*#*++*####%#******#%@%%##***+=+*+*++**+==:+++++===+==-=
#
#                   (Sniffing out attack paths incognito)
#
# ============================================================================
# AnonymousHound v0.1 ALPHA
# Author: Kay Daskalakis
# GitHub: https://github.com/kaydaskalakis
# ============================================================================
# Purpose: Anonymize BloodHound data exports for safe sharing while preserving
#          attack path relationships and security-relevant information
#
# Like a hound in disguise, this tool masks sensitive data while keeping the
# scent of attack paths intact for analysis and collaboration.
#
# Features:
# - Supports both single file and directory processing
# - Processes 12 BloodHound data types:
#   * Core: users, groups, computers, domains, gpos, ous
#   * PKI: containers, certtemplates, ntauthstores, aiacas, rootcas, enterprisecas
# - Maintains consistent domain and OU mappings across all file types
# - Preserves well-known security principals and structure
# - Anonymizes PII: names, emails, descriptions, certificate thumbprints
# - Idempotent: safely skips already anonymized files
#
# Usage Examples:
# ---------------
# Auto-discovery mode (scans current directory and subdirectories):
#   .\AnonymousHound.ps1
#   (Interactive menu will let you select from found BloodHound data)
#
# Process entire directory (will prompt for output location):
#   .\AnonymousHound.ps1 -InputDirectory "C:\BH\Data"
#
# Process entire directory with specified output:
#   .\AnonymousHound.ps1 -InputDirectory "C:\BH\Data" -OutputDirectory "C:\BH\Anonymized"
#
# Process single file (will prompt for output location):
#   .\AnonymousHound.ps1 -InputFile "C:\BH\users.json"
#
# Process single file with specified output:
#   .\AnonymousHound.ps1 -InputFile "C:\BH\users.json" -OutputDirectory "C:\BH\Output"
#
# Use existing domain mappings:
#   .\AnonymousHound.ps1 -InputDirectory "C:\BH\Data" -OutputDirectory "C:\BH\Out" -DomainMappingFile "C:\BH\mappings.txt"
#
# With timestamp randomization:
#   .\AnonymousHound.ps1 -InputDirectory "C:\BH\Data" -OutputDirectory "C:\BH\Out" -RandomizeTimestamps
# ============================================================================

[CmdletBinding()]
param(
    # Directory containing BloodHound JSON files to anonymize
    # Use this for batch processing multiple files at once
    [Parameter(Mandatory=$false)]
    [string]$InputDirectory,

    # Single JSON file to anonymize
    # Use this when you only need to process one file
    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    # Directory where anonymized files will be saved
    # Also stores mapping files for reference
    # If not specified, user will be prompted
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory,

    # Optional: Path to existing domain mapping file
    # Use this to maintain consistency across multiple anonymization runs
    [string]$DomainMappingFile,

    # Optional: Randomize timestamps with per-object variation
    # Adds noise while maintaining temporal relationships
    [switch]$RandomizeTimestamps,

    # Optional: Keep original OS version strings
    # Useful when OS versions are relevant to the analysis
    [switch]$PreserveOSVersions
)

#region Constants and Configuration
# ============================================================================
# Anonymization Prefixes
# These prefixes are used to generate anonymized names while maintaining
# object type identification in the anonymized data
# ============================================================================
$script:ANONYMIZED_PREFIX_USER = "USR_"           # User accounts
$script:ANONYMIZED_PREFIX_GROUP = "GRP_"          # Security groups
$script:ANONYMIZED_PREFIX_COMPUTER = "COMP_"      # Computer objects
$script:ANONYMIZED_PREFIX_HOSTNAME = "HST_"       # Hostnames
$script:ANONYMIZED_PREFIX_OU = "OU_"              # Organizational Units
$script:ANONYMIZED_PREFIX_CA = "CA_"              # Certificate Authorities
$script:ANONYMIZED_PREFIX_GPO = "GPO_"            # Group Policy Objects
$script:ANONYMIZED_PREFIX_EMAIL = "email_"        # Email addresses
$script:ANONYMIZED_PREFIX_DISPLAY = "Display_"    # Display names
$script:ANONYMIZED_PREFIX_SVC = "SVC_"            # Service accounts

# ============================================================================
# Random Hex String Lengths
# Control the length of generated random identifiers for different purposes
# ============================================================================
$script:HEX_LENGTH_SHORT = 4         # Short IDs (16 bits)
$script:HEX_LENGTH_MEDIUM = 6        # Medium IDs (24 bits)
$script:HEX_LENGTH_LONG = 8          # Long IDs (32 bits) - most common
$script:HEX_LENGTH_XLONG = 10        # Extra-long IDs (40 bits)
$script:HEX_LENGTH_THUMBPRINT = 40   # Certificate thumbprints (SHA1 = 160 bits)

# ============================================================================
# Well-Known Security Principals
# These are preserved to maintain attack path validity and security context
# ============================================================================

# Well-known users - exact matches only
# These built-in accounts are critical for understanding privilege escalation paths
$script:WELL_KNOWN_USERS = @(
    'krbtgt',             # Kerberos service account (critical for Golden Ticket attacks)
    'Guest',              # Built-in guest account
    'Administrator',      # Built-in administrator account
    'DefaultAccount',     # Windows default account
    'NETWORK SERVICE',    # Built-in service account
    'LOCAL SERVICE',      # Built-in local service account
    'SYSTEM'              # Local System account
)

# Well-known groups - regex patterns for flexible matching
# These groups are preserved because they represent standard AD security groups
# that are critical for understanding permissions and attack paths
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
$script:WELL_KNOWN_GROUP_PATTERNS = @(
    '^Domain Admins$'
    '^Domain Users$'
    '^Domain Computers$'
    '^Domain Controllers$'
    '^Enterprise Admins$'
    '^Schema Admins$'
    '^Administrators$'
    '^Users$'
    '^Guests$'
    '^Backup Operators$'
    '^Account Operators$'
    '^Server Operators$'
    '^Print Operators$'
    '^Replicators?$'
    '^Remote Desktop Users$'
    '^Network Configuration Operators$'
    '^Performance (Monitor|Log) Users$'
    '^IIS_IUSRS$'
    '^Event Log Readers$'
    '^Certificate Service DCOM Access$'
    '^Hyper-V Administrators$'
    '^RDS .+$'
    '^Terminal Server .+$'
    '^Windows Authorization Access Group$'
    '^Incoming Forest Trust Builders$'
    '^Distributed COM Users$'
    '^Cryptographic Operators$'
    '^Protected Users$'
    '^Key Admins$'
    '^Enterprise (Key|Read-only)? .+$'
    '^Cloneable .+$'
    '^(Allowed|Denied) RODC .+$'
    '^Read-Only .+$'
    '^Pre-Windows .+$'
    '^Cert Publishers$'
    '^DnsAdmins$'
    '^DnsUpdateProxy$'
    '^DHCP (Administrators|Users)$'
    '^Device Owners$'
    '^Domain Guests$'
    '^RAS and IAS Servers$'
    '^Remote Management Users$'
    '^Storage Replica Administrators$'
    '^System Managed Accounts Group$'
    '^WinRMRemoteWMIUsers__$'
    '^Group Policy .+$'
    '^Exchange .+$'
    '^Organization Management$'
    '^Recipient Management$'
    '^Server Management$'
    '^Everyone$'
    '^Authenticated Users$'
    '^INTERACTIVE$'
    '^ANONYMOUS LOGON$'
    '^Storage Replica Administrators$'
    '^Access Control Assistance Operators$'
)

# Well-Known OUs (actual OU= entries, not CN= containers)
# NOTE: These are OU names (OU=), not CN containers (CN=)
# CN=Computers exists as a container AND OU=Computers exists as an OU - both are valid!
$script:WELL_KNOWN_OUS = @(
    'DOMAIN CONTROLLERS',  # Standard OU for domain controllers (OU=Domain Controllers,DC=...)
    'COMPUTERS',           # Some environments have OU=Computers (separate from CN=Computers)
    'USERS',               # Some environments have OU=Users (separate from CN=Users)
    'TIER0', 'TIER1', 'TIER2',  # Tiering model OUs
    'SERVICEACCOUNTS', 'WORKSTATIONS', 'GROUPS'  # Common administrative OUs
)

# ============================================================================
# Well-Known CN Containers
# These CN containers are critical for AD security analysis and must be preserved
# IMPORTANT: This is the single source of truth - do not redefine this list later
# ============================================================================
$script:WELL_KNOWN_CNS = @(
    # Domain NC root containers (Microsoft well-known objects)
    'USERS', 'COMPUTERS', 'BUILTIN', 'DOMAIN CONTROLLERS', 'FOREIGNSECURITYPRINCIPALS',
    'MANAGED SERVICE ACCOUNTS', 'SYSTEM', 'PROGRAM DATA', 'MICROSOFT PROGRAM DATA',
    'NTDS QUOTAS', 'LOSTANDFOUND', 'TPM DEVICES',
    # Critical CN=System stable children (CRITICAL FOR SECURITY)
    'POLICIES', 'ADMINSDHOLDER', 'RID MANAGER$',
    # Configuration NC root containers
    'SERVICES', 'SITES', 'PARTITIONS', 'FORESTUPDATES', 'EXTENDED-RIGHTS',
    'DISPLAYSPECIFIERS', 'CONFIGURATION', 'LOSTANDFOUNDCONFIG',
    # Under CN=Sites,CN=Configuration
    'DEFAULT-FIRST-SITE-NAME', 'SUBNETS', 'INTER-SITE TRANSPORTS',
    'IP', 'DEFAULTIPSITELINK', 'SMTP',
    # Schema NC
    'SCHEMA', 'AGGREGATE',
    # Additional common containers seen in BloodHound exports
    'INFRASTRUCTURE', 'DELETED OBJECTS', 'MICROSOFTDNS', 'WINDOWS NT',
    'DNSZONE', 'QUOTAS', 'OPERATIONS', 'PHYSICAL LOCATIONS',
    'WELLKNOWN SECURITY PRINCIPALS', 'NTDS SETTINGS',
    # Well-known group containers that should be preserved as CNs too
    'INCOMING FOREST TRUST BUILDERS', 'GROUP POLICY CREATOR OWNERS',
    'CERT PUBLISHERS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS',
    'DOMAIN ADMINS', 'DOMAIN USERS', 'DOMAIN COMPUTERS', 'DOMAIN GUESTS',
    'ACCOUNT OPERATORS', 'SERVER OPERATORS', 'PRINT OPERATORS',
    'BACKUP OPERATORS', 'REPLICATOR', 'GUESTS', 'ADMINISTRATORS',
    'NETWORK CONFIGURATION OPERATORS', 'PERFORMANCE LOG USERS', 'PERFORMANCE MONITOR USERS',
    'DISTRIBUTED COM USERS', 'CRYPTOGRAPHIC OPERATORS', 'EVENT LOG READERS',
    'CERTIFICATE SERVICE DCOM ACCESS', 'RDS ENDPOINT SERVERS', 'RDS MANAGEMENT SERVERS',
    'RDS REMOTE ACCESS SERVERS', 'HYPER-V ADMINISTRATORS', 'ACCESS CONTROL ASSISTANCE OPERATORS',
    'REMOTE DESKTOP USERS', 'REMOTE MANAGEMENT USERS', 'IIS_IUSRS',
    'TERMINAL SERVER LICENSE SERVERS', 'DNSADMINS', 'DNSUPDATEPROXY',
    'ALLOWED RODC PASSWORD REPLICATION GROUP', 'DENIED RODC PASSWORD REPLICATION GROUP',
    'READ-ONLY DOMAIN CONTROLLERS', 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS',
    'CLONEABLE DOMAIN CONTROLLERS', 'PROTECTED USERS', 'KEY ADMINS', 'ENTERPRISE KEY ADMINS',
    'RAS AND IAS SERVERS', 'PRE-WINDOWS 2000 COMPATIBLE ACCESS',
    'WINDOWS AUTHORIZATION ACCESS GROUP', 'STORAGE REPLICA ADMINISTRATORS',
    'DEVICE OWNERS', 'SYSTEM MANAGED ACCOUNTS GROUP',
    # PKI / Certificate Services containers (CRITICAL for AD CS attack path analysis)
    'PUBLIC KEY SERVICES', 'CERTIFICATE TEMPLATES', 'ENROLLMENT SERVICES',
    'CERTIFICATION AUTHORITIES', 'AIA', 'CDP', 'NTAUTHCERTIFICATES',
    # Exchange System containers (CRITICAL for Exchange security analysis)
    'MICROSOFT EXCHANGE', 'MICROSOFT EXCHANGE SYSTEM OBJECTS',
    'MICROSOFT EXCHANGE AUTODISCOVER', 'ADMINISTRATIVE GROUPS',
    'GLOBAL SETTINGS', 'ADDRESSING', 'ROUTING GROUPS',
    'OFFLINE ADDRESS LISTS', 'ADDRESS LISTS CONTAINER', 'ADDRESSBOOK MAILBOX POLICIES',
    'RETENTION POLICIES CONTAINER', 'RETENTION POLICY TAG CONTAINER',
    'TRANSPORT SETTINGS', 'ACCEPTED DOMAINS', 'REMOTE ACCOUNTS POLICIES CONTAINER',
    'EXCHANGE SERVERS', 'EXCHANGE TRUSTED SUBSYSTEM', 'EXCHANGE WINDOWS PERMISSIONS',
    'EXCHANGE INSTALL DOMAIN SERVERS', 'CLIENT ACCESS',
    'ELC FOLDERS CONTAINER', 'ELC MAILBOX POLICIES', 'MOBILE MAILBOX POLICIES',
    'OWA MAILBOX POLICIES', 'TEAM MAILBOX PROVISIONING POLICIES',
    'AUTH CONFIGURATION', 'AVAILABILITY CONFIGURATION', 'FEDERATION TRUSTS',
    'HYBRID CONFIGURATION', 'PROVISIONING POLICY CONTAINER', 'PUSH NOTIFICATIONS SETTINGS',
    'MONITORING SETTINGS', 'SERVICEENDPOINTS', 'RBAC',
    # Modern AD security containers (Dynamic Access Control, gMSA, etc.)
    'GROUP KEY DISTRIBUTION SERVICE', 'SHADOW PRINCIPAL CONFIGURATION',
    'CLAIMS CONFIGURATION', 'RESOURCE PROPERTY LISTS', 'CENTRAL ACCESS POLICIES',
    'CENTRAL ACCESS RULES', 'CLAIM TYPES',
    # Additional system containers
    'CONNECTIONS', 'QUERY-POLICIES', 'DEFAULT', 'OPTIONAL FEATURES',
    'VALUE TYPES', 'MASTER ROOT KEYS'
)

$script:WELL_KNOWN_GPOS = @(
    'DEFAULT DOMAIN POLICY',
    'DEFAULT DOMAIN CONTROLLERS POLICY'
)

# Expanded service list for SPNs
$script:WELL_KNOWN_SERVICES = @(
    'HTTP', 'HTTPS', 'MSSQLSvc', 'TERMSRV', 'HOST',
    'RestrictedKrbHost', 'kadmin', 'ldap', 'DNS',
    'cifs', 'WSMAN', 'GC', 'RPC', 'Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04',
    'E3514235-4B06-11D1-AB04-00C04FC2DCD2'
)

# Exact well-known domain authorities
$script:WELL_KNOWN_DOMAINS = @(
    'NT AUTHORITY',
    'BUILTIN',
    'NT SERVICE',
    'APPLICATION PACKAGE AUTHORITY'
)

# NOTE: $script:WELL_KNOWN_CNS is defined above (line 170) with the full list
# DO NOT redefine it here - that was causing AdminSDHolder and RID Manager$ to be anonymized!

#endregion

# Validate parameters - if neither specified, scan for data
if (-not $InputDirectory -and -not $InputFile) {
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  AnonymousHound - Auto-Discovery Mode" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # Get script directory
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrEmpty($scriptDir)) {
        $scriptDir = Get-Location
    }

    Write-Host "Scanning for BloodHound data in: " -NoNewline -ForegroundColor Yellow
    Write-Host "$scriptDir" -ForegroundColor White
    Write-Host ""

    # Scan for BloodHound JSON files
    $bhFileTypes = @('*users*.json', '*groups*.json', '*computers*.json', '*domains*.json',
                     '*gpos*.json', '*ous*.json', '*containers*.json', '*certtemplates*.json',
                     '*ntauthstores*.json', '*aiacas*.json', '*rootcas*.json', '*enterprisecas*.json')

    # Find directories containing BloodHound data
    $foundDirs = @{}
    $foundFiles = @()

    # Check current directory
    foreach ($pattern in $bhFileTypes) {
        $files = Get-ChildItem -Path $scriptDir -Filter $pattern -File -ErrorAction SilentlyContinue
        if ($files) {
            $foundFiles += $files
        }
    }

    if ($foundFiles.Count -gt 0) {
        $foundDirs[$scriptDir] = $foundFiles
    }

    # Check first-level subdirectories
    $subDirs = Get-ChildItem -Path $scriptDir -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $subDirs) {
        $dirFiles = @()
        foreach ($pattern in $bhFileTypes) {
            $files = Get-ChildItem -Path $dir.FullName -Filter $pattern -File -ErrorAction SilentlyContinue
            if ($files) {
                $dirFiles += $files
            }
        }
        if ($dirFiles.Count -gt 0) {
            $foundDirs[$dir.FullName] = $dirFiles
        }
    }

    if ($foundDirs.Count -eq 0) {
        Write-Host "✗ No BloodHound data files found!" -ForegroundColor Red
        Write-Host "`nPlease specify input manually:" -ForegroundColor Yellow
        Write-Host "  Directory mode: .\script.ps1 -InputDirectory 'C:\Data'" -ForegroundColor Gray
        Write-Host "  Single file mode: .\script.ps1 -InputFile 'C:\Data\file.json'" -ForegroundColor Gray
        exit 1
    }

    # Display found data
    Write-Host "✓ Found BloodHound data in $($foundDirs.Count) location(s):" -ForegroundColor Green
    Write-Host ""

    $locationIndex = 1
    $locationMap = @{}

    foreach ($dirPath in $foundDirs.Keys) {
        $files = $foundDirs[$dirPath]
        $displayPath = if ($dirPath -eq $scriptDir) { "." } else { Split-Path $dirPath -Leaf }

        Write-Host "  [$locationIndex] " -NoNewline -ForegroundColor Cyan
        Write-Host "$displayPath" -NoNewline -ForegroundColor White
        Write-Host " ($($files.Count) files)" -ForegroundColor DarkGray

        $locationMap[$locationIndex] = @{
            Path = $dirPath
            Files = $files
        }
        $locationIndex++
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host "  [1-$($foundDirs.Count)] Process entire location" -ForegroundColor Gray
    Write-Host "  [F] View files and select specific file" -ForegroundColor Gray
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Enter your choice: " -NoNewline -ForegroundColor Yellow

    $choice = Read-Host

    if ($choice -match '^[Qq]') {
        Write-Host "`nExiting..." -ForegroundColor Yellow
        exit 0
    }
    elseif ($choice -match '^[Ff]') {
        # Show detailed file list
        Write-Host "`n" -NoNewline
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Available BloodHound Files" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $fileIndex = 1
        $fileMap = @{}

        foreach ($dirPath in $foundDirs.Keys) {
            $files = $foundDirs[$dirPath]
            $displayPath = if ($dirPath -eq $scriptDir) { "." } else { Split-Path $dirPath -Leaf }

            Write-Host "Location: $displayPath" -ForegroundColor Cyan
            foreach ($file in $files) {
                Write-Host "  [$fileIndex] " -NoNewline -ForegroundColor Yellow
                Write-Host "$($file.Name)" -NoNewline -ForegroundColor White
                Write-Host " ($([math]::Round($file.Length / 1KB, 2)) KB)" -ForegroundColor DarkGray

                $fileMap[$fileIndex] = $file.FullName
                $fileIndex++
            }
            Write-Host ""
        }

        Write-Host "Enter file number to process (or Q to quit): " -NoNewline -ForegroundColor Yellow
        $fileChoice = Read-Host

        if ($fileChoice -match '^[Qq]') {
            Write-Host "`nExiting..." -ForegroundColor Yellow
            exit 0
        }

        $fileNum = 0
        if ([int]::TryParse($fileChoice, [ref]$fileNum) -and $fileMap.ContainsKey($fileNum)) {
            $InputFile = $fileMap[$fileNum]
            Write-Host "`n✓ Selected: " -NoNewline -ForegroundColor Green
            Write-Host "$InputFile" -ForegroundColor White
            Write-Host ""
        }
        else {
            Write-Error "Invalid file selection"
            exit 1
        }
    }
    elseif ($choice -match '^\d+$') {
        $locationNum = [int]$choice
        if ($locationMap.ContainsKey($locationNum)) {
            $InputDirectory = $locationMap[$locationNum].Path
            Write-Host "`n✓ Selected: " -NoNewline -ForegroundColor Green
            Write-Host "$InputDirectory" -ForegroundColor White
            Write-Host ""
        }
        else {
            Write-Error "Invalid location selection"
            exit 1
        }
    }
    else {
        Write-Error "Invalid choice"
        exit 1
    }
}

if ($InputDirectory -and $InputFile) {
    Write-Error "Specify either -InputDirectory OR -InputFile, not both"
    exit 1
}

if ($InputFile -and -not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}

if ($InputDirectory -and -not (Test-Path $InputDirectory)) {
    Write-Error "Input directory not found: $InputDirectory"
    exit 1
}

# Prompt for output directory if not specified
if (-not $OutputDirectory) {
    $currentDir = Get-Location
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Output Directory Selection" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "`nCurrent directory: " -NoNewline -ForegroundColor Yellow
    Write-Host "$currentDir" -ForegroundColor White
    Write-Host "`nWould you like to output anonymized files to the current directory?" -ForegroundColor Yellow
    Write-Host "[Y] Yes  [N] No (specify different directory)  [Default: Y]: " -NoNewline -ForegroundColor Gray

    $response = Read-Host

    if ([string]::IsNullOrWhiteSpace($response) -or $response -match '^[Yy]') {
        $OutputDirectory = $currentDir.Path
        Write-Host "`n✓ Using current directory: $OutputDirectory" -ForegroundColor Green
    }
    else {
        Write-Host "`nPlease enter the output directory path: " -NoNewline -ForegroundColor Yellow
        $OutputDirectory = Read-Host

        if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
            Write-Error "Output directory cannot be empty"
            exit 1
        }
    }
    Write-Host ""
}

# Initialize script-level variables with case-insensitive comparers
$script:DomainMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:DomainSidToDomain = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:OuMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:GroupMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:UserMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:ComputerMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:HostnameMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:SPNMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:CAMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:DomainSidMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:GuidMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:CNMapping = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
$script:ObjectTimestampOffsets = @{}

# Track preserved (non-anonymized) items with reasons
$script:PreservedItems = @{
    Computers = @{}  # Key = computer name, Value = reason
    Users = @{}
    Groups = @{}
    OUs = @{}
    CNs = @{}
    Domains = @{}
}

# Base time offset (optionally randomize per object)
# NOTE: This is set once at script start and remains constant across all collections
# to maintain consistent temporal relationships
# WARNING: Timestamp randomization can introduce temporal inaccuracies that may affect
#          time-based analysis. Use -RandomizeTimestamps switch to enable.
if ($RandomizeTimestamps) {
    $script:BaseTimeOffset = Get-Random -Minimum -365 -Maximum 365
    Write-Host ""
    Write-Host "⚠️  WARNING: Timestamp randomization is ENABLED" -ForegroundColor Yellow
    Write-Host "   Timestamps will be shifted by a random offset (-365 to +365 days)" -ForegroundColor Yellow
    Write-Host "   This may introduce temporal inaccuracies in time-based analysis!" -ForegroundColor Yellow
    Write-Host "   Temporal relationships between objects will be preserved." -ForegroundColor Yellow
    Write-Host ""
} else {
    $script:BaseTimeOffset = 0
}

# Domain counter for generating anonymized domain names
$script:domainCounter = 0

# Collection mappings storage (for multi-collection scenarios)
$script:CollectionMappings = @{}

# Function to create a shallow copy of a dictionary
function Copy-Dictionary {
    [CmdletBinding()]
    param([object]$Dictionary)

    $newDict = New-Object 'System.Collections.Generic.Dictionary[string,string]'([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $Dictionary.Keys) {
        $newDict[$key] = $Dictionary[$key]
    }
    return $newDict
}

# Function to create a shallow copy of preserved items
function Copy-PreservedItems {
    [CmdletBinding()]
    param([hashtable]$PreservedItems)

    return @{
        Computers = $PreservedItems.Computers.Clone()
        Users = $PreservedItems.Users.Clone()
        Groups = $PreservedItems.Groups.Clone()
        OUs = $PreservedItems.OUs.Clone()
        CNs = $PreservedItems.CNs.Clone()
        Domains = $PreservedItems.Domains.Clone()
    }
}

# Function to reset mapping tables for collection isolation
function Reset-MappingTables {
    [CmdletBinding()]
    param()

    Write-ScriptLog "Resetting mapping tables for new collection" -Level Info

    # Clear all mapping dictionaries
    $script:DomainMapping.Clear()
    $script:DomainSidToDomain.Clear()
    $script:OuMapping.Clear()
    $script:GroupMapping.Clear()
    $script:UserMapping.Clear()
    $script:ComputerMapping.Clear()
    $script:HostnameMapping.Clear()
    $script:SPNMapping.Clear()
    $script:CAMapping.Clear()
    $script:DomainSidMapping.Clear()
    $script:GuidMapping.Clear()
    $script:CNMapping.Clear()
    $script:ObjectTimestampOffsets.Clear()

    # Reset preserved items tracking
    $script:PreservedItems = @{
        Computers = @{}
        Users = @{}
        Groups = @{}
        OUs = @{}
        CNs = @{}
        Domains = @{}
    }

    # Reset domain counter
    $script:domainCounter = 0
}

# Well-known principals including all built-in groups and special identity groups
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-special-identities-groups
$script:WellKnownPrincipals = @{
    # BUILTIN groups (S-1-5-32-*)
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
    'S-1-5-32-546' = 'BUILTIN\Guests'
    'S-1-5-32-547' = 'BUILTIN\Power Users'
    'S-1-5-32-548' = 'BUILTIN\Account Operators'
    'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-550' = 'BUILTIN\Print Operators'
    'S-1-5-32-551' = 'BUILTIN\Backup Operators'
    'S-1-5-32-552' = 'BUILTIN\Replicator'
    'S-1-5-32-554' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'
    'S-1-5-32-556' = 'BUILTIN\Network Configuration Operators'
    'S-1-5-32-557' = 'BUILTIN\Incoming Forest Trust Builders'
    'S-1-5-32-558' = 'BUILTIN\Performance Monitor Users'
    'S-1-5-32-559' = 'BUILTIN\Performance Log Users'
    'S-1-5-32-560' = 'BUILTIN\Windows Authorization Access Group'
    'S-1-5-32-561' = 'BUILTIN\Terminal Server License Servers'
    'S-1-5-32-562' = 'BUILTIN\Distributed COM Users'
    'S-1-5-32-568' = 'BUILTIN\IIS_IUSRS'
    'S-1-5-32-569' = 'BUILTIN\Cryptographic Operators'
    'S-1-5-32-573' = 'BUILTIN\Event Log Readers'
    'S-1-5-32-574' = 'BUILTIN\Certificate Service DCOM Access'
    'S-1-5-32-575' = 'BUILTIN\RDS Remote Access Servers'
    'S-1-5-32-576' = 'BUILTIN\RDS Endpoint Servers'
    'S-1-5-32-577' = 'BUILTIN\RDS Management Servers'
    'S-1-5-32-578' = 'BUILTIN\Hyper-V Administrators'
    'S-1-5-32-579' = 'BUILTIN\Access Control Assistance Operators'
    'S-1-5-32-580' = 'BUILTIN\Remote Management Users'
    'S-1-5-32-582' = 'BUILTIN\Storage Replica Administrators'

    # NT AUTHORITY (S-1-5-*)
    'S-1-5-1'  = 'NT AUTHORITY\Dialup'
    'S-1-5-2'  = 'NT AUTHORITY\NETWORK'
    'S-1-5-3'  = 'NT AUTHORITY\BATCH'
    'S-1-5-4'  = 'NT AUTHORITY\INTERACTIVE'
    'S-1-5-6'  = 'NT AUTHORITY\SERVICE'
    'S-1-5-7'  = 'NT AUTHORITY\ANONYMOUS LOGON'
    'S-1-5-9'  = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
    'S-1-5-10' = 'NT AUTHORITY\Principal Self'
    'S-1-5-11' = 'NT AUTHORITY\Authenticated Users'
    'S-1-5-12' = 'NT AUTHORITY\Restricted'
    'S-1-5-13' = 'NT AUTHORITY\Terminal Server User'
    'S-1-5-14' = 'NT AUTHORITY\Remote Interactive Logon'
    'S-1-5-15' = 'NT AUTHORITY\This Organization'
    'S-1-5-17' = 'NT AUTHORITY\IUSR'
    'S-1-5-18' = 'NT AUTHORITY\SYSTEM'
    'S-1-5-19' = 'NT AUTHORITY\LOCAL SERVICE'
    'S-1-5-20' = 'NT AUTHORITY\NETWORK SERVICE'
    'S-1-5-113' = 'NT AUTHORITY\Local account'
    'S-1-5-114' = 'NT AUTHORITY\Local account and member of Administrators group'
    'S-1-5-1000' = 'NT AUTHORITY\Other Organization'

    # NT AUTHORITY\Authentication (S-1-5-64-*)
    'S-1-5-64-10' = 'NT AUTHORITY\NTLM Authentication'
    'S-1-5-64-14' = 'NT AUTHORITY\SChannel Authentication'
    'S-1-5-64-21' = 'NT AUTHORITY\Digest Authentication'

    # NT AUTHORITY\Service (S-1-5-80-*)
    'S-1-5-80-0' = 'NT AUTHORITY\All Services'

    # NT AUTHORITY\Virtual Machines (S-1-5-83-*)
    'S-1-5-83-0' = 'NT AUTHORITY\NT VIRTUAL MACHINE\Virtual Machines'

    # Window Manager (S-1-5-90-*)
    'S-1-5-90-0' = 'NT AUTHORITY\Window Manager\Window Manager Group'

    # Authentication Authority Asserted Identity (S-1-18-*)
    'S-1-18-1' = 'Authentication Authority Asserted Identity'
    'S-1-18-2' = 'Service Asserted Identity'
    'S-1-18-3' = 'Fresh Public Key Identity'
    'S-1-18-4' = 'Key Trust'
    'S-1-18-5' = 'MFA Key Property'
    'S-1-18-6' = 'Attested Key Property'

    # Creator groups (S-1-3-*)
    'S-1-3-0' = 'Creator Owner'
    'S-1-3-1' = 'Creator Group'
    'S-1-3-4' = 'Owner Rights'

    # Universal
    'S-1-1-0' = 'Everyone'
    'S-1-2-0' = 'LOCAL'
    'S-1-2-1' = 'CONSOLE LOGON'
}

$script:domainCounter = 0
$script:ErrorLog = @()

#region Helper Functions

function Write-ScriptLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }

    $prefix = switch ($Level) {
        'Info' { '[INFO]' }
        'Warning' { '[WARN]' }
        'Error' { '[ERROR]' }
        'Success' { '[OK]' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color

    if ($Level -eq 'Error') {
        $script:ErrorLog += "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    }
}

function Get-RandomHex {
    [CmdletBinding()]
    param([int]$Length = 8)

    $hex = ''
    for ($i = 0; $i -lt $Length; $i++) {
        $hex += '{0:X}' -f (Get-Random -Maximum 16)
    }
    return $hex
}

function Test-WellKnownDomain {
    [CmdletBinding()]
    param([string]$Domain)

    if ([string]::IsNullOrEmpty($Domain)) {
        return $false
    }

    # Exact match against well-known domain authorities
    return ($script:WELL_KNOWN_DOMAINS -contains $Domain)
}

function Test-WellKnownGroup {
    [CmdletBinding()]
    param([string]$GroupName)

    if ([string]::IsNullOrEmpty($GroupName)) {
        return $false
    }

    # Test against regex patterns
    foreach ($pattern in $script:WELL_KNOWN_GROUP_PATTERNS) {
        if ($GroupName -match $pattern) {
            return $true
        }
    }

    return $false
}

function Get-AnonymizedDomain {
    [CmdletBinding()]
    param([string]$Domain)

    if ([string]::IsNullOrEmpty($Domain)) {
        return $Domain
    }

    # Check for well-known domains
    if (Test-WellKnownDomain $Domain) {
        $script:PreservedItems.Domains[$Domain] = "Well-known domain"
        return $Domain
    }

    # Handle well-known LDAP partition prefixes (preserve them, only anonymize base domain)
    # Examples: _msdcs.domain.com, DomainDnsZones.domain.com, ForestDnsZones.domain.com
    $wellKnownPrefixes = @('_msdcs', 'DomainDnsZones', 'ForestDnsZones', 'X-MS-OLAuthPolicy')

    foreach ($prefix in $wellKnownPrefixes) {
        if ($Domain -match "^$prefix\.(.+)$") {
            $baseDomain = $matches[1]
            # Recursively anonymize the base domain
            $anonBaseDomain = Get-AnonymizedDomain $baseDomain
            # Return prefix + anonymized base domain
            return "$prefix.$anonBaseDomain"
        }
    }

    # Case-insensitive lookup using the dictionary
    if ($script:DomainMapping.ContainsKey($Domain)) {
        return $script:DomainMapping[$Domain]
    }

    # Preserve forest hierarchy: if this is a child domain, inherit parent's anonymized root
    # Examples:
    #   WRAITH.CORP          -> DOMAIN2.LOCAL
    #   CHILD.WRAITH.CORP    -> CHILD.DOMAIN2.LOCAL
    #   SUB.CHILD.WRAITH.CORP -> SUB.CHILD.DOMAIN2.LOCAL
    if ($Domain -match '^([^.]+)\.(.+)$') {
        $leftmostLabel = $matches[1]
        $parentDomain = $matches[2]

        # Check if parent domain is already mapped (indicating this is a child domain)
        # Recursively anonymize parent first to ensure proper mapping order
        $anonParentDomain = Get-AnonymizedDomain $parentDomain

        # If parent was mapped (not a well-known domain), construct child as label.parent
        if ($script:DomainMapping.ContainsKey($parentDomain)) {
            $anonDomain = "$leftmostLabel.$anonParentDomain"
            $script:DomainMapping[$Domain] = $anonDomain
            Write-Verbose "Mapped child domain: $Domain -> $anonDomain (preserving forest hierarchy)"
            return $anonDomain
        }
    }

    # Create new anonymized root domain
    $script:domainCounter++
    $anonDomain = "DOMAIN$($script:domainCounter).LOCAL"
    $script:DomainMapping[$Domain] = $anonDomain

    Write-Verbose "Mapped root domain: $Domain -> $anonDomain"

    return $anonDomain
}

function Get-AnonymizedGuid {
    [CmdletBinding()]
    param([string]$Guid)

    if ([string]::IsNullOrEmpty($Guid)) {
        return $Guid
    }

    # Validate GUID format - CASE INSENSITIVE
    if ($Guid -notmatch '(?i)^[0-9a-f\-]{36}$') {
        return $Guid
    }

    # Normalize to uppercase for consistent lookup
    $GuidUpper = $Guid.ToUpper()

    # Check mapping for consistency
    if ($script:GuidMapping.ContainsKey($GuidUpper)) {
        return $script:GuidMapping[$GuidUpper]
    }

    $newGuid = [guid]::NewGuid().ToString().ToUpper()
    $script:GuidMapping[$GuidUpper] = $newGuid

    return $newGuid
}

function Get-AnonymizedDomainSid {
    [CmdletBinding()]
    param([string]$Sid)

    if ([string]::IsNullOrEmpty($Sid)) {
        return $Sid
    }

    # Check if it's a well-known SID
    if ($script:WellKnownPrincipals.ContainsKey($Sid)) {
        return $Sid
    }

    # Check for BUILTIN and other well-known SIDs (any S-1-5-32-* or S-1-5-XX where XX < 22)
    if ($Sid -match '^S-1-5-32-\d+$') {
        return $Sid
    }
    if ($Sid -match '^S-1-5-(\d+)$' -and [int]$matches[1] -lt 22) {
        return $Sid
    }
    if ($Sid -match '^S-1-[12]-\d+$') {
        return $Sid
    }

    # Handle domain-prefixed well-known SIDs (e.g., GHOST.CORP-S-1-5-20)
    # Anonymize the domain prefix and keep the well-known SID
    if ($Sid -match '^(.+?)-(S-1-5-32-\d+|S-1-5-(\d+)|S-1-[12]-\d+)$') {
        $domainPart = $matches[1]
        $sidPart = $matches[2]

        # Check if the SID part is a well-known SID (S-1-5-XX where XX < 22, or S-1-5-32-*, or S-1-[12]-*)
        $isWellKnown = $false
        if ($sidPart -match '^S-1-5-32-\d+$') {
            $isWellKnown = $true
        } elseif ($sidPart -match '^S-1-5-(\d+)$' -and [int]$matches[1] -lt 22) {
            $isWellKnown = $true
        } elseif ($sidPart -match '^S-1-[12]-\d+$') {
            $isWellKnown = $true
        }

        if ($isWellKnown) {
            # Anonymize the domain part and keep the well-known SID
            $anonDomain = Get-AnonymizedDomain $domainPart
            return "$anonDomain-$sidPart"
        }
    }

    # Handle domain-prefixed domain SIDs (e.g., DOMAIN-S-1-5-21-...)
    # STRIP the domain prefix and return ONLY the SID
    if ($Sid -match '^[^-]+-((S-1-5-21(-\d+){3})(-\d+)?)$') {
        $sidOnly = $matches[1]
        return Get-AnonymizedDomainSid $sidOnly
    }

    # Handle regular domain SIDs (S-1-5-21-xxx-xxx-xxx[-RID])
    if ($Sid -match '^(S-1-5-21(-\d+){3})(-\d+)?$') {
        $baseSid = $matches[1]
        $ridPart = if ($matches[3]) { $matches[3] } else { '' }

        # Check if we've already mapped this BASE SID
        if ($script:DomainSidMapping.ContainsKey($baseSid)) {
            return "$($script:DomainSidMapping[$baseSid])$ridPart"
        }

        # Generate new anonymized domain SID
        $anonBaseSid = "S-1-5-21-$(Get-Random -Maximum 999999999)-$(Get-Random -Maximum 999999999)-$(Get-Random -Maximum 999999999)"
        $script:DomainSidMapping[$baseSid] = $anonBaseSid

        return "$anonBaseSid$ridPart"
    }

    return $Sid
}

function Split-DistinguishedName {
    [CmdletBinding()]
    param([string]$DN)

    if ([string]::IsNullOrEmpty($DN)) {
        return @()
    }

    # Split by comma, but not escaped commas (\,)
    $parts = [regex]::Split($DN, '(?<!\\),')

    return $parts | ForEach-Object { $_.Trim() }
}

function Set-DNLeafCN {
    [CmdletBinding()]
    param(
        [string]$DN,
        [string]$NewLeafCN
    )

    if ([string]::IsNullOrWhiteSpace($DN)) {
        return $DN
    }

    $parts = Split-DistinguishedName $DN
    if ($parts.Count -gt 0 -and $parts[0] -match '^CN=') {
        $parts[0] = "CN=$NewLeafCN"
        return ($parts -join ',')
    }

    return $DN
}

function Get-AnonymizedOuPath {
    [CmdletBinding()]
    param([string]$DN)

    if ([string]::IsNullOrEmpty($DN)) {
        return $DN
    }

    try {
        # Parse DN components with escape handling
        $parts = Split-DistinguishedName $DN
        $anonParts = @()
        $parentPath = ""

        # Find the first DC= component index (all DC= parts come at the end)
        $firstDcIndex = -1
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -match '^DC=') {
                $firstDcIndex = $i
                break
            }
        }

        # Process non-DC components (CN, OU, etc.)
        $endIndex = if ($firstDcIndex -ge 0) { $firstDcIndex } else { $parts.Count }
        for ($i = 0; $i -lt $endIndex; $i++) {
            $part = $parts[$i]

            if ($part -match '^CN=(.+)$') {
                $cn = $matches[1]

                # Preserve Foreign Security Principal leaf CNs (SID values)
                # FSPs live under CN=ForeignSecurityPrincipals and use literal SIDs as CN values
                # This keeps Foreign Members/Admins/GPO Controllers counts accurate
                if ($parentPath.ToUpper() -match 'CN=FOREIGNSECURITYPRINCIPALS(,|$)') {
                    $anonParts += "CN=$cn"
                    if ($cn -match '^S-\d+-\d+(-\d+)+$') {
                        $script:PreservedItems.CNs[$cn] = "Foreign Security Principal SID"
                    }
                    $parentPath += $part + ","
                    continue
                }

                # Check for well-known CNs (preserve them) - case insensitive
                if ($cn.ToUpper() -in $script:WELL_KNOWN_CNS) {
                    # Preserve well-known CNs in their original case
                    $anonParts += "CN=$cn"
                    $script:PreservedItems.CNs[$cn] = "Well-known CN container"
                } else {
                    # Include parent path in key for unique CN mapping
                    $cnKey = "$parentPath|$cn"
                    if ($script:CNMapping.ContainsKey($cnKey)) {
                        $anonParts += "CN=$($script:CNMapping[$cnKey])"
                    } else {
                        $anonCN = "CN_" + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                        $script:CNMapping[$cnKey] = $anonCN
                        $anonParts += "CN=$anonCN"
                    }
                }
                $parentPath += $part + ","
            }
            elseif ($part -match '^OU=(.+)$') {
                $ou = $matches[1]
                # Check if this is a well-known OU that should be preserved
                if ($ou.ToUpper() -in $script:WELL_KNOWN_OUS) {
                    # Preserve well-known OUs in uppercase
                    $anonParts += "OU=$($ou.ToUpper())"
                    $script:PreservedItems.OUs[$ou] = "Well-known OU"
                } else {
                    if (-not $script:OuMapping.ContainsKey($ou)) {
                        $script:OuMapping[$ou] = $script:ANONYMIZED_PREFIX_OU + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                    }
                    $anonParts += "OU=$($script:OuMapping[$ou])"
                }
                $parentPath += $part + ","
            }
            else {
                $anonParts += $part
                $parentPath += $part + ","
            }
        }

        # Process DC components atomically (rewrite all trailing DC= segments at once)
        if ($firstDcIndex -ge 0) {
            # Extract all DC parts and reconstruct full domain
            $dcParts = $parts[$firstDcIndex..($parts.Count - 1)] | Where-Object { $_ -match '^DC=' }
            $domainFull = ($dcParts -join '.' -replace 'DC=', '')

            # Get anonymized domain and convert back to DC components
            $anonDomain = Get-AnonymizedDomain $domainFull
            $anonDomainParts = $anonDomain -split '\.'

            # Append all anonymized DC components
            foreach ($anonDc in $anonDomainParts) {
                $anonParts += "DC=$anonDc"
            }
        }

        return $anonParts -join ','
    }
    catch {
        Write-ScriptLog "Error parsing DN '$DN': $_" -Level Error
        return $DN
    }
}

function Get-AnonymizedTimestamp {
    [CmdletBinding()]
    param(
        [long]$Timestamp,
        [string]$ObjectId
    )

    if ($Timestamp -le 0) {
        return $Timestamp
    }

    if ($RandomizeTimestamps -and -not [string]::IsNullOrEmpty($ObjectId)) {
        # Use per-object random offset for additional privacy
        if (-not $script:ObjectTimestampOffsets.ContainsKey($ObjectId)) {
            $script:ObjectTimestampOffsets[$ObjectId] = Get-Random -Minimum -180 -Maximum 180
        }
        $offset = $script:BaseTimeOffset + $script:ObjectTimestampOffsets[$ObjectId]
    } else {
        $offset = $script:BaseTimeOffset
    }

    $result = $Timestamp + ([long]$offset * 86400)

    # Clamp at zero to prevent negative timestamps
    if ($result -lt 0) {
        return 0
    }

    return $result
}

function Process-ACEPrincipalSID {
    [CmdletBinding()]
    param([string]$PrincipalSID)

    if ([string]::IsNullOrEmpty($PrincipalSID)) {
        return $PrincipalSID
    }

    # Check if it's a well-known SID
    if ($script:WellKnownPrincipals.ContainsKey($PrincipalSID)) {
        return $PrincipalSID
    }

    # Check for BUILTIN SIDs with optional domain prefix
    if ($PrincipalSID -match '^(.*?-)?(S-1-5-32-\d+|S-1-5-\d+|S-1-[12]-\d+)$') {
        $domainPrefix = $matches[1]
        $sid = $matches[2]

        # Check if the SID part is a well-known SID
        $isWellKnown = $false
        if ($sid -match '^S-1-5-32-\d+$') {
            $isWellKnown = $true
        } elseif ($sid -match '^S-1-5-(\d+)$' -and [int]$matches[1] -lt 22) {
            $isWellKnown = $true
        } elseif ($sid -match '^S-1-[12]-\d+$') {
            $isWellKnown = $true
        }

        if ($isWellKnown) {
            # If there's a domain prefix, anonymize it and keep the well-known SID
            if ($domainPrefix) {
                $domainPart = $domainPrefix.TrimEnd('-')
                $anonDomain = Get-AnonymizedDomain $domainPart
                return "$anonDomain-$sid"
            }
            # No domain prefix, return the well-known SID as-is
            return $sid
        }
    }

    # Process regular SIDs
    return Get-AnonymizedDomainSid $PrincipalSID
}

function Get-AnonymizedSPN {
    [CmdletBinding()]
    param([string]$SPN)

    if ([string]::IsNullOrEmpty($SPN)) {
        return $SPN
    }

    # Check if already mapped
    if ($script:SPNMapping.ContainsKey($SPN)) {
        return $script:SPNMapping[$SPN]
    }

    try {
        # Parse SPN: service/host:port/name
        # Host part should stop at either : (port) or / (suffix)
        if ($SPN -match '^([^/]+)/([^/:]+)(:\d+)?(/.*)?$') {
            $service = $matches[1]
            $spnHost = $matches[2]
            $port = if ($matches[3]) { $matches[3] } else { '' }
            $nameSuffix = if ($matches[4]) { $matches[4] } else { '' }

            # Keep common services visible
            if ($service -notin $script:WELL_KNOWN_SERVICES) {
                $service = $script:ANONYMIZED_PREFIX_SVC + (Get-RandomHex $script:HEX_LENGTH_SHORT)
            }

            # Anonymize host
            if ($spnHost -match '^(.+?)\.(.+)$') {
                $hostname = $matches[1]
                $domainPart = $matches[2]

                # Normalize hostname for mapping lookup
                $hostnameUpper = $hostname.ToUpper()

                # Check HOSTNAME mapping first (separate from computer names)
                if ($script:HostnameMapping.ContainsKey($hostnameUpper)) {
                    $hostname = $script:HostnameMapping[$hostnameUpper]
                } elseif ($hostname -match '^(DC\d+|RODC\d+)$') {
                    # Keep DC patterns
                } else {
                    $anonHost = $script:ANONYMIZED_PREFIX_HOSTNAME + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                    $script:HostnameMapping[$hostnameUpper] = $anonHost
                    $hostname = $anonHost
                }

                # Use full domain for mapping (including subdomains) to ensure consistency
                # Examples:
                #   contoso.com -> DOMAIN1.LOCAL
                #   corp.contoso.com -> DOMAIN2.LOCAL (separate mapping!)
                #   _msdcs.corp.contoso.com -> _msdcs.DOMAIN2.LOCAL (reuses corp.contoso.com mapping)
                $fullDomain = $domainPart
                $anonFullDomain = Get-AnonymizedDomain $fullDomain
                $anonHostFull = "$hostname.$anonFullDomain"
                $anonDomain = $anonFullDomain
            } else {
                $hostUpper = $spnHost.ToUpper()
                if ($script:HostnameMapping.ContainsKey($hostUpper)) {
                    $anonHostFull = $script:HostnameMapping[$hostUpper]
                } else {
                    $anonHostFull = $script:ANONYMIZED_PREFIX_HOSTNAME + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                    $script:HostnameMapping[$hostUpper] = $anonHostFull
                }
                $anonDomain = $null  # No domain part in host-only SPN
            }

            # Anonymize the name suffix if it contains domain references
            # Example: /phantom.corp or /DomainDnsZones.phantom.corp
            # IMPORTANT: Use full domain mapping to maintain consistency
            $anonNameSuffix = $nameSuffix
            if ($nameSuffix -match '^/(.+)$') {
                $suffixContent = $matches[1]

                # Check if it looks like a domain (has a dot)
                if ($suffixContent -match '\.') {
                    # Use the full domain for mapping (no base domain extraction)
                    # This ensures consistency: corp.contoso.com always maps to same anonymized domain
                    $anonNameSuffix = "/$(Get-AnonymizedDomain $suffixContent)"
                } else {
                    # Looks like a NetBIOS name, not a FQDN
                    if ($suffixContent.Length -gt 0) {
                        # Use the anonymized domain we already have
                        if ($anonDomain) {
                            # Use just the NetBIOS part (first label) of anonymized domain
                            $anonNetBIOS = ($anonDomain -split '\.')[0].ToUpper()
                            $anonNameSuffix = "/$anonNetBIOS"
                        } else {
                            # Can't determine base domain, keep generic
                            $anonNameSuffix = "/DOMAIN"
                        }
                    }
                }
            }

            $anonSPN = "$service/$anonHostFull$port$anonNameSuffix"
            $script:SPNMapping[$SPN] = $anonSPN

            return $anonSPN
        }
    }
    catch {
        Write-ScriptLog "Error parsing SPN '$SPN': $_" -Level Error
    }

    return $SPN
}

function Get-SafeJsonDepth {
    return 20  # Restored to 20 for deep structures
}

function ConvertTo-SafeJson {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    try {
        return $InputObject | ConvertTo-Json -Depth (Get-SafeJsonDepth) -Compress:$false
    }
    catch {
        Write-ScriptLog "JSON serialization error: $_" -Level Error
        throw
    }
}

function ConvertFrom-SafeJson {
    [CmdletBinding()]
    param([string]$Json)

    try {
        return $Json | ConvertFrom-Json
    }
    catch {
        Write-ScriptLog "JSON parsing error: $_" -Level Error
        throw
    }
}

function Copy-ObjectDeep {
    [CmdletBinding()]
    param($Object)

    try {
        $json = $Object | ConvertTo-SafeJson
        return ConvertFrom-SafeJson $json
    }
    catch {
        Write-ScriptLog "Deep copy failed: $_" -Level Error
        throw
    }
}

function Get-AnonymizedOS {
    [CmdletBinding()]
    param([string]$OS)

    if ([string]::IsNullOrEmpty($OS)) {
        return $OS
    }

    if ($PreserveOSVersions) {
        # Preserve major version categories
        if ($OS -match 'Server 20(\d{2})') {
            return "Windows Server 20$($matches[1])"
        }
        elseif ($OS -match 'Server') {
            return "Windows Server (version unknown)"
        }
        elseif ($OS -match 'Windows 10') {
            return "Windows 10"
        }
        elseif ($OS -match 'Windows 11') {
            return "Windows 11"
        }
        elseif ($OS -match 'Windows 8') {
            return "Windows 8.x"
        }
        elseif ($OS -match 'Windows 7') {
            return "Windows 7"
        }
        else {
            return "Windows Client (unknown version)"
        }
    } else {
        # Aggressive collapsing
        if ($OS -match 'Server') {
            return "Windows Server"
        } else {
            return "Windows Client"
        }
    }
}

function Process-StandardDomainProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        $AnonymizedObject,
        [string]$OriginalDomain
    )

    # Domain and SID
    if ($Object.Properties.domain) {
        $AnonymizedObject.Properties.domain = Get-AnonymizedDomain $Object.Properties.domain
    }

    if ($Object.Properties.domainsid) {
        $origDomainSid = $Object.Properties.domainsid
        $AnonymizedObject.Properties.domainsid = Get-AnonymizedDomainSid $origDomainSid

        if ($OriginalDomain) {
            $script:DomainSidToDomain[$origDomainSid] = $OriginalDomain
        }
    }

    # Distinguished name
    if ($Object.Properties.distinguishedname) {
        $AnonymizedObject.Properties.distinguishedname = Get-AnonymizedOuPath $Object.Properties.distinguishedname
    }

    # Timestamps with object-specific offsets
    $objectId = if ($Object.ObjectIdentifier) { $Object.ObjectIdentifier } else { $Object.Properties.name }

    foreach ($prop in @('lastlogon', 'lastlogontimestamp', 'pwdlastset', 'whencreated')) {
        if ($Object.Properties.$prop) {
            $AnonymizedObject.Properties.$prop = Get-AnonymizedTimestamp -Timestamp $Object.Properties.$prop -ObjectId $objectId
        }
    }
}

function Process-ACEWithNames {
    [CmdletBinding()]
    param($ACE)

    $anonACE = Copy-ObjectDeep $ACE

    if ($anonACE.PrincipalSID) {
        $anonACE.PrincipalSID = Process-ACEPrincipalSID $anonACE.PrincipalSID
    }

    # Anonymize PrincipalName if present
    if ($anonACE.PrincipalName) {
        $anonACE.PrincipalName = "Principal_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
    }

    return $anonACE
}

function Process-ObjectRelationships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        $AnonymizedObject
    )

    # Process ACEs
    if ($Object.Aces -and $Object.Aces.Count -gt 0) {
        $AnonymizedObject.Aces = @($Object.Aces | ForEach-Object {
            try {
                Process-ACEWithNames $_
            }
            catch {
                Write-ScriptLog "Error processing ACE: $_" -Level Warning
                $_
            }
        })
    }

    # Process ContainedBy
    if ($Object.ContainedBy) {
        $AnonymizedObject.ContainedBy = Copy-ObjectDeep $Object.ContainedBy
        if ($AnonymizedObject.ContainedBy.ObjectIdentifier) {
            if ($AnonymizedObject.ContainedBy.ObjectIdentifier -match '(?i)^[0-9a-f\-]{36}$') {
                $AnonymizedObject.ContainedBy.ObjectIdentifier = Get-AnonymizedGuid $AnonymizedObject.ContainedBy.ObjectIdentifier
            } else {
                $AnonymizedObject.ContainedBy.ObjectIdentifier = Get-AnonymizedDomainSid $AnonymizedObject.ContainedBy.ObjectIdentifier
            }
        }
    }

    # Process ChildObjects
    if ($Object.ChildObjects -and $Object.ChildObjects.Count -gt 0) {
        $AnonymizedObject.ChildObjects = @($Object.ChildObjects | ForEach-Object {
            try {
                $child = Copy-ObjectDeep $_
                if ($child.ObjectIdentifier) {
                    if ($child.ObjectIdentifier -match '(?i)^[0-9a-f\-]{36}$') {
                        $child.ObjectIdentifier = Get-AnonymizedGuid $child.ObjectIdentifier
                    } else {
                        $child.ObjectIdentifier = Get-AnonymizedDomainSid $child.ObjectIdentifier
                    }
                }
                $child
            }
            catch {
                Write-ScriptLog "Error processing child object: $_" -Level Warning
                $_
            }
        })
    }

    # Process Members (for groups)
    if ($Object.Members -and $Object.Members.Count -gt 0) {
        $AnonymizedObject.Members = @($Object.Members | ForEach-Object {
            try {
                $member = Copy-ObjectDeep $_
                if ($member.ObjectIdentifier) {
                    $member.ObjectIdentifier = Get-AnonymizedDomainSid $member.ObjectIdentifier
                }
                # Anonymize MemberName if present
                if ($member.MemberName) {
                    $member.MemberName = "Member_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
                }
                $member
            }
            catch {
                Write-ScriptLog "Error processing member: $_" -Level Warning
                $_
            }
        })
    }
}

function Process-GPOLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        $AnonymizedObject
    )

    if ($Object.Links -and $Object.Links.Count -gt 0) {
        $AnonymizedObject.Links = @($Object.Links | ForEach-Object {
            try {
                $link = Copy-ObjectDeep $_

                if ($link.GUID) {
                    # Use unified GUID mapping
                    $link.GUID = Get-AnonymizedGuid $link.GUID
                }

                $link
            }
            catch {
                Write-ScriptLog "Error processing GPO link: $_" -Level Warning
                $_
            }
        })
    }
}

function Process-GPOChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        $AnonymizedObject
    )

    if ($Object.GPOChanges) {
        try {
            $anonGPOChanges = Copy-ObjectDeep $Object.GPOChanges

            # Process AffectedComputers
            if ($anonGPOChanges.AffectedComputers -and $anonGPOChanges.AffectedComputers.Count -gt 0) {
                $anonGPOChanges.AffectedComputers = @($anonGPOChanges.AffectedComputers | ForEach-Object {
                    $comp = Copy-ObjectDeep $_
                    if ($comp.ObjectIdentifier) {
                        $comp.ObjectIdentifier = Get-AnonymizedDomainSid $comp.ObjectIdentifier
                    }
                    $comp
                })
            }

            # Process LocalAdmins, RemoteDesktopUsers, DcomUsers, PSRemoteUsers
            foreach ($groupType in @('LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers')) {
                if ($anonGPOChanges.$groupType -and $anonGPOChanges.$groupType.Count -gt 0) {
                    $anonGPOChanges.$groupType = @($anonGPOChanges.$groupType | ForEach-Object {
                        $item = Copy-ObjectDeep $_
                        if ($item.ObjectIdentifier) {
                            $item.ObjectIdentifier = Get-AnonymizedDomainSid $item.ObjectIdentifier
                        }
                        # Anonymize Name if present
                        if ($item.Name) {
                            $item.Name = "GPOObject_" + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                        }
                        $item
                    })
                }
            }

            $AnonymizedObject.GPOChanges = $anonGPOChanges
        }
        catch {
            Write-ScriptLog "Error processing GPO changes: $_" -Level Warning
        }
    }
}

#endregion

#region Object Anonymization Functions

function Get-AnonymizedUser {
    [CmdletBinding()]
    param($User)

    try {
        $anonymizedUser = Copy-ObjectDeep $User

        # Track original properties for mapping
        $originalSAM = $User.Properties.samaccountname
        $originalDomain = $User.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $User -AnonymizedObject $anonymizedUser -OriginalDomain $originalDomain

        # Check if this is a well-known user (preserve as-is)
        $isWellKnownUser = $false
        if ($User.Properties.samaccountname -and $User.Properties.samaccountname -in $script:WELL_KNOWN_USERS) {
            $isWellKnownUser = $true
            $script:PreservedItems.Users[$User.Properties.samaccountname] = "Well-known user account"
        }

        if (-not $isWellKnownUser) {
            # Build a single alias token to use for UPN, displayName, and DN leaf CN
            # This makes the anonymized data much more readable and consistent
            $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG

            # Anonymize sAMAccountName first (used for mapping)
            if ($User.Properties.samaccountname) {
                $anonSAM = $script:ANONYMIZED_PREFIX_USER + $aliasToken
                $anonymizedUser.Properties.samaccountname = $anonSAM
                if ($originalSAM) {
                    $script:UserMapping[$originalSAM] = $anonSAM
                }
            }

            # UPN/name - use same alias token with domain mapping
            if ($User.Properties.name) {
                $origName = $User.Properties.name
                if ($origName -match '^(.+?)@(.+)$') {
                    $domainPart = $matches[2]

                    # For email domains, check if it's a single-label domain (NetBIOS name)
                    # and try to find a matching FQDN in existing mappings
                    $emailDomain = $domainPart
                    if ($domainPart -notmatch '\.' -and $domainPart -ne '') {
                        # Single-label domain (e.g., "corp" from "user@corp")
                        # Look for existing mappings that might be the FQDN version
                        $potentialFQDN = $script:DomainMapping.Keys | Where-Object {
                            $_ -match "^$domainPart\." -or ($_ -split '\.')[0] -eq $domainPart
                        } | Select-Object -First 1

                        if ($potentialFQDN) {
                            $emailDomain = $potentialFQDN
                        }
                    }

                    $anonDomain = Get-AnonymizedDomain $emailDomain
                    $anonymizedUser.Properties.name = ("USER_{0}@{1}" -f $aliasToken, $anonDomain).ToUpper()
                } else {
                    $anonymizedUser.Properties.name = "USER_" + $aliasToken
                }
            }

            # displayName - use same alias token
            if ($User.Properties.displayname) {
                $anonymizedUser.Properties.displayname = ("{0}_{1}" -f $script:ANONYMIZED_PREFIX_DISPLAY.TrimEnd('_'), $aliasToken)
            }

            # distinguishedName - anonymize OU/DC parts, then force leaf CN to match alias
            if ($User.Properties.distinguishedname) {
                # First anonymize the full DN (OU/DC and any non-leaf CNs)
                $anonDN = Get-AnonymizedOuPath $User.Properties.distinguishedname
                # Then replace ONLY the leaf CN to align with UPN/displayName
                $anonymizedUser.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN ("CN_{0}" -f $aliasToken)
            }

            # Email anonymization - correlate with domain
            if ($User.Properties.email) {
                $email = $User.Properties.email
                if ($email -match '^(.+?)@(.+)$') {
                    $localPart = $script:ANONYMIZED_PREFIX_EMAIL + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)

                    # Correlate email domain with AD domain
                    # Use the anonymized AD domain directly for realism
                    # Example: DOMAIN1.LOCAL -> user@domain1.local
                    $anonDomain = Get-AnonymizedDomain $originalDomain
                    $emailDomain = $anonDomain.ToLower()

                    $anonymizedUser.Properties.email = "$localPart@$emailDomain"
                }
            }
        }

        if ($User.Properties.description -and $User.Properties.samaccountname -notin $script:WELL_KNOWN_USERS) {
            $anonymizedUser.Properties.description = $null
        }

        # SPNs
        if ($User.Properties.serviceprincipalnames -and $User.Properties.serviceprincipalnames.Count -gt 0) {
            $anonymizedUser.Properties.serviceprincipalnames = @($User.Properties.serviceprincipalnames | ForEach-Object {
                Get-AnonymizedSPN $_
            })
        }

        # Object identifier
        if ($User.ObjectIdentifier) {
            $anonymizedUser.ObjectIdentifier = Get-AnonymizedDomainSid $User.ObjectIdentifier
        }

        # Process relationships
        Process-ObjectRelationships -Object $User -AnonymizedObject $anonymizedUser

        return $anonymizedUser
    }
    catch {
        Write-ScriptLog "Error anonymizing user: $_" -Level Error
        throw
    }
}

function Get-AnonymizedGroup {
    [CmdletBinding()]
    param($Group)

    try {
        $anonymizedGroup = Copy-ObjectDeep $Group

        # Track original properties for mapping
        $originalSAM = $Group.Properties.samaccountname
        $originalDomain = $Group.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $Group -AnonymizedObject $anonymizedGroup -OriginalDomain $originalDomain

        # Check if this is a well-known group (preserve as-is)
        $isWellKnownGroup = $false
        if ($Group.Properties.samaccountname) {
            $isWellKnownGroup = Test-WellKnownGroup $Group.Properties.samaccountname
            if ($isWellKnownGroup) {
                $script:PreservedItems.Groups[$Group.Properties.samaccountname] = "Well-known group (matched regex pattern)"
            }
        }

        # Check for Exchange/special groups (starting with $) - handle separately
        $isExchangeGroup = $false
        if ($Group.Properties.samaccountname -and $Group.Properties.samaccountname -match '^\$') {
            $isExchangeGroup = $true
        }

        if (-not $isWellKnownGroup -and -not $isExchangeGroup) {
            # Build a single alias token for name, sAMAccountName, and DN leaf CN
            $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG

            # Group name (UPN format)
            if ($Group.Properties.name) {
                $origName = $Group.Properties.name
                if ($origName -match '^(.+?)@(.+)$') {
                    $domainPart = $matches[2]
                    $anonDomain = Get-AnonymizedDomain $domainPart
                    $anonymizedGroup.Properties.name = ("GROUP_{0}@{1}" -f $aliasToken, $anonDomain).ToUpper()
                } else {
                    $anonymizedGroup.Properties.name = "GROUP_" + $aliasToken
                }
            }

            # sAMAccountName - use same alias token
            if ($Group.Properties.samaccountname) {
                $anonSAM = $script:ANONYMIZED_PREFIX_GROUP + $aliasToken
                $anonymizedGroup.Properties.samaccountname = $anonSAM
                if ($originalSAM) {
                    $script:GroupMapping[$originalSAM] = $anonSAM
                }
            }

            # distinguishedName - anonymize OU/DC parts, then force leaf CN to match alias
            if ($Group.Properties.distinguishedname) {
                # First anonymize the full DN (OU/DC and any non-leaf CNs)
                $anonDN = Get-AnonymizedOuPath $Group.Properties.distinguishedname
                # Then replace ONLY the leaf CN to align with name/sAMAccountName
                $anonymizedGroup.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN ("CN_{0}" -f $aliasToken)
            }
        } elseif ($isExchangeGroup) {
            # Keep Exchange/special groups format (any group starting with $)
            # Examples: $D31000-NDAG01AAG0, $A31000-..., $xxxxxxxx-xxxx-xxxx...
            $anonSAM = '$' + (Get-RandomHex $script:HEX_LENGTH_MEDIUM) + '-' + (Get-RandomHex $script:HEX_LENGTH_XLONG)
            $anonymizedGroup.Properties.samaccountname = $anonSAM
        }

        # Description
        if ($Group.Properties.description) {
            $isWellKnown = Test-WellKnownGroup $Group.Properties.samaccountname
            if (-not $isWellKnown) {
                $anonymizedGroup.Properties.description = $null
            }
        }

        # Object identifier
        if ($Group.ObjectIdentifier) {
            $anonymizedGroup.ObjectIdentifier = Get-AnonymizedDomainSid $Group.ObjectIdentifier
        }

        # Process relationships
        Process-ObjectRelationships -Object $Group -AnonymizedObject $anonymizedGroup

        return $anonymizedGroup
    }
    catch {
        Write-ScriptLog "Error anonymizing group: $_" -Level Error
        throw
    }
}

function Get-AnonymizedComputer {
    [CmdletBinding()]
    param($Computer)

    try {
        $anonymizedComputer = Copy-ObjectDeep $Computer

        # Track original properties for mapping
        $originalName = $Computer.Properties.name
        $originalDomain = $Computer.Properties.domain

        # Generate consistent computer name
        $computerBaseName = $null
        if ($originalName) {
            # Extract computer name without domain
            if ($originalName -match '^(.+?)\.') {
                $computerName = $matches[1]
            } else {
                $computerName = $originalName
            }

            $computerNameUpper = $computerName.ToUpper()

            # Check if it's a DC
            if ($computerName -match '^(DC\d+|RODC\d+)$') {
                $computerBaseName = $computerName
                $script:PreservedItems.Computers[$computerName] = "Domain Controller pattern (DC\d+|RODC\d+)"
            } else {
                if (-not $script:ComputerMapping.ContainsKey($computerNameUpper)) {
                    $script:ComputerMapping[$computerNameUpper] = $script:ANONYMIZED_PREFIX_COMPUTER + (Get-RandomHex $script:HEX_LENGTH_LONG)
                }
                $computerBaseName = $script:ComputerMapping[$computerNameUpper]
            }
        }

        # Process standard properties
        Process-StandardDomainProperties -Object $Computer -AnonymizedObject $anonymizedComputer -OriginalDomain $originalDomain

        # Computer identity fields - use shared alias for name, sAMAccountName, and DN leaf CN
        if ($Computer.Properties.name -and $computerBaseName) {
            $anonDomain = Get-AnonymizedDomain $originalDomain
            # BloodHound expects computer names in UPPERCASE format
            $anonymizedComputer.Properties.name = "$($computerBaseName.ToUpper()).$($anonDomain.ToUpper())"
        }

        if ($Computer.Properties.samaccountname -and $computerBaseName) {
            # sAMAccountName for computers ends with $ (strip it from base name, then re-add)
            $anonymizedComputer.Properties.samaccountname = "$($computerBaseName.ToUpper())$"
        }

        # distinguishedName - anonymize OU/DC parts, then force leaf CN to match computer alias
        if ($Computer.Properties.distinguishedname -and $computerBaseName) {
            # First anonymize the full DN (OU/DC and any non-leaf CNs)
            $anonDN = Get-AnonymizedOuPath $Computer.Properties.distinguishedname
            # Then replace ONLY the leaf CN to align with name/sAMAccountName
            $anonymizedComputer.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN $computerBaseName.ToUpper()
        }

        # Operating system
        if ($Computer.Properties.operatingsystem) {
            $anonymizedComputer.Properties.operatingsystem = Get-AnonymizedOS $Computer.Properties.operatingsystem
        }

        # SPNs
        if ($Computer.Properties.serviceprincipalnames -and $Computer.Properties.serviceprincipalnames.Count -gt 0) {
            $anonymizedComputer.Properties.serviceprincipalnames = @($Computer.Properties.serviceprincipalnames | ForEach-Object {
                Get-AnonymizedSPN $_
            })
        }

        # Allowed to delegate
        if ($Computer.Properties.allowedtodelegate -and $Computer.Properties.allowedtodelegate.Count -gt 0) {
            $anonymizedComputer.Properties.allowedtodelegate = @($Computer.Properties.allowedtodelegate | ForEach-Object {
                Get-AnonymizedSPN $_
            })
        }

        # Object identifier
        if ($Computer.ObjectIdentifier) {
            $anonymizedComputer.ObjectIdentifier = Get-AnonymizedDomainSid $Computer.ObjectIdentifier
        }

        # Process Sessions
        # NOTE: Sessions, PrivilegedSessions, RegistrySessions can be either a single object OR an array
        # We must preserve the original structure (BloodHound expects single object, not array)
        foreach ($sessionType in @('Sessions', 'PrivilegedSessions', 'RegistrySessions')) {
            if ($Computer.$sessionType) {
                $isArray = $Computer.$sessionType -is [array]

                if ($isArray) {
                    # Original is an array - process each item
                    $anonymizedComputer.$sessionType = @($Computer.$sessionType | ForEach-Object {
                        try {
                            $session = Copy-ObjectDeep $_
                            if ($session.Results) {
                                $session.Results = @($session.Results | ForEach-Object {
                                    $result = $_
                                    if ($result.UserSID) {
                                        $result.UserSID = Get-AnonymizedDomainSid $result.UserSID
                                    }
                                    if ($result.ComputerSID) {
                                        $result.ComputerSID = Get-AnonymizedDomainSid $result.ComputerSID
                                    }
                                    $result
                                })
                            }
                            $session
                        }
                        catch {
                            Write-ScriptLog "Error processing session: $_" -Level Warning
                            $_
                        }
                    })
                } else {
                    # Original is a single object - keep as single object
                    $session = Copy-ObjectDeep $Computer.$sessionType
                    if ($session.Results) {
                        $session.Results = @($session.Results | ForEach-Object {
                            $result = $_
                            if ($result.UserSID) {
                                $result.UserSID = Get-AnonymizedDomainSid $result.UserSID
                            }
                            if ($result.ComputerSID) {
                                $result.ComputerSID = Get-AnonymizedDomainSid $result.ComputerSID
                            }
                            $result
                        })
                    }
                    $anonymizedComputer.$sessionType = $session
                }
            }
        }

        # Process LocalGroups
        if ($Computer.LocalGroups -and $Computer.LocalGroups.Count -gt 0) {
            $anonymizedComputer.LocalGroups = @($Computer.LocalGroups | ForEach-Object {
                try {
                    $localGroup = Copy-ObjectDeep $_
                    if ($localGroup.ObjectIdentifier) {
                        $localGroup.ObjectIdentifier = Process-ACEPrincipalSID $localGroup.ObjectIdentifier
                    }
                    if ($localGroup.Results -and $localGroup.Results.Count -gt 0) {
                        $localGroup.Results = @($localGroup.Results | ForEach-Object {
                            $result = Copy-ObjectDeep $_
                            if ($result.ObjectIdentifier) {
                                $result.ObjectIdentifier = Get-AnonymizedDomainSid $result.ObjectIdentifier
                            }
                            if ($result.Name) {
                                $result.Name = "LocalMember_" + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                            }
                            $result
                        })
                    }
                    $localGroup
                }
                catch {
                    Write-ScriptLog "Error processing local group: $_" -Level Warning
                    $_
                }
            })
        }

        # Process UserRights
        if ($Computer.UserRights -and $Computer.UserRights.Count -gt 0) {
            $anonymizedComputer.UserRights = @($Computer.UserRights | ForEach-Object {
                try {
                    $right = Copy-ObjectDeep $_
                    if ($right.Results -and $right.Results.Count -gt 0) {
                        $right.Results = @($right.Results | ForEach-Object {
                            $result = Copy-ObjectDeep $_
                            if ($result.ObjectIdentifier) {
                                $result.ObjectIdentifier = Get-AnonymizedDomainSid $result.ObjectIdentifier
                            }
                            if ($result.Name) {
                                $result.Name = "Principal_" + (Get-RandomHex $script:HEX_LENGTH_MEDIUM)
                            }
                            $result
                        })
                    }
                    $right
                }
                catch {
                    Write-ScriptLog "Error processing user right: $_" -Level Warning
                    $_
                }
            })
        }

        # Process DumpSMSAPassword
        if ($Computer.DumpSMSAPassword -and $Computer.DumpSMSAPassword.Count -gt 0) {
            $anonymizedComputer.DumpSMSAPassword = @($Computer.DumpSMSAPassword | ForEach-Object {
                try {
                    $dump = Copy-ObjectDeep $_
                    if ($dump.ObjectIdentifier) {
                        $dump.ObjectIdentifier = Get-AnonymizedDomainSid $dump.ObjectIdentifier
                    }
                    $dump
                }
                catch {
                    Write-ScriptLog "Error processing SMSA password dump: $_" -Level Warning
                    $_
                }
            })
        }

        # Process relationships
        Process-ObjectRelationships -Object $Computer -AnonymizedObject $anonymizedComputer

        return $anonymizedComputer
    }
    catch {
        Write-ScriptLog "Error anonymizing computer: $_" -Level Error
        throw
    }
}

function Get-AnonymizedDomainObject {
    [CmdletBinding()]
    param($Domain)

    try {
        $anonymizedDomain = Copy-ObjectDeep $Domain

        # Track original domain name
        $originalDomainName = $Domain.Properties.domain

        # Domain properties
        if ($Domain.Properties.domain) {
            $anonymizedDomain.Properties.domain = Get-AnonymizedDomain $Domain.Properties.domain
        }

        if ($Domain.Properties.name) {
            $anonymizedDomain.Properties.name = Get-AnonymizedDomain $Domain.Properties.name
        }

        if ($Domain.Properties.domainsid) {
            $origDomainSid = $Domain.Properties.domainsid
            $anonymizedDomain.Properties.domainsid = Get-AnonymizedDomainSid $origDomainSid

            # Map the domain SID to domain name
            if ($originalDomainName) {
                $script:DomainSidToDomain[$origDomainSid] = $originalDomainName
            }
        }

        if ($Domain.Properties.distinguishedname) {
            $anonymizedDomain.Properties.distinguishedname = Get-AnonymizedOuPath $Domain.Properties.distinguishedname
        }

        # Anonymize timestamp
        $objectId = if ($Domain.ObjectIdentifier) { $Domain.ObjectIdentifier } else { $Domain.Properties.domain }
        if ($Domain.Properties.whencreated) {
            $anonymizedDomain.Properties.whencreated = Get-AnonymizedTimestamp -Timestamp $Domain.Properties.whencreated -ObjectId $objectId
        }

        # Remove description
        if ($Domain.Properties.description) {
            $anonymizedDomain.Properties.description = $null
        }

        # Object identifier (domain SID)
        if ($Domain.ObjectIdentifier) {
            $anonymizedDomain.ObjectIdentifier = Get-AnonymizedDomainSid $Domain.ObjectIdentifier
        }

        # Process GPOChanges
        Process-GPOChanges -Object $Domain -AnonymizedObject $anonymizedDomain

        # Process Trusts
        if ($Domain.Trusts -and $Domain.Trusts.Count -gt 0) {
            $anonymizedDomain.Trusts = @($Domain.Trusts | ForEach-Object {
                try {
                    $trust = Copy-ObjectDeep $_

                    if ($trust.TargetDomainName) {
                        $trust.TargetDomainName = Get-AnonymizedDomain $trust.TargetDomainName
                    }

                    if ($trust.TargetDomainSid) {
                        $trust.TargetDomainSid = Get-AnonymizedDomainSid $trust.TargetDomainSid
                    }

                    $trust
                }
                catch {
                    Write-ScriptLog "Error processing trust: $_" -Level Warning
                    $_
                }
            })
        }

        # Process Links (GPO links)
        Process-GPOLinks -Object $Domain -AnonymizedObject $anonymizedDomain

        # Process relationships
        Process-ObjectRelationships -Object $Domain -AnonymizedObject $anonymizedDomain

        return $anonymizedDomain
    }
    catch {
        Write-ScriptLog "Error anonymizing domain: $_" -Level Error
        throw
    }
}

function Get-AnonymizedGPO {
    [CmdletBinding()]
    param($GPO)

    try {
        $anonymizedGPO = Copy-ObjectDeep $GPO

        # Extract GUID from distinguishedname for consistency (case-insensitive)
        $gpoGuid = $null
        if ($GPO.Properties.distinguishedname -match '(?i)CN=\{([A-F0-9\-]+)\}') {
            $gpoGuid = Get-AnonymizedGuid $matches[1]
        }

        $originalDomain = $GPO.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $GPO -AnonymizedObject $anonymizedGPO -OriginalDomain $originalDomain

        # GPO name - preserve well-known policy names
        if ($GPO.Properties.name) {
            $origName = $GPO.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $policyPart = $matches[1]
                $domainPart = $matches[2]

                $isWellKnown = $policyPart -in $script:WELL_KNOWN_GPOS

                if (-not $isWellKnown) {
                    $policyPart = $script:ANONYMIZED_PREFIX_GPO + (Get-RandomHex $script:HEX_LENGTH_LONG)
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedGPO.Properties.name = "$policyPart@$anonDomain".ToUpper()
            }
        }

        # Distinguished name with consistent GUID (case-insensitive replace)
        if ($GPO.Properties.distinguishedname -and $gpoGuid) {
            $dn = $GPO.Properties.distinguishedname
            $anonDN = $dn -replace '(?i)\{[A-F0-9\-]+\}', "{$gpoGuid}"
            $anonymizedGPO.Properties.distinguishedname = Get-AnonymizedOuPath $anonDN
        }

        # GPC Path with consistent GUID (case-insensitive)
        if ($GPO.Properties.gpcpath -and $gpoGuid) {
            $path = $GPO.Properties.gpcpath
            if ($path -match '(?i)\\\\(.+?)\\SYSVOL\\(.+?)\\POLICIES\\(\{[A-F0-9\-]+\})') {
                $anonDomain = Get-AnonymizedDomain $matches[1]
                $anonymizedGPO.Properties.gpcpath = "\\$anonDomain\SYSVOL\$anonDomain\POLICIES\{$gpoGuid}"
            }
        }

        # Object identifier - use unified GUID mapping
        if ($GPO.ObjectIdentifier) {
            $anonymizedGPO.ObjectIdentifier = Get-AnonymizedGuid $GPO.ObjectIdentifier
        }

        # Process relationships
        Process-ObjectRelationships -Object $GPO -AnonymizedObject $anonymizedGPO

        return $anonymizedGPO
    }
    catch {
        Write-ScriptLog "Error anonymizing GPO: $_" -Level Error
        throw
    }
}

function Get-AnonymizedOU {
    [CmdletBinding()]
    param($OU)

    try {
        $anonymizedOU = Copy-ObjectDeep $OU

        # Track original OU name for mapping
        $originalDomain = $OU.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $OU -AnonymizedObject $anonymizedOU -OriginalDomain $originalDomain

        # OU name - preserve tier structure and well-known OUs
        if ($OU.Properties.name) {
            $origName = $OU.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $ouPart = $matches[1]
                $domainPart = $matches[2]

                $isWellKnown = $ouPart.ToUpper() -in $script:WELL_KNOWN_OUS

                if (-not $isWellKnown) {
                    if (-not $script:OuMapping.ContainsKey($ouPart)) {
                        $script:OuMapping[$ouPart] = $script:ANONYMIZED_PREFIX_OU + (Get-RandomHex $script:HEX_LENGTH_LONG)
                    }
                    $ouPart = $script:OuMapping[$ouPart]
                } else {
                    $ouPart = $ouPart.ToUpper()
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedOU.Properties.name = "$ouPart@$anonDomain".ToUpper()
            }
        }

        # Remove description unless it's a well-known OU
        if ($OU.Properties.description) {
            if ($OU.Properties.name -notmatch 'DOMAIN CONTROLLERS') {
                $anonymizedOU.Properties.description = $null
            }
        }

        # Object identifier (GUID)
        if ($OU.ObjectIdentifier) {
            $anonymizedOU.ObjectIdentifier = Get-AnonymizedGuid $OU.ObjectIdentifier
        }

        # Process GPOChanges
        Process-GPOChanges -Object $OU -AnonymizedObject $anonymizedOU

        # Process Links (GPO links)
        Process-GPOLinks -Object $OU -AnonymizedObject $anonymizedOU

        # Process relationships
        Process-ObjectRelationships -Object $OU -AnonymizedObject $anonymizedOU

        return $anonymizedOU
    }
    catch {
        Write-ScriptLog "Error anonymizing OU: $_" -Level Error
        throw
    }
}

function Get-AnonymizedContainer {
    <#
    .SYNOPSIS
        Anonymizes an Active Directory Container object.

    .DESCRIPTION
        Containers are organizational objects in AD (like USERS, COMPUTERS, SYSTEM).
        This function preserves well-known container names while anonymizing custom ones.
        Handles: Properties, Aces, ObjectIdentifier, ContainedBy relationships.

    .PARAMETER Container
        The container object to anonymize

    .OUTPUTS
        Anonymized container object with preserved structure
    #>
    [CmdletBinding()]
    param($Container)

    try {
        $anonymizedContainer = Copy-ObjectDeep $Container

        # Track original container name for mapping
        $originalDomain = $Container.Properties.domain

        # Process standard properties (domain, domainsid, distinguishedname, timestamps)
        Process-StandardDomainProperties -Object $Container -AnonymizedObject $anonymizedContainer -OriginalDomain $originalDomain

        # Container name - preserve well-known containers (USERS, COMPUTERS, SYSTEM, etc.)
        if ($Container.Properties.name) {
            $origName = $Container.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $containerPart = $matches[1]
                $domainPart = $matches[2]

                # List of well-known containers to preserve
                $wellKnownContainers = @(
                    'USERS', 'COMPUTERS', 'SYSTEM', 'FOREIGNSECURITYPRINCIPALS',
                    'PROGRAM DATA', 'MICROSOFT', 'KEYS', 'MANAGED SERVICE ACCOUNTS',
                    'MICROSOFTDNS', 'WINSOCKSERVICES', 'RPCSERVICES', 'MEETINGS',
                    'POLICIES', 'RAS AND IAS SERVERS ACCESS CHECK', 'IP SECURITY',
                    'ADMINSDHOLDER', 'COMPARTITIONS', 'COMPARTITIONSETS', 'WMIPOLICY',
                    'POLICYTEMPLATE', 'SOM', 'POLICYTYPE', 'WMIGPO', 'PSPS',
                    'SERVICES', 'QUERY-POLICIES', 'WINDOWS NT', 'NETSERVICES',
                    'OPTIONAL FEATURES', 'RRAS', 'PUBLIC KEY SERVICES',
                    'ENROLLMENT SERVICES', 'CERTIFICATE TEMPLATES', 'DIRECTORY SERVICE'
                )

                $isWellKnown = $containerPart.ToUpper() -in $wellKnownContainers

                if (-not $isWellKnown) {
                    if (-not $script:ContainerMapping) {
                        $script:ContainerMapping = @{}
                    }
                    if (-not $script:ContainerMapping.ContainsKey($containerPart)) {
                        $script:ContainerMapping[$containerPart] = $script:ANONYMIZED_PREFIX_OU + (Get-RandomHex $script:HEX_LENGTH_LONG)
                    }
                    $containerPart = $script:ContainerMapping[$containerPart]
                } else {
                    $containerPart = $containerPart.ToUpper()
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedContainer.Properties.name = "$containerPart@$anonDomain".ToUpper()
            }
        }

        # Object identifier (GUID)
        if ($Container.ObjectIdentifier) {
            $anonymizedContainer.ObjectIdentifier = Get-AnonymizedGuid $Container.ObjectIdentifier
        }

        # Process relationships (Aces, ContainedBy, ChildObjects)
        Process-ObjectRelationships -Object $Container -AnonymizedObject $anonymizedContainer

        return $anonymizedContainer
    }
    catch {
        Write-ScriptLog "Error anonymizing Container: $_" -Level Error
        throw
    }
}

function Get-AnonymizedCertTemplate {
    <#
    .SYNOPSIS
        Anonymizes an Active Directory Certificate Template object.

    .DESCRIPTION
        Certificate templates define the format and usage of certificates issued by CAs.
        This function preserves well-known templates (User, Computer, etc.) while anonymizing
        custom templates. Also anonymizes OIDs, display names, and certificate thumbprints.
        Critical for AD CS attack path analysis (ESC1-ESC13).

    .PARAMETER CertTemplate
        The certificate template object to anonymize

    .OUTPUTS
        Anonymized certificate template with preserved security settings
    #>
    [CmdletBinding()]
    param($CertTemplate)

    try {
        $anonymizedCertTemplate = Copy-ObjectDeep $CertTemplate

        # Track original domain for SID mapping
        $originalDomain = $CertTemplate.Properties.domain

        # Process standard properties (domain, domainsid, distinguishedname, whencreated)
        Process-StandardDomainProperties -Object $CertTemplate -AnonymizedObject $anonymizedCertTemplate -OriginalDomain $originalDomain

        # List of well-known certificate template names to preserve
        $wellKnownTemplates = @(
            'SMARTCARDLOGON', 'SMARTCARDUSER', 'USER', 'MACHINE', 'DOMAINCONTROLLER',
            'WEBSERVER', 'ENROLLMENTAGENT', 'EXCHANGEUSER', 'EXCHANGESIGNATURE',
            'ADMINISTRATOR', 'IPSECINTERMEDIATEONLINE', 'IPSECINTERMEDIATEOFFLINE',
            'COMPUTER', 'CA', 'SUBORDINATECERTIFICATIONAUTHORITY', 'CROSSCERTIFICATIONAUTHORITY',
            'KEYPOLICYRECOVERYAGENT', 'USERSIGNATURE', 'CAEXCHANGE', 'CERTIFICATIONAUTHORITY',
            'DIRECTORYEMAILREPLICATION', 'DOMAINCONTROLLERAUTHENTICATION',
            'EKERECOVERY', 'EKEREQUEST', 'IPSECUSER', 'KERBAGENT', 'KERBEROS',
            'ROOTCERTIFICATIONAUTHORITY', 'SMARTCARDLOGONREQUIRED', 'TESTCERTIFICATE',
            'TRUSTLISTSIGNING', 'WORKSTATION'
        )

        # Check if this is a well-known template
        $isWellKnown = $false
        $templateNamePart = $null
        if ($CertTemplate.Properties.name -and $CertTemplate.Properties.name -match '^(.+?)@') {
            $templateNamePart = $matches[1]
            $isWellKnown = $templateNamePart.ToUpper() -in $wellKnownTemplates
        }

        if (-not $isWellKnown) {
            # Build a single alias token for name, displayname, and DN leaf CN
            $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG

            # Certificate template name
            if ($CertTemplate.Properties.name -and $CertTemplate.Properties.name -match '^(.+?)@(.+)$') {
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedCertTemplate.Properties.name = ("CERTTEMPLATE_{0}@{1}" -f $aliasToken, $anonDomain).ToUpper()
            }

            # Display name - use same alias token
            if ($CertTemplate.Properties.displayname) {
                $anonymizedCertTemplate.Properties.displayname = "Certificate Template " + $aliasToken
            }

            # distinguishedName - anonymize OU/DC parts, then force leaf CN to match alias
            if ($CertTemplate.Properties.distinguishedname) {
                # First anonymize the full DN (OU/DC and any non-leaf CNs)
                $anonDN = Get-AnonymizedOuPath $CertTemplate.Properties.distinguishedname
                # Then replace ONLY the leaf CN to align with name/displayname
                $anonymizedCertTemplate.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN $aliasToken
            }
        } else {
            # Preserve well-known template names
            if ($CertTemplate.Properties.name -and $CertTemplate.Properties.name -match '^(.+?)@(.+)$') {
                $templatePart = $matches[1].ToUpper()
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedCertTemplate.Properties.name = "$templatePart@$anonDomain".ToUpper()
            }
        }

        # OID - anonymize (unique identifier for certificate template)
        if ($CertTemplate.Properties.oid) {
            if (-not $script:OidMapping) {
                $script:OidMapping = @{}
            }
            $origOid = $CertTemplate.Properties.oid
            if (-not $script:OidMapping.ContainsKey($origOid)) {
                # Generate a fake OID in the format 1.3.6.1.4.1.311.21.8.X.X.X.X.X.X.X.X
                $oidParts = @()
                for ($i = 0; $i -lt 8; $i++) {
                    $oidParts += Get-Random -Minimum 1000000 -Maximum 9999999
                }
                $script:OidMapping[$origOid] = "1.3.6.1.4.1.311.21.8." + ($oidParts -join '.')
            }
            $anonymizedCertTemplate.Properties.oid = $script:OidMapping[$origOid]
        }

        # Remove description
        if ($CertTemplate.Properties.description) {
            $anonymizedCertTemplate.Properties.description = $null
        }

        # Object identifier (GUID)
        if ($CertTemplate.ObjectIdentifier) {
            $anonymizedCertTemplate.ObjectIdentifier = Get-AnonymizedGuid $CertTemplate.ObjectIdentifier
        }

        # Process relationships (Aces, ContainedBy)
        Process-ObjectRelationships -Object $CertTemplate -AnonymizedObject $anonymizedCertTemplate

        return $anonymizedCertTemplate
    }
    catch {
        Write-ScriptLog "Error anonymizing Certificate Template: $_" -Level Error
        throw
    }
}

function Get-AnonymizedNTAuthStore {
    <#
    .SYNOPSIS
        Anonymizes an NTAuthStore (NT Authentication Certificate Store) object.

    .DESCRIPTION
        NTAuthStores contain trusted root certificates for smart card/certificate authentication.
        This function anonymizes certificate thumbprints while preserving the trust relationships.
        Note: Has unique root-level DomainSID field (not just in Properties).

    .PARAMETER NTAuthStore
        The NTAuthStore object to anonymize

    .OUTPUTS
        Anonymized NTAuthStore with consistent certificate thumbprint mappings
    #>
    [CmdletBinding()]
    param($NTAuthStore)

    try {
        $anonymizedNTAuthStore = Copy-ObjectDeep $NTAuthStore

        # Track original domain for SID mapping
        $originalDomain = $NTAuthStore.Properties.domain

        # Process standard properties (domain, domainsid, distinguishedname, whencreated)
        Process-StandardDomainProperties -Object $NTAuthStore -AnonymizedObject $anonymizedNTAuthStore -OriginalDomain $originalDomain

        # NTAuthStore name - typically NTAUTHCERTIFICATES (standard well-known name)
        if ($NTAuthStore.Properties.name) {
            $origName = $NTAuthStore.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $storePart = $matches[1]
                $domainPart = $matches[2]

                # NTAUTHCERTIFICATES is the standard well-known name
                if ($storePart.ToUpper() -eq 'NTAUTHCERTIFICATES') {
                    $storePart = 'NTAUTHCERTIFICATES'
                } else {
                    # Unlikely, but handle custom names
                    if (-not $script:NTAuthStoreMapping) {
                        $script:NTAuthStoreMapping = @{}
                    }
                    if (-not $script:NTAuthStoreMapping.ContainsKey($storePart)) {
                        $script:NTAuthStoreMapping[$storePart] = "NTAUTHSTORE_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
                    }
                    $storePart = $script:NTAuthStoreMapping[$storePart]
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedNTAuthStore.Properties.name = "$storePart@$anonDomain".ToUpper()
            }
        }

        # Certificate thumbprints - anonymize (SHA1 hashes)
        if ($NTAuthStore.Properties.certthumbprints -and $NTAuthStore.Properties.certthumbprints.Count -gt 0) {
            if (-not $script:CertThumbprintMapping) {
                $script:CertThumbprintMapping = @{}
            }
            $anonymizedNTAuthStore.Properties.certthumbprints = @($NTAuthStore.Properties.certthumbprints | ForEach-Object {
                $origThumbprint = $_
                if (-not $script:CertThumbprintMapping.ContainsKey($origThumbprint)) {
                    # Generate a fake SHA1 thumbprint (40 hex characters)
                    $script:CertThumbprintMapping[$origThumbprint] = (Get-RandomHex 40).ToUpper()
                }
                $script:CertThumbprintMapping[$origThumbprint]
            })
        }

        # Remove description
        if ($NTAuthStore.Properties.description) {
            $anonymizedNTAuthStore.Properties.description = $null
        }

        # DomainSID - this is at the root level, not in Properties!
        if ($NTAuthStore.DomainSID) {
            $anonymizedNTAuthStore.DomainSID = Get-AnonymizedDomainSid $NTAuthStore.DomainSID
        }

        # Object identifier (GUID)
        if ($NTAuthStore.ObjectIdentifier) {
            $anonymizedNTAuthStore.ObjectIdentifier = Get-AnonymizedGuid $NTAuthStore.ObjectIdentifier
        }

        # Process relationships (Aces, ContainedBy)
        Process-ObjectRelationships -Object $NTAuthStore -AnonymizedObject $anonymizedNTAuthStore

        return $anonymizedNTAuthStore
    }
    catch {
        Write-ScriptLog "Error anonymizing NTAuthStore: $_" -Level Error
        throw
    }
}

function Get-AnonymizedAIACA {
    <#
    .SYNOPSIS
        Anonymizes an AIA CA (Authority Information Access Certificate Authority) object.

    .DESCRIPTION
        AIA CAs provide certificate chain information for validation purposes.
        This function anonymizes CA names and certificate thumbprints while preserving
        certificate chain relationships. Uses shared CertThumbprintMapping with NTAuthStores
        to maintain consistency across certificate references.

    .PARAMETER AIACA
        The AIA CA object to anonymize

    .OUTPUTS
        Anonymized AIA CA with consistent certificate chain mappings
    #>
    [CmdletBinding()]
    param($AIACA)

    try {
        $anonymizedAIACA = Copy-ObjectDeep $AIACA

        # Track original domain for SID mapping
        $originalDomain = $AIACA.Properties.domain

        # Process standard properties (domain, domainsid, distinguishedname, whencreated)
        Process-StandardDomainProperties -Object $AIACA -AnonymizedObject $anonymizedAIACA -OriginalDomain $originalDomain

        # AIACA name - typically includes CA hostname/name and domain
        if ($AIACA.Properties.name) {
            $origName = $AIACA.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $caNamePart = $matches[1]
                $domainPart = $matches[2]

                # Anonymize CA name
                if (-not $script:AIACANameMapping) {
                    $script:AIACANameMapping = @{}
                }
                if (-not $script:AIACANameMapping.ContainsKey($caNamePart)) {
                    $script:AIACANameMapping[$caNamePart] = "AIACA_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
                }
                $caNamePart = $script:AIACANameMapping[$caNamePart]

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedAIACA.Properties.name = "$caNamePart@$anonDomain".ToUpper()
            }
        }

        # Certificate thumbprint - anonymize (SHA1 hash)
        if ($AIACA.Properties.certthumbprint) {
            if (-not $script:CertThumbprintMapping) {
                $script:CertThumbprintMapping = @{}
            }
            $origThumbprint = $AIACA.Properties.certthumbprint
            if (-not $script:CertThumbprintMapping.ContainsKey($origThumbprint)) {
                # Generate a fake SHA1 thumbprint (40 hex characters)
                $script:CertThumbprintMapping[$origThumbprint] = (Get-RandomHex 40).ToUpper()
            }
            $anonymizedAIACA.Properties.certthumbprint = $script:CertThumbprintMapping[$origThumbprint]
        }

        # Certificate name - typically same as thumbprint
        if ($AIACA.Properties.certname) {
            if (-not $script:CertThumbprintMapping) {
                $script:CertThumbprintMapping = @{}
            }
            $origCertName = $AIACA.Properties.certname
            if (-not $script:CertThumbprintMapping.ContainsKey($origCertName)) {
                $script:CertThumbprintMapping[$origCertName] = (Get-RandomHex 40).ToUpper()
            }
            $anonymizedAIACA.Properties.certname = $script:CertThumbprintMapping[$origCertName]
        }

        # Certificate chain - array of thumbprints
        if ($AIACA.Properties.certchain -and $AIACA.Properties.certchain.Count -gt 0) {
            if (-not $script:CertThumbprintMapping) {
                $script:CertThumbprintMapping = @{}
            }
            $anonymizedAIACA.Properties.certchain = @($AIACA.Properties.certchain | ForEach-Object {
                $origThumbprint = $_
                if (-not $script:CertThumbprintMapping.ContainsKey($origThumbprint)) {
                    $script:CertThumbprintMapping[$origThumbprint] = (Get-RandomHex 40).ToUpper()
                }
                $script:CertThumbprintMapping[$origThumbprint]
            })
        }

        # Cross certificate pair - array of certificate data (if present)
        if ($AIACA.Properties.crosscertificatepair -and $AIACA.Properties.crosscertificatepair.Count -gt 0) {
            # Typically empty, but if present, would need anonymization
            # For now, preserve the structure but anonymize if needed
            $anonymizedAIACA.Properties.crosscertificatepair = @($AIACA.Properties.crosscertificatepair | ForEach-Object {
                # If these are thumbprints or certificate data, anonymize them
                if ($_ -match '^[A-F0-9]{40}$') {
                    if (-not $script:CertThumbprintMapping.ContainsKey($_)) {
                        $script:CertThumbprintMapping[$_] = (Get-RandomHex 40).ToUpper()
                    }
                    $script:CertThumbprintMapping[$_]
                } else {
                    $_
                }
            })
        }

        # Remove description
        if ($AIACA.Properties.description) {
            $anonymizedAIACA.Properties.description = $null
        }

        # Object identifier (GUID)
        if ($AIACA.ObjectIdentifier) {
            $anonymizedAIACA.ObjectIdentifier = Get-AnonymizedGuid $AIACA.ObjectIdentifier
        }

        # Process relationships (Aces, ContainedBy)
        Process-ObjectRelationships -Object $AIACA -AnonymizedObject $anonymizedAIACA

        return $anonymizedAIACA
    }
    catch {
        Write-ScriptLog "Error anonymizing AIACA: $_" -Level Error
        throw
    }
}

function Get-AnonymizedRootCA {
    [CmdletBinding()]
    param($CA)

    try {
        $anonymizedCA = Copy-ObjectDeep $CA

        # Track original domain
        $originalDomain = $CA.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $CA -AnonymizedObject $anonymizedCA -OriginalDomain $originalDomain

        # Build a single alias token for CA name and DN leaf CN
        $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG
        $caAlias = $null

        # CA name
        if ($CA.Properties.name -and $CA.Properties.name -match '^(.+?)@(.+)$') {
            $caPart = $matches[1]
            $domainPart = $matches[2]

            # Check if it contains DC name pattern (preserve DC naming)
            if ($caPart -match '(.+)-(DC\d+)-CA') {
                $prefix = $matches[1]
                $dcPart = $matches[2]

                $anonPrefix = Get-AnonymizedDomain $prefix
                $anonPrefix = ($anonPrefix -split '\.')[0].ToUpper()

                $caAlias = "$anonPrefix-$dcPart-CA"
            } else {
                # Use unified alias token
                $caAlias = $script:ANONYMIZED_PREFIX_CA + $aliasToken
            }

            $anonDomain = Get-AnonymizedDomain $domainPart
            $anonymizedCA.Properties.name = "$caAlias@$anonDomain".ToUpper()
        }

        # Distinguished name - force leaf CN to match CA alias
        if ($CA.Properties.distinguishedname -and $caAlias) {
            # First anonymize the full DN (OU/DC and any non-leaf CNs)
            $anonDN = Get-AnonymizedOuPath $CA.Properties.distinguishedname
            # Then replace ONLY the leaf CN to align with CA name
            $anonymizedCA.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN $caAlias
        }

        # Certificate properties - anonymize but keep format
        if ($CA.Properties.certthumbprint) {
            if (-not $script:CAMapping.ContainsKey("THUMB_" + $CA.Properties.certthumbprint)) {
                $script:CAMapping["THUMB_" + $CA.Properties.certthumbprint] = (Get-RandomHex $script:HEX_LENGTH_THUMBPRINT).ToUpper()
            }
            $anonymizedCA.Properties.certthumbprint = $script:CAMapping["THUMB_" + $CA.Properties.certthumbprint]
        }

        if ($CA.Properties.certname) {
            $anonymizedCA.Properties.certname = $anonymizedCA.Properties.certthumbprint
        }

        if ($CA.Properties.certchain -and $CA.Properties.certchain.Count -gt 0) {
            $anonymizedCA.Properties.certchain = @($anonymizedCA.Properties.certthumbprint)
        }

        # Remove description
        if ($CA.Properties.description) {
            $anonymizedCA.Properties.description = $null
        }

        # DomainSID (separate from Properties.domainsid)
        if ($CA.DomainSID) {
            $anonymizedCA.DomainSID = Get-AnonymizedDomainSid $CA.DomainSID
        }

        # Object identifier (GUID)
        if ($CA.ObjectIdentifier) {
            $anonymizedCA.ObjectIdentifier = Get-AnonymizedGuid $CA.ObjectIdentifier
        }

        # Process relationships
        Process-ObjectRelationships -Object $CA -AnonymizedObject $anonymizedCA

        return $anonymizedCA
    }
    catch {
        Write-ScriptLog "Error anonymizing root CA: $_" -Level Error
        throw
    }
}

function Get-AnonymizedEnterpriseCA {
    [CmdletBinding()]
    param($CA)

    try {
        $anonymizedCA = Copy-ObjectDeep $CA

        # Track original domain
        $originalDomain = $CA.Properties.domain

        # Process standard properties
        Process-StandardDomainProperties -Object $CA -AnonymizedObject $anonymizedCA -OriginalDomain $originalDomain

        # Build a single alias token for CA name, caname, and DN leaf CN
        $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG
        $caAlias = $null

        # CA name - preserve pattern
        if ($CA.Properties.name -and $CA.Properties.name -match '^(.+?)@(.+)$') {
            $caPart = $matches[1]
            $domainPart = $matches[2]

            # Check for DC or SRV pattern (preserve DC/server naming)
            if ($caPart -match '(.+?)-(DC\d+|SRV-.+)-CA') {
                $prefix = $matches[1]
                $serverPart = $matches[2]

                $anonPrefix = Get-AnonymizedDomain $prefix
                $anonPrefix = ($anonPrefix -split '\.')[0].ToUpper()

                # Handle SRV names
                if ($serverPart -match '^SRV-(.+)$') {
                    $srvName = $matches[1]
                    $srvNameUpper = $srvName.ToUpper()
                    if ($srvNameUpper -eq 'SHARPHOUND') {
                        $anonServerPart = "SRV-SHARPHOUND"
                    } else {
                        if (-not $script:HostnameMapping.ContainsKey("SRV-$srvNameUpper")) {
                            $script:HostnameMapping["SRV-$srvNameUpper"] = "SRV-" + (Get-RandomHex $script:HEX_LENGTH_LONG)
                        }
                        $anonServerPart = $script:HostnameMapping["SRV-$srvNameUpper"]
                    }
                } else {
                    $anonServerPart = $serverPart
                }

                $caAlias = "$anonPrefix-$anonServerPart-CA"
            } else {
                # Use unified alias token
                $caAlias = $script:ANONYMIZED_PREFIX_CA + $aliasToken
            }

            $anonDomain = Get-AnonymizedDomain $domainPart
            $anonymizedCA.Properties.name = "$caAlias@$anonDomain".ToUpper()
        }

        # CA display name (caname property) - use same alias
        if ($CA.Properties.caname -and $caAlias) {
            $anonymizedCA.Properties.caname = $caAlias.ToLower()
        }

        # DNS hostname
        if ($CA.Properties.dnshostname) {
            $hostname = $CA.Properties.dnshostname
            if ($hostname -match '^([^.]+)\.(.+)$') {
                $hostPart = $matches[1]
                $domainPart = $matches[2]

                $hostPartUpper = $hostPart.ToUpper()

                # Check hostname mapping
                if ($script:HostnameMapping.ContainsKey($hostPartUpper)) {
                    $anonHost = $script:HostnameMapping[$hostPartUpper]
                } elseif ($hostPart -match '^DC\d+$') {
                    $anonHost = $hostPart
                } elseif ($hostPartUpper -eq 'SRV-SHARPHOUND') {
                    $anonHost = 'SRV-SHARPHOUND'
                } else {
                    $anonHost = $script:ANONYMIZED_PREFIX_HOSTNAME + (Get-RandomHex $script:HEX_LENGTH_LONG)
                    $script:HostnameMapping[$hostPartUpper] = $anonHost
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedCA.Properties.dnshostname = "$anonHost.$anonDomain".ToLower()
            }
        }

        # Distinguished name - force leaf CN to match CA alias
        if ($CA.Properties.distinguishedname -and $caAlias) {
            # First anonymize the full DN (OU/DC and any non-leaf CNs)
            $anonDN = Get-AnonymizedOuPath $CA.Properties.distinguishedname
            # Then replace ONLY the leaf CN to align with CA name
            $anonymizedCA.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN $caAlias
        }

        # Certificate properties
        if ($CA.Properties.certthumbprint) {
            if (-not $script:CAMapping.ContainsKey("THUMB_" + $CA.Properties.certthumbprint)) {
                $script:CAMapping["THUMB_" + $CA.Properties.certthumbprint] = (Get-RandomHex $script:HEX_LENGTH_THUMBPRINT).ToUpper()
            }
            $anonymizedCA.Properties.certthumbprint = $script:CAMapping["THUMB_" + $CA.Properties.certthumbprint]
        }

        if ($CA.Properties.certname) {
            $anonymizedCA.Properties.certname = $anonymizedCA.Properties.certthumbprint
        }

        if ($CA.Properties.certchain -and $CA.Properties.certchain.Count -gt 0) {
            $anonymizedCA.Properties.certchain = @()
            foreach ($cert in $CA.Properties.certchain) {
                if (-not $script:CAMapping.ContainsKey("THUMB_$cert")) {
                    $script:CAMapping["THUMB_$cert"] = (Get-RandomHex $script:HEX_LENGTH_THUMBPRINT).ToUpper()
                }
                $anonymizedCA.Properties.certchain += $script:CAMapping["THUMB_$cert"]
            }
        }

        # Remove description
        if ($CA.Properties.description) {
            $anonymizedCA.Properties.description = $null
        }

        # Hosting Computer
        if ($CA.HostingComputer) {
            $anonymizedCA.HostingComputer = Get-AnonymizedDomainSid $CA.HostingComputer
        }

        # CA Registry Data
        if ($CA.CARegistryData) {
            $anonRegData = Copy-ObjectDeep $CA.CARegistryData

            # Process CASecurity
            if ($anonRegData.CASecurity.Data -and $anonRegData.CASecurity.Data.Count -gt 0) {
                $anonRegData.CASecurity.Data = @($anonRegData.CASecurity.Data | ForEach-Object {
                    try {
                        Process-ACEWithNames $_
                    }
                    catch {
                        Write-ScriptLog "Error processing CA security: $_" -Level Warning
                        $_
                    }
                })
            }

            $anonymizedCA.CARegistryData = $anonRegData
        }

        # Enabled Certificate Templates
        if ($CA.EnabledCertTemplates -and $CA.EnabledCertTemplates.Count -gt 0) {
            $anonymizedCA.EnabledCertTemplates = @($CA.EnabledCertTemplates | ForEach-Object {
                try {
                    $template = Copy-ObjectDeep $_
                    if ($template.ObjectIdentifier) {
                        $template.ObjectIdentifier = Get-AnonymizedGuid $template.ObjectIdentifier
                    }
                    $template
                }
                catch {
                    Write-ScriptLog "Error processing certificate template: $_" -Level Warning
                    $_
                }
            })
        }

        # Object identifier (GUID)
        if ($CA.ObjectIdentifier) {
            $anonymizedCA.ObjectIdentifier = Get-AnonymizedGuid $CA.ObjectIdentifier
        }

        # Process relationships
        Process-ObjectRelationships -Object $CA -AnonymizedObject $anonymizedCA

        return $anonymizedCA
    }
    catch {
        Write-ScriptLog "Error anonymizing enterprise CA: $_" -Level Error
        throw
    }
}

#endregion

#region File Processing Functions

function Process-UsersFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing users file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        # Validate structure
        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($user in $data.data) {
            if ($user.Properties.domain -and -not (Test-WellKnownDomain $user.Properties.domain)) {
                $null = Get-AnonymizedDomain $user.Properties.domain
            }
            if ($user.Properties.domainsid -and $user.Properties.domain) {
                $script:DomainSidToDomain[$user.Properties.domainsid] = $user.Properties.domain
            }
        }

        # Second pass: process users
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($user in $data.data) {
            try {
                $anonUser = Get-AnonymizedUser $user
                $anonymized.data += $anonUser
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize user: $_" -Level Warning
            }
        }

        # Write without BOM
        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount users" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing users file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-GroupsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing groups file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($group in $data.data) {
            if ($group.Properties.domain -and -not (Test-WellKnownDomain $group.Properties.domain)) {
                $null = Get-AnonymizedDomain $group.Properties.domain
            }
            if ($group.Properties.domainsid -and $group.Properties.domain) {
                $script:DomainSidToDomain[$group.Properties.domainsid] = $group.Properties.domain
            }
        }

        # Second pass: process groups
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($group in $data.data) {
            try {
                $anonGroup = Get-AnonymizedGroup $group
                $anonymized.data += $anonGroup
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize group: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount groups" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing groups file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-ComputersFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing computers file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($computer in $data.data) {
            if ($computer.Properties.domain -and -not (Test-WellKnownDomain $computer.Properties.domain)) {
                $null = Get-AnonymizedDomain $computer.Properties.domain
            }
            if ($computer.Properties.domainsid -and $computer.Properties.domain) {
                $script:DomainSidToDomain[$computer.Properties.domainsid] = $computer.Properties.domain
            }
        }

        # Second pass: process computers
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $computerMappingBefore = $script:ComputerMapping.Count
        $processedCount = 0
        foreach ($computer in $data.data) {
            try {
                $anonComputer = Get-AnonymizedComputer $computer
                $anonymized.data += $anonComputer
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize computer: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        $computerMappingAfter = $script:ComputerMapping.Count
        $anonymizedCount = $computerMappingAfter - $computerMappingBefore
        $preservedCount = $processedCount - $anonymizedCount
        Write-ScriptLog "Processed $processedCount computers ($anonymizedCount anonymized, $preservedCount preserved)" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing computers file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-DomainsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing domains file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($domain in $data.data) {
            if ($domain.Properties.domain -and -not (Test-WellKnownDomain $domain.Properties.domain)) {
                $null = Get-AnonymizedDomain $domain.Properties.domain
            }
            if ($domain.Properties.domainsid -and $domain.Properties.domain) {
                $script:DomainSidToDomain[$domain.Properties.domainsid] = $domain.Properties.domain
            }
        }

        # Second pass: process domains
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($domain in $data.data) {
            try {
                $anonDomain = Get-AnonymizedDomainObject $domain
                $anonymized.data += $anonDomain
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize domain: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount domains" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing domains file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-GPOsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing GPOs file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($gpo in $data.data) {
            if ($gpo.Properties.domain -and -not (Test-WellKnownDomain $gpo.Properties.domain)) {
                $null = Get-AnonymizedDomain $gpo.Properties.domain
            }
            if ($gpo.Properties.domainsid -and $gpo.Properties.domain) {
                $script:DomainSidToDomain[$gpo.Properties.domainsid] = $gpo.Properties.domain
            }
        }

        # Second pass: process GPOs
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($gpo in $data.data) {
            try {
                $anonGPO = Get-AnonymizedGPO $gpo
                $anonymized.data += $anonGPO
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize GPO: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount GPOs" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing GPOs file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-OUsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing OUs file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($ou in $data.data) {
            if ($ou.Properties.domain -and -not (Test-WellKnownDomain $ou.Properties.domain)) {
                $null = Get-AnonymizedDomain $ou.Properties.domain
            }
            if ($ou.Properties.domainsid -and $ou.Properties.domain) {
                $script:DomainSidToDomain[$ou.Properties.domainsid] = $ou.Properties.domain
            }
        }

        # Second pass: process OUs
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($ou in $data.data) {
            try {
                $anonOU = Get-AnonymizedOU $ou
                $anonymized.data += $anonOU
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize OU: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount OUs" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing OUs file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-ContainersFile {
    <#
    .SYNOPSIS
        Processes and anonymizes a BloodHound containers.json file.

    .DESCRIPTION
        Two-pass processing:
        1. First pass: Collect all domain names and SIDs for consistent mapping
        2. Second pass: Anonymize each container object using Get-AnonymizedContainer

        Preserves: Well-known container names, ACL structure, relationships
        Anonymizes: Custom container names, GUIDs, domain names

    .PARAMETER FilePath
        Path to the input containers.json file

    .PARAMETER OutputPath
        Path where the anonymized file will be saved
    #>
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing Containers file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings for consistent anonymization across all containers
        foreach ($container in $data.data) {
            if ($container.Properties.domain -and -not (Test-WellKnownDomain $container.Properties.domain)) {
                $null = Get-AnonymizedDomain $container.Properties.domain
            }
            if ($container.Properties.domainsid -and $container.Properties.domain) {
                $script:DomainSidToDomain[$container.Properties.domainsid] = $container.Properties.domain
            }
        }

        # Second pass: process containers
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($container in $data.data) {
            try {
                $anonContainer = Get-AnonymizedContainer $container
                $anonymized.data += $anonContainer
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize container: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount Containers" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing Containers file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-CertTemplatesFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing Certificate Templates file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($template in $data.data) {
            if ($template.Properties.domain -and -not (Test-WellKnownDomain $template.Properties.domain)) {
                $null = Get-AnonymizedDomain $template.Properties.domain
            }
            if ($template.Properties.domainsid -and $template.Properties.domain) {
                $script:DomainSidToDomain[$template.Properties.domainsid] = $template.Properties.domain
            }
        }

        # Second pass: process certificate templates
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($template in $data.data) {
            try {
                $anonTemplate = Get-AnonymizedCertTemplate $template
                $anonymized.data += $anonTemplate
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize certificate template: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount Certificate Templates" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing Certificate Templates file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-NTAuthStoresFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing NTAuthStores file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($store in $data.data) {
            if ($store.Properties.domain -and -not (Test-WellKnownDomain $store.Properties.domain)) {
                $null = Get-AnonymizedDomain $store.Properties.domain
            }
            if ($store.Properties.domainsid -and $store.Properties.domain) {
                $script:DomainSidToDomain[$store.Properties.domainsid] = $store.Properties.domain
            }
            # Also track DomainSID at root level
            if ($store.DomainSID -and $store.Properties.domain) {
                $script:DomainSidToDomain[$store.DomainSID] = $store.Properties.domain
            }
        }

        # Second pass: process NTAuthStores
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($store in $data.data) {
            try {
                $anonStore = Get-AnonymizedNTAuthStore $store
                $anonymized.data += $anonStore
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize NTAuthStore: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount NTAuthStores" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing NTAuthStores file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-AIACAsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing AIA CAs file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($aiaca in $data.data) {
            if ($aiaca.Properties.domain -and -not (Test-WellKnownDomain $aiaca.Properties.domain)) {
                $null = Get-AnonymizedDomain $aiaca.Properties.domain
            }
            if ($aiaca.Properties.domainsid -and $aiaca.Properties.domain) {
                $script:DomainSidToDomain[$aiaca.Properties.domainsid] = $aiaca.Properties.domain
            }
        }

        # Second pass: process AIA CAs
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($aiaca in $data.data) {
            try {
                $anonAIACA = Get-AnonymizedAIACA $aiaca
                $anonymized.data += $anonAIACA
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize AIA CA: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount AIA CAs" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing AIA CAs file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-RootCAsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing Root CAs file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($ca in $data.data) {
            if ($ca.Properties.domain -and -not (Test-WellKnownDomain $ca.Properties.domain)) {
                $null = Get-AnonymizedDomain $ca.Properties.domain
            }
            if ($ca.Properties.domainsid -and $ca.Properties.domain) {
                $script:DomainSidToDomain[$ca.Properties.domainsid] = $ca.Properties.domain
            }
        }

        # Second pass: process root CAs
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($ca in $data.data) {
            try {
                $anonCA = Get-AnonymizedRootCA $ca
                $anonymized.data += $anonCA
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize root CA: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount Root CAs" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing Root CAs file '$FilePath': $_" -Level Error
        throw
    }
}

function Process-EnterpriseCAsFile {
    [CmdletBinding()]
    param([string]$FilePath, [string]$OutputPath)

    try {
        Write-ScriptLog "Processing Enterprise CAs file: $FilePath" -Level Info
        $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop
        $data = ConvertFrom-SafeJson $jsonContent

        if (-not $data.data) {
            throw "Invalid JSON structure: missing 'data' property"
        }

        # First pass: collect domain mappings
        foreach ($ca in $data.data) {
            if ($ca.Properties.domain -and -not (Test-WellKnownDomain $ca.Properties.domain)) {
                $null = Get-AnonymizedDomain $ca.Properties.domain
            }
            if ($ca.Properties.domainsid -and $ca.Properties.domain) {
                $script:DomainSidToDomain[$ca.Properties.domainsid] = $ca.Properties.domain
            }
        }

        # Second pass: process enterprise CAs
        $anonymized = [ordered]@{
            data = @()
            meta = $data.meta
        }

        $processedCount = 0
        foreach ($ca in $data.data) {
            try {
                $anonCA = Get-AnonymizedEnterpriseCA $ca
                $anonymized.data += $anonCA
                $processedCount++
            }
            catch {
                Write-ScriptLog "Failed to anonymize enterprise CA: $_" -Level Warning
            }
        }

        # Update meta.count to match actual data count
        if ($anonymized.meta) {
            $anonymized.meta.count = $anonymized.data.Count
        }
        $jsonOutput = $anonymized | ConvertTo-SafeJson
        [System.IO.File]::WriteAllText($OutputPath, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Anonymized $processedCount Enterprise CAs" -Level Success
    }
    catch {
        Write-ScriptLog "Error processing Enterprise CAs file '$FilePath': $_" -Level Error
        throw
    }
}

function Get-FileTypeFromName {
    [CmdletBinding()]
    param([string]$FileName)

    # Relaxed pattern matching - allows files with or without timestamps
    if ($FileName -match 'users\.json$') { return 'users' }
    if ($FileName -match 'groups\.json$') { return 'groups' }
    if ($FileName -match 'computers\.json$') { return 'computers' }
    if ($FileName -match 'domains\.json$') { return 'domains' }
    if ($FileName -match 'gpos\.json$') { return 'gpos' }
    if ($FileName -match 'ous\.json$') { return 'ous' }
    if ($FileName -match 'containers\.json$') { return 'containers' }
    if ($FileName -match 'certtemplates\.json$') { return 'certtemplates' }
    if ($FileName -match 'ntauthstores\.json$') { return 'ntauthstores' }
    if ($FileName -match 'aiacas\.json$') { return 'aiacas' }
    if ($FileName -match 'rootcas\.json$') { return 'rootcas' }
    if ($FileName -match 'enterprisecas\.json$') { return 'enterprisecas' }

    return $null
}

#endregion

#region Domain Mapping Functions

function Load-DomainMappings {
    if ($DomainMappingFile -and (Test-Path $DomainMappingFile)) {
        try {
            Write-ScriptLog "Loading domain mappings from $DomainMappingFile" -Level Info
            Get-Content $DomainMappingFile | ForEach-Object {
                if ($_ -match '^(.+?)=(.+)$') {
                    $script:DomainMapping[$matches[1]] = $matches[2]
                }
            }
            Write-ScriptLog "Loaded $($script:DomainMapping.Count) domain mappings" -Level Success
        }
        catch {
            Write-ScriptLog "Error loading domain mappings: $_" -Level Error
        }
    }
}

function Save-ComprehensiveMappings {
    [CmdletBinding()]
    param([string]$OutputPath)

    try {
        $mappingFile = Join-Path $OutputPath "anonymization_mappings.txt"
        $lines = @()

        # Header
        $lines += "# BloodHound Anonymization Mappings"
        $lines += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $lines += "# Format: OriginalValue=AnonymizedValue"
        $lines += ""

        # Domain Mappings
        if ($script:DomainMapping.Count -gt 0) {
            $lines += "## DOMAIN MAPPINGS ($($script:DomainMapping.Count) entries)"
            $lines += ""
            $script:DomainMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "DOMAIN: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # User Mappings
        if ($script:UserMapping.Count -gt 0) {
            $lines += "## USER MAPPINGS ($($script:UserMapping.Count) entries)"
            $lines += ""
            $script:UserMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "USER: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # Group Mappings
        if ($script:GroupMapping.Count -gt 0) {
            $lines += "## GROUP MAPPINGS ($($script:GroupMapping.Count) entries)"
            $lines += ""
            $script:GroupMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "GROUP: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # Computer Mappings
        if ($script:ComputerMapping.Count -gt 0) {
            $lines += "## COMPUTER MAPPINGS ($($script:ComputerMapping.Count) entries)"
            $lines += ""
            $script:ComputerMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "COMPUTER: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # Hostname Mappings (from SPNs)
        if ($script:HostnameMapping.Count -gt 0) {
            $lines += "## HOSTNAME MAPPINGS ($($script:HostnameMapping.Count) entries)"
            $lines += ""
            $script:HostnameMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "HOSTNAME: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # OU Mappings
        if ($script:OuMapping.Count -gt 0) {
            $lines += "## OU MAPPINGS ($($script:OuMapping.Count) entries)"
            $lines += ""
            $script:OuMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "OU: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # CN Mappings
        if ($script:CNMapping.Count -gt 0) {
            $lines += "## CN MAPPINGS ($($script:CNMapping.Count) entries)"
            $lines += ""
            $script:CNMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "CN: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # CA Mappings
        if ($script:CAMapping.Count -gt 0) {
            $lines += "## CA MAPPINGS ($($script:CAMapping.Count) entries)"
            $lines += ""
            $script:CAMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "CA: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # Domain SID Mappings
        if ($script:DomainSidMapping.Count -gt 0) {
            $lines += "## DOMAIN SID MAPPINGS ($($script:DomainSidMapping.Count) entries)"
            $lines += ""
            $script:DomainSidMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "SID: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # GUID Mappings
        if ($script:GuidMapping.Count -gt 0) {
            $lines += "## GUID MAPPINGS ($($script:GuidMapping.Count) entries)"
            $lines += ""
            $script:GuidMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "GUID: $($_.Key)=$($_.Value)"
            }
            $lines += ""
        }

        # SPN Mappings (sample - can be very large)
        if ($script:SPNMapping.Count -gt 0) {
            $lines += "## SPN MAPPINGS ($($script:SPNMapping.Count) entries)"
            $lines += ""
            # Limit to first 100 for readability, or save all
            $spnEntries = $script:SPNMapping.GetEnumerator() | Sort-Object Key
            if ($spnEntries.Count -gt 100) {
                $lines += "# Showing first 100 of $($spnEntries.Count) SPNs"
                $lines += ""
                $spnEntries | Select-Object -First 100 | ForEach-Object {
                    $lines += "SPN: $($_.Key)=$($_.Value)"
                }
                $lines += "# ... $($spnEntries.Count - 100) more SPNs omitted"
            } else {
                $spnEntries | ForEach-Object {
                    $lines += "SPN: $($_.Key)=$($_.Value)"
                }
            }
            $lines += ""
        }

        # Preserved Items Section
        $lines += "## PRESERVED ITEMS (Not Anonymized)"
        $lines += ""
        $lines += "# These items were intentionally preserved and not anonymized to maintain"
        $lines += "# attack path integrity and security analysis accuracy"
        $lines += ""

        $totalPreserved = 0

        # Preserved Computers
        if ($script:PreservedItems.Computers.Count -gt 0) {
            $lines += "### PRESERVED COMPUTERS ($($script:PreservedItems.Computers.Count) entries)"
            $lines += ""
            $script:PreservedItems.Computers.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "COMPUTER: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.Computers.Count
        }

        # Preserved Users
        if ($script:PreservedItems.Users.Count -gt 0) {
            $lines += "### PRESERVED USERS ($($script:PreservedItems.Users.Count) entries)"
            $lines += ""
            $script:PreservedItems.Users.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "USER: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.Users.Count
        }

        # Preserved Groups
        if ($script:PreservedItems.Groups.Count -gt 0) {
            $lines += "### PRESERVED GROUPS ($($script:PreservedItems.Groups.Count) entries)"
            $lines += ""
            $script:PreservedItems.Groups.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "GROUP: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.Groups.Count
        }

        # Preserved OUs
        if ($script:PreservedItems.OUs.Count -gt 0) {
            $lines += "### PRESERVED OUS ($($script:PreservedItems.OUs.Count) entries)"
            $lines += ""
            $script:PreservedItems.OUs.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "OU: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.OUs.Count
        }

        # Preserved CNs
        if ($script:PreservedItems.CNs.Count -gt 0) {
            $lines += "### PRESERVED CNS ($($script:PreservedItems.CNs.Count) entries)"
            $lines += ""
            $script:PreservedItems.CNs.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "CN: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.CNs.Count
        }

        # Preserved Domains
        if ($script:PreservedItems.Domains.Count -gt 0) {
            $lines += "### PRESERVED DOMAINS ($($script:PreservedItems.Domains.Count) entries)"
            $lines += ""
            $script:PreservedItems.Domains.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $lines += "DOMAIN: $($_.Key) - Reason: $($_.Value)"
            }
            $lines += ""
            $totalPreserved += $script:PreservedItems.Domains.Count
        }

        $lines += "TOTAL PRESERVED ITEMS: $totalPreserved"
        $lines += ""

        # Summary
        $lines += "## SUMMARY"
        $lines += ""

        # Calculate total items anonymized
        $totalItems = $script:DomainMapping.Count +
                     $script:UserMapping.Count +
                     $script:GroupMapping.Count +
                     $script:ComputerMapping.Count +
                     $script:HostnameMapping.Count +
                     $script:OuMapping.Count +
                     $script:CNMapping.Count +
                     $script:CAMapping.Count +
                     $script:DomainSidMapping.Count +
                     $script:GuidMapping.Count +
                     $script:SPNMapping.Count

        $lines += "TOTAL ITEMS ANONYMIZED: $totalItems"
        $lines += ""
        $lines += "Breakdown:"
        $lines += "  Domains: $($script:DomainMapping.Count)"
        $lines += "  Users: $($script:UserMapping.Count)"
        $lines += "  Groups: $($script:GroupMapping.Count)"
        $lines += "  Computers: $($script:ComputerMapping.Count)"
        $lines += "  Hostnames: $($script:HostnameMapping.Count)"
        $lines += "  OUs: $($script:OuMapping.Count)"
        $lines += "  CNs: $($script:CNMapping.Count)"
        $lines += "  CAs: $($script:CAMapping.Count)"
        $lines += "  Domain SIDs: $($script:DomainSidMapping.Count)"
        $lines += "  GUIDs: $($script:GuidMapping.Count)"
        $lines += "  SPNs: $($script:SPNMapping.Count)"
        $lines += ""
        if ($RandomizeTimestamps) {
            $lines += "Timestamp Randomization: ENABLED"
            $lines += "  Base Time Offset: $($script:BaseTimeOffset) days"
            $lines += "  WARNING: Timestamps have been randomized and may not reflect accurate temporal relationships"
        } else {
            $lines += "Timestamp Randomization: DISABLED (timestamps preserved)"
        }

        [System.IO.File]::WriteAllLines($mappingFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Comprehensive mappings saved to: $mappingFile" -Level Success
    }
    catch {
        Write-ScriptLog "Error saving comprehensive mappings: $_" -Level Error
    }
}

function Save-ErrorLog {
    [CmdletBinding()]
    param([string]$OutputPath)

    if ($script:ErrorLog.Count -gt 0) {
        try {
            $errorLogFile = Join-Path $OutputPath "anonymization_errors.log"
            [System.IO.File]::WriteAllLines($errorLogFile, $script:ErrorLog, (New-Object System.Text.UTF8Encoding($false)))
            Write-ScriptLog "Error log saved to: $errorLogFile" -Level Warning
        }
        catch {
            Write-ScriptLog "Failed to save error log: $_" -Level Error
        }
    }
}

function Organize-OutputAndCreateZip {
    [CmdletBinding()]
    param([string]$OutputPath)

    try {
        Write-Host "`n" -NoNewline
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Organizing Output Files" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        # Create AnonymizedData subfolder
        $anonymizedDataFolder = Join-Path $OutputPath "AnonymizedData"
        if (-not (Test-Path $anonymizedDataFolder)) {
            New-Item -ItemType Directory -Path $anonymizedDataFolder -Force | Out-Null
        }

        # Get all anonymized files and mapping files
        $anonymizedFiles = Get-ChildItem -Path $OutputPath -Filter "ANONYMIZED_*.json" -File -ErrorAction SilentlyContinue
        $mappingFile = Get-ChildItem -Path $OutputPath -Filter "anonymization_mappings.txt" -File -ErrorAction SilentlyContinue
        $errorLogFile = Get-ChildItem -Path $OutputPath -Filter "anonymization_errors.log" -File -ErrorAction SilentlyContinue

        # Move anonymized JSON files to AnonymizedData folder
        if ($anonymizedFiles) {
            Write-Host "📁 Moving anonymized JSON files to AnonymizedData folder..." -ForegroundColor Yellow
            foreach ($file in $anonymizedFiles) {
                $destination = Join-Path $anonymizedDataFolder $file.Name
                Move-Item -Path $file.FullName -Destination $destination -Force
                Write-Host "   ✓ $($file.Name)" -ForegroundColor Gray
            }
        }

        # Move mapping file to AnonymizedData folder
        if ($mappingFile) {
            Write-Host "📄 Moving mapping file to AnonymizedData folder..." -ForegroundColor Yellow
            $destination = Join-Path $anonymizedDataFolder $mappingFile.Name
            Move-Item -Path $mappingFile.FullName -Destination $destination -Force
            Write-Host "   ✓ $($mappingFile.Name)" -ForegroundColor Gray
        }

        # Move error log if it exists
        if ($errorLogFile) {
            Write-Host "📝 Moving error log to AnonymizedData folder..." -ForegroundColor Yellow
            $destination = Join-Path $anonymizedDataFolder $errorLogFile.Name
            Move-Item -Path $errorLogFile.FullName -Destination $destination -Force
            Write-Host "   ✓ $($errorLogFile.Name)" -ForegroundColor Gray
        }

        Write-Host ""

        # Create ZIP archive
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $zipFileName = "AnonymizedData_$timestamp.zip"
        $zipFilePath = Join-Path $OutputPath $zipFileName

        Write-Host "📦 Creating ZIP archive..." -ForegroundColor Yellow

        # Use .NET compression (works on PowerShell 5.1+)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($anonymizedDataFolder, $zipFilePath, 'Optimal', $false)

        Write-Host "   ✓ $zipFileName" -ForegroundColor Gray

        $zipSize = (Get-Item $zipFilePath).Length
        $zipSizeMB = [math]::Round($zipSize / 1MB, 2)
        Write-Host "   Size: $zipSizeMB MB" -ForegroundColor DarkGray

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        # Return paths for display
        return @{
            Folder = $anonymizedDataFolder
            ZipFile = $zipFilePath
            FileCount = ($anonymizedFiles.Count + 1) # +1 for mapping file
        }
    }
    catch {
        Write-ScriptLog "Error organizing output files: $_" -Level Error
        return $null
    }
}

#endregion

#region Main Execution

Write-Host "`nBloodHound Data Anonymization Script v10 - COMPREHENSIVE FIX" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null
        Write-ScriptLog "Created output directory: $OutputDirectory" -Level Success
    }
    catch {
        Write-ScriptLog "Failed to create output directory: $_" -Level Error
        exit 1
    }
}

# Load existing domain mappings if provided
Load-DomainMappings

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Initialize domain counter based on existing mappings (if loaded from file)
$script:domainCounter = $script:DomainMapping.Count

# Begin file processing
try {
    # ========================================================================
    # SINGLE FILE MODE
    # Process one BloodHound JSON file
    # ========================================================================
    if ($InputFile) {
        $fileName = Split-Path $InputFile -Leaf

        # Idempotence guard: skip already anonymized files
        if ($fileName -match '^ANONYMIZED_') {
            Write-ScriptLog "File '$fileName' appears to already be anonymized (starts with ANONYMIZED_). Skipping to avoid double-scrubbing." -Level Warning
            exit 0
        }

        # Determine file type
        $fileType = Get-FileTypeFromName $fileName

        if (-not $fileType) {
            Write-ScriptLog "Cannot determine file type for '$fileName'. Expected pattern: *users.json, *groups.json, etc." -Level Error
            exit 1
        }

        # Generate output name
        $outputFileName = $fileName -replace '\d{14}_', 'ANONYMIZED_'
        if ($outputFileName -eq $fileName) {
            $outputFileName = "ANONYMIZED_$fileName"
        }

        $outputPath = Join-Path $OutputDirectory $outputFileName

        # Process based on file type
        switch ($fileType) {
            'users' { Process-UsersFile -FilePath $InputFile -OutputPath $outputPath }
            'groups' { Process-GroupsFile -FilePath $InputFile -OutputPath $outputPath }
            'computers' { Process-ComputersFile -FilePath $InputFile -OutputPath $outputPath }
            'domains' { Process-DomainsFile -FilePath $InputFile -OutputPath $outputPath }
            'gpos' { Process-GPOsFile -FilePath $InputFile -OutputPath $outputPath }
            'ous' { Process-OUsFile -FilePath $InputFile -OutputPath $outputPath }
            'containers' { Process-ContainersFile -FilePath $InputFile -OutputPath $outputPath }
            'certtemplates' { Process-CertTemplatesFile -FilePath $InputFile -OutputPath $outputPath }
            'ntauthstores' { Process-NTAuthStoresFile -FilePath $InputFile -OutputPath $outputPath }
            'aiacas' { Process-AIACAsFile -FilePath $InputFile -OutputPath $outputPath }
            'rootcas' { Process-RootCAsFile -FilePath $InputFile -OutputPath $outputPath }
            'enterprisecas' { Process-EnterpriseCAsFile -FilePath $InputFile -OutputPath $outputPath }
        }
    }
    else {
        # ========================================================================
        # DIRECTORY MODE
        # Process all BloodHound JSON files in a directory
        # Group by collection timestamp to avoid merging separate collections
        # ========================================================================
        $allFiles = Get-ChildItem -Path $InputDirectory -Filter "*.json" | Where-Object {
            # Skip already anonymized files (idempotence guard)
            if ($_.Name -match '^ANONYMIZED_') {
                Write-ScriptLog "Skipping '$($_.Name)' (already anonymized)" -Level Info
                return $false
            }

            $fileType = Get-FileTypeFromName $_.Name
            $fileType -ne $null
        }

        if ($allFiles.Count -eq 0) {
            Write-ScriptLog "No BloodHound JSON files found in $InputDirectory" -Level Error
            exit 1
        }

        # Group files by collection timestamp
        # Expected format: YYYYMMDDHHMMSS_type.json (e.g., 20240305110427_users.json)
        $collections = @{}

        foreach ($file in $allFiles) {
            # Extract timestamp from filename
            if ($file.Name -match '^(\d{14})_') {
                $timestamp = $matches[1]
                if (-not $collections.ContainsKey($timestamp)) {
                    $collections[$timestamp] = @()
                }
                $collections[$timestamp] += $file
            }
            else {
                # Files without timestamp go into "default" collection
                if (-not $collections.ContainsKey('default')) {
                    $collections['default'] = @()
                }
                $collections['default'] += $file
            }
        }

        Write-ScriptLog "Found $($collections.Count) collection(s) with $($allFiles.Count) total files" -Level Success

        # Display collections found
        foreach ($collectionKey in ($collections.Keys | Sort-Object)) {
            $fileCount = $collections[$collectionKey].Count
            if ($collectionKey -eq 'default') {
                Write-ScriptLog "  - Collection: No timestamp ($fileCount files)" -Level Info
            }
            else {
                Write-ScriptLog "  - Collection: $collectionKey ($fileCount files)" -Level Info
            }
        }

        # Process each collection separately
        # NOTE: Mapping tables are SHARED across all collections to maintain consistency
        # (e.g., PHANTOM.CORP always maps to the same DOMAIN1.LOCAL in all collections)
        $collectionIndex = 0
        foreach ($collectionKey in ($collections.Keys | Sort-Object)) {
            $files = $collections[$collectionKey]
            $collectionIndex++

            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            if ($collectionKey -eq 'default') {
                Write-Host "  Processing Collection: No timestamp ($($files.Count) files)" -ForegroundColor Cyan
            }
            else {
                Write-Host "  Processing Collection: $collectionKey ($($files.Count) files)" -ForegroundColor Cyan
            }
            Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

            foreach ($file in $files) {
                $fileType = Get-FileTypeFromName $file.Name

                # Preserve the timestamp in the output filename to keep collections separate
                if ($collectionKey -eq 'default') {
                    $outputFileName = "ANONYMIZED_$($file.Name)"
                }
                else {
                    # Keep the timestamp: 20240305110427_users.json -> ANONYMIZED_20240305110427_users.json
                    $outputFileName = $file.Name -replace '^(\d{14}_)', 'ANONYMIZED_$1'
                }

                $outputPath = Join-Path $OutputDirectory $outputFileName

                switch ($fileType) {
                    'users' { Process-UsersFile -FilePath $file.FullName -OutputPath $outputPath }
                    'groups' { Process-GroupsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'computers' { Process-ComputersFile -FilePath $file.FullName -OutputPath $outputPath }
                    'domains' { Process-DomainsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'gpos' { Process-GPOsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'ous' { Process-OUsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'containers' { Process-ContainersFile -FilePath $file.FullName -OutputPath $outputPath }
                    'certtemplates' { Process-CertTemplatesFile -FilePath $file.FullName -OutputPath $outputPath }
                    'ntauthstores' { Process-NTAuthStoresFile -FilePath $file.FullName -OutputPath $outputPath }
                    'aiacas' { Process-AIACAsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'rootcas' { Process-RootCAsFile -FilePath $file.FullName -OutputPath $outputPath }
                    'enterprisecas' { Process-EnterpriseCAsFile -FilePath $file.FullName -OutputPath $outputPath }
                }
            }

            Write-Host ""
            Write-Host "✓ Collection $collectionKey processed" -ForegroundColor Green
        }
    }

    # ========================================================================
    # POST-PROCESSING
    # Save mapping files and display summary
    # ========================================================================

    # Save comprehensive mappings to file for reference and future runs
    # This will now include all collections if multiple were processed
    Save-ComprehensiveMappings -OutputPath $OutputDirectory

    # Save error log if any errors occurred during processing
    Save-ErrorLog -OutputPath $OutputDirectory

    # Organize output files and create ZIP archive
    $organizedOutput = Organize-OutputAndCreateZip -OutputPath $OutputDirectory

    # Display completion summary with statistics
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ✓ Anonymization Complete!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📊 Statistics:" -ForegroundColor Yellow
    Write-Host "   Domains mapped: $($script:DomainMapping.Count)" -ForegroundColor White
    Write-Host "   Users mapped: $($script:UserMapping.Count)" -ForegroundColor White
    Write-Host "   Groups mapped: $($script:GroupMapping.Count)" -ForegroundColor White
    Write-Host "   Computers mapped: $($script:ComputerMapping.Count)" -ForegroundColor White
    if ($RandomizeTimestamps) {
        Write-Host "   Timestamp randomization: ENABLED (offset: $($script:BaseTimeOffset) days)" -ForegroundColor Yellow
    } else {
        Write-Host "   Timestamp randomization: Disabled (timestamps preserved)" -ForegroundColor White
    }
    if ($PreserveOSVersions) {
        Write-Host "   OS version preservation: Enabled" -ForegroundColor White
    }
    if ($script:ErrorLog.Count -gt 0) {
        Write-Host "   ⚠️  Errors encountered: $($script:ErrorLog.Count) (see error log)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "📁 Output Locations:" -ForegroundColor Yellow
    if ($organizedOutput) {
        Write-Host "   Folder: $($organizedOutput.Folder)" -ForegroundColor White
        Write-Host "   ZIP Archive: $($organizedOutput.ZipFile)" -ForegroundColor White
        Write-Host "   Files: $($organizedOutput.FileCount) anonymized files + mapping" -ForegroundColor White
    } else {
        Write-Host "   Directory: $OutputDirectory" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "🎉 Ready to share! Your anonymized BloodHound data is in:" -ForegroundColor Green
    if ($organizedOutput) {
        Write-Host "   $($organizedOutput.ZipFile)" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: Keep the mapping file private - it contains the key" -ForegroundColor Yellow
    Write-Host "   to reverse the anonymization!" -ForegroundColor Yellow
    Write-Host ""
}
catch {
    # Handle any fatal errors that occur during processing
    Write-ScriptLog "Fatal error during processing: $_" -Level Error
    Save-ErrorLog -OutputPath $OutputDirectory
    exit 1
}

#endregion

# ============================================================================
# END OF SCRIPT
# ============================================================================
# Successfully anonymized BloodHound data while preserving attack paths
#
# Output files:
# - ANONYMIZED_*.json - Anonymized BloodHound data files
# - anonymization_mappings.txt - Comprehensive mapping reference
# - anonymization_errors.log - Error log (if any errors occurred)
#
# The anonymized data maintains all security relationships and can be
# safely imported into BloodHound for analysis without exposing PII
# ============================================================================
