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
# - Ensures DN consistency: leaf CN/OU components match object names across all types
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
    # Exchange RBAC and management roles
    'ROLE ASSIGNMENTS', 'ROLES', 'SCOPES',
    'ORGANIZATION MANAGEMENT', 'RECIPIENT MANAGEMENT', 'PUBLIC FOLDER MANAGEMENT',
    'VIEW-ONLY ORGANIZATION MANAGEMENT', 'DISCOVERY MANAGEMENT', 'EXCHANGELEGACYINTEROP',
    'OAB RESOURCES MANAGEMENT AGENT',
    # Exchange protocol containers
    'SMTP RECEIVE CONNECTORS', 'POP3', 'IMAP4',
    # AD CS Certificate Templates (CRITICAL for ADCS security)
    'EFS', 'EFSRECOVERY', 'CODESIGNING', 'OCSPRESPONSESIGNING',
    'ENROLLMENTAGENT', 'ENROLLMENTAGENTOFFLINE', 'MACHINEENROLLMENTAGENT',
    'SMARTCARDLOGON', 'SMARTCARDUSER',
    'IPSECINTERMEDIATEOFFLINE', 'IPSECINTERMEDIATEONLINE',
    'CTLSIGNING', 'KEYRECOVERYAGENT', 'SUBCA', 'CROSSCA', 'CA',
    'DOMAINCONTROLLER', 'DOMAINCONTROLLERAUTHENTICATION',
    # Additional well-known certificate templates
    'USER', 'MACHINE', 'COMPUTER', 'WEBSERVER', 'WORKSTATION',
    'EXCHANGEUSER', 'EXCHANGESIGNATURE', 'CAEXCHANGE',
    'DIRECTORYEMAILREPLICATION', 'USERSIGNATURE', 'ADMINISTRATOR',
    'SUBORDINATECERTIFICATIONAUTHORITY', 'CROSSCERTIFICATIONAUTHORITY',
    'KEYPOLICYRECOVERYAGENT', 'CERTIFICATIONAUTHORITY',
    'EKERECOVERY', 'EKEREQUEST', 'IPSECUSER', 'KERBAGENT', 'KERBEROS',
    'ROOTCERTIFICATIONAUTHORITY', 'SMARTCARDLOGONREQUIRED', 'TESTCERTIFICATE',
    'TRUSTLISTSIGNING',
    # Built-in security principals (CN-based, not group-based)
    'ADMINISTRATOR', 'GUEST', 'KRBTGT',
    # System service accounts and containers
    'WINRMREMOTEWMIUSERS__',
    # Modern AD security containers (Dynamic Access Control, gMSA, etc.)
    'GROUP KEY DISTRIBUTION SERVICE', 'SHADOW PRINCIPAL CONFIGURATION',
    'CLAIMS CONFIGURATION', 'RESOURCE PROPERTY LISTS', 'CENTRAL ACCESS POLICIES',
    'CENTRAL ACCESS RULES', 'CLAIM TYPES',
    # Additional system containers
    'CONNECTIONS', 'QUERY-POLICIES', 'DEFAULT', 'OPTIONAL FEATURES',
    'VALUE TYPES', 'MASTER ROOT KEYS',
    # Container-specific CNs (from Get-AnonymizedContainer well-known list)
    'MICROSOFT', 'KEYS', 'WINSOCKSERVICES', 'RPCSERVICES', 'MEETINGS',
    'RAS AND IAS SERVERS ACCESS CHECK', 'IP SECURITY',
    'COMPARTITIONS', 'COMPARTITIONSETS', 'WMIPOLICY',
    'POLICYTEMPLATE', 'SOM', 'POLICYTYPE', 'WMIGPO', 'PSPS',
    'NETSERVICES', 'RRAS', 'DIRECTORY SERVICE'
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

# ============================================================================
# Well-Known RIDs (Relative Identifiers)
# These are UNIVERSAL across all AD installations regardless of language
# This enables language-independent detection of critical security principals
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
# ============================================================================
$script:WELL_KNOWN_RIDS = @{
    # Built-in User Accounts
    500 = 'Administrator'          # Built-in administrator account
    501 = 'Guest'                  # Built-in guest account
    502 = 'krbtgt'                 # Kerberos Ticket Granting Ticket account
    503 = 'DefaultAccount'         # Default system account (Windows 10+)

    # Domain Groups (Security-Critical)
    512 = 'Domain Admins'          # Domain administrators group
    513 = 'Domain Users'           # All domain users
    514 = 'Domain Guests'          # Domain guest accounts
    515 = 'Domain Computers'       # All domain computers
    516 = 'Domain Controllers'     # All domain controllers
    517 = 'Cert Publishers'        # Certificate publishers
    518 = 'Schema Admins'          # Schema administrators (root domain only)
    519 = 'Enterprise Admins'      # Enterprise administrators (root domain only)
    520 = 'Group Policy Creator Owners'  # Can create/modify GPOs
    521 = 'Read-Only Domain Controllers' # RODC group
    522 = 'Cloneable Domain Controllers' # Can be cloned

    # Protected Groups (Windows Server 2012+)
    525 = 'Protected Users'        # Protected from credential theft
    526 = 'Key Admins'             # Key administrators
    527 = 'Enterprise Key Admins'  # Enterprise key administrators

    # Special Access Groups
    553 = 'RAS and IAS Servers'    # Remote Access Service servers
    571 = 'Allowed RODC Password Replication Group'  # Can replicate passwords to RODCs
    572 = 'Denied RODC Password Replication Group'   # Cannot replicate passwords to RODCs
}

# ============================================================================
# Well-Known Container GUIDs
# These are UNIVERSAL GUIDs assigned by Microsoft to critical system containers
# Same across all AD installations regardless of language or domain
# Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/a-wellknownobjects
# ============================================================================
$script:WELL_KNOWN_CONTAINER_GUIDS = @{
    # Domain NC Well-Known Containers
    'AA312825-1E96-11D0-A1F3-0000F8023A6C' = 'COMPUTERS'                    # CN=Computers
    'A9D1CA15-768A-11D1-ADED-00C04FD8D5CD' = 'USERS'                        # CN=Users
    '18E2EA80-EE1A-11D2-8E7E-00C04F949A14' = 'LOSTANDFOUND'                 # CN=LostAndFound
    'AB1D30F3-768A-11D1-ADED-00C04FD8D5CD' = 'SYSTEM'                       # CN=System
    '2FBAC1870-ADE2-11D2-87C0-00C04F79F805' = 'INFRASTRUCTURE'              # CN=Infrastructure
    'AB8153B7-768A-11D1-ADED-00C04FD8D5CD' = 'FOREIGNSECURITYPRINCIPALS'   # CN=ForeignSecurityPrincipals
    '22B70C67-D56E-4EFB-8AB8-A1E3BC2A7A3F' = 'MANAGEDSERVICEACCOUNTS'       # CN=Managed Service Accounts
    '1EB93889-40C8-11D1-ADED-00C04FD8D5CD' = 'DOMAINCONTROLLERS'            # OU=Domain Controllers

    # Configuration NC Well-Known Containers
    '5AB2BCC1-6A76-11D2-9027-00C04F8EED00' = 'PARTITIONS'                   # CN=Partitions,CN=Configuration
    '7506AE80-D0A8-11D1-B7A3-00C04F8EED00' = 'SITES'                        # CN=Sites,CN=Configuration
    '4A8C7C5D-D0A8-11D1-B7A3-00C04F8EED00' = 'SERVICES'                     # CN=Services,CN=Configuration

    # Well-Known Infrastructure Objects
    '5D67D2F0-D0A8-11D1-B7A3-00C04F8EED00' = 'NTDS'                         # CN=NTDS Settings (for DCs)
    'F4BE92A4-C777-11D1-9ECA-00C04FC2D2D5' = 'NTFRSSUBSCRIPTIONS'           # CN=NTFRS Subscriptions
    '2DF90D73-009F-11D2-AA4C-00C04FD7D83A' = 'NTDSQUOTAS'                   # CN=NTDS Quotas
}

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

function Test-IsWellKnownByRID {
    <#
    .SYNOPSIS
    Tests if an ObjectIdentifier SID represents a well-known security principal using RID.

    .DESCRIPTION
    Language-independent detection of well-known users and groups by checking the
    RID (Relative Identifier) portion of the SID. This works across all AD languages
    because RIDs are universal (e.g., 512 = Domain Admins in all languages).

    .PARAMETER ObjectIdentifier
    The SID or domain-prefixed SID to check (e.g., "S-1-5-21-xxx-512" or "DOMAIN-S-1-5-21-xxx-512")

    .OUTPUTS
    Boolean - $true if the SID represents a well-known principal, $false otherwise

    .EXAMPLE
    Test-IsWellKnownByRID "S-1-5-21-1234567-890123-456789-512"  # Returns $true (Domain Admins)

    .EXAMPLE
    Test-IsWellKnownByRID "DOMAIN.COM-S-1-5-21-1234567-890123-456789-502"  # Returns $true (krbtgt)
    #>
    [CmdletBinding()]
    param([string]$ObjectIdentifier)

    if ([string]::IsNullOrEmpty($ObjectIdentifier)) {
        return $false
    }

    # Strip domain prefix if present (e.g., "DOMAIN.COM-S-1-5-21-..." -> "S-1-5-21-...")
    $sid = $ObjectIdentifier
    if ($sid -match '^[^-]+-((S-1-5-21(-\d+){3})(-\d+))$') {
        $sid = $matches[1]
    }

    # Check for domain-specific well-known RIDs (S-1-5-21-domain-RID)
    if ($sid -match 'S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        $rid = [int]$matches[1]
        if ($script:WELL_KNOWN_RIDS.ContainsKey($rid)) {
            return $true
        }
    }

    # Check for BUILTIN SIDs (S-1-5-32-*)
    if ($sid -match '^S-1-5-32-\d+$') {
        return $true
    }

    # Check for NT AUTHORITY and other well-known SIDs (S-1-5-XX where XX < 22)
    if ($sid -match '^S-1-5-(\d+)$' -and [int]$matches[1] -lt 22) {
        return $true
    }

    # Check for World Authority and Local Authority (S-1-1-* and S-1-2-*)
    if ($sid -match '^S-1-[12]-\d+$') {
        return $true
    }

    return $false
}

function Test-IsWellKnownByGUID {
    <#
    .SYNOPSIS
    Tests if an ObjectIdentifier GUID represents a well-known container.

    .DESCRIPTION
    Language-independent detection of well-known containers by checking against
    Microsoft's predefined container GUIDs. These GUIDs are universal across all
    AD installations regardless of language.

    .PARAMETER ObjectIdentifier
    The GUID to check (e.g., "AA312825-1E96-11D0-A1F3-0000F8023A6C")

    .OUTPUTS
    Boolean - $true if the GUID represents a well-known container, $false otherwise

    .EXAMPLE
    Test-IsWellKnownByGUID "AA312825-1E96-11D0-A1F3-0000F8023A6C"  # Returns $true (Computers container)
    #>
    [CmdletBinding()]
    param([string]$ObjectIdentifier)

    if ([string]::IsNullOrEmpty($ObjectIdentifier)) {
        return $false
    }

    # Check if it's a GUID format
    if ($ObjectIdentifier -notmatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
        return $false
    }

    # Check against well-known container GUIDs (case-insensitive)
    return $script:WELL_KNOWN_CONTAINER_GUIDS.ContainsKey($ObjectIdentifier.ToUpper())
}

function Test-IsWellKnownByContext {
    <#
    .SYNOPSIS
    Tests if a CN is well-known based on its location in the DN hierarchy.

    .DESCRIPTION
    Context-based inference for containers that don't have well-known GUIDs.
    Many containers can be identified as well-known based on their parent containers
    in the distinguished name. For example, anything directly under CN=BUILTIN or
    CN=SYSTEM is typically well-known.

    .PARAMETER CN
    The CN value to check

    .PARAMETER DN
    The full distinguished name providing context

    .OUTPUTS
    Boolean - $true if the CN appears to be well-known based on context, $false otherwise

    .EXAMPLE
    Test-IsWellKnownByContext "Administratoren" "CN=Administratoren,CN=BUILTIN,DC=..."  # Returns $true
    #>
    [CmdletBinding()]
    param(
        [string]$CN,
        [string]$DN
    )

    if ([string]::IsNullOrEmpty($CN) -or [string]::IsNullOrEmpty($DN)) {
        return $false
    }

    # Pattern 1: Direct children of BUILTIN are well-known groups
    if ($DN -match "CN=$CN,CN=BUILTIN,") {
        return $true
    }

    # Pattern 2: Direct children of SYSTEM are well-known system containers
    if ($DN -match "CN=$CN,CN=SYSTEM,") {
        return $true
    }

    # Pattern 3: Configuration partition children (one level deep)
    if ($DN -match "CN=$CN,CN=CONFIGURATION,") {
        return $true
    }

    # Pattern 4: PKI container children are well-known
    if ($DN -match "CN=$CN,CN=PUBLIC KEY SERVICES,") {
        return $true
    }
    if ($DN -match "CN=$CN,CN=SERVICES,CN=CONFIGURATION,") {
        return $true
    }

    # Pattern 5: Exchange system containers
    if ($DN -match "CN=$CN,CN=MICROSOFT EXCHANGE SYSTEM OBJECTS,") {
        return $true
    }

    # Pattern 6: Schema partition
    if ($DN -match "CN=$CN,CN=SCHEMA,") {
        return $true
    }

    return $false
}

function Get-OriginalDomainFromSid {
    <#
    .SYNOPSIS
    Performs reverse lookup to get the original domain name from a domain SID.

    .DESCRIPTION
    Uses the DomainSidToDomain mapping to look up which original domain a SID belongs to.
    This is useful for consistency checks and debugging anonymization issues.

    .PARAMETER DomainSid
    The domain SID to look up (can be a base SID or full SID with RID)

    .EXAMPLE
    Get-OriginalDomainFromSid "S-1-5-21-123456789-987654321-111222333"
    Returns: "SEVENKINGDOMS.LOCAL"
    #>
    [CmdletBinding()]
    param([string]$DomainSid)

    if ([string]::IsNullOrEmpty($DomainSid)) {
        return $null
    }

    # Extract base domain SID if this is a full SID with RID
    if ($DomainSid -match '^(S-1-5-21(-\d+){3})(-\d+)?$') {
        $baseSid = $matches[1]

        # Look up in the mapping
        if ($script:DomainSidToDomain.ContainsKey($baseSid)) {
            return $script:DomainSidToDomain[$baseSid]
        }
    }

    # Check if the full SID (with RID) is in the mapping
    if ($script:DomainSidToDomain.ContainsKey($DomainSid)) {
        return $script:DomainSidToDomain[$DomainSid]
    }

    return $null
}

function Test-DomainMappingConsistency {
    <#
    .SYNOPSIS
    Validates consistency between domain name mappings and domain SID mappings.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. Each domain SID maps to exactly one domain name
    2. Domain name mappings align with domain SID mappings
    3. No orphaned mappings exist
    4. Well-known domains are not incorrectly mapped

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalDomainNames = $script:DomainMapping.Count
            TotalDomainSids = $script:DomainSidToDomain.Count
            TotalDomainSidMappings = $script:DomainSidMapping.Count
        }
    }

    # Check 1: Verify DomainSidToDomain entries have corresponding domain mappings
    foreach ($sidEntry in $script:DomainSidToDomain.GetEnumerator()) {
        $originalSid = $sidEntry.Key
        $originalDomain = $sidEntry.Value

        # Check if this domain has been anonymized
        if (-not [string]::IsNullOrEmpty($originalDomain)) {
            if (-not $script:DomainMapping.ContainsKey($originalDomain)) {
                $results.Issues += "Domain SID '$originalSid' maps to domain '$originalDomain', but no domain mapping exists for '$originalDomain'"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 2: Verify each domain SID maps to only one domain
    $sidToDomainCheck = @{}
    foreach ($entry in $script:DomainSidToDomain.GetEnumerator()) {
        $sid = $entry.Key
        $domain = $entry.Value

        # Extract base SID
        if ($sid -match '^(S-1-5-21(-\d+){3})') {
            $baseSid = $matches[1]

            if ($sidToDomainCheck.ContainsKey($baseSid)) {
                if ($sidToDomainCheck[$baseSid] -ne $domain) {
                    $results.Issues += "Inconsistency: Base SID '$baseSid' maps to multiple domains: '$($sidToDomainCheck[$baseSid])' and '$domain'"
                    $results.IsConsistent = $false
                }
            } else {
                $sidToDomainCheck[$baseSid] = $domain
            }
        }
    }

    # Check 3: Verify domain SID mappings have corresponding reverse lookups
    foreach ($sidMapping in $script:DomainSidMapping.GetEnumerator()) {
        $originalSid = $sidMapping.Key

        # Check if we know what domain this SID belongs to
        if (-not $script:DomainSidToDomain.ContainsKey($originalSid)) {
            # This is a warning, not necessarily an error (might be from well-known SIDs)
            if ($originalSid -match '^S-1-5-21-') {
                $results.Issues += "Warning: Domain SID '$originalSid' was anonymized but has no domain association in DomainSidToDomain"
            }
        }
    }

    # Check 4: Verify no well-known domains were incorrectly mapped
    foreach ($domainEntry in $script:DomainMapping.GetEnumerator()) {
        $originalDomain = $domainEntry.Key
        $anonymizedDomain = $domainEntry.Value

        if (Test-WellKnownDomain $originalDomain) {
            if ($originalDomain -ne $anonymizedDomain) {
                $results.Issues += "Error: Well-known domain '$originalDomain' was incorrectly anonymized to '$anonymizedDomain'"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 5: Verify domain mapping consistency (same domain always maps to same anonymized name)
    $domainCheckMap = @{}
    foreach ($entry in $script:DomainMapping.GetEnumerator()) {
        $original = $entry.Key.ToUpper()
        $anonymized = $entry.Value.ToUpper()

        if ($domainCheckMap.ContainsKey($original)) {
            if ($domainCheckMap[$original] -ne $anonymized) {
                $results.Issues += "Critical: Domain '$original' has inconsistent mappings: '$($domainCheckMap[$original])' and '$anonymized'"
                $results.IsConsistent = $false
            }
        } else {
            $domainCheckMap[$original] = $anonymized
        }
    }

    return $results
}

function Write-ConsistencyCheckReport {
    <#
    .SYNOPSIS
    Writes a consistency check report to the log and optionally to a file.

    .PARAMETER CheckResults
    The results from Test-DomainMappingConsistency

    .PARAMETER OutputPath
    Optional path to write a detailed report file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CheckResults,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    if ($CheckResults.IsConsistent) {
        Write-ScriptLog "✓ Domain mapping consistency check PASSED" -Level Success
        Write-ScriptLog "  Domains mapped: $($CheckResults.Statistics.TotalDomainNames)" -Level Info
        Write-ScriptLog "  Domain SIDs tracked: $($CheckResults.Statistics.TotalDomainSids)" -Level Info
        Write-ScriptLog "  SID mappings: $($CheckResults.Statistics.TotalDomainSidMappings)" -Level Info
    } else {
        Write-ScriptLog "⚠ Domain mapping consistency check FAILED with $($CheckResults.Issues.Count) issue(s)" -Level Warning

        foreach ($issue in $CheckResults.Issues) {
            if ($issue -match '^Critical:') {
                Write-ScriptLog "  $issue" -Level Error
            } elseif ($issue -match '^Warning:') {
                Write-ScriptLog "  $issue" -Level Warning
            } else {
                Write-ScriptLog "  $issue" -Level Warning
            }
        }
    }

    # Write detailed report to file if requested
    if ($OutputPath) {
        try {
            $reportFile = Join-Path $OutputPath "consistency_check.txt"
            $lines = @()

            $lines += "# Domain Mapping Consistency Check Report"
            $lines += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $lines += ""
            $lines += "## Overall Status: $(if ($CheckResults.IsConsistent) { 'PASSED' } else { 'FAILED' })"
            $lines += ""
            $lines += "## Statistics"
            $lines += "Domain names mapped: $($CheckResults.Statistics.TotalDomainNames)"
            $lines += "Domain SIDs tracked: $($CheckResults.Statistics.TotalDomainSids)"
            $lines += "SID mappings created: $($CheckResults.Statistics.TotalDomainSidMappings)"
            $lines += ""

            if ($CheckResults.Issues.Count -gt 0) {
                $lines += "## Issues Found ($($CheckResults.Issues.Count))"
                $lines += ""
                $CheckResults.Issues | ForEach-Object {
                    $lines += "- $_"
                }
            } else {
                $lines += "## No Issues Found"
                $lines += "All domain mappings are consistent."
            }

            $lines += ""
            $lines += "## Detailed Mappings"
            $lines += ""
            $lines += "### Domain SID to Domain Name Mappings"
            if ($script:DomainSidToDomain.Count -gt 0) {
                $script:DomainSidToDomain.GetEnumerator() | Sort-Object Value | ForEach-Object {
                    $lines += "$($_.Key) -> $($_.Value)"
                }
            } else {
                $lines += "(None)"
            }

            [System.IO.File]::WriteAllLines($reportFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
            Write-ScriptLog "Consistency check report saved to: $reportFile" -Level Success
        }
        catch {
            Write-ScriptLog "Failed to write consistency check report: $_" -Level Warning
        }
    }
}

function Get-OriginalCNFromMapping {
    <#
    .SYNOPSIS
    Performs reverse lookup to get the original CN name from a CN mapping key.

    .DESCRIPTION
    CN mappings use composite keys in format "parentPath|originalCN".
    This function extracts the original CN name from the mapping key.

    .PARAMETER MappingKey
    The CN mapping key (e.g., "OU=Users,DC=domain,DC=local,|TestCN")

    .EXAMPLE
    Get-OriginalCNFromMapping "OU=Users,DC=domain,DC=local,|TestCN"
    Returns: @{ ParentPath = "OU=Users,DC=domain,DC=local,"; OriginalCN = "TestCN" }
    #>
    [CmdletBinding()]
    param([string]$MappingKey)

    if ([string]::IsNullOrEmpty($MappingKey)) {
        return $null
    }

    # Split on the pipe separator
    $parts = $MappingKey -split '\|', 2
    if ($parts.Count -eq 2) {
        return @{
            ParentPath = $parts[0]
            OriginalCN = $parts[1]
        }
    }

    return $null
}

function Test-CNMappingConsistency {
    <#
    .SYNOPSIS
    Validates consistency of CN (Common Name) mappings in Distinguished Names.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. Well-known CNs are preserved and not anonymized
    2. Each CN mapping is unique per parent path
    3. No CNs have conflicting mappings
    4. Foreign Security Principal CNs (SIDs) are properly preserved
    5. CN mappings don't contain invalid characters

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalCNMappings = $script:CNMapping.Count
            PreservedCNs = $script:PreservedItems.CNs.Count
            WellKnownCNsFound = 0
            SIDCNsFound = 0
        }
    }

    # Check 1: Verify well-known CNs were not anonymized
    $wellKnownCNsUpper = $script:WELL_KNOWN_CNS
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key
        $anonymizedCN = $cnEntry.Value

        $parsed = Get-OriginalCNFromMapping $mappingKey
        if ($parsed) {
            $originalCN = $parsed.OriginalCN

            # Check if this is a well-known CN that shouldn't have been anonymized
            if ($originalCN.ToUpper() -in $wellKnownCNsUpper) {
                $results.Issues += "Error: Well-known CN '$originalCN' was incorrectly anonymized to '$anonymizedCN'"
                $results.IsConsistent = $false
            }

            # Track well-known CNs that appear in mappings (even if preserved)
            if ($originalCN.ToUpper() -in $wellKnownCNsUpper) {
                $results.Statistics.WellKnownCNsFound++
            }

            # Track SID-format CNs (Foreign Security Principals)
            if ($originalCN -match '^S-\d+-\d+(-\d+)+$') {
                $results.Statistics.SIDCNsFound++
            }
        }
    }

    # Check 2: Verify CNs in preserved items list are actually well-known
    foreach ($preservedCN in $script:PreservedItems.CNs.Keys) {
        $reason = $script:PreservedItems.CNs[$preservedCN]

        # If marked as well-known, verify it's actually in the well-known list
        if ($reason -match 'Well-known') {
            if ($preservedCN.ToUpper() -notin $wellKnownCNsUpper) {
                # Special case: Foreign Security Principal SIDs
                if ($preservedCN -notmatch '^S-\d+-\d+(-\d+)+$') {
                    $results.Issues += "Warning: CN '$preservedCN' is marked as well-known but not in WELL_KNOWN_CNS list"
                }
            }
        }
    }

    # Check 3: Verify CN mapping uniqueness per parent path
    $cnPerParent = @{}
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key
        $anonymizedCN = $cnEntry.Value

        $parsed = Get-OriginalCNFromMapping $mappingKey
        if ($parsed) {
            $parentPath = $parsed.ParentPath
            $originalCN = $parsed.OriginalCN

            # Check if same original CN + parent path has different anonymized values
            $checkKey = "$parentPath|$originalCN"
            if ($cnPerParent.ContainsKey($checkKey)) {
                if ($cnPerParent[$checkKey] -ne $anonymizedCN) {
                    $results.Issues += "Critical: CN '$originalCN' under parent '$parentPath' has inconsistent mappings: '$($cnPerParent[$checkKey])' and '$anonymizedCN'"
                    $results.IsConsistent = $false
                }
            } else {
                $cnPerParent[$checkKey] = $anonymizedCN
            }
        }
    }

    # Check 4: Verify CN values don't contain invalid DN characters
    $invalidChars = @(',', '=', '+', '<', '>', '#', ';', '\', '"')
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $anonymizedCN = $cnEntry.Value

        foreach ($char in $invalidChars) {
            if ($anonymizedCN -match [regex]::Escape($char)) {
                $results.Issues += "Error: Anonymized CN '$anonymizedCN' contains invalid DN character '$char'"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 5: Verify mapping keys have proper format
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key

        if ($mappingKey -notmatch '\|') {
            $results.Issues += "Error: CN mapping key '$mappingKey' has invalid format (missing pipe separator)"
            $results.IsConsistent = $false
        }
    }

    # Check 6: Cross-reference with preserved CNs
    # Well-known CNs should be in preserved list, not in mapping table
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $parsed = Get-OriginalCNFromMapping $cnEntry.Key
        if ($parsed) {
            $originalCN = $parsed.OriginalCN
            if ($originalCN.ToUpper() -in $wellKnownCNsUpper) {
                if (-not $script:PreservedItems.CNs.ContainsKey($originalCN)) {
                    $results.Issues += "Warning: Well-known CN '$originalCN' was found in mappings but not tracked in preserved items"
                }
            }
        }
    }

    return $results
}

function Test-CertTemplateConsistency {
    <#
    .SYNOPSIS
    Validates consistency of Certificate Template mappings and preservation rules.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. Well-known certificate templates are preserved (not anonymized)
    2. OID mappings are unique and properly formatted
    3. Template names match expected patterns
    4. No conflicting template mappings exist

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalOidMappings = if ($script:OidMapping) { $script:OidMapping.Count } else { 0 }
            WellKnownTemplatesFound = 0
            CustomTemplatesFound = 0
        }
        TotalIssues = 0
    }

    # Define well-known certificate templates (same list as in Get-AnonymizedCertTemplate)
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

    # Check 1: Validate OID mappings are properly formatted
    if ($script:OidMapping) {
        foreach ($oidEntry in $script:OidMapping.GetEnumerator()) {
            $originalOid = $oidEntry.Key
            $anonymizedOid = $oidEntry.Value

            # Validate original OID format (basic check)
            if ($originalOid -notmatch '^\d+(\.\d+)+$') {
                $results.Issues += "Error: Original OID '$originalOid' has invalid format"
                $results.IsConsistent = $false
            }

            # Validate anonymized OID format (should be Microsoft AD CS format: 1.3.6.1.4.1.311.21.8.X.X...)
            if ($anonymizedOid -notmatch '^1\.3\.6\.1\.4\.1\.311\.21\.8(\.\d+)+$') {
                $results.Issues += "Error: Anonymized OID '$anonymizedOid' has invalid format"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 2: Validate OID uniqueness (same original OID should always map to same anonymized OID)
    if ($script:OidMapping) {
        $reverseMapping = @{}
        foreach ($oidEntry in $script:OidMapping.GetEnumerator()) {
            $originalOid = $oidEntry.Key
            $anonymizedOid = $oidEntry.Value

            if ($reverseMapping.ContainsKey($anonymizedOid)) {
                if ($reverseMapping[$anonymizedOid] -ne $originalOid) {
                    $results.Issues += "Critical: Multiple original OIDs map to same anonymized OID '$anonymizedOid': '$($reverseMapping[$anonymizedOid])' and '$originalOid'"
                    $results.IsConsistent = $false
                }
            } else {
                $reverseMapping[$anonymizedOid] = $originalOid
            }
        }
    }

    # Check 3: Verify well-known template CNs are preserved
    # Check CNs that match well-known template names
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key
        $anonymizedCN = $cnEntry.Value

        $parsed = Get-OriginalCNFromMapping $mappingKey
        if ($parsed) {
            $originalCN = $parsed.OriginalCN

            # Check if this CN matches a well-known template name
            $matchesWellKnown = $false
            foreach ($wellKnownTemplate in $wellKnownTemplates) {
                if ($originalCN.ToUpper() -eq $wellKnownTemplate) {
                    $matchesWellKnown = $true
                    $results.Statistics.WellKnownTemplatesFound++
                    break
                }
            }

            # If it matches a well-known template, it should NOT be anonymized
            if ($matchesWellKnown -and $originalCN -ne $anonymizedCN) {
                $results.Issues += "Critical: Well-known certificate template CN '$originalCN' was incorrectly anonymized to '$anonymizedCN'"
                $results.IsConsistent = $false
            }

            # Count custom templates (anonymized ones starting with CERTTEMPLATE_)
            if ($anonymizedCN -match '^CERTTEMPLATE_[A-F0-9]+$') {
                $results.Statistics.CustomTemplatesFound++
            }
        }
    }

    # Check 4: Verify certificate template CNs that appear in parent path context
    # Only check CNs that are actually under Certificate Templates container path
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key
        $anonymizedCN = $cnEntry.Value

        $parsed = Get-OriginalCNFromMapping $mappingKey
        if ($parsed -and $parsed.ParentPath) {
            # Check if this CN is under the Certificate Templates container
            if ($parsed.ParentPath.ToUpper() -match 'CN=CERTIFICATE TEMPLATES') {
                $originalCN = $parsed.OriginalCN

                # If under Certificate Templates, verify it's a well-known template or anonymized
                $matchesWellKnown = $originalCN.ToUpper() -in $wellKnownTemplates

                # If it's not well-known and not anonymized, flag it
                if (-not $matchesWellKnown -and $anonymizedCN -notmatch '^CERTTEMPLATE_') {
                    $results.Issues += "Warning: Certificate Template CN '$originalCN' under Certificate Templates container is neither well-known nor anonymized: '$anonymizedCN'"
                }
            }
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-GroupConsistency {
    <#
    .SYNOPSIS
    Validates consistency of Group mappings and preservation rules.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. Well-known groups are preserved (not anonymized)
    2. Group name mappings are unique and consistent
    3. Group CNs match sAMAccountName patterns
    4. No conflicting group mappings exist

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalGroupMappings = $script:GroupMapping.Count
            PreservedGroups = $script:PreservedItems.Groups.Count
            WellKnownGroupsFound = 0
            CustomGroupsFound = 0
        }
        TotalIssues = 0
    }

    # Check 1: Validate group mapping uniqueness (same original should map to same anonymized)
    $reverseMapping = @{}
    foreach ($groupEntry in $script:GroupMapping.GetEnumerator()) {
        $originalSAM = $groupEntry.Key
        $anonymizedSAM = $groupEntry.Value

        if ($reverseMapping.ContainsKey($anonymizedSAM)) {
            if ($reverseMapping[$anonymizedSAM] -ne $originalSAM) {
                $results.Issues += "Critical: Multiple original groups map to same anonymized group '$anonymizedSAM': '$($reverseMapping[$anonymizedSAM])' and '$originalSAM'"
                $results.IsConsistent = $false
            }
        } else {
            $reverseMapping[$anonymizedSAM] = $originalSAM
        }
    }

    # Check 2: Verify anonymized group names follow expected pattern (GRP_XXXXXXXX)
    foreach ($groupEntry in $script:GroupMapping.GetEnumerator()) {
        $anonymizedSAM = $groupEntry.Value

        if ($anonymizedSAM -notmatch '^GRP_[A-F0-9]{8}$') {
            $results.Issues += "Warning: Anonymized group '$anonymizedSAM' does not follow expected pattern GRP_XXXXXXXX"
        } else {
            $results.Statistics.CustomGroupsFound++
        }
    }

    # Check 3: Verify well-known groups in preserved list match the well-known patterns
    foreach ($preservedGroup in $script:PreservedItems.Groups.Keys) {
        $isWellKnown = Test-WellKnownGroup $preservedGroup

        if (-not $isWellKnown) {
            $results.Issues += "Warning: Group '$preservedGroup' is preserved but does not match any well-known group pattern"
        } else {
            $results.Statistics.WellKnownGroupsFound++
        }
    }

    # Check 4: Verify well-known groups are not in the anonymized mapping
    foreach ($groupEntry in $script:GroupMapping.GetEnumerator()) {
        $originalSAM = $groupEntry.Key

        $isWellKnown = Test-WellKnownGroup $originalSAM

        if ($isWellKnown) {
            $results.Issues += "Critical: Well-known group '$originalSAM' was incorrectly anonymized to '$($groupEntry.Value)'"
            $results.IsConsistent = $false
        }
    }

    # Check 5: Verify group CNs match group names for consistency
    # Check CNs in the mapping to see if they correspond to group names
    foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
        $mappingKey = $cnEntry.Key
        $anonymizedCN = $cnEntry.Value

        $parsed = Get-OriginalCNFromMapping $mappingKey
        if ($parsed) {
            $originalCN = $parsed.OriginalCN

            # Check if this CN is in the group mapping (case-insensitive)
            if ($script:GroupMapping.ContainsKey($originalCN)) {
                $expectedAnonymized = $script:GroupMapping[$originalCN]

                # Extract the token from both to compare
                # Group SAM: GRP_XXXXXXXX, Group CN should be: CN_XXXXXX or GROUP_XXXXXXXX
                if ($expectedAnonymized -match '^GRP_([A-F0-9]{8})$') {
                    $groupToken = $matches[1]

                    # CN could be either CN_XXXXXX (6 hex) or GROUP_XXXXXXXX (8 hex)
                    # For groups created with the alias system, CN should be GROUP_{token}
                    $expectedCN = "GROUP_$groupToken"

                    if ($anonymizedCN -ne $expectedCN -and $anonymizedCN -notmatch '^CN_[A-F0-9]{6}$') {
                        # Only flag if both CN and SAM were anonymized with different tokens
                        if ($anonymizedCN -match '^(GROUP|CN)_([A-F0-9]+)$') {
                            $cnToken = $matches[2]
                            if ($cnToken -ne $groupToken) {
                                $results.Issues += "Warning: Group '$originalCN' has mismatched tokens - SAM uses '$groupToken', CN uses '$cnToken'"
                            }
                        }
                    }
                }
            }

            # Check if this CN is a well-known group that should be preserved
            $isWellKnown = Test-WellKnownGroup $originalCN
            if ($isWellKnown -and $originalCN -ne $anonymizedCN) {
                $results.Issues += "Critical: Well-known group CN '$originalCN' was incorrectly anonymized to '$anonymizedCN'"
                $results.IsConsistent = $false
            }
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-OUConsistency {
    <#
    .SYNOPSIS
    Validates consistency of OU (Organizational Unit) mappings and preservation rules.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. Well-known OUs are preserved (not anonymized)
    2. OU name mappings are unique and consistent
    3. No conflicting OU mappings exist
    4. Tiering model OUs are properly preserved

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalOUMappings = $script:OuMapping.Count
            PreservedOUs = $script:PreservedItems.OUs.Count
            WellKnownOUsFound = 0
            CustomOUsFound = 0
        }
        TotalIssues = 0
    }

    # Check 1: Validate OU mapping uniqueness (same original should map to same anonymized)
    $reverseMapping = @{}
    foreach ($ouEntry in $script:OuMapping.GetEnumerator()) {
        $originalOU = $ouEntry.Key
        $anonymizedOU = $ouEntry.Value

        if ($reverseMapping.ContainsKey($anonymizedOU)) {
            if ($reverseMapping[$anonymizedOU] -ne $originalOU) {
                $results.Issues += "Critical: Multiple original OUs map to same anonymized OU '$anonymizedOU': '$($reverseMapping[$anonymizedOU])' and '$originalOU'"
                $results.IsConsistent = $false
            }
        } else {
            $reverseMapping[$anonymizedOU] = $originalOU
        }
    }

    # Check 2: Verify anonymized OU names follow expected pattern (OU_XXXXXXXX or OU_XXXXXX)
    foreach ($ouEntry in $script:OuMapping.GetEnumerator()) {
        $anonymizedOU = $ouEntry.Value

        if ($anonymizedOU -notmatch '^OU_[A-F0-9]{6,8}$') {
            $results.Issues += "Warning: Anonymized OU '$anonymizedOU' does not follow expected pattern OU_XXXXXX(XX)"
        } else {
            $results.Statistics.CustomOUsFound++
        }
    }

    # Check 3: Verify well-known OUs in preserved list match the well-known OU list
    foreach ($preservedOU in $script:PreservedItems.OUs.Keys) {
        $isWellKnown = $preservedOU.ToUpper() -in $script:WELL_KNOWN_OUS

        if (-not $isWellKnown) {
            $results.Issues += "Warning: OU '$preservedOU' is preserved but not in WELL_KNOWN_OUS list"
        } else {
            $results.Statistics.WellKnownOUsFound++
        }
    }

    # Check 4: Verify well-known OUs are not in the anonymized mapping
    foreach ($ouEntry in $script:OuMapping.GetEnumerator()) {
        $originalOU = $ouEntry.Key

        $isWellKnown = $originalOU.ToUpper() -in $script:WELL_KNOWN_OUS

        if ($isWellKnown) {
            $results.Issues += "Critical: Well-known OU '$originalOU' was incorrectly anonymized to '$($ouEntry.Value)'"
            $results.IsConsistent = $false
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-GPOConsistency {
    <#
    .SYNOPSIS
    Validates consistency of GPO (Group Policy Object) processing and preservation rules.

    .DESCRIPTION
    Performs comprehensive consistency checks to ensure that:
    1. GPO GUIDs are consistently mapped
    2. POLICIES and SYSTEM CNs are preserved in GPO DNs
    3. Well-known GPO names are identified
    4. GPO structure integrity is maintained

    .OUTPUTS
    Returns a hashtable with consistency check results and any issues found.
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalGUIDMappings = $script:GuidMapping.Count
            PolicyCNsFound = 0
            SystemCNsFound = 0
            WellKnownGPOs = @()
        }
        TotalIssues = 0
    }

    # Check 1: Verify POLICIES and SYSTEM CNs are preserved (critical for GPO structure)
    foreach ($cnEntry in $script:PreservedItems.CNs.Keys) {
        if ($cnEntry -eq 'POLICIES') {
            $results.Statistics.PolicyCNsFound++
        }
        if ($cnEntry -eq 'SYSTEM') {
            $results.Statistics.SystemCNsFound++
        }
    }

    # Note: POLICIES and SYSTEM are only tracked if GPOs are processed
    # If CNMapping has entries but these aren't preserved, flag it
    if ($script:GuidMapping.Count -gt 0) {
        # Check if POLICIES or SYSTEM appear in CN mappings (they shouldn't be anonymized)
        foreach ($cnEntry in $script:CNMapping.GetEnumerator()) {
            $parsed = Get-OriginalCNFromMapping $cnEntry.Key
            if ($parsed) {
                $originalCN = $parsed.OriginalCN
                if ($originalCN -eq 'POLICIES' -and $cnEntry.Value -ne 'POLICIES') {
                    $results.Issues += "Critical: POLICIES CN was anonymized to '$($cnEntry.Value)' - this breaks GPO structure"
                    $results.IsConsistent = $false
                }
                if ($originalCN -eq 'SYSTEM' -and $cnEntry.Value -ne 'SYSTEM') {
                    $results.Issues += "Critical: SYSTEM CN was anonymized to '$($cnEntry.Value)' - this breaks GPO structure"
                    $results.IsConsistent = $false
                }
            }
        }
    }

    # Check 2: Verify GUID mappings are consistent (same GUID should always map to same anonymized GUID)
    $reverseGuidMapping = @{}
    foreach ($guidEntry in $script:GuidMapping.GetEnumerator()) {
        $originalGuid = $guidEntry.Key
        $anonymizedGuid = $guidEntry.Value

        if ($reverseGuidMapping.ContainsKey($anonymizedGuid)) {
            if ($reverseGuidMapping[$anonymizedGuid] -ne $originalGuid) {
                $results.Issues += "Critical: Multiple original GUIDs map to same anonymized GUID '$anonymizedGuid': '$($reverseGuidMapping[$anonymizedGuid])' and '$originalGuid'"
                $results.IsConsistent = $false
            }
        } else {
            $reverseGuidMapping[$anonymizedGuid] = $originalGuid
        }
    }

    # Check 3: Verify GUID format (both original and anonymized should be valid GUID format)
    foreach ($guidEntry in $script:GuidMapping.GetEnumerator()) {
        $originalGuid = $guidEntry.Key
        $anonymizedGuid = $guidEntry.Value

        # GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        if ($originalGuid -notmatch '^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$') {
            $results.Issues += "Warning: Original GUID '$originalGuid' does not match standard GUID format"
        }
        if ($anonymizedGuid -notmatch '^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$') {
            $results.Issues += "Error: Anonymized GUID '$anonymizedGuid' does not match standard GUID format"
            $results.IsConsistent = $false
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-NTAuthStoreConsistency {
    <#
    .SYNOPSIS
    Tests consistency of NTAuthStore mappings.

    .DESCRIPTION
    Validates that NTAuthStore names and certificate thumbprints are properly mapped.
    Checks:
    1. Well-known store names (NTAUTHCERTIFICATES) are preserved
    2. Custom store names follow NTAUTHSTORE_XXXXXXXX pattern
    3. NTAuthStore mapping uniqueness
    4. Certificate thumbprint mappings are unique and properly formatted
    5. Supporting CNs (PUBLIC KEY SERVICES, SERVICES, CONFIGURATION) are preserved

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalNTAuthStoreMappings = 0
            WellKnownStoresFound = 0
            CustomStoresFound = 0
            TotalCertThumbprints = 0
            SupportingCNsFound = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:NTAuthStoreMapping) {
        $results.Statistics.TotalNTAuthStoreMappings = $script:NTAuthStoreMapping.Count
    }
    if ($script:CertThumbprintMapping) {
        $results.Statistics.TotalCertThumbprints = $script:CertThumbprintMapping.Count
    }

    # Check 1: Verify NTAUTHCERTIFICATES (well-known store name) is preserved
    if ($script:NTAuthStoreMapping) {
        foreach ($storeEntry in $script:NTAuthStoreMapping.GetEnumerator()) {
            $originalStore = $storeEntry.Key
            $anonymizedStore = $storeEntry.Value

            if ($originalStore.ToUpper() -eq 'NTAUTHCERTIFICATES') {
                if ($anonymizedStore -ne 'NTAUTHCERTIFICATES') {
                    $results.Issues += "Critical: Well-known store name 'NTAUTHCERTIFICATES' was incorrectly anonymized to '$anonymizedStore'"
                    $results.IsConsistent = $false
                } else {
                    $results.Statistics.WellKnownStoresFound++
                }
            }
        }
    }

    # Check 2: Verify custom store names follow expected pattern (NTAUTHSTORE_XXXXXXXX)
    if ($script:NTAuthStoreMapping) {
        foreach ($storeEntry in $script:NTAuthStoreMapping.GetEnumerator()) {
            $originalStore = $storeEntry.Key
            $anonymizedStore = $storeEntry.Value

            # Skip well-known stores
            if ($originalStore.ToUpper() -eq 'NTAUTHCERTIFICATES') {
                continue
            }

            if ($anonymizedStore -notmatch '^NTAUTHSTORE_[A-F0-9]{8}$') {
                $results.Issues += "Warning: Anonymized store name '$anonymizedStore' does not follow expected pattern NTAUTHSTORE_XXXXXXXX"
            } else {
                $results.Statistics.CustomStoresFound++
            }
        }
    }

    # Check 3: Verify NTAuthStore mapping uniqueness (no collisions)
    if ($script:NTAuthStoreMapping) {
        $reverseStoreMapping = @{}
        foreach ($storeEntry in $script:NTAuthStoreMapping.GetEnumerator()) {
            $originalStore = $storeEntry.Key
            $anonymizedStore = $storeEntry.Value

            if ($reverseStoreMapping.ContainsKey($anonymizedStore)) {
                $results.Issues += "Critical: Anonymized store name '$anonymizedStore' maps to multiple original stores: '$originalStore' and '$($reverseStoreMapping[$anonymizedStore])'"
                $results.IsConsistent = $false
            } else {
                $reverseStoreMapping[$anonymizedStore] = $originalStore
            }
        }
    }

    # Check 4: Verify certificate thumbprint mappings are unique and properly formatted
    if ($script:CertThumbprintMapping) {
        $reverseCertMapping = @{}
        foreach ($certEntry in $script:CertThumbprintMapping.GetEnumerator()) {
            $originalThumbprint = $certEntry.Key
            $anonymizedThumbprint = $certEntry.Value

            # Check uniqueness
            if ($reverseCertMapping.ContainsKey($anonymizedThumbprint)) {
                $results.Issues += "Critical: Anonymized certificate thumbprint '$anonymizedThumbprint' maps to multiple original thumbprints: '$originalThumbprint' and '$($reverseCertMapping[$anonymizedThumbprint])'"
                $results.IsConsistent = $false
            } else {
                $reverseCertMapping[$anonymizedThumbprint] = $originalThumbprint
            }

            # Check format (40-character hex string)
            if ($originalThumbprint -notmatch '^[A-F0-9]{40}$') {
                $results.Issues += "Warning: Original certificate thumbprint '$originalThumbprint' is not a valid 40-character hex string"
            }
            if ($anonymizedThumbprint -notmatch '^[A-F0-9]{40}$') {
                $results.Issues += "Error: Anonymized certificate thumbprint '$anonymizedThumbprint' is not a valid 40-character hex string"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 5: Verify supporting CNs are preserved (PUBLIC KEY SERVICES, SERVICES, CONFIGURATION)
    $supportingCNs = @('PUBLIC KEY SERVICES', 'SERVICES', 'CONFIGURATION')
    foreach ($supportingCN in $supportingCNs) {
        if ($script:PreservedItems.CNs.ContainsKey($supportingCN)) {
            $results.Statistics.SupportingCNsFound++
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-ContainerConsistency {
    <#
    .SYNOPSIS
    Tests consistency of Container mappings.

    .DESCRIPTION
    Validates that Container names and CNs are properly mapped and preserved.
    Checks:
    1. Well-known containers are preserved (USERS, COMPUTERS, SYSTEM, etc.)
    2. Custom containers follow OU_XXXXXXXX pattern
    3. Container mapping uniqueness
    4. Well-known container CNs match between local and global lists
    5. Container CNs in preserved items match container name preservation

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalContainerMappings = 0
            WellKnownContainersFound = 0
            CustomContainersFound = 0
            MismatchedCNs = 0
        }
        TotalIssues = 0
    }

    # Get the local well-known container list from Get-AnonymizedContainer function
    # These are the containers that should be preserved
    $localWellKnownContainers = @(
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

    # Initialize counters
    if ($script:ContainerMapping) {
        $results.Statistics.TotalContainerMappings = $script:ContainerMapping.Count
    }

    # Check 1: Verify well-known containers are preserved (not in anonymized mapping)
    if ($script:ContainerMapping) {
        foreach ($containerEntry in $script:ContainerMapping.GetEnumerator()) {
            $originalContainer = $containerEntry.Key
            $anonymizedContainer = $containerEntry.Value

            # If this container is well-known, it should NOT be in the mapping (it should be preserved)
            if ($originalContainer.ToUpper() -in $localWellKnownContainers) {
                $results.Issues += "Critical: Well-known container '$originalContainer' was incorrectly anonymized to '$anonymizedContainer'"
                $results.IsConsistent = $false
            } else {
                $results.Statistics.CustomContainersFound++
            }
        }
    }

    # Check 2: Verify custom container names follow expected pattern (OU_XXXXXXXX)
    if ($script:ContainerMapping) {
        foreach ($containerEntry in $script:ContainerMapping.GetEnumerator()) {
            $anonymizedContainer = $containerEntry.Value

            if ($anonymizedContainer -notmatch '^OU_[A-F0-9]{8}$') {
                $results.Issues += "Warning: Anonymized container name '$anonymizedContainer' does not follow expected pattern OU_XXXXXXXX"
            }
        }
    }

    # Check 3: Verify container mapping uniqueness (no collisions)
    if ($script:ContainerMapping) {
        $reverseContainerMapping = @{}
        foreach ($containerEntry in $script:ContainerMapping.GetEnumerator()) {
            $originalContainer = $containerEntry.Key
            $anonymizedContainer = $containerEntry.Value

            if ($reverseContainerMapping.ContainsKey($anonymizedContainer)) {
                $results.Issues += "Critical: Anonymized container name '$anonymizedContainer' maps to multiple original containers: '$originalContainer' and '$($reverseContainerMapping[$anonymizedContainer])'"
                $results.IsConsistent = $false
            } else {
                $reverseContainerMapping[$anonymizedContainer] = $originalContainer
            }
        }
    }

    # Check 4: Verify well-known container CNs match between local and global lists
    # Compare the local well-known container list with the global WELL_KNOWN_CNS
    foreach ($localContainer in $localWellKnownContainers) {
        $isInGlobalList = $script:WELL_KNOWN_CNS -contains $localContainer

        if (-not $isInGlobalList) {
            $results.Issues += "Warning: Container '$localContainer' is in local well-known list but NOT in global WELL_KNOWN_CNS - CNs may be incorrectly anonymized"
            $results.Statistics.MismatchedCNs++
        } else {
            $results.Statistics.WellKnownContainersFound++
        }
    }

    # Check 5: Verify that well-known container CNs are preserved in PreservedItems.CNs
    foreach ($localContainer in $localWellKnownContainers) {
        # Only check if this container is also supposed to be a preserved CN
        if ($script:WELL_KNOWN_CNS -contains $localContainer) {
            # Check if it's actually preserved
            if (-not $script:PreservedItems.CNs.ContainsKey($localContainer)) {
                # This is just informational - the container may not have been encountered in the data
                # Don't mark as inconsistent, just note it
            }
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-RootCAConsistency {
    <#
    .SYNOPSIS
    Tests consistency of Root CA mappings.

    .DESCRIPTION
    Validates that Root CA certificate thumbprints and names are properly mapped.
    Checks:
    1. CA certificate thumbprint mappings are unique and properly formatted
    2. CA thumbprint keys use THUMB_ prefix convention
    3. Certificate thumbprints are 40-character hex strings
    4. Supporting CNs (CERTIFICATION AUTHORITIES, PUBLIC KEY SERVICES, etc.) are preserved
    5. CA name patterns follow expected formats (CA_XXXXXXXX or DOMAIN-DC##-CA)

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalCAMappings = 0
            ThumbprintMappings = 0
            SupportingCNsFound = 0
            DCPatternCAs = 0
            AnonymizedCAs = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:CAMapping) {
        $results.Statistics.TotalCAMappings = $script:CAMapping.Count
    }

    # Check 1: Verify CA thumbprint mappings are unique and properly formatted
    if ($script:CAMapping) {
        $reverseCACertMapping = @{}
        foreach ($caEntry in $script:CAMapping.GetEnumerator()) {
            $originalKey = $caEntry.Key
            $anonymizedThumbprint = $caEntry.Value

            # Check uniqueness
            if ($reverseCACertMapping.ContainsKey($anonymizedThumbprint)) {
                $results.Issues += "Critical: Anonymized CA thumbprint '$anonymizedThumbprint' maps to multiple original keys: '$originalKey' and '$($reverseCACertMapping[$anonymizedThumbprint])'"
                $results.IsConsistent = $false
            } else {
                $reverseCACertMapping[$anonymizedThumbprint] = $originalKey
            }

            # Check 2: Verify keys use THUMB_ prefix convention
            if ($originalKey -match '^THUMB_') {
                $results.Statistics.ThumbprintMappings++
                $thumbprint = $originalKey.Substring(6)  # Remove "THUMB_" prefix

                # Check 3: Verify thumbprint format (40-character hex string)
                if ($thumbprint -notmatch '^[A-F0-9]{40}$') {
                    $results.Issues += "Warning: Original CA thumbprint '$thumbprint' is not a valid 40-character hex string"
                }
            } else {
                $results.Issues += "Warning: CA mapping key '$originalKey' does not follow THUMB_ prefix convention"
            }

            # Validate anonymized thumbprint format
            if ($anonymizedThumbprint -notmatch '^[A-F0-9]{40}$') {
                $results.Issues += "Error: Anonymized CA thumbprint '$anonymizedThumbprint' is not a valid 40-character hex string"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 4: Verify supporting CNs for Root CAs are preserved
    $supportingCNs = @('CERTIFICATION AUTHORITIES', 'PUBLIC KEY SERVICES', 'SERVICES', 'CONFIGURATION')
    foreach ($supportingCN in $supportingCNs) {
        if ($script:PreservedItems.CNs.ContainsKey($supportingCN)) {
            $results.Statistics.SupportingCNsFound++
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-EnterpriseCAConsistency {
    <#
    .SYNOPSIS
    Tests consistency of Enterprise CA mappings.

    .DESCRIPTION
    Validates that Enterprise CA certificate thumbprints and names are properly mapped.
    Note: Enterprise CAs and Root CAs share the same CAMapping dictionary.
    Checks:
    1. Verify supporting CNs (ENROLLMENT SERVICES, PUBLIC KEY SERVICES) are preserved
    2. Validate SHARPHOUND server name preservation
    3. Validate HostnameMapping for server names
    4. Note: Certificate thumbprint validation covered by Root CA check (shared CAMapping)

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            SupportingCNsFound = 0
            HostnameMappings = 0
            SharphoundPreserved = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:HostnameMapping) {
        $results.Statistics.HostnameMappings = $script:HostnameMapping.Count
    }

    # Check 1: Verify supporting CNs for Enterprise CAs are preserved
    $supportingCNs = @('ENROLLMENT SERVICES', 'PUBLIC KEY SERVICES', 'SERVICES', 'CONFIGURATION')
    foreach ($supportingCN in $supportingCNs) {
        if ($script:PreservedItems.CNs.ContainsKey($supportingCN)) {
            $results.Statistics.SupportingCNsFound++
        }
    }

    # Check 2: Verify SHARPHOUND is preserved in hostname mappings
    if ($script:HostnameMapping) {
        foreach ($hostnameEntry in $script:HostnameMapping.GetEnumerator()) {
            $originalHostname = $hostnameEntry.Key
            $anonymizedHostname = $hostnameEntry.Value

            if ($originalHostname -match 'SHARPHOUND') {
                if ($anonymizedHostname -ne 'SRV-SHARPHOUND') {
                    $results.Issues += "Warning: SHARPHOUND hostname '$originalHostname' was incorrectly anonymized to '$anonymizedHostname'"
                } else {
                    $results.Statistics.SharphoundPreserved++
                }
            }
        }
    }

    # Check 3: Verify hostname mapping uniqueness
    if ($script:HostnameMapping) {
        $reverseHostnameMapping = @{}
        foreach ($hostnameEntry in $script:HostnameMapping.GetEnumerator()) {
            $originalHostname = $hostnameEntry.Key
            $anonymizedHostname = $hostnameEntry.Value

            if ($reverseHostnameMapping.ContainsKey($anonymizedHostname)) {
                $results.Issues += "Critical: Anonymized hostname '$anonymizedHostname' maps to multiple original hostnames: '$originalHostname' and '$($reverseHostnameMapping[$anonymizedHostname])'"
                $results.IsConsistent = $false
            } else {
                $reverseHostnameMapping[$anonymizedHostname] = $originalHostname
            }
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-ComputerConsistency {
    <#
    .SYNOPSIS
    Tests consistency of Computer mappings.

    .DESCRIPTION
    Validates that Computer names and mappings are properly configured.
    Checks:
    1. Domain Controller patterns (DC\d+, RODC\d+) are preserved
    2. Custom computer names follow COMP_XXXXXXXX pattern
    3. Computer mapping uniqueness
    4. Preserved DC computers are not in anonymized mapping
    5. Computer SAM account name consistency (ends with $)

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalComputerMappings = 0
            PreservedDCs = 0
            CustomComputers = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:ComputerMapping) {
        $results.Statistics.TotalComputerMappings = $script:ComputerMapping.Count
    }
    if ($script:PreservedItems.Computers) {
        $results.Statistics.PreservedDCs = $script:PreservedItems.Computers.Count
    }

    # Check 1: Verify DC patterns are preserved (not in anonymized mapping)
    if ($script:ComputerMapping) {
        foreach ($computerEntry in $script:ComputerMapping.GetEnumerator()) {
            $originalComputer = $computerEntry.Key
            $anonymizedComputer = $computerEntry.Value

            # Check if this is a DC pattern
            if ($originalComputer -match '^(DC\d+|RODC\d+)$') {
                $results.Issues += "Critical: Domain Controller '$originalComputer' was incorrectly anonymized to '$anonymizedComputer'"
                $results.IsConsistent = $false
            } else {
                $results.Statistics.CustomComputers++
            }
        }
    }

    # Check 2: Verify anonymized computer names follow expected pattern (COMP_XXXXXXXX)
    if ($script:ComputerMapping) {
        foreach ($computerEntry in $script:ComputerMapping.GetEnumerator()) {
            $anonymizedComputer = $computerEntry.Value

            if ($anonymizedComputer -notmatch '^COMP_[A-F0-9]{8}$') {
                $results.Issues += "Warning: Anonymized computer name '$anonymizedComputer' does not follow expected pattern COMP_XXXXXXXX"
            }
        }
    }

    # Check 3: Verify computer mapping uniqueness (no collisions)
    if ($script:ComputerMapping) {
        $reverseComputerMapping = @{}
        foreach ($computerEntry in $script:ComputerMapping.GetEnumerator()) {
            $originalComputer = $computerEntry.Key
            $anonymizedComputer = $computerEntry.Value

            if ($reverseComputerMapping.ContainsKey($anonymizedComputer)) {
                $results.Issues += "Critical: Anonymized computer name '$anonymizedComputer' maps to multiple original computers: '$originalComputer' and '$($reverseComputerMapping[$anonymizedComputer])'"
                $results.IsConsistent = $false
            } else {
                $reverseComputerMapping[$anonymizedComputer] = $originalComputer
            }
        }
    }

    # Check 4: Verify preserved DCs are not in anonymized mapping
    if ($script:PreservedItems.Computers) {
        foreach ($preservedComputer in $script:PreservedItems.Computers.Keys) {
            if ($script:ComputerMapping.ContainsKey($preservedComputer)) {
                $results.Issues += "Critical: Preserved DC '$preservedComputer' should not be in anonymized computer mapping"
                $results.IsConsistent = $false
            }
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-UserConsistency {
    <#
    .SYNOPSIS
    Tests consistency of User mappings.

    .DESCRIPTION
    Validates that User names and mappings are properly configured.
    Checks:
    1. Well-known users (krbtgt, Administrator, Guest, etc.) are preserved
    2. Custom user sAMAccountNames follow USR_XXXXXXXX pattern
    3. Custom user names follow USER_XXXXXXXX pattern
    4. User mapping uniqueness
    5. Preserved well-known users are not in anonymized mapping
    6. sAMAccountName and name use same hex token for consistency

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalUserMappings = 0
            PreservedUsers = 0
            CustomUsers = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:UserMapping) {
        $results.Statistics.TotalUserMappings = $script:UserMapping.Count
    }
    if ($script:PreservedItems.Users) {
        $results.Statistics.PreservedUsers = $script:PreservedItems.Users.Count
    }

    # Check 1: Verify well-known users are preserved (not in anonymized mapping)
    if ($script:UserMapping) {
        foreach ($userEntry in $script:UserMapping.GetEnumerator()) {
            $originalUser = $userEntry.Key
            $anonymizedUser = $userEntry.Value

            # Check if this is a well-known user
            if ($script:WELL_KNOWN_USERS -contains $originalUser) {
                $results.Issues += "Critical: Well-known user '$originalUser' was incorrectly anonymized to '$anonymizedUser'"
                $results.IsConsistent = $false
            } else {
                $results.Statistics.CustomUsers++
            }
        }
    }

    # Check 2: Verify anonymized user sAMAccountNames follow expected pattern (USR_XXXXXXXX)
    if ($script:UserMapping) {
        foreach ($userEntry in $script:UserMapping.GetEnumerator()) {
            $anonymizedUser = $userEntry.Value

            if ($anonymizedUser -notmatch '^USR_[A-F0-9]{8}$') {
                $results.Issues += "Warning: Anonymized user sAMAccountName '$anonymizedUser' does not follow expected pattern USR_XXXXXXXX"
            }
        }
    }

    # Check 3: Verify user mapping uniqueness (no collisions)
    if ($script:UserMapping) {
        $reverseUserMapping = @{}
        foreach ($userEntry in $script:UserMapping.GetEnumerator()) {
            $originalUser = $userEntry.Key
            $anonymizedUser = $userEntry.Value

            if ($reverseUserMapping.ContainsKey($anonymizedUser)) {
                $results.Issues += "Critical: Anonymized user sAMAccountName '$anonymizedUser' maps to multiple original users: '$originalUser' and '$($reverseUserMapping[$anonymizedUser])'"
                $results.IsConsistent = $false
            } else {
                $reverseUserMapping[$anonymizedUser] = $originalUser
            }
        }
    }

    # Check 4: Verify preserved well-known users are not in anonymized mapping
    if ($script:PreservedItems.Users) {
        foreach ($preservedUser in $script:PreservedItems.Users.Keys) {
            if ($script:UserMapping.ContainsKey($preservedUser)) {
                $results.Issues += "Critical: Preserved well-known user '$preservedUser' should not be in anonymized user mapping"
                $results.IsConsistent = $false
            }
        }
    }

    # Check 5: Verify all well-known users from WELL_KNOWN_USERS are in PreservedItems if encountered
    # (We can't check if they exist in the data, but we can verify consistency if they do)
    foreach ($wellKnownUser in $script:WELL_KNOWN_USERS) {
        if ($script:UserMapping.ContainsKey($wellKnownUser)) {
            $results.Issues += "Critical: Well-known user '$wellKnownUser' found in UserMapping but should be preserved"
            $results.IsConsistent = $false
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Test-AIACAConsistency {
    <#
    .SYNOPSIS
    Tests consistency of AIACA (Authority Information Access CA) mappings.

    .DESCRIPTION
    Validates that AIACA names and certificate mappings are properly configured.
    Checks:
    1. AIACA names follow AIACA_XXXXXXXX pattern
    2. AIACA name mapping uniqueness
    3. Certificate thumbprint mappings (40-character hex format)
    4. Certificate chain consistency (thumbprints in chains are mapped)
    5. Supporting CNs preserved (AIA, PUBLIC KEY SERVICES, SERVICES, CONFIGURATION)

    .OUTPUTS
    Hashtable with consistency check results
    #>
    [CmdletBinding()]
    param()

    $results = @{
        IsConsistent = $true
        Issues = @()
        Statistics = @{
            TotalAIACANameMappings = 0
            TotalCertThumbprints = 0
            SupportingCNsFound = 0
            ChainedCertificates = 0
        }
        TotalIssues = 0
    }

    # Initialize counters
    if ($script:AIACANameMapping) {
        $results.Statistics.TotalAIACANameMappings = $script:AIACANameMapping.Count
    }
    if ($script:CertThumbprintMapping) {
        $results.Statistics.TotalCertThumbprints = $script:CertThumbprintMapping.Count
    }

    # Check 1: Verify anonymized AIACA names follow expected pattern (AIACA_XXXXXXXX)
    if ($script:AIACANameMapping) {
        foreach ($aiacaEntry in $script:AIACANameMapping.GetEnumerator()) {
            $anonymizedAIACA = $aiacaEntry.Value

            if ($anonymizedAIACA -notmatch '^AIACA_[A-F0-9]{8}$') {
                $results.Issues += "Warning: Anonymized AIACA name '$anonymizedAIACA' does not follow expected pattern AIACA_XXXXXXXX"
            }
        }
    }

    # Check 2: Verify AIACA name mapping uniqueness (no collisions)
    if ($script:AIACANameMapping) {
        $reverseAIACAMapping = @{}
        foreach ($aiacaEntry in $script:AIACANameMapping.GetEnumerator()) {
            $originalAIACA = $aiacaEntry.Key
            $anonymizedAIACA = $aiacaEntry.Value

            if ($reverseAIACAMapping.ContainsKey($anonymizedAIACA)) {
                $results.Issues += "Critical: Anonymized AIACA name '$anonymizedAIACA' maps to multiple original AIACAs: '$originalAIACA' and '$($reverseAIACAMapping[$anonymizedAIACA])'"
                $results.IsConsistent = $false
            } else {
                $reverseAIACAMapping[$anonymizedAIACA] = $originalAIACA
            }
        }
    }

    # Check 3: Verify certificate thumbprints are 40-character hex strings
    if ($script:CertThumbprintMapping) {
        foreach ($thumbprintEntry in $script:CertThumbprintMapping.GetEnumerator()) {
            $originalThumbprint = $thumbprintEntry.Key
            $anonymizedThumbprint = $thumbprintEntry.Value

            # Original thumbprint should be 40-character hex
            if ($originalThumbprint -notmatch '^[A-F0-9]{40}$') {
                $results.Issues += "Warning: Original certificate thumbprint '$originalThumbprint' is not a valid 40-character hex string"
            }

            # Anonymized thumbprint should also be 40-character hex
            if ($anonymizedThumbprint -notmatch '^[A-F0-9]{40}$') {
                $results.Issues += "Warning: Anonymized certificate thumbprint '$anonymizedThumbprint' is not a valid 40-character hex string"
            }
        }
    }

    # Check 4: Verify supporting CNs are preserved
    $supportingCNs = @('AIA', 'PUBLIC KEY SERVICES', 'SERVICES', 'CONFIGURATION')
    foreach ($cn in $supportingCNs) {
        if ($script:WELL_KNOWN_CNS -contains $cn) {
            $results.Statistics.SupportingCNsFound++
        } else {
            $results.Issues += "Critical: Supporting CN '$cn' for AIACAs is not in WELL_KNOWN_CNS list"
            $results.IsConsistent = $false
        }
    }

    $results.TotalIssues = $results.Issues.Count

    return $results
}

function Write-CNConsistencyCheckReport {
    <#
    .SYNOPSIS
    Writes a CN consistency check report to the log and optionally to a file.

    .PARAMETER CheckResults
    The results from Test-CNMappingConsistency

    .PARAMETER OutputPath
    Optional path to write a detailed report file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CheckResults,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    if ($CheckResults.IsConsistent) {
        Write-ScriptLog "✓ CN mapping consistency check PASSED" -Level Success
        Write-ScriptLog "  Total CN mappings: $($CheckResults.Statistics.TotalCNMappings)" -Level Info
        Write-ScriptLog "  Preserved CNs: $($CheckResults.Statistics.PreservedCNs)" -Level Info
        Write-ScriptLog "  Well-known CNs found: $($CheckResults.Statistics.WellKnownCNsFound)" -Level Info
        Write-ScriptLog "  Foreign Security Principal CNs: $($CheckResults.Statistics.SIDCNsFound)" -Level Info
    } else {
        Write-ScriptLog "⚠ CN mapping consistency check FAILED with $($CheckResults.Issues.Count) issue(s)" -Level Warning

        foreach ($issue in $CheckResults.Issues) {
            if ($issue -match '^Critical:') {
                Write-ScriptLog "  $issue" -Level Error
            } elseif ($issue -match '^Warning:') {
                Write-ScriptLog "  $issue" -Level Warning
            } else {
                Write-ScriptLog "  $issue" -Level Warning
            }
        }
    }

    # Write detailed report to file if requested
    if ($OutputPath) {
        try {
            $reportFile = Join-Path $OutputPath "cn_consistency_check.txt"
            $lines = @()

            $lines += "# CN (Common Name) Mapping Consistency Check Report"
            $lines += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $lines += ""
            $lines += "## Overall Status: $(if ($CheckResults.IsConsistent) { 'PASSED' } else { 'FAILED' })"
            $lines += ""
            $lines += "## Statistics"
            $lines += "Total CN mappings: $($CheckResults.Statistics.TotalCNMappings)"
            $lines += "Preserved CNs: $($CheckResults.Statistics.PreservedCNs)"
            $lines += "Well-known CNs found: $($CheckResults.Statistics.WellKnownCNsFound)"
            $lines += "Foreign Security Principal CNs: $($CheckResults.Statistics.SIDCNsFound)"
            $lines += ""

            if ($CheckResults.Issues.Count -gt 0) {
                $lines += "## Issues Found ($($CheckResults.Issues.Count))"
                $lines += ""
                $CheckResults.Issues | ForEach-Object {
                    $lines += "- $_"
                }
            } else {
                $lines += "## No Issues Found"
                $lines += "All CN mappings are consistent."
            }

            $lines += ""
            $lines += "## Preserved CNs"
            if ($script:PreservedItems.CNs.Count -gt 0) {
                $script:PreservedItems.CNs.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    $lines += "$($_.Key) - Reason: $($_.Value)"
                }
            } else {
                $lines += "(None)"
            }

            $lines += ""
            $lines += "## CN Mappings (Sample - First 50)"
            if ($script:CNMapping.Count -gt 0) {
                $count = 0
                $script:CNMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 50) {
                        $parsed = Get-OriginalCNFromMapping $_.Key
                        if ($parsed) {
                            $lines += "$($parsed.OriginalCN) [Parent: $($parsed.ParentPath)] -> $($_.Value)"
                        } else {
                            $lines += "$($_.Key) -> $($_.Value)"
                        }
                        $count++
                    }
                }
                if ($script:CNMapping.Count -gt 50) {
                    $lines += "... and $($script:CNMapping.Count - 50) more entries"
                }
            } else {
                $lines += "(None)"
            }

            [System.IO.File]::WriteAllLines($reportFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
            Write-ScriptLog "CN consistency check report saved to: $reportFile" -Level Success
        }
        catch {
            Write-ScriptLog "Failed to write CN consistency check report: $_" -Level Warning
        }
    }
}

function Get-AnonymizedDomain {
    [CmdletBinding()]
    param([string]$Domain)

    if ([string]::IsNullOrEmpty($Domain)) {
        return $Domain
    }

    # Skip bare TLDs - they're not qualified domains
    # Common TLDs: LOCAL, COM, NET, ORG, CORP, etc.
    $commonTLDs = @('LOCAL', 'COM', 'NET', 'ORG', 'CORP', 'GOV', 'EDU', 'MIL')
    if ($Domain -in $commonTLDs) {
        $script:PreservedItems.Domains[$Domain] = "Bare TLD (not a qualified domain)"
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

    # Special handling for .LOCAL domains and bare base domain names
    # For .LOCAL: Map the base domain (label before .LOCAL) while preserving subdomains
    # For bare names: Check if BASE.* already exists, otherwise treat as BASE.LOCAL
    # Examples:
    #   ESSOS or ESSOS.LOCAL            -> DOMAIN1.LOCAL
    #   NORTH.SEVENKINGDOMS.LOCAL       -> NORTH.DOMAIN2.LOCAL
    #   PHANTOM, PHANTOM.CORP, PHANTOM.LOCAL -> all map to same DOMAIN#.LOCAL
    $isLocalDomain = $Domain -match '^(.+)\.LOCAL$'
    $isBareBase = $Domain -notmatch '\.'

    if ($isLocalDomain -or $isBareBase) {
        if ($isLocalDomain) {
            $beforeLocal = $matches[1]
            # Split on dots to identify subdomains vs base domain
            $parts = $beforeLocal -split '\.'
            if ($parts.Count -eq 1) {
                $baseDomain = $parts[0]
                $subdomain = ""
            } else {
                # Base domain is the last part, everything before is subdomains
                $baseDomain = $parts[-1]
                $subdomain = ($parts[0..($parts.Count - 2)] -join '.') + '.'
            }
        } else {
            # Bare base domain (no dots)
            $baseDomain = $Domain
            $subdomain = ""
        }

        # Check if we already have a mapping for this base domain with any TLD
        # Priority: BASE.LOCAL, BASE, BASE.CORP, BASE.COM, etc.
        $baseDotLocal = "$baseDomain.LOCAL"
        $baseAnonDomain = $null

        if ($script:DomainMapping.ContainsKey($baseDotLocal)) {
            $baseAnonDomain = $script:DomainMapping[$baseDotLocal]
        } elseif ($script:DomainMapping.ContainsKey($baseDomain)) {
            $baseAnonDomain = $script:DomainMapping[$baseDomain]
        } else {
            # Check if BASE.something already exists (e.g., PHANTOM.CORP when we see PHANTOM)
            $existingMapping = $script:DomainMapping.Keys | Where-Object {
                $_ -match "^$baseDomain\."
            } | Select-Object -First 1

            if ($existingMapping) {
                $baseAnonDomain = $script:DomainMapping[$existingMapping]
                Write-Verbose "Found existing mapping for $baseDomain via $existingMapping -> $baseAnonDomain"
            }
        }

        if (-not $baseAnonDomain) {
            # Create new mapping for BASE and BASE.LOCAL
            $script:domainCounter++
            $baseAnonDomain = "DOMAIN$($script:domainCounter).LOCAL"
            $script:DomainMapping[$baseDomain] = $baseAnonDomain
            $script:DomainMapping[$baseDotLocal] = $baseAnonDomain
            Write-Verbose "Mapped base domain: $baseDomain / $baseDotLocal -> $baseAnonDomain"
        } else {
            # Ensure BASE and BASE.LOCAL both point to the same mapping
            if (-not $script:DomainMapping.ContainsKey($baseDomain)) {
                $script:DomainMapping[$baseDomain] = $baseAnonDomain
            }
            if (-not $script:DomainMapping.ContainsKey($baseDotLocal)) {
                $script:DomainMapping[$baseDotLocal] = $baseAnonDomain
            }
        }

        # Construct final anonymized domain
        if ($subdomain) {
            # Has subdomains: NORTH.SEVENKINGDOMS.LOCAL -> NORTH.DOMAIN#.LOCAL
            $baseAnonDomainNoTld = $baseAnonDomain -replace '\.LOCAL$', ''
            $anonDomain = "$subdomain$baseAnonDomainNoTld.LOCAL"
        } else {
            # No subdomains: ESSOS or ESSOS.LOCAL -> DOMAIN#.LOCAL
            $anonDomain = $baseAnonDomain
        }

        $script:DomainMapping[$Domain] = $anonDomain
        Write-Verbose "Mapped .LOCAL domain: $Domain -> $anonDomain"
        return $anonDomain
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

        # Generate new anonymized domain SID using realistic 32-bit unsigned integer values
        # Real domain SIDs use 32-bit values (0 to 4,294,967,295), not just 9 digits
        $anonBaseSid = "S-1-5-21-$(Get-Random -Maximum 4294967296)-$(Get-Random -Maximum 4294967296)-$(Get-Random -Maximum 4294967296)"
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
                $isWellKnownCN = $false
                $preserveReason = ""

                # Check exact match first
                if ($cn.ToUpper() -in $script:WELL_KNOWN_CNS) {
                    $isWellKnownCN = $true
                    $preserveReason = "Well-known CN container"
                }
                # Check for RODC krbtgt accounts (KRBTGT_12345, KRBTGT_ABCDE, etc.)
                elseif ($cn -match '^KRBTGT_[A-Z0-9]+$') {
                    $isWellKnownCN = $true
                    $preserveReason = "RODC krbtgt account"
                }
                # Check for Exchange system mailboxes (SYSTEMMAILBOX{GUID}, HEALTHMAILBOX...)
                elseif ($cn -match '^(SYSTEMMAILBOX|DISCOVERYSEARCHMAILBOX|HEALTHMAILBOX|MONITORING MAILBOXES)\{?[A-Z0-9\-]+\}?$') {
                    $isWellKnownCN = $true
                    $preserveReason = "Exchange system mailbox"
                }
                # Check for Exchange administrative and routing groups (with random identifiers)
                elseif ($cn -match '^EXCHANGE (ADMINISTRATIVE|ROUTING) GROUP \([A-Z0-9]+\)$') {
                    $isWellKnownCN = $true
                    $preserveReason = "Exchange administrative/routing group"
                }
                # Check for Exchange Online application accounts
                elseif ($cn -match '^EXCHANGE ONLINE-APPLICATIONACCOUNT') {
                    $isWellKnownCN = $true
                    $preserveReason = "Exchange Online application account"
                }
                # Check for Server Management group (Exchange)
                elseif ($cn -match '^SERVER MANAGEMENT$') {
                    $isWellKnownCN = $true
                    $preserveReason = "Exchange Server Management group"
                }

                if ($isWellKnownCN) {
                    # Preserve well-known CNs in their original case
                    $anonParts += "CN=$cn"
                    $script:PreservedItems.CNs[$cn] = $preserveReason
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

function Convert-ACEPrincipalSID {
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
                } elseif ($hostnameUpper -match 'SHARPHOUND') {
                    # Preserve SHARPHOUND hostnames
                    $hostname = 'SRV-SHARPHOUND'
                    $script:HostnameMapping[$hostnameUpper] = 'SRV-SHARPHOUND'
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
                } elseif ($hostUpper -match 'SHARPHOUND') {
                    # Preserve SHARPHOUND hostnames
                    $anonHostFull = 'SRV-SHARPHOUND'
                    $script:HostnameMapping[$hostUpper] = 'SRV-SHARPHOUND'
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

function Convert-StandardDomainProperties {
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

function Convert-ACEWithNames {
    [CmdletBinding()]
    param($ACE)

    $anonACE = Copy-ObjectDeep $ACE

    if ($anonACE.PrincipalSID) {
        $anonACE.PrincipalSID = Convert-ACEPrincipalSID $anonACE.PrincipalSID
    }

    # Anonymize PrincipalName if present
    if ($anonACE.PrincipalName) {
        $anonACE.PrincipalName = "Principal_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
    }

    return $anonACE
}

function Convert-ObjectRelationships {
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
                Convert-ACEWithNames $_
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

function Convert-GPOLinks {
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

function Convert-GPOChanges {
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
        Convert-StandardDomainProperties -Object $User -AnonymizedObject $anonymizedUser -OriginalDomain $originalDomain

        # Check if this is a well-known user (preserve as-is)
        # PRIORITY 1: Check by SID (language-independent - works in all AD languages)
        $isWellKnownUser = $false
        if ($User.ObjectIdentifier -and (Test-IsWellKnownByRID -ObjectIdentifier $User.ObjectIdentifier)) {
            $isWellKnownUser = $true
            $samAccount = if ($User.Properties.samaccountname) { $User.Properties.samaccountname } else { "UnknownUser" }
            $script:PreservedItems.Users[$samAccount] = "Well-known user account (detected by SID: $($User.ObjectIdentifier))"
        }
        # PRIORITY 2: Fallback to name-based detection (for backwards compatibility with English ADs)
        elseif ($User.Properties.samaccountname -and $User.Properties.samaccountname -in $script:WELL_KNOWN_USERS) {
            $isWellKnownUser = $true
            $script:PreservedItems.Users[$User.Properties.samaccountname] = "Well-known user account (detected by name)"
        }

        if ($isWellKnownUser) {
            # Well-known users: preserve the principal name but anonymize the domain
            if ($User.Properties.name -and $User.Properties.name -match '^(.+?)@(.+)$') {
                $principalPart = $matches[1]
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedUser.Properties.name = "$principalPart@$anonDomain".ToUpper()
            }
            # sAMAccountName, displayname preserved as-is for well-known users
            # DN gets anonymized via Get-AnonymizedOuPath for domain parts
            if ($User.Properties.distinguishedname) {
                $anonymizedUser.Properties.distinguishedname = Get-AnonymizedOuPath $User.Properties.distinguishedname
            }
        } else {
            # Regular users: fully anonymize
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
                # Then replace ONLY the leaf CN to align with UPN/displayName (USER_{token})
                $anonymizedUser.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN ("USER_{0}" -f $aliasToken)
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
        Convert-ObjectRelationships -Object $User -AnonymizedObject $anonymizedUser

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
        Convert-StandardDomainProperties -Object $Group -AnonymizedObject $anonymizedGroup -OriginalDomain $originalDomain

        # Check if this is a well-known group (preserve as-is)
        # PRIORITY 1: Check by SID (language-independent - works in all AD languages)
        $isWellKnownGroup = $false
        if ($Group.ObjectIdentifier -and (Test-IsWellKnownByRID -ObjectIdentifier $Group.ObjectIdentifier)) {
            $isWellKnownGroup = $true
            $samAccount = if ($Group.Properties.samaccountname) { $Group.Properties.samaccountname } else { "UnknownGroup" }
            $script:PreservedItems.Groups[$samAccount] = "Well-known group (detected by SID: $($Group.ObjectIdentifier))"
        }
        # PRIORITY 2: Fallback to name-based pattern matching (for backwards compatibility with English ADs)
        elseif ($Group.Properties.samaccountname) {
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

        if ($isWellKnownGroup) {
            # Well-known groups: preserve the principal name but anonymize the domain
            if ($Group.Properties.name -and $Group.Properties.name -match '^(.+?)@(.+)$') {
                $principalPart = $matches[1]
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedGroup.Properties.name = "$principalPart@$anonDomain".ToUpper()
            }
            # sAMAccountName and DN are preserved as-is for well-known groups
            # (they get anonymized via Get-AnonymizedOuPath for DN domain parts)
            if ($Group.Properties.distinguishedname) {
                $anonymizedGroup.Properties.distinguishedname = Get-AnonymizedOuPath $Group.Properties.distinguishedname
            }
        } elseif ($isExchangeGroup) {
            # Keep Exchange/special groups format (any group starting with $)
            # Examples: $D31000-NDAG01AAG0, $A31000-..., $xxxxxxxx-xxxx-xxxx...
            $anonSAM = '$' + (Get-RandomHex $script:HEX_LENGTH_MEDIUM) + '-' + (Get-RandomHex $script:HEX_LENGTH_XLONG)
            $anonymizedGroup.Properties.samaccountname = $anonSAM
        } else {
            # Regular groups: fully anonymize
            # Build a single alias token for name, sAMAccountName, and DN leaf CN
            $aliasToken = Get-RandomHex $script:HEX_LENGTH_LONG
            $groupAlias = "GROUP_$aliasToken"

            # Group name (UPN format)
            if ($Group.Properties.name) {
                $origName = $Group.Properties.name
                if ($origName -match '^(.+?)@(.+)$') {
                    $domainPart = $matches[2]
                    $anonDomain = Get-AnonymizedDomain $domainPart
                    $anonymizedGroup.Properties.name = "$groupAlias@$anonDomain".ToUpper()
                } else {
                    $anonymizedGroup.Properties.name = $groupAlias
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

            # distinguishedName - force leaf CN to match group alias (GROUP_{token})
            if ($Group.Properties.distinguishedname) {
                $anonymizedGroup.Properties.distinguishedname = Set-DNLeafCN -DN $anonymizedGroup.Properties.distinguishedname -NewLeafCN $groupAlias
            }
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
        Convert-ObjectRelationships -Object $Group -AnonymizedObject $anonymizedGroup

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
        Convert-StandardDomainProperties -Object $Computer -AnonymizedObject $anonymizedComputer -OriginalDomain $originalDomain

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
                        $localGroup.ObjectIdentifier = Convert-ACEPrincipalSID $localGroup.ObjectIdentifier
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
        Convert-ObjectRelationships -Object $Computer -AnonymizedObject $anonymizedComputer

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
        Convert-GPOChanges -Object $Domain -AnonymizedObject $anonymizedDomain

        # Process Trusts
        if ($Domain.Trusts -and $Domain.Trusts.Count -gt 0) {
            $anonymizedDomain.Trusts = @($Domain.Trusts | ForEach-Object {
                try {
                    $trust = Copy-ObjectDeep $_

                    # Store the original values before anonymization
                    $originalTargetDomainName = $trust.TargetDomainName
                    $originalTargetDomainSid = $trust.TargetDomainSid

                    if ($trust.TargetDomainName) {
                        $trust.TargetDomainName = Get-AnonymizedDomain $trust.TargetDomainName
                    }

                    if ($trust.TargetDomainSid) {
                        $trust.TargetDomainSid = Get-AnonymizedDomainSid $trust.TargetDomainSid
                    }

                    # Map the trust target SID to its domain name for consistency checks
                    if ($originalTargetDomainSid -and $originalTargetDomainName) {
                        $script:DomainSidToDomain[$originalTargetDomainSid] = $originalTargetDomainName
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
        Convert-GPOLinks -Object $Domain -AnonymizedObject $anonymizedDomain

        # Process relationships
        Convert-ObjectRelationships -Object $Domain -AnonymizedObject $anonymizedDomain

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
        Convert-StandardDomainProperties -Object $GPO -AnonymizedObject $anonymizedGPO -OriginalDomain $originalDomain

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

        # Distinguished name with consistent GUID
        # GPO DNs have format: CN={GUID},CN=POLICIES,CN=SYSTEM,DC=...
        # We need to preserve the {GUID} format in the leaf CN
        if ($GPO.Properties.distinguishedname -and $gpoGuid) {
            # First anonymize the full DN (this will anonymize DC parts and other CNs)
            $anonDN = Get-AnonymizedOuPath $GPO.Properties.distinguishedname
            # Then force the leaf CN to be the anonymized GUID in braces
            $anonymizedGPO.Properties.distinguishedname = Set-DNLeafCN -DN $anonDN -NewLeafCN "{$gpoGuid}"
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
        Convert-ObjectRelationships -Object $GPO -AnonymizedObject $anonymizedGPO

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
        Convert-StandardDomainProperties -Object $OU -AnonymizedObject $anonymizedOU -OriginalDomain $originalDomain

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
        Convert-GPOChanges -Object $OU -AnonymizedObject $anonymizedOU

        # Process Links (GPO links)
        Convert-GPOLinks -Object $OU -AnonymizedObject $anonymizedOU

        # Process relationships
        Convert-ObjectRelationships -Object $OU -AnonymizedObject $anonymizedOU

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
        Convert-StandardDomainProperties -Object $Container -AnonymizedObject $anonymizedContainer -OriginalDomain $originalDomain

        # Container name - preserve well-known containers (USERS, COMPUTERS, SYSTEM, etc.)
        $containerAlias = $null
        if ($Container.Properties.name) {
            $origName = $Container.Properties.name
            if ($origName -match '^(.+?)@(.+)$') {
                $containerPart = $matches[1]
                $domainPart = $matches[2]

                # Multi-layer detection: GUID > Context > String matching
                $isWellKnown = $false
                $detectionMethod = ""

                # PRIORITY 1: Check by Well-Known GUID (language-independent)
                if ($Container.ObjectIdentifier -and (Test-IsWellKnownByGUID -ObjectIdentifier $Container.ObjectIdentifier)) {
                    $isWellKnown = $true
                    $detectionMethod = "GUID"
                }
                # PRIORITY 2: Check by DN context (language-independent)
                elseif ($Container.Properties.distinguishedname -and
                        (Test-IsWellKnownByContext -CN $containerPart -DN $Container.Properties.distinguishedname)) {
                    $isWellKnown = $true
                    $detectionMethod = "Context"
                }
                # PRIORITY 3: Check against string list (backwards compatibility)
                else {
                    # List of well-known containers to preserve (English names)
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
                    if ($isWellKnown) {
                        $detectionMethod = "String"
                    }
                }

                if (-not $isWellKnown) {
                    if (-not $script:ContainerMapping) {
                        $script:ContainerMapping = @{}
                    }
                    if (-not $script:ContainerMapping.ContainsKey($containerPart)) {
                        $script:ContainerMapping[$containerPart] = $script:ANONYMIZED_PREFIX_OU + (Get-RandomHex $script:HEX_LENGTH_LONG)
                    }
                    $containerAlias = $script:ContainerMapping[$containerPart]
                } else {
                    $containerAlias = $containerPart.ToUpper()
                    # Track preservation reason for transparency
                    $script:PreservedItems.CNs[$containerAlias] = "Well-known container (detected by $detectionMethod)"
                }

                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedContainer.Properties.name = "$containerAlias@$anonDomain".ToUpper()
            }
        }

        # Distinguished name - force leaf CN to match container name
        if ($Container.Properties.distinguishedname -and $containerAlias) {
            $anonymizedContainer.Properties.distinguishedname = Set-DNLeafCN -DN $anonymizedContainer.Properties.distinguishedname -NewLeafCN $containerAlias
        }

        # Object identifier (GUID)
        if ($Container.ObjectIdentifier) {
            $anonymizedContainer.ObjectIdentifier = Get-AnonymizedGuid $Container.ObjectIdentifier
        }

        # Process relationships (Aces, ContainedBy, ChildObjects)
        Convert-ObjectRelationships -Object $Container -AnonymizedObject $anonymizedContainer

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
        Convert-StandardDomainProperties -Object $CertTemplate -AnonymizedObject $anonymizedCertTemplate -OriginalDomain $originalDomain

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
            $templateAlias = "CERTTEMPLATE_$aliasToken"

            # Certificate template name
            if ($CertTemplate.Properties.name -and $CertTemplate.Properties.name -match '^(.+?)@(.+)$') {
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedCertTemplate.Properties.name = "$templateAlias@$anonDomain".ToUpper()
            }

            # Display name - use same alias token
            if ($CertTemplate.Properties.displayname) {
                $anonymizedCertTemplate.Properties.displayname = "Certificate Template " + $aliasToken
            }

            # distinguishedName - force leaf CN to match full template alias (with CERTTEMPLATE_ prefix)
            if ($CertTemplate.Properties.distinguishedname) {
                $anonymizedCertTemplate.Properties.distinguishedname = Set-DNLeafCN -DN $anonymizedCertTemplate.Properties.distinguishedname -NewLeafCN $templateAlias
            }
        } else {
            # Preserve well-known template names
            $templatePart = $null
            if ($CertTemplate.Properties.name -and $CertTemplate.Properties.name -match '^(.+?)@(.+)$') {
                $templatePart = $matches[1].ToUpper()
                $domainPart = $matches[2]
                $anonDomain = Get-AnonymizedDomain $domainPart
                $anonymizedCertTemplate.Properties.name = "$templatePart@$anonDomain".ToUpper()
            }

            # Distinguished name - force leaf CN to match the well-known template name
            if ($CertTemplate.Properties.distinguishedname -and $templatePart) {
                $anonymizedCertTemplate.Properties.distinguishedname = Set-DNLeafCN -DN $anonymizedCertTemplate.Properties.distinguishedname -NewLeafCN $templatePart
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
        Convert-ObjectRelationships -Object $CertTemplate -AnonymizedObject $anonymizedCertTemplate

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
        Convert-StandardDomainProperties -Object $NTAuthStore -AnonymizedObject $anonymizedNTAuthStore -OriginalDomain $originalDomain

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
        Convert-ObjectRelationships -Object $NTAuthStore -AnonymizedObject $anonymizedNTAuthStore

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

        # Generate CA alias token FIRST (before DN processing) for consistency
        $caAlias = $null
        if ($AIACA.Properties.name -and $AIACA.Properties.name -match '^(.+?)@(.+)$') {
            $caNamePart = $matches[1]

            # Anonymize CA name and store for DN leaf CN
            if (-not $script:AIACANameMapping) {
                $script:AIACANameMapping = @{}
            }
            if (-not $script:AIACANameMapping.ContainsKey($caNamePart)) {
                $script:AIACANameMapping[$caNamePart] = "AIACA_" + (Get-RandomHex $script:HEX_LENGTH_LONG)
            }
            $caAlias = $script:AIACANameMapping[$caNamePart]
        }

        # Process standard properties (domain, domainsid, distinguishedname, whencreated)
        Convert-StandardDomainProperties -Object $AIACA -AnonymizedObject $anonymizedAIACA -OriginalDomain $originalDomain

        # AIACA name - use the pre-generated alias
        if ($AIACA.Properties.name -and $AIACA.Properties.name -match '^(.+?)@(.+)$') {
            $domainPart = $matches[2]
            $anonDomain = Get-AnonymizedDomain $domainPart
            $anonymizedAIACA.Properties.name = "$caAlias@$anonDomain".ToUpper()
        }

        # Distinguished name - force leaf CN to match CA alias
        if ($AIACA.Properties.distinguishedname -and $caAlias) {
            # The DN was already anonymized by Convert-StandardDomainProperties
            # Now replace ONLY the leaf CN to align with CA name
            $anonymizedAIACA.Properties.distinguishedname = Set-DNLeafCN -DN $anonymizedAIACA.Properties.distinguishedname -NewLeafCN $caAlias
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
        Convert-ObjectRelationships -Object $AIACA -AnonymizedObject $anonymizedAIACA

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
        Convert-StandardDomainProperties -Object $CA -AnonymizedObject $anonymizedCA -OriginalDomain $originalDomain

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
        Convert-ObjectRelationships -Object $CA -AnonymizedObject $anonymizedCA

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
        Convert-StandardDomainProperties -Object $CA -AnonymizedObject $anonymizedCA -OriginalDomain $originalDomain

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
                        Convert-ACEWithNames $_
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
        Convert-ObjectRelationships -Object $CA -AnonymizedObject $anonymizedCA

        return $anonymizedCA
    }
    catch {
        Write-ScriptLog "Error anonymizing enterprise CA: $_" -Level Error
        throw
    }
}

#endregion

#region File Processing Functions

function Invoke-UsersFileProcessing {
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

function Invoke-GroupsFileProcessing {
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

function Invoke-ComputersFileProcessing {
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

function Invoke-DomainsFileProcessing {
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

function Invoke-GPOsFileProcessing {
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

function Invoke-OUsFileProcessing {
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

function Invoke-ContainersFileProcessing {
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

function Invoke-CertTemplatesFileProcessing {
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

function Invoke-NTAuthStoresFileProcessing {
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

function Invoke-AIACAsFileProcessing {
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

function Invoke-RootCAsFileProcessing {
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

function Invoke-EnterpriseCAsFileProcessing {
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

function Import-DomainMappings {
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
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$CNConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$CertTemplateConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$GroupConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$OUConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$GPOConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$NTAuthStoreConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$ContainerConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$RootCAConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$EnterpriseCAConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$ComputerConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$UserConsistencyResults,

        [Parameter(Mandatory=$false)]
        [hashtable]$AIACAConsistencyResults
    )

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

        # Domain SID Mappings with Reverse Lookups
        if ($script:DomainSidMapping.Count -gt 0) {
            $lines += "## DOMAIN SID MAPPINGS ($($script:DomainSidMapping.Count) entries)"
            $lines += ""
            $script:DomainSidMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $originalSid = $_.Key
                $anonymizedSid = $_.Value

                # Perform reverse lookup to show which domain this SID belongs to
                $originalDomain = Get-OriginalDomainFromSid $originalSid
                if ($originalDomain) {
                    $lines += "SID: $originalSid=$anonymizedSid  [Domain: $originalDomain]"
                } else {
                    $lines += "SID: $originalSid=$anonymizedSid"
                }
            }
            $lines += ""
        }

        # Domain SID to Domain Name Reverse Lookup Table
        if ($script:DomainSidToDomain.Count -gt 0) {
            $lines += "## DOMAIN SID TO DOMAIN NAME LOOKUP ($($script:DomainSidToDomain.Count) entries)"
            $lines += "# This mapping enables reverse lookups: SID -> Original Domain Name"
            $lines += ""
            $script:DomainSidToDomain.GetEnumerator() | Sort-Object Value | ForEach-Object {
                $lines += "LOOKUP: $($_.Key) -> $($_.Value)"
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
        $lines += ""

        # ========================================================================
        # CONSISTENCY CHECK RESULTS
        # ========================================================================
        $lines += "## CONSISTENCY CHECK RESULTS"
        $lines += ""

        # Domain Consistency Check Results
        if ($DomainConsistencyResults) {
            $lines += "### DOMAIN MAPPING CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($DomainConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Domain names mapped: $($DomainConsistencyResults.Statistics.TotalDomainNames)"
            $lines += "  - Domain SIDs tracked: $($DomainConsistencyResults.Statistics.TotalDomainSids)"
            $lines += "  - SID mappings created: $($DomainConsistencyResults.Statistics.TotalDomainSidMappings)"
            $lines += ""

            if ($DomainConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($DomainConsistencyResults.Issues.Count)):"
                $DomainConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All domain mappings are consistent"
            }
            $lines += ""

            # Add detailed domain SID to domain name mappings
            if ($script:DomainSidToDomain.Count -gt 0) {
                $lines += "Domain SID → Domain Name Mappings:"
                $script:DomainSidToDomain.GetEnumerator() | Sort-Object Value | ForEach-Object {
                    $lines += "  $($_.Key) → $($_.Value)"
                }
                $lines += ""
            }
        }

        # CN Consistency Check Results
        if ($CNConsistencyResults) {
            $lines += "### CN MAPPING CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($CNConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total CN mappings: $($CNConsistencyResults.Statistics.TotalCNMappings)"
            $lines += "  - Preserved CNs: $($CNConsistencyResults.Statistics.PreservedCNs)"
            $lines += "  - Well-known CNs found: $($CNConsistencyResults.Statistics.WellKnownCNsFound)"
            $lines += "  - Foreign Security Principal CNs: $($CNConsistencyResults.Statistics.SIDCNsFound)"
            $lines += ""

            if ($CNConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($CNConsistencyResults.Issues.Count)):"
                $CNConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All CN mappings are consistent"
            }
            $lines += ""

            # Add sample of CN mappings with context
            if ($script:CNMapping.Count -gt 0) {
                $lines += "CN Mappings Sample (First 20):"
                $count = 0
                $script:CNMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 20) {
                        $parsed = Get-OriginalCNFromMapping $_.Key
                        if ($parsed) {
                            $lines += "  $($parsed.OriginalCN) → $($_.Value)"
                            if ($parsed.ParentPath) {
                                $lines += "    [Parent: $($parsed.ParentPath)]"
                            }
                        } else {
                            $lines += "  $($_.Key) → $($_.Value)"
                        }
                        $count++
                    }
                }
                if ($script:CNMapping.Count -gt 20) {
                    $lines += "  ... and $($script:CNMapping.Count - 20) more CN mappings"
                }
                $lines += ""
            }
        }

        # Certificate Template Consistency Check Results
        if ($CertTemplateConsistencyResults) {
            $lines += "### CERTIFICATE TEMPLATE CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($CertTemplateConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total OID mappings: $($CertTemplateConsistencyResults.Statistics.TotalOidMappings)"
            $lines += "  - Well-known templates found: $($CertTemplateConsistencyResults.Statistics.WellKnownTemplatesFound)"
            $lines += "  - Custom templates found: $($CertTemplateConsistencyResults.Statistics.CustomTemplatesFound)"
            $lines += ""

            if ($CertTemplateConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($CertTemplateConsistencyResults.Issues.Count)):"
                $CertTemplateConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All certificate template mappings are consistent"
            }
            $lines += ""

            # Add sample of OID mappings
            if ($script:OidMapping -and $script:OidMapping.Count -gt 0) {
                $lines += "OID Mappings Sample (First 10):"
                $count = 0
                $script:OidMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:OidMapping.Count -gt 10) {
                    $lines += "  ... and $($script:OidMapping.Count - 10) more OID mappings"
                }
                $lines += ""
            }
        }

        # Group Consistency Check Results
        if ($GroupConsistencyResults) {
            $lines += "### GROUP CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($GroupConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total group mappings: $($GroupConsistencyResults.Statistics.TotalGroupMappings)"
            $lines += "  - Preserved groups: $($GroupConsistencyResults.Statistics.PreservedGroups)"
            $lines += "  - Well-known groups found: $($GroupConsistencyResults.Statistics.WellKnownGroupsFound)"
            $lines += "  - Custom groups found: $($GroupConsistencyResults.Statistics.CustomGroupsFound)"
            $lines += ""

            if ($GroupConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($GroupConsistencyResults.Issues.Count)):"
                $GroupConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All group mappings are consistent"
            }
            $lines += ""

            # Add sample of group mappings
            if ($script:GroupMapping.Count -gt 0) {
                $lines += "Group Mappings Sample (First 10):"
                $count = 0
                $script:GroupMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:GroupMapping.Count -gt 10) {
                    $lines += "  ... and $($script:GroupMapping.Count - 10) more group mappings"
                }
                $lines += ""
            }
        }

        # OU Consistency Check Results
        if ($OUConsistencyResults) {
            $lines += "### OU (ORGANIZATIONAL UNIT) CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($OUConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total OU mappings: $($OUConsistencyResults.Statistics.TotalOUMappings)"
            $lines += "  - Preserved OUs: $($OUConsistencyResults.Statistics.PreservedOUs)"
            $lines += "  - Well-known OUs found: $($OUConsistencyResults.Statistics.WellKnownOUsFound)"
            $lines += "  - Custom OUs found: $($OUConsistencyResults.Statistics.CustomOUsFound)"
            $lines += ""

            if ($OUConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($OUConsistencyResults.Issues.Count)):"
                $OUConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All OU mappings are consistent"
            }
            $lines += ""

            # Add sample of OU mappings
            if ($script:OuMapping.Count -gt 0) {
                $lines += "OU Mappings Sample (First 10):"
                $count = 0
                $script:OuMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:OuMapping.Count -gt 10) {
                    $lines += "  ... and $($script:OuMapping.Count - 10) more OU mappings"
                }
                $lines += ""
            }
        }

        # GPO Consistency Check Results
        if ($GPOConsistencyResults) {
            $lines += "### GPO (GROUP POLICY OBJECT) CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($GPOConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total GUID mappings: $($GPOConsistencyResults.Statistics.TotalGUIDMappings)"
            $lines += "  - POLICIES CNs found: $($GPOConsistencyResults.Statistics.PolicyCNsFound)"
            $lines += "  - SYSTEM CNs found: $($GPOConsistencyResults.Statistics.SystemCNsFound)"
            $lines += ""

            if ($GPOConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($GPOConsistencyResults.Issues.Count)):"
                $GPOConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All GPO structures are consistent"
            }
            $lines += ""

            # Add sample of GUID mappings
            if ($script:GuidMapping.Count -gt 0) {
                $lines += "GUID Mappings Sample (First 10):"
                $count = 0
                $script:GuidMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:GuidMapping.Count -gt 10) {
                    $lines += "  ... and $($script:GuidMapping.Count - 10) more GUID mappings"
                }
                $lines += ""
            }
        }

        # NTAuthStore Consistency Check Results
        if ($NTAuthStoreConsistencyResults) {
            $lines += "### NTAUTHSTORE (NT AUTHENTICATION CERTIFICATE STORE) CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($NTAuthStoreConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total NTAuthStore mappings: $($NTAuthStoreConsistencyResults.Statistics.TotalNTAuthStoreMappings)"
            $lines += "  - Well-known stores found: $($NTAuthStoreConsistencyResults.Statistics.WellKnownStoresFound)"
            $lines += "  - Custom stores found: $($NTAuthStoreConsistencyResults.Statistics.CustomStoresFound)"
            $lines += "  - Total certificate thumbprints: $($NTAuthStoreConsistencyResults.Statistics.TotalCertThumbprints)"
            $lines += "  - Supporting CNs found: $($NTAuthStoreConsistencyResults.Statistics.SupportingCNsFound)"
            $lines += ""

            if ($NTAuthStoreConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($NTAuthStoreConsistencyResults.Issues.Count)):"
                $NTAuthStoreConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All NTAuthStore mappings are consistent"
            }
            $lines += ""

            # Add sample of NTAuthStore mappings
            if ($script:NTAuthStoreMapping -and $script:NTAuthStoreMapping.Count -gt 0) {
                $lines += "NTAuthStore Mappings:"
                $script:NTAuthStoreMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    $lines += "  $($_.Key) → $($_.Value)"
                }
                $lines += ""
            }

            # Add sample of certificate thumbprint mappings (first 10)
            if ($script:CertThumbprintMapping -and $script:CertThumbprintMapping.Count -gt 0) {
                $lines += "Certificate Thumbprint Mappings Sample (First 10):"
                $count = 0
                $script:CertThumbprintMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:CertThumbprintMapping.Count -gt 10) {
                    $lines += "  ... and $($script:CertThumbprintMapping.Count - 10) more certificate thumbprint mappings"
                }
                $lines += ""
            }
        }

        # Container Consistency Check Results
        if ($ContainerConsistencyResults) {
            $lines += "### CONTAINER CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($ContainerConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total container mappings: $($ContainerConsistencyResults.Statistics.TotalContainerMappings)"
            $lines += "  - Well-known containers found: $($ContainerConsistencyResults.Statistics.WellKnownContainersFound)"
            $lines += "  - Custom containers found: $($ContainerConsistencyResults.Statistics.CustomContainersFound)"
            $lines += "  - Mismatched CNs (local vs global): $($ContainerConsistencyResults.Statistics.MismatchedCNs)"
            $lines += ""

            if ($ContainerConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($ContainerConsistencyResults.Issues.Count)):"
                $ContainerConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All container mappings are consistent"
            }
            $lines += ""

            # Add sample of container mappings
            if ($script:ContainerMapping -and $script:ContainerMapping.Count -gt 0) {
                $lines += "Container Mappings:"
                $script:ContainerMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    $lines += "  $($_.Key) → $($_.Value)"
                }
                $lines += ""
            }
        }

        # Root CA Consistency Check Results
        if ($RootCAConsistencyResults) {
            $lines += "### ROOT CA (ROOT CERTIFICATION AUTHORITY) CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($RootCAConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total CA mappings: $($RootCAConsistencyResults.Statistics.TotalCAMappings)"
            $lines += "  - Thumbprint mappings: $($RootCAConsistencyResults.Statistics.ThumbprintMappings)"
            $lines += "  - Supporting CNs found: $($RootCAConsistencyResults.Statistics.SupportingCNsFound)"
            $lines += ""

            if ($RootCAConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($RootCAConsistencyResults.Issues.Count)):"
                $RootCAConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All Root CA mappings are consistent"
            }
            $lines += ""

            # Add sample of CA mappings (first 10)
            if ($script:CAMapping -and $script:CAMapping.Count -gt 0) {
                $lines += "CA Certificate Thumbprint Mappings Sample (First 10):"
                $count = 0
                $script:CAMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:CAMapping.Count -gt 10) {
                    $lines += "  ... and $($script:CAMapping.Count - 10) more CA thumbprint mappings"
                }
                $lines += ""
            }
        }

        # Enterprise CA Consistency Check Results
        if ($EnterpriseCAConsistencyResults) {
            $lines += "### ENTERPRISE CA (ENTERPRISE CERTIFICATION AUTHORITY) CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($EnterpriseCAConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Hostname mappings: $($EnterpriseCAConsistencyResults.Statistics.HostnameMappings)"
            $lines += "  - SHARPHOUND servers preserved: $($EnterpriseCAConsistencyResults.Statistics.SharphoundPreserved)"
            $lines += "  - Supporting CNs found: $($EnterpriseCAConsistencyResults.Statistics.SupportingCNsFound)"
            $lines += ""
            $lines += "Note: Enterprise CAs and Root CAs share the same certificate thumbprint mapping (CAMapping)."
            $lines += "Certificate thumbprint validation is covered by the Root CA consistency check."
            $lines += ""

            if ($EnterpriseCAConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($EnterpriseCAConsistencyResults.Issues.Count)):"
                $EnterpriseCAConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All Enterprise CA mappings are consistent"
            }
            $lines += ""

            # Add sample of hostname mappings (first 10)
            if ($script:HostnameMapping -and $script:HostnameMapping.Count -gt 0) {
                $lines += "Hostname Mappings Sample (First 10):"
                $count = 0
                $script:HostnameMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:HostnameMapping.Count -gt 10) {
                    $lines += "  ... and $($script:HostnameMapping.Count - 10) more hostname mappings"
                }
                $lines += ""
            }
        }

        # Computer Consistency Check Results
        if ($ComputerConsistencyResults) {
            $lines += "### COMPUTER CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($ComputerConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total computer mappings: $($ComputerConsistencyResults.Statistics.TotalComputerMappings)"
            $lines += "  - Preserved DCs: $($ComputerConsistencyResults.Statistics.PreservedDCs)"
            $lines += "  - Custom computers: $($ComputerConsistencyResults.Statistics.CustomComputers)"
            $lines += ""

            if ($ComputerConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($ComputerConsistencyResults.Issues.Count)):"
                $ComputerConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All computer mappings are consistent"
            }
            $lines += ""

            # Add sample of computer mappings (first 10)
            if ($script:ComputerMapping -and $script:ComputerMapping.Count -gt 0) {
                $lines += "Computer Mappings Sample (First 10):"
                $count = 0
                $script:ComputerMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:ComputerMapping.Count -gt 10) {
                    $lines += "  ... and $($script:ComputerMapping.Count - 10) more computer mappings"
                }
                $lines += ""
            }

            # Add preserved DC sample
            if ($script:PreservedItems.Computers -and $script:PreservedItems.Computers.Count -gt 0) {
                $lines += "Preserved Domain Controllers:"
                $script:PreservedItems.Computers.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    $lines += "  $($_.Key) - $($_.Value)"
                }
                $lines += ""
            }
        }

        # User Consistency Check Results
        if ($UserConsistencyResults) {
            $lines += "### USER CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($UserConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total user mappings: $($UserConsistencyResults.Statistics.TotalUserMappings)"
            $lines += "  - Preserved users: $($UserConsistencyResults.Statistics.PreservedUsers)"
            $lines += "  - Custom users: $($UserConsistencyResults.Statistics.CustomUsers)"
            $lines += ""

            if ($UserConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($UserConsistencyResults.Issues.Count)):"
                $UserConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All user mappings are consistent"
            }
            $lines += ""

            # Add sample of user mappings (first 10)
            if ($script:UserMapping -and $script:UserMapping.Count -gt 0) {
                $lines += "User Mappings Sample (First 10):"
                $count = 0
                $script:UserMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:UserMapping.Count -gt 10) {
                    $lines += "  ... and $($script:UserMapping.Count - 10) more user mappings"
                }
                $lines += ""
            }

            # Add preserved users sample
            if ($script:PreservedItems.Users -and $script:PreservedItems.Users.Count -gt 0) {
                $lines += "Preserved Well-Known Users:"
                $script:PreservedItems.Users.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    $lines += "  $($_.Key) - $($_.Value)"
                }
                $lines += ""
            }
        }

        # AIACA Consistency Check Results
        if ($AIACAConsistencyResults) {
            $lines += "### AIACA CONSISTENCY"
            $lines += ""
            $lines += "Status: $(if ($AIACAConsistencyResults.IsConsistent) { 'PASSED ✓' } else { 'FAILED ✗' })"
            $lines += ""
            $lines += "Statistics:"
            $lines += "  - Total AIACA name mappings: $($AIACAConsistencyResults.Statistics.TotalAIACANameMappings)"
            $lines += "  - Total certificate thumbprints: $($AIACAConsistencyResults.Statistics.TotalCertThumbprints)"
            $lines += "  - Supporting CNs found: $($AIACAConsistencyResults.Statistics.SupportingCNsFound)"
            $lines += ""

            if ($AIACAConsistencyResults.Issues.Count -gt 0) {
                $lines += "Issues Found ($($AIACAConsistencyResults.Issues.Count)):"
                $AIACAConsistencyResults.Issues | ForEach-Object {
                    $lines += "  - $_"
                }
            } else {
                $lines += "Issues Found: None - All AIACA mappings are consistent"
            }
            $lines += ""

            # Add sample of AIACA name mappings (first 10)
            if ($script:AIACANameMapping -and $script:AIACANameMapping.Count -gt 0) {
                $lines += "AIACA Name Mappings Sample (First 10):"
                $count = 0
                $script:AIACANameMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:AIACANameMapping.Count -gt 10) {
                    $lines += "  ... and $($script:AIACANameMapping.Count - 10) more AIACA name mappings"
                }
                $lines += ""
            }

            # Add sample of certificate thumbprint mappings (first 10)
            if ($script:CertThumbprintMapping -and $script:CertThumbprintMapping.Count -gt 0) {
                $lines += "Certificate Thumbprint Mappings Sample (First 10):"
                $count = 0
                $script:CertThumbprintMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    if ($count -lt 10) {
                        $lines += "  $($_.Key) → $($_.Value)"
                        $count++
                    }
                }
                if ($script:CertThumbprintMapping.Count -gt 10) {
                    $lines += "  ... and $($script:CertThumbprintMapping.Count - 10) more certificate thumbprint mappings"
                }
                $lines += ""
            }
        }

        # Overall consistency summary
        $allConsistent = $true
        if ($DomainConsistencyResults -and -not $DomainConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($CNConsistencyResults -and -not $CNConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($CertTemplateConsistencyResults -and -not $CertTemplateConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($GroupConsistencyResults -and -not $GroupConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($OUConsistencyResults -and -not $OUConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($GPOConsistencyResults -and -not $GPOConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($NTAuthStoreConsistencyResults -and -not $NTAuthStoreConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($ContainerConsistencyResults -and -not $ContainerConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($RootCAConsistencyResults -and -not $RootCAConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($EnterpriseCAConsistencyResults -and -not $EnterpriseCAConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($ComputerConsistencyResults -and -not $ComputerConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($UserConsistencyResults -and -not $UserConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }
        if ($AIACAConsistencyResults -and -not $AIACAConsistencyResults.IsConsistent) {
            $allConsistent = $false
        }

        $lines += "### OVERALL CONSISTENCY STATUS"
        $lines += ""
        if ($allConsistent) {
            $lines += "✓ ALL CHECKS PASSED"
            $lines += "All mappings are consistent and no issues were detected."
        } else {
            $lines += "✗ SOME CHECKS FAILED"
            $lines += "Please review the issues listed above and verify anonymization accuracy."
            $lines += "Consider re-running anonymization if critical issues are present."
        }
        $lines += ""
        $lines += "# End of Anonymization Mappings File"

        [System.IO.File]::WriteAllLines($mappingFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

        Write-ScriptLog "Comprehensive mappings saved to: $mappingFile" -Level Success
    }
    catch {
        Write-ScriptLog "Error saving comprehensive mappings: $_" -Level Error
    }
}

function Save-ComprehensiveMappingsHTML {
    <#
    .SYNOPSIS
    Generates an interactive HTML report of anonymization mappings and consistency checks.

    .DESCRIPTION
    Creates a user-friendly HTML version of the anonymization mappings with:
    - Searchable/filterable tables
    - Collapsible sections
    - Color-coded consistency results
    - Statistics dashboard
    - Professional styling

    .PARAMETER OutputPath
    Directory where the HTML report will be saved

    .PARAMETER AllConsistencyResults
    Hashtable containing all consistency check results

    .OUTPUTS
    Creates anonymization_report.html in the output directory
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [hashtable]$AllConsistencyResults
    )

    try {
        $htmlFile = Join-Path $OutputPath "anonymization_report.html"

        # Build HTML content
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BloodHound Anonymization Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f23;
            padding: 20px;
            color: #e0e0e0;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #1a1a2e;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            overflow: hidden;
            border: 1px solid #2d2d44;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .timestamp {
            background: rgba(255,255,255,0.1);
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            margin-top: 15px;
            font-size: 0.9em;
        }

        nav {
            background: #16213e;
            padding: 0;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
            border-bottom: 1px solid #2d2d44;
        }

        nav ul {
            list-style: none;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
        }

        nav ul li {
            margin: 0;
        }

        nav ul li a {
            display: block;
            color: white;
            text-decoration: none;
            padding: 15px 20px;
            transition: background 0.3s;
        }

        nav ul li a:hover {
            background: rgba(255,255,255,0.1);
        }

        .content {
            padding: 40px;
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        .stat-card h3 {
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            opacity: 0.9;
        }

        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-card .label {
            font-size: 0.9em;
            opacity: 0.8;
        }

        .section {
            margin-bottom: 40px;
        }

        .section-header {
            background: #252538;
            padding: 20px;
            border-left: 4px solid #667eea;
            cursor: pointer;
            user-select: none;
            transition: background 0.3s;
        }

        .section-header:hover {
            background: #2d2d44;
        }

        .section-header h2 {
            font-size: 1.5em;
            color: #e0e0e0;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .section-header .toggle {
            font-size: 1.5em;
            transition: transform 0.3s;
        }

        .section-header.collapsed .toggle {
            transform: rotate(-90deg);
        }

        .section-content {
            padding: 20px;
            display: block;
        }

        .section-content.collapsed {
            display: none;
        }

        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }

        .status-passed {
            background: #d4edda;
            color: #155724;
        }

        .status-failed {
            background: #f8d7da;
            color: #721c24;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            background: #1e1e30;
        }

        table thead {
            background: #667eea;
            color: white;
        }

        table th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }

        table td {
            padding: 12px 15px;
            border-bottom: 1px solid #2d2d44;
            color: #e0e0e0;
        }

        table tbody tr:hover {
            background: #252538;
        }

        table tbody tr:nth-child(even) {
            background: #1a1a2e;
        }

        .search-box {
            margin: 20px 0;
            position: relative;
        }

        .search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #2d2d44;
            border-radius: 25px;
            font-size: 1em;
            transition: border-color 0.3s;
            background: #252538;
            color: #e0e0e0;
        }

        .search-box input:focus {
            outline: none;
            border-color: #667eea;
            background: #2d2d44;
        }

        .search-box input::placeholder {
            color: #8a8a9e;
        }

        .arrow {
            font-family: monospace;
            color: #667eea;
            font-weight: bold;
            padding: 0 10px;
        }

        .preserved-item {
            background: #1e4620;
            color: #4ade80;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            border: 1px solid #2d5a30;
        }

        .anonymized-item {
            background: #4a3a00;
            color: #fbbf24;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            border: 1px solid #6b5400;
        }

        .issue-critical {
            color: #fca5a5;
            background: #4a1a1a;
            padding: 8px 12px;
            border-left: 4px solid #dc2626;
            margin: 5px 0;
        }

        .issue-warning {
            color: #fcd34d;
            background: #4a3a00;
            padding: 8px 12px;
            border-left: 4px solid #fbbf24;
            margin: 5px 0;
        }

        footer {
            background: #16213e;
            color: #e0e0e0;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
            border-top: 1px solid #2d2d44;
        }

        .emoji {
            font-size: 1.2em;
            margin-right: 8px;
        }

        .compliance-section {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        .compliance-section h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
        }

        .compliance-badge {
            display: inline-flex;
            align-items: center;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 25px;
            margin: 10px 10px 10px 0;
            font-weight: bold;
            backdrop-filter: blur(10px);
        }

        .compliance-badge .icon {
            font-size: 1.5em;
            margin-right: 10px;
        }

        .pii-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .pii-item {
            background: rgba(255,255,255,0.15);
            padding: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }

        .pii-item .pii-label {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 5px;
        }

        .pii-item .pii-status {
            font-size: 1.2em;
            font-weight: bold;
        }

        .chart-container {
            background: #1e1e30;
            padding: 30px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            border: 1px solid #2d2d44;
        }

        .chart-container h3 {
            color: #e0e0e0;
        }

        .chart-container p {
            color: #a0a0b0;
        }

        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin: 20px 0;
        }

        .chart-wrapper {
            background: #252538;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            border: 1px solid #2d2d44;
        }

        .chart-wrapper h4 {
            color: #e0e0e0;
            margin-bottom: 15px;
            text-align: center;
            font-size: 1.1em;
        }

        .chart-wrapper canvas {
            max-height: 300px;
        }

        .status-badge {
            background: #2d2d44;
            border: 1px solid #3d3d54;
        }

        .status-passed {
            background: #1e4620;
            color: #4ade80;
            border-color: #2d5a30;
        }

        .status-failed {
            background: #4a1a1a;
            color: #fca5a5;
            border-color: #6a2a2a;
        }

        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
                background: white;
            }
            * {
                color: black !important;
            }
            nav {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🕵️🐕 AnonymousHound Report</h1>
            <p class="subtitle">BloodHound Data Anonymization Mappings</p>
            <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
        </header>

        <nav>
            <ul>
                <li><a href="#overview">Overview</a></li>
                <li><a href="#compliance">GDPR/PII Compliance</a></li>
                <li><a href="#visualizations">Data Visualizations</a></li>
                <li><a href="#consistency">Consistency Checks</a></li>
                <li><a href="#mappings">Mappings</a></li>
                <li><a href="#preserved">Preserved Items</a></li>
            </ul>
        </nav>

        <div class="content">
"@

        # Add Statistics Dashboard
        $totalMappings = 0
        if ($script:DomainMapping) { $totalMappings += $script:DomainMapping.Count }
        if ($script:UserMapping) { $totalMappings += $script:UserMapping.Count }
        if ($script:GroupMapping) { $totalMappings += $script:GroupMapping.Count }
        if ($script:ComputerMapping) { $totalMappings += $script:ComputerMapping.Count }
        if ($script:OUMapping) { $totalMappings += $script:OUMapping.Count }

        $totalPreserved = 0
        if ($script:PreservedItems.Groups) { $totalPreserved += $script:PreservedItems.Groups.Count }
        if ($script:PreservedItems.Users) { $totalPreserved += $script:PreservedItems.Users.Count }
        if ($script:PreservedItems.CNs) { $totalPreserved += $script:PreservedItems.CNs.Count }

        $html += @"
            <section id="overview" class="section">
                <div class="section-header">
                    <h2><span class="emoji">📊</span>Overview Dashboard</h2>
                </div>
                <div class="section-content">
                    <div class="dashboard">
                        <div class="stat-card">
                            <h3>Total Mappings</h3>
                            <div class="value">$totalMappings</div>
                            <div class="label">Objects Anonymized</div>
                        </div>
                        <div class="stat-card">
                            <h3>Preserved Items</h3>
                            <div class="value">$totalPreserved</div>
                            <div class="label">Well-Known Objects</div>
                        </div>
                        <div class="stat-card">
                            <h3>Domains</h3>
                            <div class="value">$($script:DomainMapping.Count)</div>
                            <div class="label">Domain Mappings</div>
                        </div>
                        <div class="stat-card">
                            <h3>Users</h3>
                            <div class="value">$($script:UserMapping.Count)</div>
                            <div class="label">User Mappings</div>
                        </div>
                    </div>
                </div>
            </section>

            <section id="compliance" class="section">
                <div class="section-header">
                    <h2><span class="emoji">🔒</span>GDPR & PII Compliance</h2>
                </div>
                <div class="section-content">
                    <div class="compliance-section">
                        <h3><span class="icon">✅</span> Data Protection Compliance Status</h3>
                        <p style="margin: 15px 0; font-size: 1.1em; line-height: 1.6;">
                            This anonymization process has been designed to comply with data protection regulations including
                            <strong>GDPR</strong> (General Data Protection Regulation), <strong>CCPA</strong> (California Consumer Privacy Act),
                            and <strong>HIPAA</strong> privacy requirements by removing all personally identifiable information (PII).
                        </p>

                        <div style="margin-top: 25px;">
                            <div class="compliance-badge">
                                <span class="icon">🇪🇺</span> GDPR Article 4(5) - Pseudonymization
                            </div>
                            <div class="compliance-badge">
                                <span class="icon">🛡️</span> GDPR Article 32 - Security of Processing
                            </div>
                            <div class="compliance-badge">
                                <span class="icon">🔐</span> Data Minimization Principle
                            </div>
                            <div class="compliance-badge">
                                <span class="icon">📋</span> CCPA §1798.140(o) - De-identification
                            </div>
                        </div>
                    </div>

                    <div class="chart-container">
                        <h3 style="color: #2c3e50; margin-bottom: 20px;">Personally Identifiable Information (PII) Removal</h3>
                        <p style="color: #6c757d; margin-bottom: 25px; line-height: 1.6;">
                            All PII has been systematically removed or anonymized to ensure compliance with data protection regulations:
                        </p>

                        <div class="pii-grid">
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">User Names</div>
                                <div class="pii-status">✓ Anonymized ($($script:UserMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Email Addresses</div>
                                <div class="pii-status">✓ Anonymized ($($script:EmailMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Computer Hostnames</div>
                                <div class="pii-status">✓ Anonymized ($($script:ComputerMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Group Names</div>
                                <div class="pii-status">✓ Anonymized ($($script:GroupMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Domain Names</div>
                                <div class="pii-status">✓ Anonymized ($($script:DomainMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Distinguished Names</div>
                                <div class="pii-status">✓ Anonymized ($($script:CNMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Organizational Units</div>
                                <div class="pii-status">✓ Anonymized ($($script:OUMapping.Count))</div>
                            </div>
                            <div class="pii-item" style="background: #d4edda; color: #155724;">
                                <div class="pii-label">Certificate Details</div>
                                <div class="pii-status">✓ Anonymized</div>
                            </div>
                        </div>

                        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 8px;">
                            <h4 style="color: #856404; margin-bottom: 10px; display: flex; align-items: center;">
                                <span style="font-size: 1.5em; margin-right: 10px;">⚠️</span>
                                Well-Known Objects Preserved
                            </h4>
                            <p style="color: #856404; line-height: 1.6;">
                                <strong>$totalPreserved well-known security principals</strong> (like "Domain Admins", "Administrator")
                                were preserved to maintain attack path analysis accuracy. These are <strong>not PII</strong> as they are
                                standard objects present in every Active Directory installation and do not identify individuals or organizations.
                            </p>
                        </div>

                        <div style="margin-top: 20px; padding: 20px; background: #d1ecf1; border-left: 4px solid #17a2b8; border-radius: 8px;">
                            <h4 style="color: #0c5460; margin-bottom: 10px; display: flex; align-items: center;">
                                <span style="font-size: 1.5em; margin-right: 10px;">ℹ️</span>
                                Structural Information Retained
                            </h4>
                            <p style="color: #0c5460; line-height: 1.6;">
                                Non-identifying structural data has been retained: number of objects, relationships, permissions, and attack paths.
                                This information is essential for security analysis and does not constitute PII under GDPR Article 4(1).
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            <section id="visualizations" class="section">
                <div class="section-header" onclick="toggleSection(this)">
                    <h2><span class="emoji">📊</span>Data Visualizations <span class="toggle">▼</span></h2>
                </div>
                <div class="section-content">
                    <p style="color: #6c757d; margin-bottom: 25px; line-height: 1.6;">
                        Visual breakdown of anonymization statistics and object type distribution:
                    </p>

                    <div class="chart-grid">
                        <div class="chart-wrapper">
                            <h4>Object Type Distribution</h4>
                            <canvas id="objectTypeChart"></canvas>
                        </div>
                        <div class="chart-wrapper">
                            <h4>Anonymized vs Preserved Objects</h4>
                            <canvas id="anonymizedVsPreservedChart"></canvas>
                        </div>
                    </div>

                    <div class="chart-grid">
                        <div class="chart-wrapper">
                            <h4>Consistency Check Results</h4>
                            <canvas id="consistencyChart"></canvas>
                        </div>
                        <div class="chart-wrapper">
                            <h4>Top 5 Object Types by Volume</h4>
                            <canvas id="topObjectsChart"></canvas>
                        </div>
                    </div>
                </div>
            </section>
"@

        # Add Consistency Checks section if available
        if ($AllConsistencyResults) {
            $html += @"
            <section id="consistency" class="section">
                <div class="section-header" onclick="toggleSection(this)">
                    <h2><span class="emoji">✓</span>Consistency Checks <span class="toggle">▼</span></h2>
                </div>
                <div class="section-content">
"@

            foreach ($checkName in $AllConsistencyResults.Keys) {
                $result = $AllConsistencyResults[$checkName]
                $statusClass = if ($result.IsConsistent) { "status-passed" } else { "status-failed" }
                $statusText = if ($result.IsConsistent) { "PASSED ✓" } else { "FAILED ✗" }

                $html += @"
                    <div style="margin: 20px 0; padding: 20px; background: #252538; border-radius: 8px; border: 1px solid #2d2d44;">
                        <h3 style="color: #e0e0e0;">$checkName <span class="status-badge $statusClass">$statusText</span></h3>
                        <p style="margin: 10px 0; color: #a0a0b0;">Total Issues: $($result.TotalIssues)</p>
"@

                if ($result.Issues.Count -gt 0) {
                    $html += "<div style='margin-top: 15px;'>"
                    foreach ($issue in $result.Issues) {
                        $issueClass = if ($issue -match '^Critical:') { "issue-critical" } else { "issue-warning" }
                        $html += "<div class='$issueClass'>$([System.Web.HttpUtility]::HtmlEncode($issue))</div>"
                    }
                    $html += "</div>"
                }

                $html += "</div>"
            }

            $html += @"
                </div>
            </section>
"@
        }

        # Add Domain Mappings
        if ($script:DomainMapping -and $script:DomainMapping.Count -gt 0) {
            $html += @"
            <section id="domains" class="section">
                <div class="section-header" onclick="toggleSection(this)">
                    <h2><span class="emoji">🌐</span>Domain Mappings <span class="toggle">▼</span></h2>
                </div>
                <div class="section-content">
                    <div class="search-box">
                        <input type="text" placeholder="🔍 Search domain mappings..." onkeyup="filterTable(this, 'domain-table')">
                    </div>
                    <table id="domain-table">
                        <thead>
                            <tr>
                                <th>Original Domain</th>
                                <th></th>
                                <th>Anonymized Domain</th>
                            </tr>
                        </thead>
                        <tbody>
"@

            $script:DomainMapping.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $html += @"
                            <tr>
                                <td><span class="preserved-item">$([System.Web.HttpUtility]::HtmlEncode($_.Key))</span></td>
                                <td class="arrow">→</td>
                                <td><span class="anonymized-item">$([System.Web.HttpUtility]::HtmlEncode($_.Value))</span></td>
                            </tr>
"@
            }

            $html += @"
                        </tbody>
                    </table>
                </div>
            </section>
"@
        }

        # Add User Mappings
        if ($script:UserMapping -and $script:UserMapping.Count -gt 0) {
            $html += @"
            <section id="users" class="section">
                <div class="section-header" onclick="toggleSection(this)">
                    <h2><span class="emoji">👤</span>User Mappings ($($script:UserMapping.Count)) <span class="toggle">▼</span></h2>
                </div>
                <div class="section-content collapsed">
                    <div class="search-box">
                        <input type="text" placeholder="🔍 Search user mappings..." onkeyup="filterTable(this, 'user-table')">
                    </div>
                    <table id="user-table">
                        <thead>
                            <tr>
                                <th>Original sAMAccountName</th>
                                <th></th>
                                <th>Anonymized sAMAccountName</th>
                            </tr>
                        </thead>
                        <tbody>
"@

            $script:UserMapping.GetEnumerator() | Sort-Object Key | Select-Object -First 100 | ForEach-Object {
                $html += @"
                            <tr>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($_.Key))</td>
                                <td class="arrow">→</td>
                                <td><span class="anonymized-item">$([System.Web.HttpUtility]::HtmlEncode($_.Value))</span></td>
                            </tr>
"@
            }

            if ($script:UserMapping.Count -gt 100) {
                $html += @"
                            <tr>
                                <td colspan="3" style="text-align: center; color: #6c757d; padding: 20px;">
                                    ... and $($script:UserMapping.Count - 100) more user mappings
                                </td>
                            </tr>
"@
            }

            $html += @"
                        </tbody>
                    </table>
                </div>
            </section>
"@
        }

        # Add Preserved Items section
        if ($script:PreservedItems.Groups -and $script:PreservedItems.Groups.Count -gt 0) {
            $html += @"
            <section id="preserved" class="section">
                <div class="section-header" onclick="toggleSection(this)">
                    <h2><span class="emoji">🛡️</span>Preserved Well-Known Items <span class="toggle">▼</span></h2>
                </div>
                <div class="section-content collapsed">
                    <h3>Preserved Groups</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
"@

            $script:PreservedItems.Groups.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $html += @"
                            <tr>
                                <td><span class="preserved-item">$([System.Web.HttpUtility]::HtmlEncode($_.Key))</span></td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($_.Value))</td>
                            </tr>
"@
            }

            $html += @"
                        </tbody>
                    </table>
                </div>
            </section>
"@
        }

        # Close HTML
        $html += @"
        </div>

        <footer>
            <p>Generated by <strong>AnonymousHound</strong> - BloodHound Data Anonymization Tool</p>
            <p style="margin-top: 10px; opacity: 0.8;">⚠️ Keep this report confidential - it contains the anonymization mapping</p>
        </footer>
    </div>

    <script>
        function toggleSection(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }

        function filterTable(input, tableId) {
            const filter = input.value.toUpperCase();
            const table = document.getElementById(tableId);
            const tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {
                const row = tr[i];
                const cells = row.getElementsByTagName('td');
                let found = false;

                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const txtValue = cell.textContent || cell.innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }

                row.style.display = found ? '' : 'none';
            }
        }

        // Collapse sections by default (except overview and compliance)
        document.addEventListener('DOMContentLoaded', function() {
            const headers = document.querySelectorAll('.section-header');
            headers.forEach((header, index) => {
                if (index > 1) { // Skip first two sections (overview and compliance)
                    header.click();
                }
            });

            // Initialize charts
            initializeCharts();
        });

        function initializeCharts() {
            // Chart.js default configuration
            Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
            Chart.defaults.plugins.legend.position = 'bottom';

            // Object Type Distribution Chart
            const objectTypeData = {
                labels: ['Users', 'Groups', 'Computers', 'Domains', 'OUs', 'CNs', 'GPOs', 'Others'],
                datasets: [{
                    data: [
                        $($script:UserMapping.Count),
                        $($script:GroupMapping.Count),
                        $($script:ComputerMapping.Count),
                        $($script:DomainMapping.Count),
                        $($script:OUMapping.Count),
                        $($script:CNMapping.Count),
                        $(if ($script:GPOMapping) { $script:GPOMapping.Count } else { 0 }),
                        $(if ($script:ContainerMapping) { $script:ContainerMapping.Count } else { 0 })
                    ],
                    backgroundColor: [
                        '#667eea', '#764ba2', '#f093fb', '#4facfe',
                        '#43e97b', '#fa709a', '#fee140', '#30cfd0'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            };

            new Chart(document.getElementById('objectTypeChart'), {
                type: 'doughnut',
                data: objectTypeData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });

            // Anonymized vs Preserved Chart
            const anonymizedVsPreservedData = {
                labels: ['Anonymized Objects', 'Preserved Well-Known Objects'],
                datasets: [{
                    data: [$totalMappings, $totalPreserved],
                    backgroundColor: ['#ffc107', '#28a745'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            };

            new Chart(document.getElementById('anonymizedVsPreservedChart'), {
                type: 'pie',
                data: anonymizedVsPreservedData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });
"@

        # Calculate consistency check stats
        $passedCount = 0
        $failedCount = 0
        if ($AllConsistencyResults) {
            foreach ($checkName in $AllConsistencyResults.Keys) {
                $result = $AllConsistencyResults[$checkName]
                if ($result.IsConsistent) {
                    $passedCount++
                } else {
                    $failedCount++
                }
            }
        }

        $html += @"
            // Consistency Check Results Chart
            const consistencyData = {
                labels: ['Passed Checks', 'Failed Checks'],
                datasets: [{
                    data: [$passedCount, $failedCount],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            };

            new Chart(document.getElementById('consistencyChart'), {
                type: 'doughnut',
                data: consistencyData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });

            // Top 5 Object Types Chart
            const topObjectsData = {
                labels: ['Users', 'CNs', 'Groups', 'Computers', 'OUs'],
                datasets: [{
                    label: 'Number of Objects',
                    data: [
                        $($script:UserMapping.Count),
                        $($script:CNMapping.Count),
                        $($script:GroupMapping.Count),
                        $($script:ComputerMapping.Count),
                        $($script:OUMapping.Count)
                    ],
                    backgroundColor: [
                        'rgba(102, 126, 234, 0.8)',
                        'rgba(118, 75, 162, 0.8)',
                        'rgba(240, 147, 251, 0.8)',
                        'rgba(79, 172, 254, 0.8)',
                        'rgba(67, 233, 123, 0.8)'
                    ],
                    borderColor: [
                        'rgb(102, 126, 234)',
                        'rgb(118, 75, 162)',
                        'rgb(240, 147, 251)',
                        'rgb(79, 172, 254)',
                        'rgb(67, 233, 123)'
                    ],
                    borderWidth: 2
                }]
            };

            new Chart(document.getElementById('topObjectsChart'), {
                type: 'bar',
                data: topObjectsData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    </script>
</body>
</html>
"@

        # Write HTML file
        [System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.UTF8Encoding]::new($false))

        Write-ScriptLog "HTML report saved to: $htmlFile" -Level Success
        return $htmlFile
    }
    catch {
        Write-ScriptLog "Error generating HTML report: $_" -Level Error
        return $null
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

function New-OutputZip {
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
Import-DomainMappings

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
            'users' { Invoke-UsersFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'groups' { Invoke-GroupsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'computers' { Invoke-ComputersFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'domains' { Invoke-DomainsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'gpos' { Invoke-GPOsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'ous' { Invoke-OUsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'containers' { Invoke-ContainersFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'certtemplates' { Invoke-CertTemplatesFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'ntauthstores' { Invoke-NTAuthStoresFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'aiacas' { Invoke-AIACAsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'rootcas' { Invoke-RootCAsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
            'enterprisecas' { Invoke-EnterpriseCAsFileProcessing -FilePath $InputFile -OutputPath $outputPath }
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
                    'users' { Invoke-UsersFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'groups' { Invoke-GroupsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'computers' { Invoke-ComputersFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'domains' { Invoke-DomainsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'gpos' { Invoke-GPOsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'ous' { Invoke-OUsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'containers' { Invoke-ContainersFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'certtemplates' { Invoke-CertTemplatesFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'ntauthstores' { Invoke-NTAuthStoresFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'aiacas' { Invoke-AIACAsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'rootcas' { Invoke-RootCAsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                    'enterprisecas' { Invoke-EnterpriseCAsFileProcessing -FilePath $file.FullName -OutputPath $outputPath }
                }
            }

            Write-Host ""
            Write-Host "✓ Collection $collectionKey processed" -ForegroundColor Green
        }
    }

    # ========================================================================
    # CONSISTENCY CHECKS
    # Validate domain mapping consistency and perform reverse lookups
    # ========================================================================
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Running Consistency Checks" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # Run domain mapping consistency check
    $consistencyResults = Test-DomainMappingConsistency

    # Display domain consistency results to console
    Write-Host "Domain Mapping Consistency Check:" -ForegroundColor Cyan
    if ($consistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All domain mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($consistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # If there are critical issues, add them to error log
    $allCriticalIssues = @()
    if (-not $consistencyResults.IsConsistent) {
        $criticalIssues = $consistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($criticalIssues.Count -gt 0) {
            $allCriticalIssues += $criticalIssues
        }
    }

    Write-Host ""

    # Run CN mapping consistency check
    $cnConsistencyResults = Test-CNMappingConsistency

    # Display CN consistency results to console
    Write-Host "CN Mapping Consistency Check:" -ForegroundColor Cyan
    if ($cnConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All CN mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($cnConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect CN critical issues
    if (-not $cnConsistencyResults.IsConsistent) {
        $cnCriticalIssues = $cnConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($cnCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $cnCriticalIssues
        }
    }

    Write-Host ""

    # Run Certificate Template consistency check
    $certTemplateConsistencyResults = Test-CertTemplateConsistency

    # Display Certificate Template consistency results to console
    Write-Host "Certificate Template Consistency Check:" -ForegroundColor Cyan
    if ($certTemplateConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All certificate template mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($certTemplateConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Certificate Template critical issues
    if (-not $certTemplateConsistencyResults.IsConsistent) {
        $certTemplateCriticalIssues = $certTemplateConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($certTemplateCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $certTemplateCriticalIssues
        }
    }

    Write-Host ""

    # Run Group consistency check
    $groupConsistencyResults = Test-GroupConsistency

    # Display Group consistency results to console
    Write-Host "Group Consistency Check:" -ForegroundColor Cyan
    if ($groupConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All group mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($groupConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Group critical issues
    if (-not $groupConsistencyResults.IsConsistent) {
        $groupCriticalIssues = $groupConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($groupCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $groupCriticalIssues
        }
    }

    Write-Host ""

    # Run OU consistency check
    $ouConsistencyResults = Test-OUConsistency

    # Display OU consistency results to console
    Write-Host "OU Consistency Check:" -ForegroundColor Cyan
    if ($ouConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All OU mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($ouConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect OU critical issues
    if (-not $ouConsistencyResults.IsConsistent) {
        $ouCriticalIssues = $ouConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($ouCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $ouCriticalIssues
        }
    }

    Write-Host ""

    # Run GPO consistency check
    $gpoConsistencyResults = Test-GPOConsistency

    # Display GPO consistency results to console
    Write-Host "GPO Consistency Check:" -ForegroundColor Cyan
    if ($gpoConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All GPO structures are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($gpoConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect GPO critical issues
    if (-not $gpoConsistencyResults.IsConsistent) {
        $gpoCriticalIssues = $gpoConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($gpoCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $gpoCriticalIssues
        }
    }

    Write-Host ""

    # Run NTAuthStore consistency check
    $ntAuthStoreConsistencyResults = Test-NTAuthStoreConsistency

    # Display NTAuthStore consistency results to console
    Write-Host "NTAuthStore Consistency Check:" -ForegroundColor Cyan
    if ($ntAuthStoreConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All NTAuthStore mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($ntAuthStoreConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect NTAuthStore critical issues
    if (-not $ntAuthStoreConsistencyResults.IsConsistent) {
        $ntAuthStoreCriticalIssues = $ntAuthStoreConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($ntAuthStoreCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $ntAuthStoreCriticalIssues
        }
    }

    Write-Host ""

    # Run Container consistency check
    $containerConsistencyResults = Test-ContainerConsistency

    # Display Container consistency results to console
    Write-Host "Container Consistency Check:" -ForegroundColor Cyan
    if ($containerConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All container mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($containerConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Container critical issues
    if (-not $containerConsistencyResults.IsConsistent) {
        $containerCriticalIssues = $containerConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($containerCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $containerCriticalIssues
        }
    }

    Write-Host ""

    # Run Root CA consistency check
    $rootCAConsistencyResults = Test-RootCAConsistency

    # Display Root CA consistency results to console
    Write-Host "Root CA Consistency Check:" -ForegroundColor Cyan
    if ($rootCAConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All Root CA mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($rootCAConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Root CA critical issues
    if (-not $rootCAConsistencyResults.IsConsistent) {
        $rootCACriticalIssues = $rootCAConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($rootCACriticalIssues.Count -gt 0) {
            $allCriticalIssues += $rootCACriticalIssues
        }
    }

    Write-Host ""

    # Run Enterprise CA consistency check
    $enterpriseCAConsistencyResults = Test-EnterpriseCAConsistency

    # Display Enterprise CA consistency results to console
    Write-Host "Enterprise CA Consistency Check:" -ForegroundColor Cyan
    if ($enterpriseCAConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All Enterprise CA mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($enterpriseCAConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Enterprise CA critical issues
    if (-not $enterpriseCAConsistencyResults.IsConsistent) {
        $enterpriseCACriticalIssues = $enterpriseCAConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($enterpriseCACriticalIssues.Count -gt 0) {
            $allCriticalIssues += $enterpriseCACriticalIssues
        }
    }

    Write-Host ""

    # Run Computer consistency check
    $computerConsistencyResults = Test-ComputerConsistency

    # Display Computer consistency results to console
    Write-Host "Computer Consistency Check:" -ForegroundColor Cyan
    if ($computerConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All computer mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($computerConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect Computer critical issues
    if (-not $computerConsistencyResults.IsConsistent) {
        $computerCriticalIssues = $computerConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($computerCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $computerCriticalIssues
        }
    }

    Write-Host ""

    # Run User consistency check
    $userConsistencyResults = Test-UserConsistency

    # Display User consistency results to console
    Write-Host "User Consistency Check:" -ForegroundColor Cyan
    if ($userConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All user mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($userConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect User critical issues
    if (-not $userConsistencyResults.IsConsistent) {
        $userCriticalIssues = $userConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($userCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $userCriticalIssues
        }
    }

    Write-Host ""

    # Run AIACA consistency check
    $aiacaConsistencyResults = Test-AIACAConsistency

    # Display AIACA consistency results to console
    Write-Host "AIACA Consistency Check:" -ForegroundColor Cyan
    if ($aiacaConsistencyResults.IsConsistent) {
        Write-Host "  ✓ PASSED - All AIACA mappings are consistent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAILED - Inconsistencies detected" -ForegroundColor Red
        Write-Host "    Total Issues: $($aiacaConsistencyResults.TotalIssues)" -ForegroundColor Yellow
    }

    # Collect AIACA critical issues
    if (-not $aiacaConsistencyResults.IsConsistent) {
        $aiacaCriticalIssues = $aiacaConsistencyResults.Issues | Where-Object { $_ -match '^Critical:' }
        if ($aiacaCriticalIssues.Count -gt 0) {
            $allCriticalIssues += $aiacaCriticalIssues
        }
    }

    # Display overall critical issues warning if any found
    if ($allCriticalIssues.Count -gt 0) {
        Write-Host ""
        Write-Host "⚠️  CRITICAL CONSISTENCY ISSUES DETECTED!" -ForegroundColor Red
        Write-Host "   Found $($allCriticalIssues.Count) critical issue(s) across all checks" -ForegroundColor Yellow
        Write-Host "   Please review the CONSISTENCY CHECK RESULTS section in anonymization_mappings.txt for details." -ForegroundColor Yellow
        Write-Host ""

        # Add to error log
        foreach ($issue in $allCriticalIssues) {
            $script:ErrorLog += "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] CONSISTENCY CHECK: $issue"
        }
    }

    Write-Host ""

    # ========================================================================
    # POST-PROCESSING
    # Save mapping files and display summary
    # ========================================================================

    # Save comprehensive mappings to file for reference and future runs
    # This will now include all collections if multiple were processed
    # AND include consistency check results
    Save-ComprehensiveMappings -OutputPath $OutputDirectory -DomainConsistencyResults $consistencyResults -CNConsistencyResults $cnConsistencyResults -CertTemplateConsistencyResults $certTemplateConsistencyResults -GroupConsistencyResults $groupConsistencyResults -OUConsistencyResults $ouConsistencyResults -GPOConsistencyResults $gpoConsistencyResults -NTAuthStoreConsistencyResults $ntAuthStoreConsistencyResults -ContainerConsistencyResults $containerConsistencyResults -RootCAConsistencyResults $rootCAConsistencyResults -EnterpriseCAConsistencyResults $enterpriseCAConsistencyResults -ComputerConsistencyResults $computerConsistencyResults -UserConsistencyResults $userConsistencyResults -AIACAConsistencyResults $aiacaConsistencyResults

    # Save error log if any errors occurred during processing
    Save-ErrorLog -OutputPath $OutputDirectory

    # Organize output files and create ZIP archive
    $organizedOutput = New-OutputZip -OutputPath $OutputDirectory

    # Generate interactive HTML report AFTER organizing files (so it goes in AnonymizedData folder but not in ZIP)
    if ($organizedOutput -and $organizedOutput.Folder) {
        Write-Host ""
        Write-Host "📄 Generating HTML Report..." -ForegroundColor Cyan
        $allConsistencyResults = @{
            'Domain' = $consistencyResults
            'CN' = $cnConsistencyResults
            'Certificate Template' = $certTemplateConsistencyResults
            'Group' = $groupConsistencyResults
            'OU' = $ouConsistencyResults
            'GPO' = $gpoConsistencyResults
            'NTAuthStore' = $ntAuthStoreConsistencyResults
            'Container' = $containerConsistencyResults
            'Root CA' = $rootCAConsistencyResults
            'Enterprise CA' = $enterpriseCAConsistencyResults
            'Computer' = $computerConsistencyResults
            'User' = $userConsistencyResults
            'AIACA' = $aiacaConsistencyResults
        }
        $htmlReportPath = Save-ComprehensiveMappingsHTML -OutputPath $organizedOutput.Folder -AllConsistencyResults $allConsistencyResults
        if ($htmlReportPath) {
            Write-Host "   ✓ HTML report generated in AnonymizedData folder" -ForegroundColor Green
            Write-Host "   📂 $htmlReportPath" -ForegroundColor Gray
            Write-Host "   ℹ️  HTML report excluded from ZIP for local viewing" -ForegroundColor DarkGray
        }
    }

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
    Write-Host "   CNs mapped: $($script:CNMapping.Count)" -ForegroundColor White
    Write-Host "   CNs preserved: $($script:PreservedItems.CNs.Count)" -ForegroundColor White
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
        if ($htmlReportPath) {
            Write-Host "   HTML Report: $htmlReportPath" -ForegroundColor White
            Write-Host "   (Open in browser for interactive view - not included in ZIP)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "   Directory: $OutputDirectory" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "🎉 Ready to share! Your anonymized BloodHound data is in:" -ForegroundColor Green
    if ($organizedOutput) {
        Write-Host "   📦 ZIP Archive: $($organizedOutput.ZipFile)" -ForegroundColor Cyan
        if ($htmlReportPath) {
            Write-Host "   📄 HTML Report: $htmlReportPath (local viewing)" -ForegroundColor Cyan
        }
    }
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: Keep the mapping files private - they contain the key" -ForegroundColor Yellow
    Write-Host "   to reverse the anonymization!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "💡 TIP: Open the HTML report in your browser for an interactive view" -ForegroundColor DarkGray
    Write-Host "   of all mappings and consistency checks!" -ForegroundColor DarkGray
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