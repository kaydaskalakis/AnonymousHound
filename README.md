# AnonymousHound
Mask the trail, keep the scent. AnonymousHound anonymizes sensitive data within BloodHound exports (users, groups, PKI, etc.) ensuring PII is scrubbed, but the full map of security vulnerabilities and attack paths remains 100% intact for analysis.

<img width="896" height="1152" alt="AnonymousHound" src="https://github.com/user-attachments/assets/1c04d92c-3dda-4299-967f-b9fe0b4d5f17" />

He is super anonymous.
He is...
# AnonymousHound 🕵️🐕

**Version:** 0.1 ALPHA

## What is this?

AnonymousHound is a PowerShell tool that anonymizes BloodHound data exports, allowing security professionals to safely share Active Directory security assessments without exposing sensitive organizational information.

## Why does this exist?

### The Problem

Imagine you're a security consultant who just completed a comprehensive Active Directory security assessment for a company. You discovered several critical attack paths that could allow an attacker to compromise domain administrator accounts. You want to:

- **Share your findings** with other security researchers to get peer review
- **Create training materials** showing real-world attack scenarios
- **Ask for help** on security forums without exposing your client's identity
- **Demonstrate techniques** at conferences or in blog posts

**BUT** - the BloodHound data contains extremely sensitive information:

- Employee names and usernames (e.g., "john.smith", "sarah.johnson")
- Email addresses (john.smith@acmecorp.com)
- Computer hostnames (FINANCE-PC-01, CEO-LAPTOP)
- Domain names (acmecorp.local, internal.acmecorp.com)
- Organizational structure (Sales OU, Executive OU, IT Department)
- Certificate details and infrastructure layout

**Sharing this data would be a massive privacy and security breach!**

### The Solution

AnonymousHound solves this by **disguising all identifiable information while preserving the attack paths**. Think of it like this:

#### Before Anonymization (Exposed!)
```
User: john.smith@acmecorp.com
  ├─ MemberOf: Domain Admins
  ├─ HasSession: FINANCE-PC-01.acmecorp.local
  └─ Can compromise: CEO-LAPTOP.acmecorp.local
```

#### After Anonymization (Safe to Share!)
```
User: USR_A3F2E1@domain1.local
  ├─ MemberOf: Domain Admins  ← (Preserved! Still shows privilege)
  ├─ HasSession: HOST_B7D9C2.domain1.local
  └─ Can compromise: HOST_F4E8A6.domain1.local
```

**The attack path still exists!** You can still see that:
- A user is a Domain Admin
- That user has a session somewhere
- This creates a path to compromise another computer

But now **all identifying information is gone** - no company names, no employee names, nothing that could trace back to the real organization.

### Real-World Use Cases

#### 1. **Security Research & Collaboration**
*"I found this crazy attack path but I'm not sure if it's exploitable..."*

You can now share your BloodHound data on forums like Reddit's /r/AskNetSec or security Discord servers without violating your NDA or exposing your client.

#### 2. **Training & Education**
*"I want to teach people about Active Directory attacks using real data..."*

Security trainers can use real-world anonymized datasets in courses instead of artificial lab environments, showing students what actual corporate AD environments look like.

#### 3. **Tool Development & Testing**
*"I'm building a tool that analyzes BloodHound data..."*

Developers can test their tools against diverse, real-world datasets without needing access to actual corporate environments.

#### 4. **Conference Presentations & Blog Posts**
*"I want to present my methodology at DEF CON..."*

Security researchers can demonstrate attack techniques and findings publicly without exposing the organizations they assessed.

#### 5. **Compliance & Auditing**
*"We need to show the audit team our security findings..."*

Some compliance frameworks require evidence of security testing, but showing raw data might violate privacy regulations (GDPR, HIPAA). Anonymized data satisfies both requirements.

## What Gets Anonymized?

### Personal Identifiable Information (PII)
- ✅ User names → `USR_A3F2E1`
- ✅ Email addresses → `email_b7d9c2@domain1.local`
- ✅ Computer names → `COMP_F4E8A6`
- ✅ Group names → `GRP_C9B2D1`
- ✅ Domain names → `DOMAIN1.LOCAL`, `DOMAIN2.LOCAL`
- ✅ Organizational Units → `OU_7F3A21`
- ✅ Certificate details → Randomized thumbprints
- ✅ Descriptions and display names

### What DOESN'T Get Anonymized? (Critical for Analysis!)
- ✅ **Well-known security principals** (Domain Admins, Enterprise Admins, Administrators)
- ✅ **Attack path relationships** (MemberOf, HasSession, AdminTo, etc.)
- ✅ **Permissions and ACLs** (who can do what to whom)
- ✅ **Group Policy Objects** (attack surface analysis)
- ✅ **Certificate Templates** (AD CS attack paths like ESC1-ESC13)
- ✅ **Domain trust relationships**
- ✅ **Security-relevant properties** (SPN names, encryption types, etc.)

## How It Works (Non-Technical Explanation)

Think of it like a witness protection program for data:

1. **Consistent Identity Replacement**: Every time "john.smith" appears in the data, it becomes "USR_A3F2E1". Same person, new identity, consistent across all files.

2. **Relationship Preservation**: If john.smith was a member of "Domain Admins", then USR_A3F2E1 is still a member of "Domain Admins". The connections remain intact.

3. **Well-Known Protection**: Critical built-in accounts like "Administrator" or "Domain Admins" keep their real names because they're not identifying - every Active Directory has them.

4. **Structure Preservation**: If your company had 5 domains, the anonymized data still has 5 domains. If there were 10 GPOs, there are still 10 GPOs. The structure is identical, just the names have changed.

5. **Idempotent**: Running it twice on the same data doesn't double-anonymize. It recognizes already-anonymized files and skips them.

## Quick Start

### Process an entire BloodHound collection:
```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\BloodHound\Data" -OutputDirectory "C:\BloodHound\Anonymized"
```

### Process a single file:
```powershell
.\AnonymousHound.ps1 -InputFile "C:\BloodHound\users.json" -OutputDirectory "C:\BloodHound\Output"
```

### Randomize timestamps (extra privacy):
```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\BloodHound\Data" -OutputDirectory "C:\BloodHound\Anonymized" -RandomizeTimestamps
```

## What You Get

After running AnonymousHound, you'll get:

1. **Anonymized JSON files** with the `ANONYMIZED_` prefix
2. **A mapping file** showing what was changed (keep this secret!)
3. **Data you can safely share** for research, training, or collaboration

## Important Notes

⚠️ **Keep the mapping file private!** The `domain_mappings.txt` file shows the translation between real and anonymized names. Don't share this!

✅ **Review before sharing**: While AnonymousHound removes most identifying information, always review the output to ensure nothing sensitive slipped through.

⚠️ **Structural information remains**: While names are hidden, the structure of your Active Directory (number of domains, OUs, users, etc.) is still visible. In rare cases, this might be identifying.

## Supported BloodHound File Types

- ✅ users.json
- ✅ groups.json
- ✅ computers.json
- ✅ domains.json
- ✅ gpos.json
- ✅ ous.json
- ✅ containers.json
- ✅ certtemplates.json (AD CS)
- ✅ ntauthstores.json (AD CS)
- ✅ aiacas.json (AD CS)
- ✅ rootcas.json (AD CS)
- ✅ enterprisecas.json (AD CS)

## Example: Before and After

### Before (Sensitive!)
```json
{
  "Properties": {
    "name": "JOHN.SMITH@ACMECORP.COM",
    "samaccountname": "john.smith",
    "email": "john.smith@acmecorp.com",
    "distinguishedname": "CN=John Smith,OU=Sales,OU=Employees,DC=acmecorp,DC=com"
  }
}
```

### After (Safe to Share!)
```json
{
  "Properties": {
    "name": "USR_A3F2E1@DOMAIN1.LOCAL",
    "samaccountname": "USR_A3F2E1",
    "email": "email_b7d9c2@domain1.local",
    "distinguishedname": "CN=CN_F4E8A6,OU=OU_7F3A21,OU=OU_C9B2D1,DC=DOMAIN1,DC=LOCAL"
  }
}
```

## License & Usage

This tool is designed for security professionals conducting authorized assessments. Always:
- ✅ Have permission to collect the data
- ✅ Review anonymized output before sharing
- ✅ Follow your organization's data handling policies
- ✅ Respect privacy and confidentiality agreements

## Contributing

Found a bug? Have a suggestion? Contributions are welcome! This is an ALPHA release, so expect rough edges.

## Author

**Kay Daskalakis**

GitHub: [https://github.com/kaydaskalakis](https://github.com/kaydaskalakis)

---

*"The best defense is shared knowledge, but privacy matters too."* 🎭🐕

## What's New in Version 0.1 ALPHA

This initial alpha release includes comprehensive anonymization capabilities with the following features:

### Core Anonymization Features
- ✅ **Consistent Identity Mapping** - All occurrences of the same entity receive the same anonymized name across all files
- ✅ **Relationship Preservation** - Attack paths, group memberships, and permissions remain intact
- ✅ **Well-Known Principal Protection** - Built-in security groups and accounts preserved for accurate analysis
- ✅ **Domain Controller Recognition** - Automatically identifies and preserves DC naming patterns (DC01, DC02, RODC01, etc.)
- ✅ **Certificate Services Support** - Full AD CS anonymization including templates, CAs, and NTAuthStores
- ✅ **LDAP Partition Handling** - Correctly processes DomainDnsZones, ForestDnsZones, and _msdcs partitions
- ✅ **Exchange Group Recognition** - Special handling for Exchange DAG groups and system groups
- ✅ **SPN Anonymization** - Service Principal Names anonymized while preserving service types
- ✅ **GUID and SID Mapping** - Deterministic anonymization of GUIDs and Security Identifiers

### Data Integrity Features
- ✅ **Distinguished Name Parsing** - Handles complex DNs with escaped characters and special formats
- ✅ **Case-Insensitive Mapping** - Consistent handling regardless of case variations in source data
- ✅ **CN vs OU Distinction** - Properly differentiates between CN containers and OU organizational units
- ✅ **Idempotent Processing** - Already-anonymized files are detected and skipped
- ✅ **Deep JSON Processing** - Handles nested structures and complex BloodHound schemas
- ✅ **Timestamp Randomization** - Optional feature to obfuscate collection dates

### Reporting & Transparency
- ✅ **Comprehensive Mapping File** - Complete record of all anonymization mappings organized by type
- ✅ **Preserved Items Documentation** - Detailed list of what was NOT anonymized and why
- ✅ **Console Progress Tracking** - Real-time feedback showing processed vs anonymized vs preserved counts
- ✅ **Detailed Summary Statistics** - Breakdown of all anonymized entities by category
- ✅ **Error Logging** - Separate error log for troubleshooting and validation

### Well-Known Entity Recognition
- ✅ **Built-in Security Groups** - Recognizes 50+ well-known groups (Domain Admins, Enterprise Admins, etc.)
- ✅ **System Accounts** - Preserves krbtgt, Administrator, Guest, and system service accounts
- ✅ **Default OUs** - Maintains standard OUs (Users, Computers, Domain Controllers, etc.)
- ✅ **CN Containers** - Preserves well-known containers (System, Users, Configuration, etc.)
- ✅ **Special Identity SIDs** - Recognizes SELF, CREATOR OWNER, ANONYMOUS LOGON, etc.
- ✅ **Performance Counter Groups** - Handles WMI and performance monitoring groups correctly
- ✅ **Well-Known Domains** - Preserves security-relevant domains like NT AUTHORITY

### Technical Improvements
- ✅ **Regex Pattern Matching** - Flexible group recognition using configurable regex patterns
- ✅ **Safe JSON Handling** - Automatic depth adjustment for deeply nested structures
- ✅ **Memory Efficient** - Streams large files without loading entire datasets into memory
- ✅ **UTF-8 Without BOM** - Ensures compatibility with BloodHound and other tools
- ✅ **PowerShell 5.1+ Compatible** - Works on Windows PowerShell and PowerShell Core
- ✅ **Null Reference Protection** - Defensive coding prevents crashes on malformed data
- ✅ **Verbose Logging** - Detailed diagnostics available with -Verbose parameter

### Supported BloodHound Collections
- ✅ **Users** - Full user object anonymization with email and SPN handling
- ✅ **Groups** - Group objects with membership and nesting preservation
- ✅ **Computers** - Computer objects with OS and session information
- ✅ **Domains** - Domain objects with trust relationships
- ✅ **GPOs** - Group Policy Objects with link preservation
- ✅ **OUs** - Organizational Units with hierarchy intact
- ✅ **Containers** - CN containers and special system containers
- ✅ **Certificate Templates** - AD CS certificate templates (ESC vulnerability analysis)
- ✅ **NTAuthStores** - Enterprise authentication store objects
- ✅ **AIACAs** - Authority Information Access CAs
- ✅ **RootCAs** - Root Certificate Authorities
- ✅ **EnterpriseCAs** - Enterprise Certificate Authorities (full AD CS support)

### Privacy & Security
- ✅ **PII Removal** - All personally identifiable information replaced with random identifiers
- ✅ **Email Anonymization** - Email addresses correlated with user anonymization
- ✅ **Description Sanitization** - User and group descriptions replaced with generic text
- ✅ **Display Name Removal** - Human-readable names replaced with technical identifiers
- ✅ **Hostname Anonymization** - All computer and server names randomized
- ✅ **Certificate Thumbprint Randomization** - Certificate identifiers made non-traceable

### Known Limitations (Alpha Release)
- ⚠️ Structural information (number of users, domains, OUs) remains visible
- ⚠️ Some edge cases in extremely complex DNs may need manual review
- ⚠️ Custom schema extensions are not yet supported
- ⚠️ Azure AD / Entra ID objects are not currently anonymized

### Coming Soon
- 🔄 Azure AD / Entra ID support
- 🔄 Custom well-known entity lists
- 🔄 Batch processing performance improvements
- 🔄 GUI interface option
- 🔄 Integration with BloodHound CE
