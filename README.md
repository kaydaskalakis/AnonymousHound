# AnonymousHound

Mask the trail, keep the scent. AnonymousHound anonymizes sensitive data within BloodHound exports (users, groups, PKI, etc.) ensuring PII is scrubbed, but the full map of security vulnerabilities and attack paths remains 100% intact for analysis.

<img width="896" height="1152" alt="AnonymousHound" src="https://github.com/user-attachments/assets/1c04d92c-3dda-4299-967f-b9fe0b4d5f17" />

He is super anonymous.

He is...
---

## Table of Contents
- [What is AnonymousHound?](#what-is-anonymoushound)
- [Why Does This Exist?](#why-does-this-exist)
- [Quick Start](#quick-start)
- [What's New in v0.2 BETA](#whats-new-in-v02-beta)
- [Features](#features)
- [User Experience](#user-experience)
- [Performance & Optimization](#performance--optimization)
- [What Gets Anonymized?](#what-gets-anonymized)
- [Usage Examples](#usage-examples)
- [HTML Report](#html-report)
- [Supported File Types](#supported-bloodhound-file-types)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [License & Usage](#license--usage)
- [Credits](#credits)

---
**Version:** 0.2 BETA

**Author:** Kay Daskalakis

**GitHub:** [https://github.com/kaydaskalakis](https://github.com/kaydaskalakis)

**LinkedIn:** [https://www.linkedin.com/in/kdaskalakis](https://www.linkedin.com/in/kdaskalakis)

## What is AnonymousHound?

AnonymousHound is a PowerShell tool that anonymizes BloodHound data exports, allowing security professionals to safely share Active Directory security assessments without exposing sensitive organizational information.

---

## Why Does This Exist?

### The Problem

Imagine you're a security consultant who just completed a comprehensive Active Directory security assessment for a company. You discovered several critical attack paths that could allow an attacker to compromise domain administrator accounts. You want to:

- **Share your findings** with other security researchers to get peer review
- **Create training materials** showing real-world attack scenarios
- **Ask for help** on security forums without exposing your client's identity
- **Demonstrate techniques** at conferences or in blog posts

**BUT** - the BloodHound data contains extremely sensitive information:

- Employee names and usernames (e.g., "john.smith", "sarah.johnson")
- Email addresses (<john.smith@acmecorp.com>)
- Computer hostnames (FINANCE-PC-01, CEO-LAPTOP)
- Domain names (acmecorp.local, internal.acmecorp.com)
- Organizational structure (Sales OU, Executive OU, IT Department)
- Certificate details and infrastructure layout

**Sharing this data would be a massive privacy and security breach!**

### The Solution

AnonymousHound solves this by **disguising all identifiable information while preserving the attack paths**. Think of it like this:

#### Before Anonymization (Exposed!)

```text
User: john.smith@acmecorp.com
  ├─ MemberOf: Domain Admins
  ├─ HasSession: FINANCE-PC-01.acmecorp.local
  └─ Can compromise: CEO-LAPTOP.acmecorp.local
```

#### After Anonymization (Safe to Share!)

```text
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

### 1. Security Research & Collaboration

*"I found this crazy attack path but I'm not sure if it's exploitable..."*

You can now share your BloodHound data on forums like Reddit's /r/AskNetSec or security Discord servers without violating your NDA or exposing your client.

### 2. Training & Education

*"I want to teach people about Active Directory attacks using real data..."*

Security trainers can use real-world anonymized datasets in courses instead of artificial lab environments, showing students what actual corporate AD environments look like.

### 3. Tool Development & Testing

*"I'm building a tool that analyzes BloodHound data..."*

Developers can test their tools against diverse, real-world datasets without needing access to actual corporate environments.

### 4. Conference Presentations & Blog Posts

*"I want to present my methodology at DEF CON..."*

Security researchers can demonstrate attack techniques and findings publicly without exposing the organizations they assessed.

### 5. Compliance & Auditing

*"We need to show the audit team our security findings..."*

Some compliance frameworks require evidence of security testing, but showing raw data might violate privacy regulations (GDPR, HIPAA). Anonymized data satisfies both requirements.

---

## Quick Start

### Three Ways to Run AnonymousHound

#### 1. Easiest: No Parameters (Interactive Mode)

Just run the script - it will guide you through everything!

```powershell
.\AnonymousHound.ps1
```

**What happens:**
- Automatically detects missing parameters
- Launches interactive wizard
- Step-by-step prompts
- Options for beginners or experienced users
- Drag-and-drop support for paths

**Perfect for:** First-time users, beginners, exploring options

#### 2. Fast: Command-Line Mode

Specify input and output directories directly:

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\BloodHound\Data" -OutputDirectory "C:\BloodHound\Anonymized"
```

**Perfect for:** Experienced users, automation, scripting

Need to scrub a GitHound export instead? Auto-discovery now finds `githound.json`, or target it explicitly:

```powershell
.\AnonymousHound.ps1 -InputFile ".\githound.json" -OutputDirectory ".\Anonymized"
```

**Perfect for:** GitHub graph collections, GitHound datasets, CI pipelines

#### 3. Safe: Preview First (Dry-Run Mode)

See what will happen without making any changes:

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" -WhatIf
```

**Shows:**
- Files that would be processed
- Example anonymizations
- Well-known objects preserved
- **No files are modified!**

**Perfect for:** Cautious users, verification, new datasets

---

## What's New in v0.2 BETA

Version 0.2 BETA introduces major user experience improvements, performance optimizations, and enhanced reporting. This release focuses on making AnonymousHound accessible to users of all skill levels.

### 🎯 User Experience Enhancements

#### 1. Interactive Mode - No Parameters Required

**NEW:** Run without any parameters and get a guided wizard!

```powershell
PS> .\AnonymousHound.ps1

╔═══════════════════════════════════════════════════════════════════╗
║                    🛡️  ANONYMOUSHOUND v0.2 BETA                 ║
║             BloodHound Data Anonymization Tool                    ║
╚═══════════════════════════════════════════════════════════════════╝

No input specified. Let's get started!

What would you like to do?
  [1] Quick Start - Simple guided wizard (recommended for beginners)
  [2] Specify paths only (for experienced users)
  [3] Show help and exit

Enter your choice (1, 2, or 3):
```

**Features:**
- **Step-by-step wizard** with examples and defaults
- **Drag-and-drop support** - paste paths directly from File Explorer
- **Advanced options** (optional) - preserve hostnames, OS versions, etc.
- **Confirmation screen** before processing begins

#### 2. Input Validation with Helpful Error Messages

**NEW:** Clear, actionable error messages when something's wrong:

```text
╔═══════════════════════════════════════════════════════════════════╗
║  ❌ INPUT VALIDATION ERROR                                        ║
╚═══════════════════════════════════════════════════════════════════╝

Path not found: C:\MyDat

💡 Suggestions:
  • Check that the path is spelled correctly
  • Verify the drive letter (C:\, D:\, etc.)
  • Make sure you have permission to access this location
  • Use Tab completion to auto-complete paths
  • Ensure this is a directory, not a file
```

**Validates:**
- Path existence and accessibility
- File vs directory type
- JSON file detection
- BloodHound format validation
- Provides option to continue for edge cases

#### 3. Dry-Run Mode with Preview (`-WhatIf`)

**NEW:** See exactly what will happen before committing:

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" -WhatIf
```

**Shows:**

```text
╔═══════════════════════════════════════════════════════════════════╗
║              👁️  DRY RUN MODE (Preview Only)                     ║
╚═══════════════════════════════════════════════════════════════════╝

This is a preview. No files will be modified or created.

📂 Input Directory: C:\Data

Files that would be processed:

  users.json (1 file(s))
  groups.json (1 file(s))
  computers.json (1 file(s))
  domains.json (1 file(s))

Total: 4 files
Size:  1.23 MB

Anonymization Examples:

  Original Domain:    CONTOSO.COM → DOMAIN1.LOCAL
  Original User:      john.smith@contoso.com → USR_A1B2C3@DOMAIN1.LOCAL
  Original Computer:  WKS-FINANCE-01 → COMP_X7Y8Z9
  Original Group:     Domain Admins → GRP_D4E5F6

Well-Known Objects (Preserved):
  • Domain Admins, Enterprise Admins, Administrator
  • BUILTIN groups, Everyone, Authenticated Users
  • Common service accounts (MSSQLSERVER, etc.)
```

#### 4. Enhanced Visual Feedback

#### 5. GitHound Graph Support (NEW)

AnonymousHound now recognizes GitHound exports (`githound.json`) automatically:

- Auto-discovery lists directories with GitHound data alongside classic BloodHound collections.
- Every GitHub node type (users, orgs, teams, repositories, branches, workflows, environments, roles) is anonymized using consistent alias tables.
- Edges remain unchanged so GitHub attack paths and permission relationships stay analyzable.

**NEW:** Beautiful, color-coded output with icons:

- **Borders** (═, ║, ╔, ╗, ╚, ╝) for sections
- **Icons** (🛡️, ✓, ✗, ⚠️, 💡, 📂, 📄, 📊, ⚡)
- **Colors** - Success (Green), Errors (Red), Warnings (Yellow), Info (Cyan)
- **Progress indicators** with ETA calculations

### ⚡ Performance Optimizations

#### 1. Hashtable Pre-Allocation

**NEW:** Estimates object count from file sizes and pre-allocates memory:

```text
⚡ Performance Optimizations Applied:
   • Hashtable pre-allocation (estimated: 2,500 objects)
   • Throughput (input bytes): 3.45 MB/s
   • Throughput (records): 12470 objects (~692.8 objects/sec)
```

**Impact:** 10-20% performance improvement for large datasets

#### 2. Optimized JSON Parsing

**NEW:** Smart file size detection with optimized parsers:
- Files <10MB: Fast standard `ConvertFrom-Json`
- Files >10MB: Memory-efficient .NET `System.Text.Json`
- Automatic fallback on errors

**Impact:** 30-40% reduced memory footprint for large files

#### 3. Performance Metrics Tracking

**NEW:** Real-time performance monitoring:

```text
⚡ Performance Optimizations Applied:
   • Hashtable pre-allocation (estimated: 1,247 objects)
   • Throughput (input bytes): 2.34 MB/s
   • Throughput (records): 6235 objects (~346.4 objects/sec)
```

**Metrics tracked:**
- Total processing duration
- Bytes processed (directory batches)
- Throughput (MB/s) and objects/sec when applicable
- Optimizations applied

#### 4. Progress Indicators with ETA

**IMPROVED:** Enhanced progress bars with time estimates:

```text
Anonymizing Collection: 20240101
[████████████████████░░░░] 80% - ETA: 2 min 15 sec
Current file: 20240101_computers.json
```

**Features:**
- Real-time progress percentage
- Estimated time remaining
- Current file being processed
- Formatted time display (seconds, minutes, hours)

### 📊 Enhanced HTML Reporting

#### 1. Executive Summary

**NEW:** High-level overview for stakeholders:

```text
Executive Summary
─────────────────

┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│  Success Rate   │  Risk Level     │  Objects        │  Processing     │
│  100.0%         │  LOW RISK ✅    │  1,247          │  00:12          │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

**Includes:**
- Success rate percentage
- Risk assessment (LOW/MEDIUM/HIGH)
- Total objects processed
- Processing duration
- Quick metrics at a glance

#### 2. WCAG 2.1 Level AA Compliance

**NEW:** Fully accessible HTML reports:

- **Skip navigation links** for keyboard users
- **Semantic HTML5** landmarks (header, nav, main, footer)
- **ARIA attributes** for screen readers
- **Focus indicators** (3px solid outline)
- **Color contrast ratios** meet 4.5:1 minimum
- **Keyboard navigation** support
- **Collapsible sections** with proper ARIA states

#### 3. Dark Theme

**IMPROVED:** Professional dark theme with GDPR compliance note:

- Modern gradient backgrounds
- High-contrast text
- Color-coded badges
- Responsive design
- Mobile-friendly

### 🔧 Technical Improvements

#### 1. Consistency Checks

**IMPROVED:** Domain trust SID mapping fixes:
- Fixed 3→1 domain SID association warnings
- Proper TargetDomainSid → TargetDomainName mapping
- Enhanced domain trust relationship handling

#### 2. SHARPHOUND Preservation

**FIXED:** SHARPHOUND hostnames now correctly preserved:
- Pattern matching for SHARPHOUND in SPNs
- Preserves as 'SRV-SHARPHOUND'
- No longer incorrectly anonymized

#### 3. PSScriptAnalyzer Compliance

**IMPROVED:** Reduced warnings by 97.5%:
- 200+ → 5 warnings
- Added appropriate suppressions with justifications
- Cleaner, more maintainable code

### 📝 Documentation

All documentation consolidated into README.md:
- Quick Start guide
- Interactive mode walkthrough
- Troubleshooting section
- Performance tuning guide
- Advanced usage examples
- Complete feature documentation

---

## Features

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

- ✅ **Interactive HTML Report** - WCAG 2.1 Level AA compliant with dark theme
- ✅ **Executive Summary** - High-level metrics for stakeholders
- ✅ **Comprehensive Mapping File** - Complete record of all anonymization mappings organized by type
- ✅ **Preserved Items Documentation** - Detailed list of what was NOT anonymized and why
- ✅ **Console Progress Tracking** - Real-time feedback with ETA calculations
- ✅ **Detailed Summary Statistics** - Breakdown of all anonymized entities by category
- ✅ **Error Logging** - Separate error log for troubleshooting and validation
- ✅ **Performance Metrics** - Throughput tracking and optimization reporting

---

## User Experience

### Workflows Supported

#### Workflow 1: Absolute Beginner

**Goal:** Anonymize BloodHound/GitHound data with no prior knowledge

**Steps:**
1. Run: `.\AnonymousHound.ps1`
2. Choose option [1] - Quick Start Wizard
3. Follow prompts
4. Review output

**Result:** Successfully anonymized data with confidence

#### Workflow 2: Experienced PowerShell User

**Goal:** Quick anonymization with command-line parameters

**Steps:**
1. Run: `.\AnonymousHound.ps1 -InputDirectory "C:\Data" -OutputDirectory "C:\Output"`
2. Done

**Result:** Immediate processing, no prompts

#### Workflow 3: Cautious User

**Goal:** Preview before committing

**Steps:**
1. Run: `.\AnonymousHound.ps1 -InputDirectory "C:\Data" -WhatIf`
2. Review preview
3. If satisfied, run without `-WhatIf`

**Result:** Confidence before processing

### Interactive Mode Walkthrough

#### Step 1: Select Input Type

```text
Step 1: Select Input
────────────────────
  [1] Process a directory of BloodHound/GitHound JSON files (recommended)
  [2] Process a single JSON file

Enter your choice (1 or 2): 1
```

#### Step 2: Specify Input Path

```text
Enter the path to your BloodHound/GitHound data directory:
(Example: C:\BloodHoundData or drag-and-drop folder here)
Directory path: C:\MyData
```

**Tip:** Drag-and-drop your folder into PowerShell - quotes are automatically removed!

#### Step 3: Specify Output Path

```text
Step 2: Select Output Location
───────────────────────────────
Enter the path where anonymized data should be saved:
(Press Enter for default: .\AnonymizedData)
Output directory: [Enter for default]
```

#### Step 4: Configure Options (Optional)

```text
Step 3: Options (Optional)
───────────────────────────
Would you like to configure advanced options? (y/n)
(Default: n - Use recommended settings)
Configure options: n
```

**Advanced options include:**
- Preserve original hostnames (y/n)
- Preserve OS version strings (y/n)
- Generate HTML report (y/n, default: y)

#### Step 5: Confirmation

```text
═══════════════════════════════════════════════════════════════════
  Ready to Anonymize
═══════════════════════════════════════════════════════════════════

  Input:  C:\MyData
  Output: .\AnonymizedData
  • Generating HTML report

Press Enter to begin or Ctrl+C to cancel...
```

---

## Performance & Optimization

### Performance Benchmarks

Throughput depends heavily on disk speed, CPU, and average record size. Recent builds add **linear-time output buffering** (`List[object]` instead of repeated array concatenation), **deep copies without JSON round-trips** (`FastClone`), and **`System.Text.Json` UTF-8 serialization** (`FastJsonWriter`) for writes—these typically dominate runtime on million-record exports.

| Dataset Size | Objects | Processing Time | Throughput (rough) |
|-------------|---------|-----------------|---------------------|
| Small (<100MB) | <5,000 | <30 seconds | ~3–8 MB/s input *and* hundreds–few thousand objects/sec |
| Medium (100MB–500MB) | 5,000–25,000 | 1–5 minutes | ~2–4 MB/s input |
| Large (500MB–1GB) | 25,000–50,000 | 5–15 minutes | ~1–3 MB/s input |
| Very Large (>1GB) | 50,000+ | 15–60 minutes | ~0.5–2 MB/s input |

Use the summary line **Throughput (records)** (objects/sec) after each run for apples-to-apples comparisons on your hardware.

### Memory Usage

| Dataset Size | Peak Memory (Estimated) | Notes |
|-------------|------------------------|-------|
| <100MB | <500MB | Standard processing |
| 100MB-500MB | 500MB-2GB | Hashtable pre-allocation helps |
| 500MB-1GB | 2GB-4GB | Monitor available RAM |
| >1GB | 4GB+ | Consider splitting dataset |

### Optimizations Applied

1. **Hashtable capacity hint** — Directory mode estimates collection size from total JSON bytes (informational pre-allocation hint).
2. **Smart JSON parsing** — Larger inputs use `System.Text.Json` for deserialization where beneficial; smaller files stay on `ConvertFrom-Json`.
3. **Linear output buffering** — Per-file processors append anonymized rows via `List[object]` then `ToArray()` (avoids quadratic array growth).
4. **Fast deep clone** — `Copy-ObjectDeep` uses embedded `FastClone` (PSObject walk); JSON round-trip is fallback only.
5. **Fast JSON writer** — `ConvertTo-SafeJson` uses `FastJsonWriter` (`System.Text.Json`, indented UTF-8); `ConvertTo-Json` is fallback only.
6. **Performance metrics** — Reports input MB/s (directory mode), total records processed, and **objects/sec** for the whole run.

### Parallel processing (`-EnableParallel`)

Anonymous aliases must stay **consistent across every JSON file in the same SharpHound/Azure collection**. Parallel workers do not currently share live mapping tables safely with PowerShell’s parallel APIs, so **processing remains sequential per collection**. The `-EnableParallel` / `-ThrottleLimit` switches are reserved for a future thread-safe architecture; enabling them prints an informational note only—the clone/write/list optimizations above always apply regardless.

---

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
- ✅ **Built-in accounts** (Administrator, Guest, krbtgt, etc.)
- ✅ **System groups** (Domain Admins, Enterprise Admins, Schema Admins, etc.)
- ✅ **Domain Controllers** (preserve DC naming patterns)

---

## Usage Examples

### Basic Usage

#### Process an entire directory

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\BloodHound\Data" -OutputDirectory "C:\BloodHound\Anonymized"
```

#### Process a single file

```powershell
.\AnonymousHound.ps1 -InputFile "C:\BloodHound\users.json" -OutputDirectory "C:\BloodHound\Output"
```

#### Drag-and-Drop Friendly

```powershell
# Type this, then drag your folder into PowerShell:
.\AnonymousHound.ps1 -InputDirectory "
# Paste appears as: "C:\My BloodHound Exports\Collection 2024"
# Complete the command:
" -OutputDirectory ".\Output"
```

### Advanced Usage

#### Randomize timestamps

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" -OutputDirectory "C:\Output" -RandomizeTimestamps
```

#### Keep hostnames for analysis

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" `
                     -OutputDirectory "C:\Output" `
                     -PreserveHostnames
```

**Preserves:** SERVER-DC01, WKS-FINANCE-01, etc.

**Anonymizes:** Everything else (users, groups, domains)

#### Preserve OS versions

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" `
                     -OutputDirectory "C:\Output" `
                     -PreserveOSVersions
```

**Keeps:** "Windows Server 2019", "Windows 10 Enterprise"

**Useful for:** OS-specific vulnerability analysis

#### Use existing mappings for consistency

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\NewData" `
                     -OutputDirectory "C:\Output" `
                     -DomainMappingFile "C:\PreviousOutput\domain_mapping.json"
```

**Ensures:** CONTOSO.COM always maps to DOMAIN1.LOCAL across all runs

#### Dry-run with verbose logging

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" -WhatIf -Verbose
```

### Automation & Scripting

#### Batch processing multiple collections

```powershell
$collections = Get-ChildItem "C:\Collections" -Directory

foreach ($collection in $collections) {
    $outDir = "C:\Output\$($collection.Name)"
    .\AnonymousHound.ps1 -InputDirectory $collection.FullName -OutputDirectory $outDir
}
```

#### Scheduled task for automated anonymization

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-File C:\Scripts\AnonymousHound.ps1 -InputDirectory C:\BH\Data -OutputDirectory C:\BH\Out"

$trigger = New-ScheduledTaskTrigger -Daily -At 2AM

Register-ScheduledTask -TaskName "BloodHound Anonymization" -Action $action -Trigger $trigger
```

---

## HTML Report

After processing completes, AnonymousHound generates a comprehensive HTML report with:

### Executive Summary

```text
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│  Success Rate   │  Risk Level     │  Objects        │  Processing     │
│  100.0%         │  LOW RISK ✅    │  1,247          │  00:12          │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

- **Success Rate** - Percentage of objects successfully anonymized
- **Risk Level** - LOW/MEDIUM/HIGH based on consistency checks
- **Objects** - Total objects processed
- **Processing Time** - Duration of anonymization

### Detailed Statistics

- **Objects Anonymized** - Breakdown by type (users, groups, computers, etc.)
- **Objects Preserved** - Well-known objects not anonymized
- **Consistency Checks** - Domain mappings, CN mappings, etc.
- **Performance Metrics** - Throughput and optimizations applied

### Mapping Tables

- **Domain Mappings** - Original → Anonymized domain names
- **User Mappings** - Original → Anonymized user names
- **Group Mappings** - Original → Anonymized group names
- **Computer Mappings** - Original → Anonymized computer names

### WCAG 2.1 Level AA Compliant

- **Keyboard Navigation** - Full keyboard accessibility
- **Screen Reader Support** - ARIA labels and landmarks
- **Color Contrast** - Meets 4.5:1 minimum ratio
- **Skip Links** - Jump to main content
- **Focus Indicators** - Visible focus states

**Open the report in your browser to explore all features!**

---

## Supported BloodHound / GitHound / AzureHound File Types

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
- ✅ issuancepolicies.json (AD CS — SharpHound CE 2024+)
- ✅ githound.json (GitHound export)
  - GHOrganization / GHUser / GHTeam
  - GHRepository / GHBranch / GHWorkflow / GHEnvironment
  - GHTeamRole / GHOrgRole / GHRepoRole
- ✅ azurehound*.json (AzureHound CE single-file export, e.g. `azurehound.json`, `azurehound-ce.json`)
  - AZTenant / AZUser / AZGroup / AZApp / AZServicePrincipal / AZDevice
  - AZSubscription / AZResourceGroup / AZManagementGroup
  - AZKeyVault / AZAutomationAccount / AZContainerRegistry / AZFunctionApp / AZLogicApp / AZManagedCluster / AZVM / AZVMScaleSet / AZWebApp
  - AZRole (built-in roles preserved; custom roles aliased)
  - AZFederatedIdentityCredential (subject + name aliased)
  - All `*Owner` / `*RoleAssignment` / `*UserAccessAdmin` / `*Contributor` / `AZGroupMember` relationship kinds (object IDs preserved, embedded principal records and resource paths consistently aliased)
  - See [`ANONYMIZATION_PLAN_AZURE.md`](ANONYMIZATION_PLAN_AZURE.md) for the full PII vs preserve field matrix.

---

## Troubleshooting

### Issue: "Path not found"

**Error:**

```text
❌ Error: Path not found: C:\MyData
```

**Solutions:**
- ✅ Check spelling: `C:\MyData` vs `C:\My Data`
- ✅ Verify drive letter exists
- ✅ Ensure you have read permissions
- ✅ Use Tab completion: Type `C:\My` then press Tab

### Issue: "No JSON files found"

**Error:**

```text
⚠️  WARNING: No JSON files found in directory
```

**Solutions:**
- ✅ Verify this is a BloodHound export directory
- ✅ Check for files named like: `20240101_users.json`
- ✅ Ensure files have `.json` extension
- ✅ Check if files are in a subdirectory

### Issue: "Expected a directory, but found a file"

**Error:**

```text
❌ Error: Expected a directory, but found a file
💡 Did you mean to use -InputFile instead of -InputDirectory?
```

**Solution:**

Use `-InputFile` for single files:

```powershell
.\AnonymousHound.ps1 -InputFile "C:\Data\users.json" -OutputDirectory "C:\Output"
```

### Issue: Script won't run (Execution Policy)

**Error:**

```text
cannot be loaded because running scripts is disabled on this system
```

**Solution:**

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Then run the script again.

### Issue: Want to see detailed logging

**Solution:**

Add `-Verbose` flag:

```powershell
.\AnonymousHound.ps1 -InputDirectory "C:\Data" -OutputDirectory "C:\Output" -Verbose
```

Shows detailed logging of every operation.

---

## Advanced Usage

### Get Built-in Help

```powershell
# Brief help
Get-Help .\AnonymousHound.ps1

# Detailed help
Get-Help .\AnonymousHound.ps1 -Detailed

# Examples
Get-Help .\AnonymousHound.ps1 -Examples

# Full documentation
Get-Help .\AnonymousHound.ps1 -Full
```

### Parameters Reference

| Parameter | Type | Description |
|-----------|------|-------------|
| `-InputDirectory` | String | Directory containing BloodHound JSON files |
| `-InputFile` | String | Single JSON file to anonymize |
| `-OutputDirectory` | String | Where anonymized files will be saved |
| `-DomainMappingFile` | String | Path to existing domain mapping file |
| `-RandomizeTimestamps` | Switch | Randomize timestamps with per-object variation |
| `-PreserveOSVersions` | Switch | Keep original OS version strings |
| `-PreserveHostnames` | Switch | Keep original hostnames |
| `-WhatIf` | Switch | Preview without making changes (dry-run mode) |
| `-Verbose` | Switch | Detailed logging output |

---

## Understanding the Output

After anonymization completes, you'll get:

### 1. Anonymized JSON Files

Located in: `OutputDirectory\AnonymizedData_TIMESTAMP\`

- `ANONYMIZED_20240101_users.json`
- `ANONYMIZED_20240101_groups.json`
- `ANONYMIZED_20240101_computers.json`
- etc.

### 2. Mapping File

`domain_mapping.json` - Maps original domains to anonymized versions

**⚠️ Keep this secure!** Don't share this file - it can de-anonymize your data.

### 3. HTML Report

`anonymization_report.html` - Interactive report with statistics

- Executive summary
- Detailed statistics
- Consistency checks
- Mapping tables
- Performance metrics

### 4. ZIP Archive

`AnonymizedData_TIMESTAMP.zip` - All files bundled for easy sharing

**✅ Ready to share!** Contains only anonymized data (no mapping file).

### Console Output

```text
╔═══════════════════════════════════════════════════════════════════╗
║              🎉 ANONYMIZATION COMPLETE ✓                         ║
╠═══════════════════════════════════════════════════════════════════╣
║  ⏱️  Processing Time:      00:12                                  ║
║  📊 Success Rate:          100.0%                                 ║
║  ✅ Objects Anonymized:    1,247                                  ║
║  🛡️  Objects Preserved:     89                                    ║
╠═══════════════════════════════════════════════════════════════════╣
║  👥 Users:                 453  (15 preserved)                    ║
║  👨‍👩‍👧‍👦 Groups:                128  (42 preserved)                    ║
║  💻 Computers:             312  (12 preserved)                    ║
║  🌐 Domains:               4    (0 preserved)                     ║
╚═══════════════════════════════════════════════════════════════════╝

⚡ Performance Optimizations Applied:
   • Hashtable pre-allocation (estimated: 1247 objects)
   • Throughput: 2.34 MB/s

📊 Interactive HTML Report: C:\Output\AnonymizedData_...\anonymization_report.html

📦 Output Location: C:\Output\AnonymizedData_20241014_123456
   Files: 13 BloodHound JSON files
   ZIP:   C:\Output\AnonymizedData_20241014_123456.zip (Size: 2.34 MB)
```

---

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

---

## Important Notes

⚠️ **Keep the mapping file private!** The `domain_mapping.json` file shows the translation between real and anonymized names. Don't share this!

✅ **Review before sharing**: While AnonymousHound removes most identifying information, always review the output to ensure nothing sensitive slipped through.

⚠️ **Structural information remains**: While names are hidden, the structure of your Active Directory (number of domains, OUs, users, etc.) is still visible. In rare cases, this might be identifying.

✅ **Safe to import**: Anonymized files can be imported directly into BloodHound for analysis.

---

## License & Usage

This tool is designed for security professionals conducting authorized assessments. Always:

- ✅ Have permission to collect the data
- ✅ Review anonymized output before sharing
- ✅ Follow your organization's data handling policies
- ✅ Respect privacy and confidentiality agreements

**Use responsibly and ethically.**

---

## Contributing

Found a bug? Have a suggestion? Contributions are welcome! This is a BETA release.

**Issues & Feedback:** [GitHub Issues](https://github.com/kaydaskalakis/AnonymousHound/issues)

---

## Credits

Special thanks to:

- **My Family** - For bearing with me during development
- **SpecterOps** - For being a super cool company to work for
- **Eleysia Friend** - For inspiring this project and being super patient during my Gulliver's travels
- **The BloodHound Community** - For creating amazing Active Directory analysis tools

---

## Changelog

### Version 0.2 BETA (October 2025)

**User Experience:**
- ✅ **Interactive Mode** - Run without parameters, guided wizard
- ✅ **Input Validation** - Helpful error messages with suggestions
- ✅ **Dry-Run Mode (`-WhatIf`)** - Preview before processing
- ✅ **Enhanced Visual Output** - Color-coded, bordered, with icons
- ✅ **Drag-and-Drop Support** - Paste paths directly from File Explorer

**Performance:**
- ✅ **Hashtable Pre-Allocation** - 10-20% speedup for large datasets
- ✅ **Optimized JSON Parsing** - 30-40% memory reduction for large files
- ✅ **Performance Metrics** - Real-time throughput tracking
- ✅ **Progress with ETA** - Estimated time remaining

**HTML Report:**
- ✅ **Executive Summary** - High-level metrics for stakeholders
- ✅ **WCAG 2.1 Level AA Compliance** - Full accessibility support
- ✅ **Dark Theme** - Professional appearance
- ✅ **Responsive Design** - Mobile-friendly

**Bug Fixes:**
- ✅ Fixed domain trust SID mapping (3→1 warnings)
- ✅ Fixed SHARPHOUND hostname preservation
- ✅ Reduced PSScriptAnalyzer warnings by 97.5% (200+ → 5)

**Security:**
- ✅ **ZIP excludes mapping file** - Mapping file kept only in folder for security
- ✅ ZIP archive contains ONLY anonymized JSON files (safe to share)
- ✅ Mapping file explicitly excluded from ZIP to prevent accidental disclosure

**Technical:**
- ✅ Consolidated documentation into README.md
- ✅ Added comprehensive error handling
- ✅ Improved code maintainability
- ✅ Enhanced logging and diagnostics

### Version 0.1 ALPHA (Initial Release)

**Core Features:**
- ✅ Consistent identity mapping across all files
- ✅ Relationship preservation (attack paths intact)
- ✅ Well-known principal protection
- ✅ Full AD CS support (certificates, templates, CAs)
- ✅ Domain trust handling
- ✅ Distinguished name parsing
- ✅ Idempotent processing
- ✅ HTML report generation
- ✅ Comprehensive mapping files

---

*"The best defense is shared knowledge, but privacy matters too."* 🎭🐕

**Ready to anonymize? Just run `.\AnonymousHound.ps1` and follow the prompts!** 🎉
