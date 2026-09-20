# Windows-Auditing-Share-Permissions-Lab-
Guided lab (CompTIA) on Windows object access auditing and share/NTFS permissions — sets up a SACL, traces the resulting Event Viewer entries, then verifies that a share's permissive settings are still restricted underneath by NTFS.

# Windows Auditing & Share Permissions Lab (SACLs, Event Viewer Correlation and NTFS/Share Permission Testing)

`Windows Server 2016/2019` · `Active Directory` · `Local Security Policy` · `Event Viewer` · `NTFS Permissions` · `Server Manager` · `CompTIA Labs`

## Overview
The idea behind this lab was to actually follow object access auditing end to end instead of just reading about it. That meant turning on the audit policy that makes logging possible in the first place, putting a real SACL on a real folder, doing stuff to that folder, and then going and finding the log entries that stuff should have produced. I also spent a chunk of time on the share vs. NTFS permissions side of things, comparing what a share said it allowed against what the folder underneath it actually allowed, and then testing that gap for real instead of just trusting the properties dialog.

If there's one thread running through this whole lab, it's that I kept trying to prove things to myself instead of assuming a setting worked because I clicked the checkbox. That habit paid off more than once here.

## Objective
Turn on object access auditing, scope a SACL to a specific folder, generate real activity against it, and then track that activity down in the Security log using the right event IDs. On the permissions side: look at share permissions and NTFS permissions side by side on a domain controller's file share, and confirm what actually happens when a regular domain user tries to open a file that NTFS says they shouldn't be able to.

## Environment
- **Domain:** `ad.structureality.com` (NetBIOS: `structureality`)
- **Endpoint under test:** `PC10.ad.structureality.com`, logged in as domain user `structureality\Jaime`
- **Domain controller:** `DC10`, running File and Storage Services with `NETLOGON`, `SYSVOL`, and a custom `TOOLS` share
- **Audited resource:** `C:\LABFILES` on `PC10` (22 items, ~50 MB, a mix of subfolders like `MARKETING` and `contains-nothing`, plus scripts, PCAPs, and documents)
- **Restricted resource:** `\\10.1.16.1\TOOLS\for-authorized-use-only.txt`, a text file that literally just says `This file is for admin use only.`
- **Lab platform:** CompTIA Learning Platform, hosted lab environment via LabClient (labondemand.com)

## Tools I Used

| Tool | What It Does | Why I Used It |
|------|--------------|----------------|
| **Local Security Policy (secpol.msc)** | Local audit policy editor | Flipped on Success and Failure under Local Policies → Audit Policy → **Audit object access**. Without this category enabled, a SACL just sits there and does nothing, no matter how carefully it's configured. |
| **File Explorer → Properties → Security → Advanced → Auditing** | SACL editor | Added an auditing entry for `Everyone` on `C:\LABFILES`, scoped to "This folder, subfolders and files," so activity in that folder would actually start generating events once the policy was on. |
| **Event Viewer** | Security log review | Filtered and searched the Security log for specific event IDs (4658, 4660, 4690, 5379, 4634, 4799, 5152) that the auditing entry and normal account activity had generated. |
| **Server Manager → File and Storage Services → Shares** | Share management | Looked at `NETLOGON`, `SYSVOL`, and `TOOLS` on `DC10`, then opened `TOOLS Properties` to compare share-level permissions against the folder's actual NTFS permissions. |
| **File Explorer (network path)** | Access testing | Tried to open `\\10.1.16.1\TOOLS\for-authorized-use-only.txt` as a normal authenticated user, to see whether NTFS actually blocked me even though the share itself allowed Everyone Full Control. |

## What I Did

### Turning On Object Access Auditing
Local Security Policy, by default, has every audit category set to "No auditing," object access included, right alongside account logon, account management, directory service access, logon events, policy change, privilege use, process tracking, and system events. None of it is on until you turn it on.

I went into the **Audit object access Properties** dialog and checked both **Success** and **Failure**, then applied it. There's a note in that dialog worth paying attention to: it warns that this setting might not actually be enforced if a higher-level policy, like Advanced Audit Policy Configuration, is set up to override the category-level setting. Good reminder that Windows auditing isn't one single switch, it's a small stack of settings that can quietly contradict each other.

### Configuring the SACL on LABFILES
Next I right-clicked `C:\LABFILES`, went to Properties → Security → Advanced → Auditing. The folder's owner was `Administrators (PC10\Administrators)`, and there were zero auditing entries on it to start, nothing was being watched at all.

I added an entry for the `Everyone` principal (pulled from `ad.structureality.com`), set the type to **Success**, and set "Applies to" to **This folder, subfolders and files**. My first pass at the actual permissions to audit was a little too conservative, I only checked Traverse folder/execute file, List folder/read data, Read attributes, Read extended attributes, and Read permissions. Delete, Delete subfolders and files, and Change permissions were left unchecked.

That bugged me once I thought about it, because it meant deletions wouldn't show up in the log at all, only reads. So I went back into the same entry and added **Delete** and **Delete subfolders and files**, keeping Read permissions checked too. Reopening Advanced Security Settings afterward confirmed it: a single auditing entry, Type Success, Principal Everyone, Access "Special," Inherited from None, applying to this folder, subfolders and files.

### Generating Activity and Correlating Events
With the SACL actually configured properly, I went into the folder and interacted with it the way a normal user would, right-clicking a file in the `pcaps` subfolder, poking around the context menu (Restore previous versions, among other things), just generating real activity instead of staging something artificial.

Then over to Event Viewer, Windows Logs → Security. The log was clearly alive, growing from 938 events into a much larger number as I generated more activity. I used Find to search for specific event IDs, and my first search for `4660` came back empty, "there is no event that contains the specified string." Turned out I'd started the search partway down the list instead of from the top, and Find only searches forward from wherever you're currently sitting. Restarted from the top and found it right away.

**Event ID 4660** ("An object was deleted"):
- Subject: `structureality\Jaime`, Logon ID `0x1D944B`
- Object Server: Security, Handle ID `0x1954`
- Logged 7/9/2026 6:48:13 AM on `PC10.ad.structureality.com`

Right around that same window I found **Event ID 4658** ("The handle to an object was closed"), with a different Handle ID (`0x1778`), and an **Event ID 4690** (Handle Manipulation) nearby too. Lined up together, those three events tell the whole story of one file handle's life: opened, closed, object deleted, all traceable through matching handle IDs and logon IDs rather than me just guessing based on timestamps.

I also went looking for and found **Event ID 5379** ("Enumerate Credentials"), a User Account Management event describing a read against stored credentials in Credential Manager, sitting near a **4634** logoff and a **4799** security group enumeration event in the same stretch of log.

Worth admitting: earlier in this same exercise I typed "empty" into the Find box instead of an actual event ID. No idea what I was thinking, it was clearly a copy-paste mistake, and of course it found nothing. Small thing, but it's the kind of typo that costs you a few minutes if you don't catch it fast.

### Reviewing Share vs. NTFS Permissions on DC10
Over on `DC10`, Server Manager → File and Storage Services → Shares showed three shares: `NETLOGON` (pointing at `C:\Windows\SYSVOL\sysvol\ad.str...`), `SYSVOL` (`C:\Windows\SYSVOL\sysvol`), and `TOOLS` (`C:\TOOLS`), all sitting on a volume with 39.4 GB capacity, about a third used.

Opening `TOOLS Properties → Permissions`, the share-level permission was about as wide open as it gets: **Everyone Full Control**. But the NTFS permissions underneath told a completely different story:

- `CREATOR OWNER`: Full Control, subfolders and files only
- `BUILTIN\Users`: Special (a restricted custom set) and, separately, Read & execute
- `BUILTIN\Administrators`: Full Control
- `NT AUTHORITY\SYSTEM`: Full Control
- `structureality\LocalAdmin`: Read only
- `structureality\Domain Admins`: Full Control

This is the "most restrictive permission wins" rule playing out in real life, not just a line from a study guide. The share says anyone can do anything. The folder underneath says otherwise for a normal user.

### Testing the Restrictive Permission in Practice
I went to `\\10.1.16.1\TOOLS` and found one file sitting there: `for-authorized-use-only.txt`. Tried opening it as the logged-in domain user, and Notepad threw exactly the error I expected:

> `\\10.1.16.1\tools\for-authorized-use-only.txt` — You do not have permission to open this file. See the owner of the file or an administrator to obtain permission.

That confirmed the "Users: Special" restriction I'd seen in the permissions tab wasn't just theoretical, it was actually enforced. The share saying "Everyone Full Control" meant nothing on its own. NTFS still had the final say.

## What's in This Repo

```
windows-auditing-permissions-lab/
├── README.md                          # This file
└── screenshots/
    ├── 01-local-security-policy-audit-object-access.png
    ├── 02-audit-object-access-properties-success-failure.png
    ├── 03-labfiles-auditing-entry-partial-permissions.png
    ├── 04-labfiles-auditing-entry-full-permissions.png
    ├── 05-labfiles-advanced-security-settings-summary.png
    ├── 06-event-viewer-find-4660-no-match.png
    ├── 07-event-viewer-find-4660-restarted-from-top.png
    ├── 08-event-4660-object-deleted-jaime.png
    ├── 09-server-manager-file-storage-shares.png
    ├── 10-tools-share-properties-permissions.png
    ├── 11-network-path-tools-share-file-list.png
    └── 12-notepad-access-denied-for-authorized-use-only.png
```

## Skills I Picked Up
- **Auditing needs two things turned on, not one.** The category-level policy has to be enabled *and* a SACL has to actually exist on the object, or you get nothing in the log at all. This lab made that dependency concrete instead of just something I'd memorized.
- **A SACL's scope has to match what you're actually trying to catch.** My first attempt at the LABFILES entry only tracked reads, deletions would have slipped right past it until I went back and widened it.
- **Event Viewer's Find only searches forward from wherever you're sitting**, which explains a "no match" result that isn't really a negative, it just started in the wrong spot.
- **Following one file handle across multiple event IDs** (4658, 4660, 4690) by matching Handle ID and Logon ID, instead of eyeballing timestamps and hoping they line up.
- **Share permissions and NTFS permissions get evaluated together, and the stricter one wins.** Seeing "Everyone Full Control" sitting next to a genuinely locked-down NTFS ACL, and then getting an actual access-denied error to prove it, made that rule click in a way that just reading about it never did.

## How This Applies in the Real World
Object access auditing is what turns "who deleted this file and when" from an unanswerable question into something you can actually go check. A SACL that's scoped too narrowly, or an audit policy that's technically on but not actually attached to the right objects, will quietly produce nothing, which is a dangerous kind of gap because it looks like coverage that isn't really there.

The share vs. NTFS mismatch is also just a really common source of real help desk tickets, "why can't this user open this file." Knowing to check both layers instead of trusting whichever one you looked at first is a basic but genuinely useful skill for anyone supporting a Windows file server.

## Where I'm Coming From
I'm making the jump into cybersecurity from a background in **healthcare**. It's a different field on paper, but a lot of the instincts carry over: following procedures carefully, caring about who's authorized to see or touch what, staying methodical instead of guessing when something isn't behaving the way it should. I'm studying for **CompTIA Security+** right now and building labs like this one to get the hands-on reps I don't have on paper yet.

I left the mistakes in, the typo'd "empty" search, the Find that came back empty because I started in the wrong spot, the SACL I had to go back and widen, on purpose. That's what actually happened, and I'd rather show that than a version that pretends I nailed every step the first time.

## What I Want to Learn Next
- Configuring **Advanced Audit Policy Configuration** instead of the basic category-level policy, for finer control over exactly which operations get audited
- Writing a PowerShell script to automatically pull and correlate 4658/4660/4690 events by Handle ID instead of doing it by hand in Event Viewer
- Setting up **Windows Event Forwarding** so these logs end up on a central collector instead of just sitting on the local machine
- Running the same share vs. NTFS comparison on a Linux/Samba share, to see how the two systems handle the same underlying problem differently

## Limitations & What I'd Do Differently in Production
- **A broad "Everyone" SACL entry is noisy.** In a real environment I'd scope auditing to specific groups or specific sensitive files rather than watching everything everyone does, or the Security log fills up fast with low-value entries.
- **This was all tested on one endpoint against one local folder.** In production, an audit policy like this would normally go out through Group Policy across the domain, not get configured machine by machine.
- **No log retention or forwarding was set up here**, so on a real deployment these events would eventually age out locally unless something's collecting them centrally.
- **The permissions review was a one-time snapshot.** A real assessment would also check for permission drift over time and confirm effective access using the Effective Access tab, which I saw available but didn't fully dig into this time around.

## References
- [Microsoft: Audit object access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-object-access)
- [Microsoft: Advanced security audit policy settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Microsoft: Event ID 4660 — An object was deleted](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4660)
- [Microsoft: NTFS and share permissions interaction](https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/permissions-share-and-ntfs)
- [CompTIA Security+ (SY0-701) Exam Objectives](https://www.comptia.org/certifications/security)
