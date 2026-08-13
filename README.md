# WSTG Mapper (Montoya API / Java)

A pure mapper/organizer for the 96-item OWASP WSTG v4.2 checklist inside
Burp Suite. It runs no HTTP probes and launches no scans of its own -
scanning stays entirely inside Burp. All findings come from Burp's OWN
Scanner (Active Scan you launch normally from Target/Proxy, or Live
Passive Scanning while you browse). This extension listens for those
issues live and maps each one onto the matching WSTG id(s), so you get
one table that tracks the whole checklist against real Burp results.

Requires **Burp Suite Professional** (the Scanner API this extension
uses - `MontoyaApi.scanner()` - is Professional-only; it will not work
in Community Edition).

## What it does

- Every new issue Burp's Scanner reports (active or passive) streams
  into the table live, with no host filtering, so nothing is silently
  dropped.
- **Import Burp Scanner Issues**: a manual, idempotent top-up for
  anything already sitting in Burp's issue list (e.g. from passive
  scanning before this tab was open). Filters by Burp's own Target
  Scope if one is configured; otherwise imports everything.
- Every Burp issue is keyword-matched against the WSTG checklist;
  anything that doesn't match a known keyword is still kept, in a
  dedicated `WSTG-GEN-00` "unmapped" row, so review data is never lost.
- Any WSTG id Burp hasn't reported anything for stays at "Manual"
  status with its full step-by-step guidance shown.
- **Reset All** clears this extension's local table (severities, mapped
  notes, dedup state) back to a blank slate, without touching Burp's
  own issue list or Scope, so a fresh import is easy to redo.
- **Export HTML** saves a standalone report of every WSTG item, its
  status, its manual guidance, and any mapped Burp Scanner findings.

## Building

This is a standard Gradle project. Either build it locally:

```
./gradlew build      # or: gradle build
```

(requires JDK 21 or lower - Burp does not support extensions built for
a newer Java version) - or push this repository to GitHub, where
`.github/workflows/build.yml` builds it automatically on every push and
uploads `wstg-mapper.jar` as a downloadable workflow artifact, with no
local JDK/Gradle install required.

This repo does not ship a real `gradlew`/`gradlew.bat`/`gradle/wrapper/*`
(those are generated binaries, not something to hand-write). If you need
them - e.g. the BApp Store submission checker requires them - go to the
Actions tab, select **"Generate Gradle Wrapper"**, click **"Run workflow"**
once, and it will generate and commit the real wrapper files for you.

The built jar is at `build/libs/wstg-mapper.jar`.

## Loading in Burp

Extensions > Installed > Add > Extension type: **Java** > select
`wstg-mapper.jar`.

## Project layout

```
build.gradle                        Gradle build config (Montoya API dependency)
settings.gradle                     project name
.github/workflows/build.yml         CI: builds the jar on every push
src/main/java/dev/wstgmapper/
  WstgMapperExtension.java          entry point (BurpExtension)
  WstgMapperPanel.java              Suite tab UI (table, filters, buttons, detail pane)
  FindingsStore.java                findings state + merge logic for incoming Burp issues
  Finding.java                      per-WSTG-id severity/guidance/scanner-notes
  Severity.java                     severity enum (label, color, merge rank)
  ChecklistItem.java                one WSTG checklist row
  ChecklistData.java                the full 96-item checklist
  IssueMapper.java                  Burp issue name -> WSTG id keyword table
  ReportExporter.java               HTML report builder
  TextUtil.java                     small text-formatting helpers
```

## Support

Free extension, no features gated behind payment. If it saved you time, the price of a coffee is always welcome:

BTC: your-btc-address-here
ETH: your-eth-address-here

## Warning

Only use this against targets you are authorized to test. This
extension itself sends no traffic, but the Burp Scanner findings it
imports come from real, sometimes intrusive, attack traffic that Burp
sent - only run Burp's scans against scope you're authorized to
actively test.
