# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cydreyes/threat-hunting-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

At approximately 2025-07-21T00:22:02Z, a review of the DeviceFileEvents table identified activity associated with the user cydreyes involving Tor-related files. The logs indicate that the user downloaded a Tor Browser installer, initiated actions that resulted in multiple Tor-related files being written to the Desktop directory, and subsequently created a document titled tor-shopping-list.txt. This activity suggests both the installation and subsequent use of Tor Browser on the system rather than a one-time or accidental execution.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "cyd"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-21T00:22:02.2628815Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName,FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1317" height="325" alt="image" src="https://github.com/user-attachments/assets/66585ac5-835e-4619-82b9-3245680768f7" />


---

### 2. Searched the `DeviceProcessEvents` Table

At 5:21:38 PM on July 20, 2025, DeviceProcessEvents logs show that user cydreyes executed the Tor Browser portable installer (tor-browser-windows-x86_64-portable-14.5.4.exe, SHA-256: 5035adc961d7ebae32a175061d102686c00728c750824b3099601259cead8866) from their Downloads folder on device cyd. The installer was run in silent mode (/S), resulting in a ProcessCreated event and deploying Tor Browser version 14.5.4, which includes the latest NoScript and Firefox ESR updates, enabling the user to anonymize web traffic through the Tor network.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "cyd"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1308" height="308" alt="image" src="https://github.com/user-attachments/assets/a7c7d302-0f1b-4a5e-b7ca-f7afc63b55f3" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

DeviceProcessEvents logs confirm that the user account "cydreyes" opened Tor Browser at 2025-07-21T00:22:01Z. Following this event, multiple instances of firefox.exe (the Tor ESR browser) and tor.exe were spawned, indicating that the browser was launched and actively engaged in establishing Tor network connectivity rather than remaining idle after installation.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "cyd"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1694" height="326" alt="image" src="https://github.com/user-attachments/assets/ddca28e8-19dc-4367-9b8b-75b2d410c75a" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

At 2025-07-21T00:23:26Z, DeviceNetworkEvents logs show that user cydreyes on device cyd established a successful network connection using firefox.exe from the Tor Browser directory. The connection was made to 127.0.0.1 on port 9150, a port commonly used by the Tor network for SOCKS proxy traffic, confirming that Tor routing was active. Additional outbound connections were also observed to external sites over port 443, indicating encrypted web traffic was transmitted through the Tor browser session.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "cyd"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1710" height="231" alt="image" src="https://github.com/user-attachments/assets/1fc8697e-2912-4523-8ca8-1232ba58c79d" />


---

## Chronological Event Timeline 

### 1. Process Execution - TOR Browser Installer

- **Timestamp:** `2025-07-20T17:21:38Z`
- **Event:** The user "cydreyes" executed `tor-browser-windows-x86_64-portable-14.5.4.exe` from the Downloads folder in silent mode, initiating the installation of Tor Browser (v14.5.4).
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **File Path:** `C:\Users\cydreyes\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`
- **SHA256:** `5035adc961d7ebae32a175061d102686c00728c750824b3099601259cead8866`
- **Initiating Process:** `cmd.exe`

---

### 2. Process Execution - TOR Browser Launch and Components

- **Timestamps:** `2025-07-20T17:22:01Z – 2025-07-20T17:24:43Z`
- **Event:** The user "cydreyes" launched the Tor Browser multiple times. Both `firefox.exe` (the Tor Browser ESR-based browser) and `tor.exe` (the Tor network process) were executed from the Desktop Tor Browser directory.
- **Action:** Process creation of Tor Browser-related executables detected.
- **File Paths:**  
  - `C:\Users\cydreyes\Desktop\Tor Browser\Browser\firefox.exe`  
  - `C:\Users\cydreyes\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 3. File Creation - Tor Browser Session and Profile Data

- **Timestamps:** `2025-07-20T17:22:14Z – 2025-07-20T17:24:43Z`
- **Event:** Tor Browser generated multiple session and configuration files during usage, including `storage.sqlite`, `storage-sync-v2.sqlite`, `webappsstore.sqlite`, and `formhistory.sqlite`. A desktop shortcut `Tor Browser.lnk` was also created.
- **Action:** File creation detected.
- **File Path:** `C:\Users\cydreyes\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\`
- **SHA256 for Shortcut:** `a4eddf00baa09a99623e5c37a0a8963572983505418c7a394941bd8e6ed81aa4`

---

### 4. Network Connection - TOR Network Activity

- **Timestamps:** `2025-07-20T17:23:08Z – 2025-07-20T17:23:26Z`
- **Event:** Tor Browser established multiple outbound connections, including to external IPs and a SOCKS proxy on localhost.
- **Action:** Successful network connections detected.
- **Connections:**  
  - `192.129.10.18` (port `443`)  
  - `5.255.111.104` (port `9001`)  
  - `87.236.195.216` (port `80`)  
  - `101.99.94.185` (port `443`)  
  - Local SOCKS proxy: `127.0.0.1:9150` initiated by `firefox.exe`

---

### 5. Additional Network Connections - Continued TOR Activity

- **Timestamps:**  
  - `2025-07-20T17:23:12Z` – Connection to `5.255.111.104` on port `9001` via `tor.exe`.  
  - `2025-07-20T17:23:17Z` – Connection to `101.99.94.185` on port `443`.  
  - `2025-07-20T17:23:26Z` – SOCKS proxy connection to `127.0.0.1` on port `9150` by `firefox.exe`.
- **Event:** Additional Tor network activity was recorded, indicating sustained use of the Tor Browser beyond the initial launch period.
- **Action:** Multiple network connections confirmed.
- **Processes:** `firefox.exe`, `tor.exe`

---

### 6. File Creation - User Document

- **Timestamp:** `2025-07-20T17:32:21Z`
- **Event:** The user "cydreyes" created a document titled `tor-shopping-list.txt` in the Documents folder, with a shortcut added to Recent Files.
- **Action:** File creation detected.
- **File Path:** `C:\Users\cydreyes\Documents\tor-shopping-list.txt`

---

## Summary

On July 20, 2025, the user cydreyes installed and actively used Tor Browser (version 14.5.4) on the device cyd. At 5:21 PM, they executed the Tor Browser portable installer from their Downloads folder in silent mode, allowing the program to install without prompts and deploy to the Desktop. Between 5:22 PM and 5:24 PM, the browser (firefox.exe) and its Tor network client (tor.exe) launched multiple times, generating session and profile data such as storage.sqlite, storage-sync-v2.sqlite, webappsstore.sqlite, and formhistory.sqlite, confirming active browsing activity rather than idle installation. During this time, Tor Browser established outbound connections to multiple external IP addresses over ports 443, 9001, and 80, along with a SOCKS proxy connection to 127.0.0.1:9150, validating that traffic was routed through the Tor network. At 5:32 PM, a document titled tor-shopping-list.txt was created in the user’s Documents folder, demonstrating deliberate engagement with the browser session. These events collectively confirm that cydreyes intentionally installed, configured, and used Tor Browser for anonymized browsing and content creation on the device.
---

## Response Taken
TOR usage was confirmed on endpoint cyd by the user cydreyes. The device was isolated and the user's direct manager was notified.

---
