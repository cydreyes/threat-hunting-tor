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

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
