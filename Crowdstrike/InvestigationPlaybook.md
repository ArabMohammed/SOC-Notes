# CrowdStrike Falcon Host Investigation Playbook

A set of **CrowdStrike Query Language (CQL / LogScale / NG‑SIEM)** queries for triaging a single host and deciding whether it is compromised.

## 0. Host baseline

Confirm the host is known and identify the last interactive user before hunting.

```logscale
// Recent logons — establish "who was on this box"
#event_simpleName=UserLogon ComputerName="HOtest"
| groupBy([ComputerName, UserName, UserSid, LogonType],
    function=[count(as=Logons), max(@timestamp, as=LastSeen)])
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
```

`LogonType` reference: `2` = Interactive, `3` = Network, `4` = Batch, `5` = Service, `7` = Unlock, `10` = RemoteInteractive (RDP).

---

## 1. PowerShell executions (exclude irrelevant commands)

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win ComputerName="HOtest"
| FileName=/^powershell\.exe$/i
| CmdLower := lower(CommandLine)
| !in(field=CmdLower, values=[
    "*-executionpolicy bypass -noprofile -noninteractive -windowstyle hidden -command \"compress-archive*",
    "*-executionpolicy bypass -noprofile -noninteractive -windowstyle hidden -command \"remove-item*",
    "*$rootfolder='c:\\programdata\\lenovo\\*",
    "*-executionpolicy bypass -noprofile -noninteractive -file \"c:\\programdata\\lenovo*",
    "*get-childitem -path c:\\programdata\\lenovo*",
    "*copy-item -path*",
    "*'d:\\program files\\manageengine*",
    "*-psconsolefile \"c:\\program files (x86)\\enterprise vault*",
    "*-file \"c:\\program files\\azureconnectedmachineagent*",
    "*import-module \"\"c:\\program files\\azureconnectedmachineagent*",
    "*compress-archive -force -path 'c:\\programdata\\asus*",
  ])
| groupBy([CommandLine],
    function=[count(as=cnt), collect([UserName, ParentBaseFileName, SHA256HashData]),
              min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)])
```
---

## 2. `cmd.exe` executions (allow‑list browser extensions / management tooling)

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win ComputerName="HOtest"
| FileName=/^cmd\.exe$/i
| CmdLower := lower(CommandLine)
| !in(field=CmdLower, values=[
    "*chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj*",
    "*chrome-extension://hcfeinlpkegnfnfokjfffcdlpjcfdkic*",
    "*chrome-extension://ndmegdjihnhfmljjoaiimbipfhodnbgf*",
    "*chrome-extension://fheoggkfdfchfphceeifdbepaooicaho*",
    "*chrome-extension://cdfjcmjmgdnojgaojdnefhjjpaijapci*",
    "*chrome-extension://elhekieabhbkpmcefcoobjddigjcaadp*",
    "*d:\\program files\\manageengine\\opmanager\\nmap\\nmap*",
    "*d:\\manageengine\\desktopcentral_server*"
  ])
| groupBy([CommandLine],
    function=[count(as=cnt), collect([UserName, ParentBaseFileName]),
              min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)])
```

---

## 3. LOLBIns spawned from unusual parents

`mshta` / `rundll32` / `regsvr32` / `wscript` / `cscript` are legitimate under a handful of parents.
```logscale
#event_simpleName=ProcessRollup2 event_platform=Win ComputerName="HOtest"
| in(field=FileName, values=["mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe"], ignoreCase=true)
| ParentLower := lower(ParentBaseFileName)
| !in(field=ParentLower, values=["acrobat.exe","excel.exe","hp*.exe","outlook.exe","compattelrunner.exe"])
| groupBy([ParentBaseFileName, FileName, CommandLine],
    function=[count(as=cnt), collect([UserName, SHA256HashData]), max(@timestamp, as=lastSeen)])
```

## 4. LOLBIns from script hosts touching credential / dump paths

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win ComputerName="HOtest"
| in(field=FileName, values=["mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe"], ignoreCase=true)
| ParentLower := lower(ParentBaseFileName)
| in(field=ParentLower, values=["powershell.exe","cmd.exe","wscript.exe","cscript.exe","winword.exe","excel.exe","outlook.exe"])
| in(field=CommandLine,
     values=["*\\users\\public\\*","*\\temp\\*","*appdata*","*comsvcs*","*minidump*","*lsass*","*procdump*"],
     ignoreCase=true)
| groupBy([ParentBaseFileName, FileName, CommandLine],
    function=[count(as=cnt), collect([ComputerName, UserName, SHA256HashData])])
```

---

## 5. Scheduled tasks (persistence)

```logscale
#event_simpleName="ScheduledTask*"
| TaskNameLower := lower(TaskName)
| !in(field=TaskNameLower, values=[
    "*microsoft*","*lenovo*","*google*","*corel*","*mozilla*","*onedrive*","*hp*",
    "*zoomupdatetaskuser*","*opera*","*barco*","*intel*","*softlanding*",
    "*lvfdriverremoval*","*lvf*","*user_feed*","*wps*"])
| groupBy([#event_simpleName, TaskName, TaskExecCommand, TaskExecArguments],
    function=[count(as=cnt), collect([TaskAuthor, UserName, ComputerName])])
```

Relevant events: `ScheduledTaskRegistered`, `ScheduledTaskModified`, `ScheduledTaskDeleted`.

---

## 6. Services (persistence / lateral movement)

```logscale
#event_simpleName=CreateService ComputerName="HOtest"
| SvcPathLower := lower(ServiceImagePath)
| !in(field=SvcPathLower, values=[
    "*brother*","*citrix*","*adobe*","*google*","*intel*","*manageengine*",
    "*knowbe4*","*microsoft*","*windows*","*veeam*","*lenovo*","*filerepository*"])
| groupBy([ServiceDisplayName, ServiceImagePath, ServiceType, ServiceStart],
    function=[count(as=cnt), collect([ComputerName, UserName])])
```

`ServiceStart`: `2` = Automatic, `3` = Manual, `4` = Disabled. Also study: **`ServiceStarted`**, **`HostedServiceStarted`**, **`ModifyServiceBinary`**, **`ServicesStatusInfo`** for tampering with existing services.

---

## 7. Registry — Auto‑Start Extensibility Points (ASEP)

Use the `RegistryOperationDetectInfo` as a broader detection event.

```logscale
// Classified autoruns writes
#event_simpleName=AsepValueUpdate event_platform=Win ComputerName="HOtest"
| groupBy([RegObjectName, RegValueName, RegStringValue],
    function=[count(as=cnt), collect([ComputerName])])
```

```logscale
// Broader CurrentVersion writes
#event_simpleName=RegistryOperationDetectInfo RegObjectName="*\\Software\\Microsoft\\Windows\\CurrentVersion*"
| groupBy([RegObjectName, RegValueName, RegStringValue], function=[count(as=cnt)])
```

**ASEP registry locations worth watching**

| Category | Key |
|---|---|
| Run keys (current user) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` |
| Run keys (all users) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` |
| Winlogon | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Shell`, `Userinit` |
| Active Setup | `HKLM\Software\Microsoft\Active Setup\Installed Components` |
| AppInit_DLLs | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services` |

---

## 8. New local accounts

```logscale
#event_simpleName=UserAccountCreated
| !in(field=UserName, values=["lenovo_tmp*"])
| table([@timestamp, ComputerName, UserName, UserSid, UserRid], limit=20000)
```

Also review **`UserAccountAddedToGroup`** (privilege escalation into Administrators/Remote Desktop Users).

---

## 9. Executable creation / deletion

```logscale
#event_simpleName=PeFileWritten ComputerName="UCPRSGATE01"
| groupBy([TargetFileName, SHA256HashData],
    function=[count(as=cnt), collect([ContextBaseFileName, ComputerName]), max(@timestamp, as=lastSeen)])
```

Pair with **`ExecutableDeleted`** to catch drop‑execute‑delete patterns.

---

## 10. External / removable devices

```logscale
// USB device connections
#event_simpleName=DcUsbDeviceConnected ComputerName="HOtest"
| groupBy([DeviceInstanceId, DeviceProduct, DevicePropertyDeviceDescription],
    function=[count(as=cnt), collect([DeviceManufacturer])])
```

```logscale
// Mounted volumes
#event_simpleName=FsVolumeMounted ComputerName="HOtest"
| groupBy([DiskParentDeviceInstanceId, VolumeFileSystemDriver, VolumeMountPoint, VolumeRealDeviceName],
    function=[count(as=cnt)])
```

---

## 11. DNS requests

```logscale
#event_simpleName=DnsRequest ComputerName="HOtest"
| ContextBaseFileName=/DeskRest/i
| groupBy([DomainName, RequestType, QueryStatus, ContextBaseFileName], function=[count(as=cnt)])
```

**Hunt for dead C2 / DGA** — resolutions that fail with NXDOMAIN are a strong signal:

```logscale
#event_simpleName=DnsRequest ComputerName="HOtest" QueryStatus="9003"
| groupBy([ContextBaseFileName, DomainName], function=[count(as=cnt)])
```

**RequestType** (DNS record): `1`=A, `2`=NS, `5`=CNAME, `6`=SOA, `12`=PTR, `15`=MX, `16`=TXT, `28`=AAAA, `33`=SRV, `65`=HTTPS.

**QueryStatus** (Windows DNS API return code, not raw RCODE):

| Code | Meaning | Investigative note |
|---|---|---|
| `0` | Success | Record returned |
| `9003` | NAME_ERROR (NXDOMAIN) | Domain doesn't exist — typos, **DGA**, dead C2 |
| `9001` | FORMAT_ERROR | Malformed response |
| `9002` | SERVER_FAILURE | Resolver failed |
| `9501` | NO_RECORDS | Domain exists, no record of that type (e.g. AAAA asked, only A) |
| `9502` | NO_MORE_DATA | No further records |
| `9009` | REFUSED | Resolver refused — blocked/restricted domains |
| `9010` | NOT_IMPLEMENTED | Query type unsupported |
| `9004` | NOTAUTH | Server not authoritative |

---

## 12. HTTP requests from non‑browser processes


```logscale
#event_simpleName=HttpRequestDetect
| ContextBaseFileName=/DeskRest\.exe/i
| groupBy([ComputerName, HttpHost, HttpPath, HttpMethod],
    function=[count(as=cnt), collect([HttpRequestHeader])])
```

**HttpMethod:** `1`=GET, `2`=POST, `3`=PUT, `4`=DELETE, `5`=HEAD, `6`=OPTIONS.

---

## 13. Network connections

```logscale
#event_simpleName=NetworkConnectIP4 ComputerName="UCPRSGATE01"
| !cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"])
| groupBy([ContextBaseFileName, ContextProcessId, LocalAddressIP4, RemoteAddressIP4, RemotePort],
    function=[count(as=cnt), collect([ComputerName])])
```

---

## 14. Unmanaged / .NET execution (CLR loaded into unexpected processes)

Detects assemblies executing in‑memory by watching for the CLR loading into processes that shouldn't host it.

```logscale
#event_simpleName=ClassifiedModuleLoad event_platform=Win
| in(field=FileName, values=["clr.dll","clrjit.dll","mscoree.dll","mscoreei.dll","mscorlib.ni.dll"], ignoreCase=true)
| TargetLower := lower(TargetImageFileName)
| !in(field=TargetLower, values=[
    "*\\program files (x86)\\brother*","*\\program files (x86)\\lenovo*",
    "*\\program files (x86)\\knowbe4*","*\\program files (x86)\\hp*"])
| groupBy([FileName, TargetImageFileName],
    function=[count(as=cnt), collect([ComputerName, SHA256HashData])])
```

> In `ClassifiedModuleLoad`, `FileName` is the loaded module (the DLL), `TargetImageFileName` is the **host process** it loaded into, and `TargetProcessId` identifies that process. `TargetImageFileName` uses the `\Device\HarddiskVolumeN\` form — the `*...*` globs above handle that.

---

## 15. Correlate downloads (Mark‑of‑the‑Web) with the writing process

Ties an internet‑sourced file back to the process that created it. 

```logscale
#event_simpleName=MotwWritten ZoneIdentifier=3
| rename(field=FileName, as=DownloadedFileName)
| rename(field=ContextProcessId, as=TargetProcessId)
| join(
    query={ #event_simpleName=ProcessRollup2 | rename(field=FileName, as=ProcessFileName) },
    field=[aid, TargetProcessId],
    key=[aid, TargetProcessId],
    include=[ProcessFileName, CommandLine]
  )
| table([@timestamp, ComputerName, HostUrl, ReferrerUrl, DownloadedFileName, ProcessFileName, CommandLine])
```

`MotwWritten` fields of interest: `HostUrl` (download source), `ReferrerUrl`, `ZoneIdentifier` (`3` = internet), `FilePath`.

---

---
## 16. Detect WMI remote execution on the TARGET : payload spawned by WmiPrvSE
```logscale
// WMI remote execution on the TARGET: payload spawned by DCOM-launched WmiPrvSE
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^WmiPrvSE\.exe$/i
| join(
    query={
      #event_simpleName=ProcessRollup2 event_platform=Win
      | FileName=/^WmiPrvSE\.exe$/i
      | CmdLower := lower(CommandLine)
      | CmdLower="*-secured*-embedding*"
      | rename(field=CommandLine, as=ParentCommandLine)
    },
    field=[aid, ParentProcessId],
    key=[aid, TargetProcessId],
    include=[ParentCommandLine]
  )
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ParentCommandLine, FileName, CommandLine, SHA256HashData])
```
---