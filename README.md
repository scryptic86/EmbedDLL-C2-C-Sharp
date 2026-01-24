<img src="docx-media/media/image1.png"
style="width:3.79167in;height:3.90712in"
alt="Icon Description automatically generated" />

Practical Malware Analysis & Triage

Malware Analysis Report

C2.Bootstrap.Dropper.Loader

January 2, 2026 \| Clinton Asprey\| v1.0

# Table of Contents

[Executive Summary [3](#executive-summary)](#executive-summary)

[High-Level Technical Summary
[4](#high-level-technical-summary)](#high-level-technical-summary)

[Execution Timeline [5](#execution-timeline)](#execution-timeline)

[Malware Composition [7](#malware-composition)](#malware-composition)

[EmbedDLL.dll [7](#embeddll.dll)](#embeddll.dll)

[embed.vbs: [7](#_Toc220165545)](#_Toc220165545)

[embed.xml: [8](#_Toc220165546)](#_Toc220165546)

[Basic Static Analysis
[9](#basic-static-analysis)](#basic-static-analysis)

[Basic Dynamic Analysis
[13](#basic-dynamic-analysis)](#basic-dynamic-analysis)

[Advanced Static Analysis
[18](#advanced-static-analysis)](#advanced-static-analysis)

[Advanced Dynamic Analysis
[20](#advanced-dynamic-analysis)](#advanced-dynamic-analysis)

[Indicators of Compromise
[21](#indicators-of-compromise)](#indicators-of-compromise)

[Stage 1 Indicators of Compromise
[22](#stage-1-indicators-of-compromise)](#stage-1-indicators-of-compromise)

[Stage 2 Indicators of Compromise
[22](#stage-2-indicators-of-compromise)](#stage-2-indicators-of-compromise)

[Rules & Signatures [25](#rules-signatures)](#rules-signatures)

[Appendices [29](#appendices)](#appendices)

[A. Yara Rules [29](#yara-rules)](#yara-rules)

[A. Callback URLs [30](#callback-urls)](#callback-urls)

[B. Decompiled Code Snippets
[30](#decompiled-code-snippets)](#decompiled-code-snippets)

[Analyst Summary [31](#analyst-summary)](#analyst-summary)

[MITRE ATT&CK Technique Mapping
[31](#mitre-attck-technique-mapping)](#mitre-attck-technique-mapping)

# Executive Summary

| SHA256 hash | 732f235784cd2a40c82847b4700fb73175221c6ae6c5f7200a3f43f209989387 |
|-------------|------------------------------------------------------------------|

This report analyzes the EmbedDLL.dll malware, a .NET-based encrypted
dropper and loader that deploys a secondary payload using DLL reflection
and Living-off-the-Land binaries. The malware is designed to evade
static detection through AES-encrypted embedded resources and reflective
assembly loading. Persistence is achieved via registry Run keys and
execution is proxied through MSBuild. C2 server beaconing is also
established.

# High-Level Technical Summary

The analyzed DLL functions as a persistence-focused payload dropper.
Upon execution, it decrypts a hardcoded password-derived key, writes the
decrypted XML payload to disk, and installs a VBScript launcher in the
user’s startup registry. This VBScript leverages MSBuild to execute the
embedded XML payload, enabling fileless or proxy execution while
maintaining persistence across reboots. Callback to a C2 server is also
initiated.

# Execution Timeline

1.  Execution of EmbedDLL.dll

2.  AES decryption of embedded payload

3.  Decrypted XML payload written to disk

4.  VBS launcher created

5.  Persistence via Run registry key

6.  MSBuild execution of decrypted payload

7.  Reflective assembly load

8.  Encrypted C2 communication begins

Stage 1: Initial loader executable

Stage 2: In-memory DLL dropper / decryptor

Stage 3: Persistent script-based builder / launcher

Stage 4: Final implant / C2 agent

<img src="docx-media/media/image2.png"
style="width:5.53819in;height:9in" />

# Malware Composition

Malware.cryptlib64.dll consists of the following components:

| File Name    | SHA256 Hash                                                      |
|--------------|------------------------------------------------------------------|
| EmbedDLL.dll | 732f235784cd2a40c82847b4700fb73175221c6ae6c5f7200a3f43f209989387 |
| embed.vbs    | 66fd543f31545082cf8fcc45a6ab1094bc118c45634f2be450f84f4e5745b291 |
| embed.xml    | f1548cd02784606c8abac865abf5ed6220d34eea88c7a5715e0183d7f050f4ab |

## EmbedDLL.dll

<img src="docx-media/media/image3.png"
style="width:0.94175in;height:0.94175in" />

*Figure 1: The hidden file name of Malware.cryptlib64.dll is
EmbedDLL.dll which is detonated in this lab with rundll32.*

<span id="_Toc220165545" class="anchor"></span>embed.vbs:

<img src="docx-media/media/image4.png"
style="width:6.5in;height:1.89583in" />

*Figure 2: embed.vbs VBscript dropped by EmbedDLL.dll and ran upon user
login*

<span id="_Toc220165546" class="anchor"></span>embed.xml:

<img src="docx-media/media/image5.png"
style="width:6.5in;height:2.84375in" />

*Figure 3: The XML payload is dropped in Public user folder*

# Basic Static Analysis

{Screenshots and description about basic static artifacts and methods}

**Stage 1: Encrypted Payload Dropper and Persistence**

- **Filename:** Malware.cryptlib64.dll

- **File size:** 29184 bytes

- **Entropy:** 4.178

- **File type:** dynamic-link-library, 64-bit, console

- **Architecture:** x64

- **Compilation timestamp:** Sun Oct 10 18:14:49 2021 (UTC)

- **Digital signature:** None

- **Suspicious sections:** .sdata

- **Embedded resources:** EmbedDLL.dll

- **Indicators of packing or encryption:** AES Encryption

- **Anti-analysis techniques observed:** Hidden File Name (EmbedDLL.dll)

<img src="docx-media/media/image6.png"
style="width:6.25888in;height:1.82516in" />

*Figure : Hidden file name*

<img src="docx-media/media/image7.png"
style="width:6.5in;height:3.8875in" />

*Figure : .NET module detected*

<img src="docx-media/media/image8.png"
style="width:6.05052in;height:1.21677in" />

*Figure : Indicators of C# language and .NET Framework*

**Imported functions / APIs:**

AES_Encrypt

> AES_Decrypt
>
> CreateEncryptor
>
> GetEnvironmentVariable
>
> WriteAllText
>
> MemoryStream

**Suspicious Strings:**

**Final Stage: C2 Malware**

**SHA256:**
B8E0EC99C18BF28062FFB9BB385C0109A27AF71D332BC7FC00580D88D3A30721

.**NET Module Name:** bk1ha411.4nu.exe

**Entropy:** 5.181

**File Size:** 11776 bytes

**File Type:** MZ

**Architecture:** 64-bit, GUI

**Notable Embedded Strings and Indicators**

- **Hardcoded C2 endpoint:**  
  http://srv.masterchiefsgruntemporium.local:80

- **Beacon parameter format:**  
  i=\<id\>&data={encrypted}&session=\<token\>

- **HTTP masquerading:**

  - User-Agent: Mozilla/5.0 (Windows NT 6.1)…Chrome/41.0…

  - Cookie template: ASPSESSIONID={GUID}; SESSIONID=…

- **Encrypted message structure:**

> {"GUID":"{0}","Type":{1},"Meta":"{2}","IV":"{3}",
>
> "EncryptedMessage":"{4}","HMAC":"{5}"}

- **Certificate pinning indicators:**  
  UseCertPinning, ValidateCert, CovenantCertHash

- **Framework identifiers:**  
  GruntStager, ExecuteStager, CookieWebClient

# Basic Dynamic Analysis

{Screenshots and description about basic dynamic artifacts and methods}

This DLL functions as an encrypted dropper-loader responsible for
decrypting, staging, and executing a secondary payload via MSBuild,
while establishing user-level persistence.

During execution, the malware encrypts command-and-control (C2)
communications using AES-256 in CBC mode. Key material is derived via
PBKDF2 with SHA-1 (1,000 iterations) and a hard-coded password encoded
as UTF-16LE. Network traffic captured from the sample shows that
encrypted messages are Base64-encoded prior to transmission.

Once decrypted, the C2 payload does not conform to any standard
serialization or compression format. Instead, it consists of a
proprietary binary protocol composed of fixed-length fields. These
fields include a session identifier resembling a GUID, followed by
structured metadata such as opcode values, host identifiers, and status
or command data. No evidence of secondary compression or obfuscation is
present beyond the initial AES encryption layer.

<img src="docx-media/media/image10.png"
style="width:6.5in;height:1.51806in" />

<img src="docx-media/media/image11.png"
style="width:6.5in;height:0.22917in" />

*Figure : ProcMon shows files dropped and registry key set upon first
run*

<img src="docx-media/media/image12.png"
style="width:6.5in;height:1.73125in" />

*Figure : Persistence registry key created after initial EmbedDLL.dll
execution*

<img src="docx-media/media/image13.png"
style="width:6.5in;height:2.37083in" />

*Figure : Wireshark packet capture showing HTTP call to C2 server*

<img src="docx-media/media/image14.png"
style="width:6.5in;height:2.14514in" />

*Figure : Successful request on port 80*

Each time the infected machine’s user logs back in, embed.vbs is
executed with embed.xml arguments and the C2 server is contacted.
VBScript is used to launch a system shell and run MSBuild indirectly to
evade detection.

<img src="docx-media/media/image15.png"
style="width:6.5in;height:1.30764in" />

<img src="docx-media/media/image16.png"
style="width:6.5in;height:1.9125in" />

<img src="docx-media/media/image17.png"
style="width:6.5in;height:0.94306in" />

*Figure : XML arguments for embed.vbs to run MSBuild*

<img src="docx-media/media/image18.png"
style="width:6.5in;height:2.975in" />

*Figure : Ncat and Wireshark captured C2 beacon for decryption*

<img src="docx-media/media/image19.png"
style="width:6.44478in;height:1.52786in" />

Figure : Exported HTML POST file from PCAP

After decrypting the message portion in this HTTP POST we can identify
these possible parts:

Total bytes: 64

> GUID : 4f1113988d3b14972c77
>
> Opcode : 0x154615aa
>
> Payload length: 50
>
> Beacon ID : 0x8938d318 (2302202648)
>
> Uptime low : 0x38a4de1c (950328860)
>
> Uptime high : 0xdd007378 (3707794296)
>
> Flags : 0x5d30d302 (1563480834)
>
> OS version : 0x0d221e46 (220339782)
>
> PID : 0x1db5043a (498402362)
>
> PPID : 0xd584cc5d (3582250077)
>
> Arch : 0x981f4c53 (2552187987)
>
> Privilege : 0x8e487bff (2387115007)
>
> Net status : 0x162a26c5 (371861189)
>
> Unknown 1 : 0x30ca19da (818551258)
>
> Unknown 2 : 0x3c6764c9 (1013408969)
>
> Checksum : 0x00005a13 (23059)

# Advanced Static Analysis

{Screenshots and description about findings during advanced static
analysis}

Advanced static analysis of the malware reveals a **multi-stage dropper
and loader** implemented as a **.NET DLL** with deliberate obfuscation
and nonstandard execution behavior to hinder debugging and automated
analysis.

The DLL is not intended to be executed directly via standard loaders,
which explains debugger errors such as *“invalid extension”* when
attempting to run it in dnSpy. Instead, it is designed for **reflective
or indirect loading.**

<img src="docx-media/media/image20.png"
style="width:6.5in;height:0.84236in" />

*Figure : Hardcoded password and AES decryption of a base64 string*

<img src="docx-media/media/image21.png"
style="width:6.5in;height:1.67917in" />

*Figure : AES encryption function*

<img src="docx-media/media/image22.png"
style="width:5.86051in;height:1.37345in" />

*Figure : Name and location of dropped VBS script and XML file to be
loaded at user logon*

**Static Analysis Key Findings**

- The malware stores its primary payload as an encrypted, Base64-encoded
  embedded resource within the DLL, preventing plaintext exposure on
  disk. Decryption is performed at runtime using a custom AES-256-CBC
  implementation with PBKDF2 (SHA-1, 1000 iterations) and a hardcoded
  UTF-16LE password, with all cryptographic parameters statically
  defined.

- Once decrypted, the payload is assembled entirely in memory as a
  custom binary structure rather than a standard PE or serialized
  format. The data layout includes fixed-length fields consistent with
  session identifiers, timestamps, flags, and command metadata.

- Execution relies on reflective loading and dynamic invocation of
  managed code, avoiding disk-backed module loading. Static code paths
  also reveal registry-based persistence and indirect execution via
  trusted Windows binaries, enabling living-off-the-land techniques.

- Network communication uses a bespoke binary C2 protocol, with manually
  packed and parsed messages instead of common serialization formats,
  indicating deliberate evasion of signature-based detection.

# Advanced Dynamic Analysis

{Screenshots and description about advanced dynamic artifacts and
methods}

In order to debug Malware.cryptlib64.dll, this analyst created a .NET
4.7.2 console application named Loader.exe in Visual Studio Community to
load the DLL code. Loader.exe is not part of the original malware sample
but is included in the IOCs table below since Malware.cryptlib64.dll is
dependent upon another binary to execute its code.

## Stage 1

## Stage 2

## Stage 3

## Stage 4

<img src="docx-media/media/image23.png"
style="width:6.5in;height:1.94375in" />

# Indicators of Compromise

The full list of IOCs can be found in the Appendices.

## Stage 1 Indicators of Compromise

| Category | Indicator              | Type           | Stage   | Description                                            |
|----------|------------------------|----------------|---------|--------------------------------------------------------|
| File     | Loader.exe             | Executable     | Stage 1 | Loads malicious DLL via reflection                     |
| File     | Malware.cryptlib64.dll | DLL            | Stage 1 | Primary dropper and decryptor component                |
| File     | embed.xml              | XML Payload    | Stage 1 | Contains decrypted Stage 2 payload                     |
| File     | embed.vbs              | VBS Script     | Stage 1 | Executes decrypted payload and establishes persistence |
| Registry | HKCU...\Run            | Run Key        | Stage 1 | Registry auto-start persistence mechanism              |
| API      | Assembly.LoadFile      | Reflection API | Stage 1 | Dynamically loads malicious DLL into memory            |
| Crypto   | AES_Decrypt            | Function Call  | Stage 1 | Decrypts embedded encrypted payload                    |

<img src="docx-media/media/image24.png"
style="width:6.5in;height:2.11042in" />

*Fig 3: Wireshark packet capture of initial DNS query for callback to C2
server*

*Fig 4:.*

## Stage 2 Indicators of Compromise

| Category       | Indicator                                                                                            | Type                   | Description                                                                       |
|----------------|------------------------------------------------------------------------------------------------------|------------------------|-----------------------------------------------------------------------------------|
| Network        | http://srv.masterchiefsgruntemporium.local:80                                                        | C2 URL                 | Hardcoded command-and-control endpoint used by the implant                        |
| Network        | /en-us/index.html                                                                                    | URI Path               | Decoy HTTP path used during beaconing                                             |
| Network        | /en-us/docs.html                                                                                     | URI Path               | Alternate decoy path for C2 communications                                        |
| Network        | /en-us/test.html                                                                                     | URI Path               | Alternate decoy path for C2 communications                                        |
| Network        | i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73              | HTTP Parameter Pattern | Beacon request format containing implant ID, encrypted payload, and session token |
| Network        | Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36 | User-Agent             | Hardcoded User-Agent string used to masquerade as Chrome traffic                  |
| Network        | ASPSESSIONID={GUID}; SESSIONID=1552332971750                                                         | Cookie Template        | Session cookie format used for C2 communication                                   |
| C2 Protocol    | {"GUID":"{0}","Type":{1},"Meta":"{2}","IV":"{3}","EncryptedMessage":"{4}","HMAC":"{5}"}              | JSON Message Format    | Encrypted C2 message structure containing IV, ciphertext, and HMAC                |
| Host           | bk1ha411.4nu.exe                                                                                     | Filename               | Observed implant executable filename                                              |
| Host           | bk1ha411.4nu                                                                                         | Implant ID             | Base implant name used internally by the malware                                  |
| Crypto         | HMACSHA256                                                                                           | Algorithm              | Message authentication algorithm used to protect C2 traffic                       |
| Crypto         | aFM+yqzILW3R/AY/pnxI8VIYvdjnPdfYw8Xlqy31tvU=                                                         | Base64 Key / Hash      | Embedded cryptographic material used for HMAC or key derivation                   |
| Crypto         | c638eb59a8                                                                                           | Token / Identifier     | Short embedded identifier associated with encryption or session handling          |
| TLS / Evasion  | UseCertPinning                                                                                       | Function Name          | Enables certificate pinning to prevent TLS interception                           |
| TLS / Evasion  | ValidateCert                                                                                         | Function Name          | Custom certificate validation routine                                             |
| TLS / Evasion  | CovenantCertHash                                                                                     | Certificate Hash Label | Pinned certificate hash associated with Covenant framework                        |
| Malware Family | GruntStager                                                                                          | Class Name             | Covenant framework stager identifier                                              |
| Malware Family | ExecuteStager                                                                                        | Function Name          | Primary routine responsible for staging payload execution                         |
| Malware Family | CookieWebClient                                                                                      | Class Name             | Custom HTTP client wrapper used for C2 communications                             |

# Rules & Signatures

A full set of YARA rules is included in Appendix A.

{Information on specific signatures, i.e. strings, URLs, etc}

**Static File Signatures**

The malware can be reliably identified using a combination of the
following static indicators:

- **Hardcoded cryptographic artifacts**

  - UTF-16LE encoded AES password string used for PBKDF2 key derivation

  - Fixed PBKDF2 parameters (SHA-1, 1000 iterations, static salt)

- **Embedded resource indicators**

  - Presence of encrypted Base64 blobs stored in .rsrc / .rsdata
    sections

  - Resource names and namespaces consistent with embedded payload
    handling (e.g., EmbedDLL)

- **.NET reflection artifacts**

  - References to System.Reflection.Assembly::Load

  - Dynamic invocation patterns (GetType, GetMethod, Invoke)

- **Custom protocol constants**

  - Fixed-length binary structures used after decryption (e.g., 64-byte
    beacon headers)

  - Repeated magic values and field offsets associated with GUID/session
    identifiers

**Behavioral / Heuristic Signatures**

Additional detection opportunities exist through behavior-based rules:

- **In-memory execution**

  - Assembly loading directly from byte arrays without dropping a PE to
    disk

- **Persistence mechanisms**

  - Registry modification under:

  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run

- **Living-off-the-Land execution**

  - Use of trusted Windows binaries (e.g., MSBuild.exe) to execute
    attacker-controlled code indirectly

- **Custom cryptographic routines**

  - Manual AES decryption logic rather than use of standard secure
    communication libraries

**Network & C2 Signatures**

Although encrypted, C2 traffic exhibits detectable structure:

- **Deterministic AES-CBC encryption**

  - Static key derivation allows retrospective decryption of captured
    traffic

- **Non-standard application protocol**

  - Fixed-size binary messages rather than JSON, XML, or known
    serialization formats

  - Consistent ordering of fields such as session identifiers,
    timestamps, command IDs, and flags

- **Absence of compression**

  - Payload entropy consistent with encryption only, without secondary
    compression layers

**Strings Analysis:**

1.  **These indicate a .NET loader:**

v4.0.30319

mscoree.dll

System.Reflection

Assembly.Load

2.  **Embedded Payload Indicators:**

EmbedDLL.dll

EmbedDLL

\EmbedDLL.dll

InternalName: EmbedDLL.dll

OriginalFilename: EmbedDLL.dll

3.  **AES Encryption of Embedded Payload Indicators:**

System.Security.Cryptography

RijndaelManaged

Rfc2898DeriveBytes

AES_Encrypt

AES_Decrypt

passwordBytes

bytesToBeEncrypted

bytesToBeDecrypted

4.  **Hardcoded Password:**

p0w3r0verwh3lm1ng!

5.  **Large Base64 / High Entropy Blobs:**

pxQRI8YJc6jVr3x45Y+ti/tT8W+3HpQHbcw1yZJQ9goNh...

6.  **In-Memory Execution Indicators:**

System.Reflection

MemoryStream

Assembly

InitializeArray

MethodInfo.Invoke (implied)

7.  **Script-based Secondary Execution:**

U2V0IG9TaGVsbCA9IENyZWF0ZU9iamVjdCAoIldzY3JpcHQuU2hlbGwiKSAK... which
converts to C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe

8.  **LoL Execution Script Drop Location:**

C:\Users\Public\Documents\embed.vbs

9.  **Persistence Mechanism Registry Key:**

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Appendices

## Yara Rules

Full Yara repository located at:
https://github.com/scryptic86/EmbedDLL-C2-C-Sharp

rule EmbedDLL_PowerOverwhelming_AES_C2

{

    meta:

        author = "Clinton Asprey"

        description = "Detects EmbedDLL AES-C2 implementation"

        confidence = "high"

        malware_family = "Custom C2 .NET backdoor"

        last_updated = "2026-01-02"

    strings:

        /\* Password (UTF-16LE) \*/

        \$pwd = "p0w3r0verwh3lm1ng!" wide

        /\* PBKDF2 salt \*/

        \$salt = { 01 02 03 04 05 06 07 08 }

        /\* .NET crypto \*/

        \$rij = "RijndaelManaged"

        \$pbkdf = "Rfc2898DeriveBytes"

        /\* JSON C2 fields \*/

        \$json1 = "\\EncryptedMessage\\"

        \$json2 = "\\IV\\"

        \$json3 = "\\HMAC\\"

        \$json4 = "\\GUID\\"

        /\* Reflection loading \*/

        \$reflect = "System.Reflection"

    condition:

        uint16(0) == 0x5A4D and   // PE

        all of (\$json\*) and

        \$salt and

        \$pwd and

        2 of (\$rij, \$pbkdf, \$reflect)

}

## Callback URLs

| Domain                                      | Port |
|---------------------------------------------|------|
| hxxp:// srv.masterchiefsgruntemporium.local | 80   |
|                                             |      |
|                                             |      |

## Decompiled Code Snippets

*Fig 5:*

# Analyst Summary

This malware represents a classic encrypted loader design leveraging AES
encryption, registry persistence, and LOLBins (MSBuild) for stealthy
execution. The use of reflection and encrypted embedded payloads
significantly complicates static detection while maintaining simple
operational logic.  
  
Detection should prioritize cryptographic API usage, registry
persistence patterns, and anomalous MSBuild invocation.

# MITRE ATT&CK Technique Mapping

T1055 – Process Injection / Reflective DLL Loading

T1027 – Obfuscated / Encrypted Payloads

T1059.005 – Command and Scripting Interpreter: Visual Basic

T1218.005 – Signed Binary Proxy Execution: MSBuild

T1547.001 – Registry Run Keys

T1071.001 – Application Layer Protocol: Web

T1041 – Exfiltration Over C2 Channel
