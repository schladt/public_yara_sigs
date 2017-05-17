rule apt_fuzzbunch_ecwi : TLPWHITE
{
    meta:
        description = "Detects ecwi.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "25a473cc8026465c56893757295f9547"

    strings:
        $0 = "[-] PrepareEgg() failed to prepare the egg!"
        $1 = "[+] Using exploit socket for comms"
        $2 = "[-] CreateNetPathCanonicalizeRequest() failed to create a NetPathCanonicalize request!"
        $3 = "[-] PutUniqueString() failed to put the ServerName!"
        $4 = "[+] Exploit reused socket"
        $5 = "[+] Callback receive complete"
        $6 = "[-] InitializeCallbackSocket() failed to create the callback socket!"
        $7 = "[-] PutString() failed to put the Prefix in the request!"
        $8 = "[*] Calling in to listener"
        $9 = "[-] ReceiveCallback() failed to receive a callback from the target!"
        $10 = "[-] PutString() failed to put the PathName in the request!"
        $11 = "[-] TbMakeSocket() failed to create the call in socket!"
        $12 = "[-] TbMakeServerSocket() failed to create the callback socket!"
        $13 = "[-] BuildExploit() failed to build the exploit!"
        $14 = "[-] InitializeParameters() failed to initializate parameters!"
        $15 = "[-] CheckAuthCode() failed to verify the AuthCode from the target!"
        $16 = "[-] BuildExploitPackage() failed to build the exploit package stub!"
        $17 = "[-] PutString() failed to put the PathName2!"
        $18 = "[-] PutLong() failed to put the PathType in the request!"
        $19 = "[-] InitializeExploitSocket() failed to create the launch socket!"
        $20 = "[-] PutString() failed to put the buffer in the request!"
        $21 = "[+] Creation of the NetPathCanonicalize request complete"
        $22 = "[-] RunExploit() failed to exploit the target!"
        $23 = "[+] Creating launch socket and connecting"
        $24 = "[+] Creation of the NetPathCanonicalizeEx request complete"
        $25 = "[-] PutString() failed to put the PathName1!"
        $26 = "[-] TbInitStruct() failed to set the members of tbTarget or tbCallback or tbCallin to reasonable default values!"
        $27 = "[-] PutLong() failed to put the Flags!"
        $28 = "[-] PutLong() failed to put the OutbufLen in the request!"
        $29 = "[-] PutLong() failed to put the PathType!"

    condition:
        5 of them
}

rule apt_fuzzbunch_pcdlllauncher_2_3_1 : TLPWHITE
{
    meta:
        description = "Detects Pcdlllauncher-2.3.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "4c266bf82c5e28e20edb52d557a40e1d"

    strings:
        $0 = "[-] Recv Failed! Retval: %d"
        $1 = "[-] GetProcAddress Failed on"
        $2 = "[-] LoadLibrary Failed on %s"
        $3 = "[*] Plugin Finished"
        $4 = "[+] GetProcAddress for : %s"
        $5 = "[*] Launch LP"
        $6 = "[*] Uploading Implant"
        $7 = "[+] LoadLibrary on %s"
        $8 = "[-] Unsupported Target Architecture"
        $9 = "[*] Preparing Implant"

    condition:
        5 of them
}

rule apt_fuzzbunch_rpcproxy_1_0_1 : TLPWHITE
{
    meta:
        description = "Detects Rpcproxy-1.0.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "460bc972466813b80c9be900e56302b6"

    strings:
        $0 = "[+] Send Failed!"
        $1 = "[-] TbSimpleRecv() failed!"
        $2 = "[+] LP thread creation suceeded"
        $3 = "[*] Proxy teardown failed, will remove itself on reboot"
        $4 = "[*] ProxyComms error"
        $5 = "[-] buildPayloadRunBuffer() failed!"
        $6 = "[*] Proxy teardown complete"
        $7 = "[-] buildPayloadChunkBuffer() failed!"
        $8 = "[-] TbMakeSocketPair() failed!"
        $9 = "[-] UUID conversion failed!"
        $10 = "[+] Sending Request To Target"
        $11 = "[+] Sending Payload Chunk To Target"
        $12 = "[+] GUID : %s v%d.%d"
        $13 = "[-] TbSend() failed!"
        $14 = "[+] Building PayloadSize request"
        $15 = "[-] parsePayloadProxyBuffer() failed!"
        $16 = "[-] Failed to bind to target interface"
        $17 = "[+] Spawning thread for LP"
        $18 = "[*] Plugin complete"
        $19 = "[+] Building PayloadLaunch request"

    condition:
        5 of them
}

rule apt_fuzzbunch_doublepulsar_1_3_1 : TLPWHITE
{
    meta:
        description = "Detects Doublepulsar-1.3.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "c24315b0585b852110977dacafe6c8c1"

    strings:
        $0 = "[-] Failed to connect to target port %d"
        $1 = "[-] Error allocating temp buffer"
        $2 = "[.] Received MCS Connect response"
        $3 = "[-] ERROR - appears to be 2012 x86 which should not exist"
        $4 = "[-] NULL DLL parameter"
        $5 = "[-] DLL has invalid DOS header:%04x"
        $6 = "[-] Bytes received:%04x CNESocket error:%08x OsError:%08x"
        $7 = "[.] Initializing SSL Runtime"
        $8 = "[.] Sending shellcode to inject DLL"
        $9 = "[-] Error allocating shellcode packet"
        $10 = "[-] Error setting OutputFile"
        $11 = "[-] Unexpected X224 Connect Confirm type"
        $12 = "[*] Deleting old version of OutputFile if it exists"
        $13 = "[+] Backdoor returned code: %X - Success!"
        $14 = "[-] Failed to Create CNESocket"
        $15 = "[-] Error setting DllOrdinal"
        $16 = "[+] Backdoor returned code: %X - Error: Invalid Params"
        $17 = "[+] DLL built"
        $18 = "[-] ERROR unrecognized OS string"
        $19 = "[-] DLL has invalid Machine type:%04x"
        $20 = "[+] Command completed successfully"
        $21 = "[.] Sending %d bytes of raw shellcode"
        $22 = "[.] Sending X224 Connect request (negotiate protocol:%s)"
        $23 = "[-] Error setting ProcessName"
        $24 = "[-] Error setting TargetPort"
        $25 = "[+] Backdoor returned code: %X - Error: Allocation Failed"
        $26 = "[-] Error receiving data packet"
        $27 = "[-] SSLRead Failed to decrypt packet : SSLERR = 0x%x, GetLastError = 0x%x"
        $28 = "[-] Error allocating memory"
        $29 = "[-] Error setting TargetIp"
        $30 = "[-] Error setting NetworkTimeout"
        $31 = "[.] Connecting to target..."
        $32 = "[-] SSLWrite Failed to decrypt packet : SSLERR = 0x%x, GetLastError = 0x%x"
        $33 = "[-] SSL_new failed"
        $34 = "[-] SSL_CTX_new failed - ssl_ctx:%08x"
        $35 = "[+] Connected to target, pinging backdoor..."
        $36 = "[-] Failed to establish connection"
        $37 = "[-] Bad or unknown status returned"
        $38 = "[-] ERROR missing OS information or invalid protocol"
        $39 = "[-] Error receiving TPKT packet"
        $40 = "[-] Error setting Target"
        $41 = "[-] Error receiving TPKT packet header"
        $42 = "[+] Backdoor killed"
        $43 = "[.] Sending burn implant message"
        $44 = "[-] Negotiate error code is:%08x"
        $45 = "[-] Negotiated protocol is not SSL:%04x"
        $46 = "[-] SSL_set_fd failed"
        $47 = "[.] Parsing ping version result - Major:%d  Minor:%d  ServicePack:%d  Architecture:%d  ProductType:%d"
        $48 = "[-] Packet MID is zero, backdoor not present"
        $49 = "[.] Closing and cleaning up RDP session"
        $50 = "[.] Sending MCS Connect Initial request"
        $51 = "[+] Selected Protocol %s"
        $52 = "[-] Negotiate response type is:%02x"
        $53 = "[+] Backdoor returned code: %X - Error: Unknown error"
        $54 = "[-] SSL_Connect unexpectedly failed (%d)"
        $55 = "[-] X224 response type is:%02x"
        $56 = "[*] Output file not specified"
        $57 = "[+] Writing Installer to disk"
        $58 = "[-] DLL Architecture is: %s"
        $59 = "[-] DLL NOT built"
        $60 = "[-] Error setting Architecture"
        $61 = "[.] Target is pre-Vista - Warning: connection not encrypted"
        $62 = "[-] Receive size too small"
        $63 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X"
        $64 = "[-] ERROR connecting to %s:%d"
        $65 = "[-] Error writing shellcode to OutputFile"
        $66 = "[*] Shellcode written to OutputFile"
        $67 = "[.] SSL rejected - reverting to old style RDP - Warning: connection not encrypted"
        $68 = "[-] ERROR doing SMB setup 0x%08X"
        $69 = "[-] Error reading from socket"
        $70 = "[-] ERROR - appears to be 2008 R2 x86 which should not exist"
        $71 = "[-] Backdoor NOT uninstalled"
        $72 = "[-] Error sending TPKT packet"
        $73 = "[-] Error setting DllPayload name"
        $74 = "[-] DLL has invalid NT Header signature:%08x"
        $75 = "[-] Error setting ProcessCommandLine"
        $76 = "[-] Error allocating buffer"
        $77 = "[-] Not enough data for X224 response"
        $78 = "[+] Backdoor installed"
        $79 = "[-] RDP Negotiate failed"
        $80 = "[-] Magic number does not match in response"

    condition:
        5 of them
}

rule apt_fuzzbunch_emeraldthreadtouch_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Emeraldthreadtouch-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "a35c794efe857bfd2cfffa97dd4a2ed3"

    strings:
        $0 = "[!] Target is *NOT* vulnerable to EMERALDTHREAD"
        $1 = "[+] Printer Count : %d"
        $2 = "[+] Unmarshalling data"
        $3 = "[!] Could not find any printer ports"
        $4 = "[*] Target *is* vulnerable to EMERALDTHREAD"
        $5 = "[-] strdup() failed!"
        $6 = "[-] Problem with EnumPorts request"
        $7 = "[-] Failed to get printer handle!"
        $8 = "[-] OutputParameters() failed!"
        $9 = "[+] Found %d printer(s)"
        $10 = "[!] Could not find any shared printers"
        $11 = "[*] Probing for shared printers"
        $12 = "[-] calloc() failed!"
        $13 = "[+] Found %d port(s)"
        $14 = "[-] Output parameter not found"
        $15 = "[-] No vulnerable printers to output!"
        $16 = "[-] RpcEnumeratePrinters() failed!"
        $17 = "[-] Touch failed!"
        $18 = "[-] Connection to target failed!"
        $19 = "[*] Outputting parameters"
        $20 = "[*] Probing for printer ports"
        $21 = "[+] Printer port probing complete"
        $22 = "[-] Problem with EnumPrinters request"
        $23 = "[-] Failed to get printer handle for port"
        $24 = "[+] Shared printer probing complete"
        $25 = "[-] Error setting output parameter"
        $26 = "[-] RpcEnumeratePorts() failed!"
        $27 = "[-] RpcClosePrinter error!"

    condition:
        5 of them
}

rule apt_fuzzbunch_erraticgophertouch_1_0_1 : TLPWHITE
{
    meta:
        description = "Detects Erraticgophertouch-1.0.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "9f60e690feabdaa2611373e93aa50450"

    strings:
        $0 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable"
        $1 = "[+] Bound to Dimsvc, target IS vulnerable"
        $2 = "[*] Touch completed"
        $3 = "[*] Touching target %s:%d for anonymous Dimsvc RPC syntax"
        $4 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable"
        $5 = "[-] TbDoSmbStartupEx() failed!"

    condition:
        5 of them
}

rule apt_fuzzbunch_printjoblist_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Printjoblist-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "619b15112ce02459d3bb414b6ea653ed"

    strings:
        $0 = "[-] Enumeration failed"
        $1 = "[+] jobId : %d"
        $2 = "[-] Problem with EnumJobs request"
        $3 = "[-] Value conversion failed"
        $4 = "[-] Error making RPC request : %08x"
        $5 = "[-] Error setting PrinterName"
        $6 = "[+] Enumerating Jobs"
        $7 = "[+] Found %d jobs"
        $8 = "[*] Enumerating Print Jobs..."
        $9 = "[-] Failed to enumerate print jobs"
        $10 = "[-] Error setting Joblist"

    condition:
        5 of them
}

rule apt_fuzzbunch_esteemaudittouch_2_1_0 : TLPWHITE
{
    meta:
        description = "Detects Esteemaudittouch-2.1.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "e30d66be8ddf31f44bb66b8c3ea799ae"

    strings:
        $0 = "[-] Setting RdpLibHertz failed!"
        $1 = "[-] RdpLib_Connect() failed - 0x%08x!"
        $2 = "[-] Setting Target failed!"
        $3 = "[-] RdpLib_SmartcardEmulate() failed - 0x%08x!"
        $4 = "[-] Network clean up failed!"
        $5 = "[+] TargetIP:        %s"
        $6 = "[-] Touching the target failed!"
        $7 = "[-] RdpLib_RegisterCallback() failed - 0x%08x!"
        $8 = "[-] Setting Architecture failed!"
        $9 = "[*] Cleaning up RDP"
        $10 = "[*] Encryption: None."
        $11 = "[*] Smart card authentication NOT supported."
        $12 = "[-] ConnectRDP() failed - 0x%08x!"
        $13 = "[*] Unable to gather encryption info."
        $14 = "[-] Setting SmartCardAuth failed!"
        $15 = "[+] Output parameter writing complete"
        $16 = "[-] RdpLib_StopSmartcardEmulate() failed - 0x%08x!"
        $17 = "[+] RDP initialization complete"
        $18 = "[*] Connecting to RDP"
        $19 = "[+] RDP clean up complete"
        $20 = "[*] Architecture: x86."
        $21 = "[*] Encryption: 56-bit."
        $22 = "[*] Architecture: x86 64-bit."
        $23 = "[-] RdpLib_ProcessIncomingPackets() failed - 0x%08x!"
        $24 = "[*] Encryption: 128-bit."
        $25 = "[+] TargetPort:      %d"
        $26 = "[-] Error could not connect to RDP server!"
        $27 = "[*] Initializing RDP"
        $28 = "[-] retVal = %d"
        $29 = "[*] Smart card authentication IS supported."
        $30 = "[-] RdpLib_Uninitialize() failed - 0x%08x!"
        $31 = "[*] Connected over RDP to %s:%d"
        $32 = "[+] PacketTimeout:   %d"
        $33 = "[-] InitializeParams() failed - %d/%d!"
        $34 = "[-] Invalid architecture!"
        $35 = "[-] ConvertOSFromRDPOS() failed!"
        $36 = "[+] RDP connection complete"
        $37 = "[*] Encryption: FIPS."
        $38 = "[-] Output parameter writing failed!"
        $39 = "[*] Running the touch"
        $40 = "[!] Wow--that's some serious network latency you have there!"
        $41 = "[+] NetworkTimeout:  %d"
        $42 = "[-] Setting EncryptionMethod failed!"
        $43 = "[-] Timeout waiting for smartcard callback - maximum process count reached - 0x%08x!"
        $44 = "[-] Error could not connect to TCP server!"
        $45 = "[-] CleanUpRDP() failed!"
        $46 = "[*] Target: %s."
        $47 = "[*] Computed RdpLibHertz = %d"
        $48 = "[-] RdpLib_Initialize() failed - 0x%08x!"
        $49 = "[*] Encryption: 40-bit."
        $50 = "[-] Invalid encryption method!"
        $51 = "[-] InitializeRDP() failed!"

    condition:
        5 of them
}

rule apt_fuzzbunch_printjobdelete_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Printjobdelete-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "6db7cd3b51f7f4d4b4f201f62d392745"

    strings:
        $0 = "[+] Print Job Deleted"
        $1 = "[-] Error making delete job RPC request"
        $2 = "[+] Making Job Conrol Request"
        $3 = "[-] Deletion failed"
        $4 = "[-] Problem with Deletejob request 0x%8.8x"
        $5 = "[+] Deleting Print Job"
        $6 = "[+] Complete"
        $7 = "[-] Error with Job control request"
        $8 = "[*] Deleting Print Job..."

    condition:
        5 of them
}

rule apt_fuzzbunch_namedpipetouch_2_0_0 : TLPWHITE
{
    meta:
        description = "Detects Namedpipetouch-2.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "23727130cf7e7476cea1e493350e68a8"

    strings:
        $0 = "[+] Pipe Found: %s"
        $1 = "[-] Error on SMB startup, aborting"
        $2 = "[+] Connection established."
        $3 = "[+] Testing %d pipes"
        $4 = "[+] Initializing Connection..."
        $5 = "[*] Summary: %d pipes found"
        $6 = "[-] Error %08X"
        $7 = "[-] Error creating socket, aborting"
        $8 = "[+] Testing for %s"
        $9 = "[-] Error allocating buffer, out of memory, aborting"

    condition:
        5 of them
}

rule apt_fuzzbunch_architouch_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Architouch-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "30380b78e730efc006216f33fa06964d"

    strings:
        $0 = "[-] Error 0x%X (%s)"
        $1 = "[*] Binding to RPC..."
        $2 = "[*] Connecting..."
        $3 = "[+] Target is %s"

    condition:
        all of them
}

rule apt_fuzzbunch_smbtouch_1_1_1 : TLPWHITE
{
    meta:
        description = "Detects Smbtouch-1.1.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "b50fff074764b3a29a00b245e4d0c863"

    strings:
        $0 = "[*] Using Remote API to determine architecture"
        $1 = "[-] No pipes accessible"
        $2 = "[-] @%d: Error 0x%X - %s"
        $3 = "[*] Credentials           %s"
        $4 = "[+] Target is %s-bit"
        $5 = "[-] Error during architecture touch"
        $6 = "[!] for these SMB exploits they are equivalent"
        $7 = "[+] Target OS Version %d.%d"
        $8 = "[*] TargetPort            %hu"
        $9 = "[+] Share is accessible"
        $10 = "[-] %-10s - Not accessible (0x%08X - %s)"
        $11 = "[+] SMB Touch started"
        $12 = "[-] Could not open file (0x%08X - %s)"
        $13 = "[+] Initiated SMB connection"
        $14 = "[*] Trying pipes..."
        $15 = "[-] Target is not vulnerable"
        $16 = "[+] Target OS Version %d.%d build %d"
        $17 = "[*] Opening file: %ls"
        $18 = "[*] Protocol              %s"
        $19 = "[*] Connecting to target..."
        $20 = "[!] Target could be either SP%d or SP%d,"
        $21 = "[*] Connecting to share: %ls"
        $22 = "[-] Hash must be exactly 16 bytes"
        $23 = "[+] %-10s - Success!"
        $24 = "[+] Target is vulnerable to %d exploit%s"
        $25 = "[*] Binding to Rpc to determine architecture"
        $26 = "[*] RedirectedTargetPort  %hu"
        $27 = "[-] Network error 0x%08X - %s"
        $28 = "[*] NetworkTimeout        %hu"
        $29 = "[!] Target is most likely 32-bit, but this value was not seen in testing!"
        $30 = "[-] Could not connect to share (0x%08X - %s)"
        $31 = "[!] Unknown error code received: 0x%X"
        $32 = "[-] Error with initial SMB connection, trying older method"
        $33 = "[*] TargetIp              %s"
        $34 = "[*] RedirectedTargetIp    %s"
        $35 = "[+] Target OS (Version numbers not specified)"

    condition:
        5 of them
}

rule apt_fuzzbunch_iistouch_1_2_2 : TLPWHITE
{
    meta:
        description = "Detects Iistouch-1.2.2.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "c21b3638c69f76071de9b33362aab22a"

    strings:
        $0 = "[+] Language found : %s"
        $1 = "[-] Bad page"
        $2 = "[*] Detecting WEBDAV"
        $3 = "[-] Language Touch Failed"
        $4 = "[-] Title not found"
        $5 = "[-] IIS Version Touch Failed"
        $6 = "[-] SEARCH Option not found."
        $7 = "[-] Unrecognized page"
        $8 = "[-] Windows Version Unknown"
        $9 = "[+] Windows XP"
        $10 = "[+] Charset match: %s"
        $11 = "[+] WebDAV is ENABLED"
        $12 = "[-] WebDAV is DISABLED (assumed since PROPFIND and SEARCH weren't found)"
        $13 = "[+] Sending HTTP Options Request"
        $14 = "[+] Target Language: %s"
        $15 = "[-] Webdav Touch Failed"
        $16 = "[+] Initializing network"
        $17 = "[-] Head Request Failed!"
        $18 = "[+] Windows 2000"
        $19 = "[+] Target Path: %s"
        $20 = "[+] Target Service Pack: %s"
        $21 = "[-] Couldn't determine IIS Version"
        $22 = "[-] Options Request Failed!"
        $23 = "[*] Finding IIS Version"
        $24 = "[+] Checking Language: %s"
        $25 = "[-] WebDAV is disabled or invalid hostname specified"
        $26 = "[-] Are you being redirectect? Need to retarget?"
        $27 = "[+] SEARCH Option found. Webdav is enabled."
        $28 = "[*] IIS Touch Complete"
        $29 = "[+] PROPFIND Option found. Webdav is enabled."
        $30 = "[+] IIS Target OS: %s"
        $31 = "[+] Checking server response for IIS version"
        $32 = "[-] PROPFIND Option not found."
        $33 = "[-] Charset not found"
        $34 = "[+] Sending HTTP Head Request"
        $35 = "[+] Found IIS version %c.%c"
        $36 = "[+] Windows 2003"
        $37 = "[+] Checking server response for Webdav"
        $38 = "[-] WebDAV is DISABLED"
        $39 = "[*] Finding Language"
        $40 = "[+] IIS Version: %c.%c"
        $41 = "[-] Failed to get response"
        $42 = "[-] Server doesn't look like IIS"
        $43 = "[-] Invalid internal language"

    condition:
        5 of them
}

rule apt_fuzzbunch_educatedscholartouch_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Educatedscholartouch-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "3d553da33796c8c73ed00b3d9a91e24e"

    strings:
        $0 = "[*] Touch Completed Successfully"
        $1 = "[*] Sending Touch Packet"
        $2 = "[!] Touch will be considered successful if no response in %d seconds"
        $3 = "[+] Target Vulnerable"
        $4 = "[!] A vulnerable target will not respond."
        $5 = "[-] Target NOT Vulernable"
        $6 = "[-] Touch Failed"
        $7 = "[-] Could not send touch packet to target"

    condition:
        5 of them
}

rule apt_fuzzbunch_eclipsedwingtouch_1_0_4 : TLPWHITE
{
    meta:
        description = "Detects Eclipsedwingtouch-1.0.4.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "212665c005dfcb483d4645572c680583"

    strings:
        $0 = "[+] Part2 -"
        $1 = "[+] Part3 -"
        $2 = "[-] RunTouch() failed to touch the target!"
        $3 = "[-] InitializeTouchSocket() failed to create the launch socket!"
        $4 = "[+] Part1 -"
        $5 = "[+] Sending touch package"
        $6 = "[*] Building touch package"
        $7 = "[+] NetPathCompareRequest -"
        $8 = "[-] Touch run failed!"
        $9 = "[-] TbCopyBuffStrToUniBuffStr() failed convert PathName2 to UNICODE!"
        $10 = "[*] Creating launch socket"
        $11 = "[+] ServerName -"
        $12 = "[-] BuildPathName1() failed to build PathName1!"
        $13 = "[-] CreateNetPathCompareRequest() failed to create a NetPathCompare request!"
        $14 = "[+] Part4 -"
        $15 = "[+] Setting username: %s"
        $16 = "[*] PathName2 build complete"
        $17 = "[+] Setting password: %s"
        $18 = "[*] Building PathName1"
        $19 = "[+] Touch build complete"
        $20 = "[+] PathName1 -"
        $21 = "[+] Touch package build complete"
        $22 = "[*] PathName1 build complete"
        $23 = "[-] PutString() failed to put the PathName2 in the request!"
        $24 = "[*] Touching the target"
        $25 = "[+] Target touching complete"
        $26 = "[-] TbDoSmbRecvData() failed!"
        $27 = "[-] TbCopyBuffStrToUniBuffStr() failed convert PathName1 to UNICODE!"
        $28 = "[+] PathType - 0x%x"
        $29 = "[+] Flags - 0x%08x"
        $30 = "[-] PutString() failed to put the PathName1 in the request!"
        $31 = "[-] BuildPathName2() failed to build PathName2!"
        $32 = "[*] Building PathName2"
        $33 = "[-] BuildTouchPackage() failed to build the touch package stub!"
        $34 = "[+] pathName2 -"
        $35 = "[+] NetPathCompareRequest TCP Request -"
        $36 = "[-] BuildTouch() failed to build the touch!"
        $37 = "[*] Building touch"
        $38 = "[-] The target is NOT vulnerable"
        $39 = "[+] The target IS VULNERABLE"

    condition:
        5 of them
}

rule apt_fuzzbunch_explodingcantouch_1_2_1 : TLPWHITE
{
    meta:
        description = "Detects Explodingcantouch-1.2.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "96affb296584515614dd1e6675dce57c"

    strings:
        $0 = "[+]The expected HTTP 500 response was returned"
        $1 = "[!]If a max size of less than %d was used, consider trying a larger size"
        $2 = "[+] Request string: %s"
        $3 = "[*] ExplodingCan Touch Complete"
        $4 = "[+] IIS Path Size: %d"
        $5 = "[+]Checking path sizes from %d to %d"
        $6 = "[!]Could not determine the path size!"
        $7 = "[*] Finding Path Size"
        $8 = "[+] Found IIS Path Size %d"
        $9 = "[+]No delay set."
        $10 = "[+]With a delay of %d seconds, max estimated delay time is %d seconds"
        $11 = "[!]Consider rerunning ExplodingCanTouch with a larger max size to verify path size"
        $12 = "[!]Warning: Error on first request - path size may actually be larger than indicated."
        $13 = "[-] Exploding Can Touch Failed"

    condition:
        5 of them
}

rule apt_fuzzbunch_rpctouch_2_1_0 : TLPWHITE
{
    meta:
        description = "Detects Rpctouch-2.1.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "a788c1b34f4487e26135572cbedb4c6f"

    strings:
        $0 = "[*] SMB String: \"%s\""
        $1 = "[*] Detected Architecture: x64"
        $2 = "[*] SMB String: (none)"
        $3 = "[*] Detected Architecture: x86"
        $4 = "[*] Failed to detect OS / Service Pack on %s:%d"
        $5 = "[*] Failed to detect Language on %s:%d"
        $6 = "[*] SMB String: %s (%s)"
        $7 = "[*] Detected Architecture: Unknown"
        $8 = "[*] Detected Language: %s"
        $9 = "[-] Unable to run architecture touch, could not get a handle to 'browser'"

    condition:
        5 of them
}

rule apt_fuzzbunch_eternalblue_2_2_0 : TLPWHITE
{
    meta:
        description = "Detects Eternalblue-2.2.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "8c80dd97c37525927c1e549cb59bcbf3"

    strings:
        $0 = "[-] Error sending transaction packet"
        $1 = "[*] Received output parameters from CORE"
        $2 = "[*] Sending egg to corrupted connection."
        $3 = "[*] Auto targeted based on SMB string"
        $4 = "[*] Target OS selected valid for OS indicated by SMB reply"
        $5 = "[-] Target was unable to allocate overflow buffer"
        $6 = "[-] Error converting TRCH input parameters to native format"
        $7 = "[*] Good reply from SMB Echo request"
        $8 = "[-] Error connecting to target"
        $9 = "[-] Unexpected failure: 0x%x"
        $10 = "[-] Error sending first packet"
        $11 = "[-] Unable to allocate buffer for shellcode"
        $12 = "[-] Error doing SMB setup 0x%08X"
        $13 = "[-] Failed making new connection for SMBv2 groom."
        $14 = "[-] Shellcode buffer too large!"
        $15 = "[-] Failed making new connection for final SMBv2 buffer."
        $16 = "[-] No response received from exploit packet. Not good."
        $17 = "[-] Shellcode MAX size: 0x%04x"
        $18 = "[*] Sending all but last fragment of exploit packet"
        $19 = "[-] Target OS selected is not valid for OS indicated by SMB reply"
        $20 = "[-] Unable auto target architecture based on SMB reply"
        $21 = "[-] Error sending data for SMBv2 groom."
        $22 = "[*] Forcing MaxExploitAttempts to 1."
        $23 = "[*] Building exploit buffer"
        $24 = "[-] Unable to automatically target based on SMB reply"
        $25 = "[*] Starting non-paged pool grooming"
        $26 = "[-] Error unpacking/processing output parameters"
        $27 = "[-] Auto targeted an unsupported OS based on SMB reply"
        $28 = "[-] Failed to unpack serialized output parameters"
        $29 = "[*] Connecting to target for exploitation."
        $30 = "[!] Hookup readerThread terminating... (%d)"
        $31 = "[*] Triggering free of corrupted buffer."
        $32 = "[-] Error sending data for final SMBv2 buffer."
        $33 = "[-] Quota was exceeded too early, not enough left for groom!"
        $34 = "[-] Shellcode size of %d bytes is too large for target"
        $35 = "[-] Failed to translated unpacked parameters to TRCH format"
        $36 = "[-] ERROR sending SMB Echo - 0x%08X"
        $37 = "[*] Receiving response from exploit packet"
        $38 = "[*] Fingerprinting SMB non-paged pool quota"
        $39 = "[-] Unexpected error code returned in response from exploit packet"
        $40 = "[*] Auto target successful based on SMB reply"
        $41 = "[*] Sending SMB Echo request"
        $42 = "[*] Sending last fragment of exploit packet!"
        $43 = "[-] Error receiving response from first transaction packet"
        $44 = "[*] Trying again with %d Groom Allocations"
        $45 = "[*] CORE sent serialized output blob"

    condition:
        5 of them
}

rule apt_fuzzbunch_eternalchampion_2_0_0 : TLPWHITE
{
    meta:
        description = "Detects Eternalchampion-2.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "d2fb01629fa2a994fbd1b18e475c9f23"

    strings:
        $0 = "[*] Credentials            %s"
        $1 = "[+] Opening pipe"
        $2 = "[+] Exploit was not thrown, but here's a consolation prize"
        $3 = "[*] TargetPort             %hu"
        $4 = "[*] Finals:   %d"
        $5 = "[*] Pipe                   %s"
        $6 = "[+] DOPU is already installed..."
        $7 = "[-] Not enough data returned for leak to work"
        $8 = "[*] Preparing to exploit..."
        $9 = "[*] Got DAVE MSG header (type=%x, length=%u)"
        $10 = "[-] Error retrieving parameters"
        $11 = "[-] Arch Leak failed"
        $12 = "[+] Connection established"
        $13 = "[-] Exploit Failed:"
        $14 = "[!] One cause for the leak failing is an incorrect architecture setting"
        $15 = "[*] Redirected TargetPort  %hu"
        $16 = "[+] SMB session established"
        $17 = "[!] DOPU returned unknown architecture!"
        $18 = "[*] Race summary:"
        $19 = "[+] Opening file"
        $20 = "[+] Exploit successful! Use DOPU to continue"
        $21 = "[*] Competition %d:"
        $22 = "[!] Failed to read DAVE MSG body (%d)"
        $23 = "[*] Target                 %s"
        $24 = "[*] Attempting information leak (rename)"
        $25 = "[!] Hookup readerThread terminating abnormally... (%d)"
        $26 = "[*] MaxExploitAttempts     %d"
        $27 = "[*] Sending shellcode to target"
        $28 = "[*] Races:    %d"
        $29 = "[+] successfully sent"
        $30 = "[+] SMB setup complete"
        $31 = "[*] Let the races begin!"
        $32 = "[*] NetworkTimeout         %hu"
        $33 = "[*] Share                  %ls"
        $34 = "[*] Redirected TargetIP    %s"
        $35 = "[*] Taking victory lap!"
        $36 = "[*] Initializing SMB connection"
        $37 = "[!] Failed to resize message buffer to %u bytes"
        $38 = "[*] Exploit Info:"
        $39 = "[!] If there is any doubt try setting TargetOsArchitecture to Unknown"
        $40 = "[*] Attempting information leak (sync)"
        $41 = "[*] TargetIp               %s"
        $42 = "[*] Attempts: %d"
        $43 = "[!] Failed to read DAVE MSG header (%d)"
        $44 = "[*] Attempting information leak (enum)"
        $45 = "[+] Successfully leaked transaction!"

    condition:
        5 of them
}

rule apt_fuzzbunch_mofconfig_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Mofconfig-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "be8dc61dd7890f8eb4bdc9b1c43e76f7"

    strings:
        $0 = "[*] Configuration Complete"
        $1 = "[+] Preprocessing complete"
        $2 = "[-] Get OutputFile error"
        $3 = "[-] Get RemoteMOFPath error"
        $4 = "[-] MOF configuration failure"
        $5 = "[-] Set RemoteDLLPath error"
        $6 = "[-] Set ConfiguredMOF error"
        $7 = "[-] Failed to replace DLL name"
        $8 = "[-] Set RemoteMOFPath error"
        $9 = "[-] Get MOFFile error"
        $10 = "[-] Failed to replace MOF name"
        $11 = "[-] Failed to replace internal var"
        $12 = "[-] Error building complier cmd line"
        $13 = "[*] Configuring MOF File"
        $14 = "[*] Setting Output Parameters"
        $15 = "[-] Get RemoteMOFTriggerPath error"
        $16 = "[*] Initializing"
        $17 = "[+] Compilation complete"
        $18 = "[+] Preprocessing MOF file"
        $19 = "[-] Failed to replace MOF Trigger name"
        $20 = "[-] Get RemoteDLLPath error"
        $21 = "[+] Compiling MOF file"
        $22 = "[-] Set RemoteMOFTriggerPath error"
        $23 = "[-] Get MOFCompiler error"

    condition:
        5 of them
}

rule apt_fuzzbunch_easypi_3_1_0 : TLPWHITE
{
    meta:
        description = "Detects Easypi-3.1.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "7e1a081a93d07705bd5ed2d2919c4eea"

    strings:
        $0 = "[-] %s - Target might not be in a usable state."
        $1 = "[+] Preparing Egg1"
        $2 = "[-] Timed out waiting for target to close our connection.  Target may be in a weird state."
        $3 = "[+] Preparing Egg0"
        $4 = "[*] Inital egg1 was not sent"
        $5 = "[*] Unexpected response to packet 1, should have been 0xAE"
        $6 = "[*] Finshed Prepping Target"
        $7 = "[*] TbSend failed on initial b080: %s"
        $8 = "[-] Could not connect!"
        $9 = "[*] Continuing, connection not accepted by target"
        $10 = "[*] TbSend failed on Egg 1: %s"
        $11 = "[+] Egg1 sent"
        $12 = "[+] Closing connections"
        $13 = "[-] Timed out waiting for Authcode."
        $14 = "[*] Prepping Target"
        $15 = "[*] Out of memory for TbPutBuff"
        $16 = "[*] Socket re-creation failed preparing for exploit packet: %s"
        $17 = "[*] Waiting for up to %d seconds for Authcode from exploit"
        $18 = "[+] Egg0 + Overflow sent"
        $19 = "[*] TbSend failed on Egg 0: %s"
        $20 = "[+] Starting Handshake for Egg1"
        $21 = "[+] Target connection state cleaned up."
        $22 = "[+] Encoding Exploit"
        $23 = "[*] TbRecv failed : %s"
        $24 = "[*] Building Exploit"
        $25 = "[*] Was not able to establish initial connections"
        $26 = "[*] Cleaning up target connection state"
        $27 = "[+] Starting Handshake for Egg0 + Overflow"
        $28 = "[*] Out if memory for TbPutBuff"
        $29 = "[-] Received data on our cleanup connection, which is odd..."
        $30 = "[*] WARNING: Egg 1 is in memory on remote host!"
        $31 = "[*] Prepping Targets"

    condition:
        5 of them
}

rule apt_fuzzbunch_emphasismine_3_4_0 : TLPWHITE
{
    meta:
        description = "Detects Emphasismine-3.4.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "76237984993d5bae7779a1c3fbe2aac2"

    strings:
        $0 = "[+] Waiting %d more seconds"
        $1 = "[*] Creating callin socket"
        $2 = "[+] InitializeCallinSocket: Initializing callin socket complete"
        $3 = "[-] CheckAuthCode failed: 0x%02x"
        $4 = "[+] MakeCallin: Calling into listener on target payload complete"
        $5 = "[-] InitializeCallbackSocket failed"
        $6 = "[*] MakeCallin: Calling into listener on target payload"
        $7 = "[-] TbMakeSocket failed: 0x%02x"
        $8 = "[-] InitializeCallinSocket() failed: 0x%02x"
        $9 = "[*] InitializeCallinSocket: Initializing callin socket"
        $10 = "[+] Callback successful"
        $11 = "[-] MakeCallin failed"
        $12 = "[-] TbInitStruct failed: 0x%02x"
        $13 = "[-] ReceiveCallback failed to receive callback"
        $14 = "[*] Waiting for callback from payload."

    condition:
        5 of them
}

rule apt_fuzzbunch_explodingcan_2_0_2 : TLPWHITE
{
    meta:
        description = "Detects Explodingcan-2.0.2.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "dc53bd258f6debef8604d441c85cb539"

    strings:
        $0 = "[-] SSL Write Error (%X)"
        $1 = "[-] PushBackdoorBridge: Socket send() error while transmitting package contents"
        $2 = "[-] TriggerBackdoor::pccp_connect(): %s"
        $3 = "[*] Waiting for Authcode from exploit"
        $4 = "[*] Attemping to trigger IIS backdoor (up to %d tries)"
        $5 = "[-] PushBackdoorBridge: failed to send package length to implant"
        $6 = "[-] Error encoding buffer 1 to UTF8"
        $7 = "[-] PushBackdoorBridge: failed to read '%s' from disk"
        $8 = "[-] TriggerBackdoor: unable to allocate buffer for HTTP trigger request"
        $9 = "[+] SendExploit() send complete"
        $10 = "[+] Decoding SSL Obscured Authcode"
        $11 = "[+] Setting callback information in Egg %s:%d"
        $12 = "[-] Listen: ListenLocalPort: %d"
        $13 = "[-] TriggerBackdoor: Socket send() error while transmitting trigger HTTP request"
        $14 = "[-] TbRecv failed to get auth code!"
        $15 = "[-] Backdoor: Parameter_U32_getValue(BackdoorIndex) failed!"
        $16 = "[-] Backdoor: Parameter_U32_getValue(BackdoorRetries) failed!"
        $17 = "[+] BackdoorValue set to random Basic Auth string (%s)"
        $18 = "[!] Retrying trigger IIS backdoor"
        $19 = "[!] Backdoor trigger request timed out; backdoor did NOT respond..."
        $20 = "[+] RecvData size = %d"
        $21 = "[-] Listen: ListenPort: %d"
        $22 = "[+] No Data on Exploit Socket"
        $23 = "[-] SendTriggerRequest: trigger got immediate but WRONG response; aborting..."
        $24 = "[-] Buffer 2 contains bad characters, cannot use this configuration"
        $25 = "[+] Using Basic Authentication"
        $26 = "[-] Backdoor: Parameter_String_getValue(BackdoorValue) failed!"
        $27 = "[+] Sending %d (0x%08x) bytes"
        $28 = "[-] Buffer 1 contains bad characters, cannot use this configuration"
        $29 = "[-] Backdoor: Parameter_U32_getValue(BackdoorDelay) failed!"
        $30 = "[-] All attempts to trigger the backdoor timed out; aborting..."
        $31 = "[-] Failed To Send Exploit"
        $32 = "[-] Encoding Exploit Payload failed to malloc memory!"
        $33 = "[-] Backdoor: Parameter_LocalFile_getValue(BackdoorBridgeDLL) failed!"
        $34 = "[+] Building HTTP Request"
        $35 = "[+] Using SSL_write"
        $36 = "[-] Can't Find Authcode in Packet!"
        $37 = "[+] Creating callback socket"
        $38 = "[-] PushBackdoorBridge: failed to DMGD-wrap bridge DLL"
        $39 = "[+] Checking For Residual Data on Exploit Socket"
        $40 = "[-] Backdoor: Parameter_LocalFile_getValue(PccpPy) failed!"
        $41 = "[-] Backdoor: Parameter_LocalFile_getValue(PythonExe) failed!"
        $42 = "[+] Sending Exploit"
        $43 = "[-] Listen: Parameter_Port_getValue(ListenLocalPort) failed!"
        $44 = "[-] Listen: Parameter_Port_getValue(ListenPort) failed!"
        $45 = "[-] SendTriggerRequest: TbRecv() failed to read trigger response"
        $46 = "[+] No Authentication"
        $47 = "[-] Failed to tear down PCCP proxy channel; aborting..."
        $48 = "[+] Using callback socket for communication"
        $49 = "[-] TriggerBackdoor: failed to build headers for HTTP trigger request"
        $50 = "[-] TriggerBackdoor: Failed to signal PCCP to begin channel filtering"
        $51 = "[-] Callback: Params_getCallbackPortValues(CallbackPort, CallbackLocalPort) failed!"
        $52 = "[+] BackdoorValue set to random Etag string (%s)"
        $53 = "[+] Setting listen information in Egg, TCP port %d"
        $54 = "[-] Error encoding buffer 2 to UTF8"
        $55 = "[-] getsockname Failed!"
        $56 = "[+] Backdoor trigger SUCCEEDED; proceeding to auth-code check"

    condition:
        5 of them
}

rule apt_fuzzbunch_eternalromance_1_4_0 : TLPWHITE
{
    meta:
        description = "Detects Eternalromance-1.4.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "4420f8917dc320a78d2ef14136032f69"

    strings:
        $0 = "[*] Installing DOUBLEPULSAR"
        $1 = "[-] Error reading shellcode file '%s'"
        $2 = "[+] shellcodeaddress = %x, shellcodefilesize=%d"
        $3 = "[*] Executing DOUBLEPULSAR"
        $4 = "[+] shellcodeaddress = %I64X, shellcodefilesize=%d"

    condition:
        all of them
}

rule apt_fuzzbunch_eclipsedwing_1_5_2 : TLPWHITE
{
    meta:
        description = "Detects Eclipsedwing-1.5.2.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "195efb4a896e41fe49395c3c165a5d2e"

    strings:
        $0 = "[+] NetPathCompare request created"
        $1 = "[*] Preparing RPC Proxy"
        $2 = "[-] PutUniqueString() failed!"
        $3 = "[-] PrepareEgg() failed!"
        $4 = "[-] PutLong() failed!"
        $5 = "[*] Building exploit package for Non-NX"
        $6 = "[+] NetPathCanonicalizeEx request created"
        $7 = "[-] BuildExploit() failed!"
        $8 = "[-] BuildExploitPackage() failed!"
        $9 = "[-] RunPrimer() failed!"
        $10 = "[-] RunExploit() failed!"
        $11 = "[-] PrepareNoNXEgg() failed!"
        $12 = "[+] Creating socket and connecting To RPC Interface"
        $13 = "[+] Primer package build complete"
        $14 = "[-] PutString() failed!"
        $15 = "[*] Building primer package"
        $16 = "[+] Primer build complete"
        $17 = "[+] Target not NX capable."
        $18 = "[+] Closing exploit socket"
        $19 = "[+] NX Capable Target"
        $20 = "[-] BuildNoNXExploitPackage() failed!"
        $21 = "[-] CreateNetPathCanonicalizeRequest() failed!"
        $22 = "[-] TbDoRpcRequestEx() failed!"
        $23 = "[+] NetPathCanonicalize request created"
        $24 = "[-] Build Heap buffer failed!"
        $25 = "[-] Failed to create the launch socket!"
        $26 = "[*] Priming target"

    condition:
        5 of them
}

rule apt_fuzzbunch_eternalromance_1_3_0 : TLPWHITE
{
    meta:
        description = "Detects Eternalromance-1.3.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "8d3ffa58cb0dc684c9c1d059a154cf43"

    strings:
        $0 = "[*] ***Backdoor was NOT removed***"
        $1 = "[*] Waiting for callback..."
        $2 = "[-] Callin did not respond, sleeping %d seconds before trying again"
        $3 = "[+] Remote Callback on port %d"
        $4 = "[~] Backdoor not present, continuing exploitation"
        $5 = "[-] Error: OS not supported! %d.%d Sp%d %s"
        $6 = "[-] Error: CallinPort cannot be 0!"
        $7 = "[*] Installing SMB Backdoor"
        $8 = "[*] Pinging to see if backdoor already exists..."
        $9 = "[-] Error setting CallbackLocalPort"
        $10 = "[-] Error setting CallbackPort"
        $11 = "[-] Error setting CallinPort"
        $12 = "[-] Error getting CallbackIp"
        $13 = "[+] Backdoor already exists!!! Skipping exploitation"
        $14 = "[*] Attempting to call in..."
        $15 = "[+] Connection to target successfully established!"
        $16 = "[-] Error getting Payload"
        $17 = "[*] Sending payload for backdoor to execute..."
        $18 = "[-] Error setting Payload - invalid entry"
        $19 = "[-] Error setting ListenPort"
        $20 = "[*] Tearing down backdoor..."

    condition:
        5 of them
}

rule apt_fuzzbunch_esteemaudit_2_1_0 : TLPWHITE
{
    meta:
        description = "Detects Esteemaudit-2.1.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "1d2db6d8d77c2e072db34ca7377722be"

    strings:
        $0 = "[+] Name Table = 0x%08X"
        $1 = "[-] build_exploit_x86(): malloc() failed!"
        $2 = "[-] Unable to register callback - 0x%08x"
        $3 = "[-] build_egg1_listen_x86(): Failed to package up CallbackPayloadDLL with DMGD!"
        $4 = "[-] build_egg0_x86(): egg0 is too large (by %d bytes) to fit in buffer2!"
        $5 = "[-] Could not emulate smart card - 0x%08x"
        $6 = "[-] build_egg1_listen_x64(): Failed to package up MigrateProcessDLL with DMGD!"
        $7 = "[-] PHASE_FUNCTION_TABLE_DETECT: Did not get sufficient data back from leak"
        $8 = "[-] build_egg1_listen_x64(): Failed to package up CallbackPayloadDLL with DMGD!"
        $9 = "[+] Exploit buffer created."
        $10 = "[!] Failed to determine VirtualProtect index (leak failed)"
        $11 = "[-] build_exploit_leak_x64(): Need (non-zero) RVA for KERNEL32's name table!"
        $12 = "[-] Could not initialize RDP library - 0x%08x"
        $13 = "[-] PHASE_FUNCTION_NAMES_DETECT: Did not get sufficient data back from leak"
        $14 = "[+] Callback successful!"
        $15 = "[-] build_all_x86(): Unknown Payload type '%s'!"
        $16 = "[*] Building exploit buffer."
        $17 = "[!] Failed to determine VirtualProtect address (bad results from leak)"
        $18 = "[+] Shellcode sent"
        $19 = "[!] build_exploit_x86(): buffer2 already allocated (?]; freeing..."
        $20 = "[-] build_egg1_callback_x64(): Failed to read MigrateProcessDLL!"
        $21 = "[+] VirtualProtect index is 0x%04X"
        $22 = "[!] Failed to determine VirtualProtect address (leak failed)"
        $23 = "[+] SELECT_FILE - Don't care which"
        $24 = "[+] Connected to target %s:%d"
        $25 = "[-] Error processing packets: 0x%08x (trying again...)"
        $26 = "[-] build_exploit_leak_x64(): Need (non-zero) index for VirtualProtect export!"
        $27 = "[-] Unable to connect to RDP service - 0x%08x"
        $28 = "[!] Failed to determine the export table RVA (leak failed)"
        $29 = "[-] Exploit failed to complete!"
        $30 = "[-] build_egg1_listen_x86(): Failed to package up MigrateProcessDLL with DMGD!"
        $31 = "[-] Exploit failed to complete, no smart card context found!"
        $32 = "[!] Failed to determine function names RVA (bad results from leak)"
        $33 = "[!] build_exploit_common_x64(): buffer2 already allocated (?]; freeing..."
        $34 = "[!] Failed to determine the Kernel32 address (leak failed)"
        $35 = "[-] Exploit NOT successful :-("
        $36 = "[!] Failed to determine the function table RVA and the name table RVA (bad results from leak)"
        $37 = "[+] Set Auth Code to: 0x%p"
        $38 = "[-] build_exploit_common_x64(): malloc() failed!"
        $39 = "[!] Failed to determine the Kernel32 address (bad results from leak)"
        $40 = "[-] RdpLib_Uninitialize() failed - 0x%08x"
        $41 = "[+] Export table RVA (PE at 0xE0) = 0x%08X"
        $42 = "[-] PHASE_EXPORT_TABLE_DETECT: Did not get sufficient data back from leak"
        $43 = "[+] SELECT_FILE - GPK Card MF"
        $44 = "[*] Waiting for callback from second stage payload."
        $45 = "[!] build_overflow_x64(): buffer1 already allocated (?]; freeing..."
        $46 = "[-] build_egg1_callback_x86(): Failed to read MigrateProcessDLL!"
        $47 = "[-] build_exploit_leak_x64(): Need (non-zero) RVA for KERNEL32's function names!"
        $48 = "[-] build_egg1_callback_x64(): Failed to package up CallbackPayloadDLL with DMGD!"
        $49 = "[-] build_egg1_callback_x64(): Failed to package up MigrateProcessDLL with DMGD!"
        $50 = "[+] GET_RESPONSE - data unit size"
        $51 = "[+] VirtualProtect() = 0x%016I64X"
        $52 = "[*] Exploit successful! :-)"
        $53 = "[+] Successfully opened ListenPayloadDLL"
        $54 = "[-] build_egg0_x64(): egg0 is too large (by %d bytes) to fit in buffer2!"
        $55 = "[-] build_exploit_leak_x64(): Need (non-zero) RVA for KERNEL32's export table!"
        $56 = "[-] Connection timeout (exceeded computed threshold of %.2f seconds)"
        $57 = "[-] build_egg1_listen_x64(): Failed to read ListenPayloadDLL!"
        $58 = "[+] Function table RVA = 0x%08X"
        $59 = "[+] Call in successful!"
        $60 = "[-] build_egg1_listen_x86(): Failed to read MigrateProcessDLL!"
        $61 = "[!] Failed to determine the function table RVA and the name table RVA (leak failed)"
        $62 = "[-] build_egg1_callback_x64(): Failed to read CallbackPayloadDLL!"
        $63 = "[!] Failed to determine the export table RVA (bad results from leak)"
        $64 = "[-] PHASE_KERNEL32_DETECT: Did not get sufficient data back from leak"
        $65 = "[+] GET_RESPONSE - from SELECT_FILE"
        $66 = "[+] Function names RVA = 0x%08X"
        $67 = "[+] READ_BINARY - unknown offset"
        $68 = "[-] PHASE_VIRTUALPROTECT_DETECT: Did not get sufficient data back from leak"
        $69 = "[-] Server broke off connection"
        $70 = "[+] Successfully opened MigrateProcessDLL"
        $71 = "[-] build_egg1_callback_x86(): Failed to package up MigrateProcessDLL with DMGD!"
        $72 = "[-] PHASE_FUNCTION_INDEX_DETECT: Failed to find VirtualProtect in name table"
        $73 = "[-] build_exploit_run_x64(): Cannot build execution ROP chain without knowing address of VirtualProtect()!"
        $74 = "[*] Computed RDP connection timeout at %.2f seconds (%d / %d)"
        $75 = "[!] build_overflow_x86(): buffer1 already allocated (?]; freeing..."
        $76 = "[+] READ_BINARY - timestamps"
        $77 = "[+] Set XOR Mask to: 0x%p"
        $78 = "[!] RDP processing landed us in an error state (0x%08x); aborting..."
        $79 = "[+] GET_RESPONSE - serial number"
        $80 = "[+] Waiting %d more seconds before calling in."
        $81 = "[-] build_egg1_callback_x86(): Failed to package up CallbackPayloadDLL with DMGD!"
        $82 = "[+] READ_BINARY - start of file"
        $83 = "[-] build_overflow_x64(): malloc() failed!"
        $84 = "[-] build_exploit_leak_x64(): Need (non-zero) RVA for KERNEL32's function table!"
        $85 = "[!] Failed to determine function names RVA (leak failed)"
        $86 = "[-] build_all_x64(): Unknown Payload type '%s'!"
        $87 = "[+] Uploading Second Stage %d/%d (%.2f%%)"
        $88 = "[-] build_egg1_listen_x86(): Failed to read ListenPayloadDLL!"
        $89 = "[-] Error building exploit buffer."
        $90 = "[-] build_exploit_leak_x64(): Need (non-zero) address for KERNEL32!"
        $91 = "[-] build_overflow_x86(): malloc() failed!"
        $92 = "[+] Successfully opened CallbackPayloadDLL"
        $93 = "[+] Sending Enter key"
        $94 = "[-] build_egg1_callback_x86(): Failed to read CallbackPayloadDLL!"
        $95 = "[*] Calling into listener payload."
        $96 = "[+] Kernel32 base = 0x%016I64X"
        $97 = "[-] PHASE_EXPORT_TABLE_DETECT: Could not find PE header in data returned by leak"
        $98 = "[-] build_egg1_listen_x64(): Failed to read MigrateProcessDLL!"

    condition:
        5 of them
}

rule apt_fuzzbunch_erraticgopher_1_0_1 : TLPWHITE
{
    meta:
        description = "Detects Erraticgopher-1.0.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "b4cb23d33c82bb66a7edcfe85e9d5361"

    strings:
        $0 = "[-] Error creating shellcode buffer"
        $1 = "[*] Callback Received!"
        $2 = "[-] Error receiving data from callback socket"
        $3 = "[-] Unable to connect to call into target"
        $4 = "[-] Error creating request buffer"
        $5 = "[-] Error receiving callback"
        $6 = "[-] Error uploading shim to convert from LEAF shellcode to EDF handoff"
        $7 = "[*] Call In Successful!"
        $8 = "[-] Error building exploit"
        $9 = "[*] Exploit initialized"
        $10 = "[-] Out of memory"
        $11 = "[-] Error doing SMB startup"
        $12 = "[*] Launching Exploit"
        $13 = "[-] Error binding to Dimsvc"
        $14 = "[+] Authcode: 0x%p"
        $15 = "[-] Error doing post processing"
        $16 = "[*] Receiving Callback."
        $17 = "[-] Error prepping callback"
        $18 = "[-] TbSend failure"
        $19 = "[*] Auth code verified!"
        $20 = "[+] Bound to Dimsvc, sending exploit request to opnum 29"
        $21 = "[+] XorMask:  0x%x"
        $22 = "[-] Error sending exploit packet"
        $23 = "[-] Error initializing TippyBelch"
        $24 = "[-] Error prepping plugin"
        $25 = "[-] Error appending receive buffer"
        $26 = "[*] Calling into target!"
        $27 = "[-] Error launching exploit"
        $28 = "[+] Exploit Payload Sent!"
        $29 = "[-] Shellcode is too big"
        $30 = "[-] Error creating socket"

    condition:
        5 of them
}

rule apt_fuzzbunch_emeraldthread_3_0_0 : TLPWHITE
{
    meta:
        description = "Detects Emeraldthread-3.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "52933e70e022054153aa37dfd44bcafa"

    strings:
        $0 = "[*] Configuring Payload"
        $1 = "[+] Adding EXE Print Job"
        $2 = "[-] Failed to Write Trigger MOF"
        $3 = "[-] Setting XorMask failed!"
        $4 = "[-] Failed To Write EXE"
        $5 = "[+] Writing Document"
        $6 = "[+] Waiting for connection..."
        $7 = "[+] Authcode : %04x"
        $8 = "[+] Exploit run complete"
        $9 = "[-] TbMalloc failed"
        $10 = "[-] Error making WritePrinter RPC request"
        $11 = "[-] Failed to Write MOF"
        $12 = "[-] InitializeCallinSocket() failed!"
        $13 = "[*] Initializing Callin Socket"
        $14 = "[-] Setting Contract failed!"
        $15 = "[+] Starting print jobs"
        $16 = "[-] Error reading MOF file"
        $17 = "[-] Setting ConnectedTcp failed!"
        $18 = "[-] Error making StartDocPrinter RPC request"
        $19 = "[+] Adding MOF Print Job"
        $20 = "[*] Exploiting target..."
        $21 = "[+] Starting Document"
        $22 = "[+] Listener address %s:%d"
        $23 = "[-] Error making EndDocPrinter RPC request"
        $24 = "[+] XorMask  : %02x"
        $25 = "[-] Problem with EndDocPrinter request 0x%8.8x"
        $26 = "[+] Adding MOF Trigger Print Job"
        $27 = "[-] Payload initialization failed!"
        $28 = "[*] Checking Payload"
        $29 = "[+] Listening on 0.0.0.0:%d"
        $30 = "[+] Ending Document"
        $31 = "[*] Running exploit"
        $32 = "[+] Print Jobs Added"
        $33 = "[-] Error reading DLL file"
        $34 = "[-] Problem with StartDocPrinter request 0x%8.8x"
        $35 = "[-] Callin failed"
        $36 = "[-] Problem with WritePrinter request 0x%8.8x"
        $37 = "[*] Receiving Target Payload Callback"

    condition:
        5 of them
}

rule apt_fuzzbunch_englishmansdentist_1_2_0 : TLPWHITE
{
    meta:
        description = "Detects Englishmansdentist-1.2.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "305a1577298d2ca68918c3840fccc958"

    strings:
        $0 = "[-] Error checking credentials for OWA email, CheckCredentialsOWA()"
        $1 = "[+] Check Mail Protocol():OWA"
        $2 = "[+] Pause so Inbox has time to register new email: GenerateIMAP4()"
        $3 = "[+] Email Sent!"
        $4 = "[-] Error checking credentials for POP3 email, CheckCredentialsPOP3()"
        $5 = "[-] Error connecting to target, TbMakeSocket() %s:%d."
        $6 = "[-] Error checking credentials for IMAP4 email, CheckCredentialsIMAP4()"
        $7 = "[-]Could not find email using POP3 TOP command to delete it"
        $8 = "[+] Checking AuthCode"
        $9 = "[*] Cleanup Exploit Email for POP3"
        $10 = "[-] Username/password check failed so quitting, checkAuth()"
        $11 = "[+] Creating Target Socket"
        $12 = "[+] GenerateIMAP4():Match found"
        $13 = "[+] Connected to IMAP4 server at %s:%d"
        $14 = "[+] Creating Trigger Socket to %d"
        $15 = "[+] Sending authentication http request"
        $16 = "[+] Triggering Email Exploit"
        $17 = "[-] Error generating TNEF attachment, GenTNEF()"
        $18 = "[-] Error when calling TbRecv(). IMAP response exceeds packet size or need to increase timeout: GenerateIMAP4"
        $19 = "[+] GenerateOWA():NetworkTimeout For OWA:%d"
        $20 = "[+] Connected to POP3 server at %s:%d"
        $21 = "[+] POP3 Logon Failed due to invalid User Credentials,checkCredentials()"
        $22 = "[-] Error authenticating: %s"
        $23 = "[-] Error contacting Exchange host via url: %s"
        $24 = "[*] Cleanup Exploit Email for OWA"
        $25 = "[+] Check Mail Protocol():POP3"
        $26 = "[+] GenerateOWA() packets to check credentials"
        $27 = "[+] Generating exploit buffer."
        $28 = "[+] Check Mail Protocol():IMAP4"
        $29 = "[+] Credentials passed for POP3 login."
        $30 = "[+] Successfully deleted email"
        $31 = "[+] ENDE AuthCode matches Egg AuthCode"
        $32 = "[+] CheckCredentials(): Checking to see if valid username/password"
        $33 = "[*] Sending e-mail to: %s"
        $34 = "[+] E-mail built."
        $35 = "[-] Error when calling TbRecv(). Fetch data exceeds packet size or need to increase timeout: GenerateIMAP4"
        $36 = "[+] Creating Callback Socket"
        $37 = "[-] Error sending username/password: %s."
        $38 = "[*] Cleanup Exploit Email for IMAP4"
        $39 = "[+] initializeParams():RandValue:%s"
        $40 = "[-] Error generating Authenticated OWASession using HTTPS protocol"
        $41 = "[+] Credentials passed for OWA login."
        $42 = "[+]POP3EmailID is a real Number"
        $43 = "[-] Deletion of email failed using POP3"
        $44 = "[+] Credentials passed for IMAP login."
        $45 = "[+] IMAP Logon Failed due to invalid User Credentials, checkCredentials()"
        $46 = "[+] Generating email."
        $47 = "[*] Check Credentials:"
        $48 = "[+] Contacting exchange host via owa: %s"
        $49 = "[+] GenerateOWA():OWAMode:%s"
        $50 = "[+] Check Mode(): Send email directly to Target Server"
        $51 = "[-] Error obtaining data from exchange server."
        $52 = "[-] Error generating Authenticated OWASession using HTTP protocol"

    condition:
        5 of them
}

rule apt_fuzzbunch_eternalsynergy_1_0_1 : TLPWHITE
{
    meta:
        description = "Detects Eternalsynergy-1.0.1.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "2a8d437f0b9ffac482750fe052223c3d"

    strings:
        $0 = "[+] AttemptIndex: %d"
        $1 = "[+] Plugin completed successfully"
        $2 = "[+] Leak successful"
        $3 = "[-] Delete this bit of code!"
        $4 = "[+] Using cred choice %i"
        $5 = "[+] Cleared RWX region"
        $6 = "[*] Triggering stub allocator"
        $7 = "[*] Copying code to target"
        $8 = "[-] Connections closed, exploit method %d unsuccessful"
        $9 = "[*] Beginning quest for executable memory..."
        $10 = "[*] Trying sizes 0x%X / 0x%X"
        $11 = "[+] ProcessListEntry.Blink: %I64X"
        $12 = "[+] KProcess: %I64X"
        $13 = "[*] Triggering DOUBLEPULSAR installer"
        $14 = "[+] ManyCoreTarget : %s"
        $15 = "[+] Searching backwards"
        $16 = "[+] Rpc bind found target is x%s"
        $17 = "[+] IrpThread: %I64X"
        $18 = "[-] Error in %s (%s line %d): Out of range write not possible. WriteOffset %X > %X (Offset to Trans: %X)"
        $19 = "[+] Base of Nt: %I64X"
        $20 = "[+] Found RWX memory!!! %I64X"
        $21 = "[-] Error in %s (%s line %d): Invalid retry count (%d), must be less than (%d)"
        $22 = "[*] Attempting info leak..."
        $23 = "[-] Error in %s (%s line %d): %s"
        $24 = "[+] PreferredWorkQueue: %I64X"

    condition:
        5 of them
}

rule apt_fuzzbunch_educatedscholar_1_0_0 : TLPWHITE
{
    meta:
        description = "Detects Educatedscholar-1.0.0.exe (and associated DLLs) of Fuzzbunch exploit kit"
        reference = "https://github.com/mdiazcl/fuzzbunch-debian"
        author = "Mike Schladt @mikeschladt"
        date = "2017-05"
        filetype = "pe"
        md5 = "0bc136522423099f72dbf8f67f99e7d8"

    strings:
        $0 = "[-] Exploit Failed"
        $1 = "[*] Pre-throw Initialization"
        $2 = "[-] InitCallbackSocket failed"
        $3 = "[*] Waiting for Callback"
        $4 = "[-] Kernel payload build failed"
        $5 = "[+] Initializing callback sockets"
        $6 = "[-] Xorw2 Encoder Failed"
        $7 = "[-] TbMakeServerSocket() failed"
        $8 = "[+] Exploiting Target"
        $9 = "[-] Could not send increment packet to target"
        $10 = "[+] Building userspace component"
        $11 = "[+] Writing 0x%08x : %02x"
        $12 = "[+] Exploit packet sent"
        $13 = "[+] Sending %d (%02x) Packets:"
        $14 = "[+] Encoding payload"
        $15 = "[-] Userspace payload build failed"
        $16 = "[-] WriteTargetMemory failed"
        $17 = "[+] Initializing outbound sockets"
        $18 = "[*] Throwing Exploit"
        $19 = "[-] BuildExploitPayload failed"
        $20 = "[*] Exploit Completed Successfully"
        $21 = "[+] Building full exploit packet"
        $22 = "[+] Building exploit payload"
        $23 = "[+] Exploit payload built"
        $24 = "[+] Building kernel component"
        $25 = "[-] Could not send exploit packet to target"
        $26 = "[+] Shellcode Callback %s:%d"
        $27 = "[-] Exploit payload build failed"
        $28 = "[-] PrepareWriteSMBHeader failed"
        $29 = "[+] Payload size: %d (0x%x) bytes"
        $30 = "[-] InitExploitSocket failed"
        $31 = "[*] Writing Target Memory"

    condition:
        5 of them
}

