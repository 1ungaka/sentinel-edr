// ============================================================
// CAU EDR — bundled YARA rules
//
// Conventions:
//   * Text strings carry `ascii wide` so they match both the narrow strings in
//     scripts and the UTF-16LE strings in Windows binaries. The original rules
//     were ASCII-only and never fired on mimikatz.exe, whose command strings
//     are wide.
//   * Byte patterns are written as hex strings, not as the text "0x89,0x00".
//   * meta.threat_level 1-5, meta.family names the family the rule claims.
//   * meta.mitre_attack is the ATT&CK technique id (comma-separated when a
//     rule is evidence for several); the fusion lattice, `cau coverage` and
//     the OCSF output read it, and `cau rules lint` requires it.

rule wannacry_ransomware
{
    meta:
        author = "CAU"
        description = "WannaCry / WanaCrypt0r dropper and payload strings"
        family = "wannacry"
        mitre_attack = "T1486"
        threat_level = 5
        in_the_wild = true

    strings:
        $b = "C:\\%s\\qeriuwjhrf" ascii wide nocase
        $c = "WNcry@2017" ascii wide nocase
        $d = "msg/m_bulgarian.wnry" ascii wide nocase
        $e = "WanaCryptor" ascii wide nocase
        $f = "tasksche.exe" ascii wide nocase
        $g = "WanaCrypt0r" ascii wide nocase

    condition:
        3 of them
}

rule mimikatz_strings
{
    meta:
        author = "CAU"
        description = "Mimikatz module and command strings (binary or script carrier)"
        family = "mimikatz"
        mitre_attack = "T1003"
        threat_level = 5
        in_the_wild = true

    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "mimikatz" ascii wide nocase
        $m3 = "lsadump::sam" ascii wide nocase
        $m4 = "kerberos::tickets" ascii wide nocase
        $m5 = "privilege::debug" ascii wide nocase
        $m6 = "gentilkiwi" ascii wide nocase

    condition:
        2 of them
}

rule generic_ransomware_extensions
{
    meta:
        author = "CAU"
        description = "Ransomware: encrypted-file extensions together with ransom-note file names"
        family = "ransomware"
        mitre_attack = "T1486"
        threat_level = 3

    strings:
        // Extensions alone are useless: Go binaries alone carry ".crypt",
        // ".locked" and ".encrypted" as ordinary identifiers (measured: 18 false
        // positives in /usr/bin). They only count next to a ransom-note name.
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypt" ascii wide nocase
        $note1 = "restore_files" ascii wide nocase
        $note2 = "how_to_decrypt" ascii wide nocase
        $note3 = "decrypt_instructions" ascii wide nocase
        $note4 = "decrypt_my_files" ascii wide nocase
        $note5 = "files have been encrypted" ascii wide nocase
        $note6 = "recover_your_files" ascii wide nocase

    condition:
        2 of ($ext*) and 1 of ($note*)
}

rule highly_sus_shellcode
{
    meta:
        author = "CAU"
        description = "x86/x64 shellcode: PEB module walk with a rotate-and-add export hash"
        family = "shellcode"
        mitre_attack = "T1027.007"
        threat_level = 3
        in_the_wild = true

    strings:
        // fs:[30h] -> Ldr -> module list, x86, in the three forms it takes.
        $walk32a = { 64 8B ?? 30 8B ?? 0C 8B ?? ?? }
        $walk32b = { 64 8B ?? 30 00 00 00 8B ?? 0C 8B ?? ?? }
        $walk32c = { 64 A1 30 00 00 00 8B ?? 0C 8B ?? ?? }
        // gs:[60h] -> Ldr -> module list, x64.
        $walk64a = { 65 48 8B ?? 60 48 8B ?? 18 48 8B ?? ?? }
        $walk64b = { 65 48 8B ?? 25 60 00 00 00 48 8B ?? 18 48 8B ?? ?? }
        // ror edi/r9d, 13 then add: the conventional export hash. The Go pass
        // (scanner/tradecraft) accepts any rotate; this rule stays narrow because
        // a YARA hit is MALICIOUS. The first version of this rule took any three
        // of a loose set of short atoms, fired on msdia140.dll and missed every
        // Metasploit stub in the lab corpus (0/11 raw payloads).
        $hash32 = { C1 CF 0D (01 | 03) }
        $hash64 = { 41 C1 C9 0D 41 (01 | 03) }

    condition:
        1 of ($walk*) and 1 of ($hash*)
}

rule lokibot_stealer
{
    meta:
        author = "CAU"
        description = "LokiBot credential-store file names"
        family = "lokibot"
        mitre_attack = "T1555"
        threat_level = 4

    strings:
        $l1 = "pass.txt" ascii wide nocase
        $l2 = "wallet.dat" ascii wide nocase
        $l3 = "cookies.sqlite" ascii wide nocase
        $l4 = "logins.json" ascii wide nocase
        $l5 = "FileZilla" ascii wide nocase

    condition:
        3 of them
}

rule obfuscated_powershell
{
    meta:
        author = "CAU"
        description = "PowerShell obfuscation and download-cradle markers"
        family = "powershell_cradle"
        mitre_attack = "T1059.001"
        threat_level = 3
        in_the_wild = true

    strings:
        // The previous version listed four base64 fragments of one specific
        // payload and was effectively a hash with extra steps.
        $ps = "powershell" ascii wide nocase
        // an -enc / -EncodedCommand switch followed by an actual base64 payload
        $enc_payload = /-e(nc|ncodedcommand)?[ \t]+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "FromBase64String(" ascii wide nocase
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        // Execute and download on one line, or a hidden window launching one.
        // These words anywhere in a file describe half of all admin scripts: a
        // whole-file version flagged 15 of 5,701 public ones as MALICIOUS.
        $cradle = /(iex|invoke-expression)[^\r\n]{0,200}(downloadstring|downloaddata)|(downloadstring|downloaddata)[^\r\n]{0,200}\|[ \t]*(iex|invoke-expression)/ ascii wide nocase
        $hidden_fetch = /-w(indowstyle)?[ \t]+hidden[^\r\n]{0,200}download(string|file|data)/ ascii wide nocase
        // Exact bootstrap URLs: download-and-execute by design, on hosts an
        // attacker cannot publish that path at.
        $trusted = /https:\/\/(community\.)?chocolatey\.org\/install\.ps1|https:\/\/get\.scoop\.sh/ ascii wide nocase
        $hid1 = "-WindowStyle Hidden" ascii wide nocase
        $hid2 = "-w hidden" ascii wide nocase
        $nop  = "-NoProfile" ascii wide nocase
        $byp  = "-ExecutionPolicy Bypass" ascii wide nocase

    condition:
        $ps and
        (
            $enc_payload or
            (($cradle or $hidden_fetch) and not $trusted) or
            (1 of ($enc*) and 1 of ($iex*) and (1 of ($hid*) or $nop or $byp))
        )
}

rule windows_netcat_shell_relay
{
    meta:
        author = "CAU"
        description = "Windows netcat lineage with the -e shell relay compiled in (nc.exe, sbd, dbd)"
        family = "netcat_backdoor"
        mitre_attack = "T1059.003"
        threat_level = 3

    strings:
        $r1 = "SessionReadShellThreadFn" ascii wide
        $r2 = "SessionWriteShellThreadFn" ascii wide
        $s1 = "failed to create shell stdout pipe" ascii wide
        $s2 = "failed to create shell stdin pipe" ascii wide
        $s3 = "failed to execute shell" ascii wide

    condition:
        uint16(0) == 0x5A4D and (1 of ($r*) or 2 of ($s*))
}

rule linpeas_script_in_binary
{
    meta:
        author = "CAU"
        description = "PEASS privilege-escalation script wrapped into an ELF by sh2bin"
        family = "linpeas"
        mitre_attack = "T1082"
        threat_level = 3

    strings:
        $w = "carlospolop/sh2bin" ascii wide

    condition:
        $w
}
