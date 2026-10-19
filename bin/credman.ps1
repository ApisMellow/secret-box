# credman.ps1: Windows Credential Manager for secret-box, the counterpart of
# /usr/bin/security on macOS. Items are generic credentials: the service is
# the credential's target name, the account its user name, and the mod tags
# the items it saves with the comment `secret-box`.
#
#   credman.ps1 get    -Service S [-Account A]   the value, as it is, for "$(...)" in a command
#   credman.ps1 exists -Service S [-Account A]   exit 0 when the item is there, 44 when not
#   credman.ps1 add    -Service S [-Account A]   prompts for the value, masked (run it in your own terminal)
#   credman.ps1 delete -Service S [-Account A]   removes the item
#   credman.ps1 list                             names only: target, user and comment of every generic credential, hex
#   credman.ps1 read   -Stdin                    the mod's read: names and value as hex, never the text
#   credman.ps1 set    -Stdin                    the mod's save: service, account and value as hex lines on stdin
#
# -Stdin reads the service, the account and (for set) the value from stdin as
# hex lines, so none of them sits in the command line, where any process of
# this user can read it. Nothing here prints a value but `get`, and it prints
# only to stdout.
#
# Exit codes: 0 done; 44 no such item (the code `security` uses); 2 usage;
# 3 the value can't be printed as it is (not printable ASCII); 4 too large for
# Credential Manager; 5 the service is held under another account; 6 no
# terminal to prompt in; 1 anything else.
#
# Run with: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File credman.ps1 ...
# (bin/credman does this for Git Bash.)

param(
  [Parameter(Position = 0)] [string]$Command = '',
  [Alias('s')] [string]$Service = '',
  [Alias('a')] [string]$Account = '',
  [string]$Comment = 'secret-box',
  [switch]$Stdin,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Fail([int]$code, [string]$why) {
  [Console]::Error.WriteLine("credman: $why")
  exit $code
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class SecretBoxCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL {
    public int Flags;
    public int Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
  }

  [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredRead(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWrite(ref CREDENTIAL cred, int flags);
  [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDelete(string target, int type, int flags);
  [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr creds);
  [DllImport("advapi32.dll")]
  static extern void CredFree(IntPtr buffer);

  const int GENERIC = 1;
  const int LOCAL_MACHINE = 2;
  public const int NOT_FOUND = 1168;
  public const int MAX_BLOB = 2560;

  // 0 and the item's user name and value bytes, or the Win32 error
  public static int Read(string target, out string user, out byte[] blob) {
    user = null;
    blob = null;
    IntPtr p;
    if (!CredRead(target, GENERIC, 0, out p)) return Marshal.GetLastWin32Error();
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      user = c.UserName ?? "";
      blob = new byte[c.CredentialBlobSize];
      if (c.CredentialBlobSize > 0) Marshal.Copy(c.CredentialBlob, blob, 0, c.CredentialBlobSize);
      return 0;
    } finally {
      CredFree(p);
    }
  }

  public static int Write(string target, string user, string comment, byte[] blob) {
    CREDENTIAL c = new CREDENTIAL();
    c.Type = GENERIC;
    c.TargetName = target;
    c.UserName = user;
    c.Comment = comment;
    c.Persist = LOCAL_MACHINE;
    c.CredentialBlobSize = blob.Length;
    c.CredentialBlob = Marshal.AllocHGlobal(Math.Max(blob.Length, 1));
    try {
      Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
      return CredWrite(ref c, 0) ? 0 : Marshal.GetLastWin32Error();
    } finally {
      // The value's bytes are cleared before the memory goes back
      Marshal.Copy(new byte[blob.Length], 0, c.CredentialBlob, blob.Length);
      Marshal.FreeHGlobal(c.CredentialBlob);
    }
  }

  public static int Delete(string target) {
    return CredDelete(target, GENERIC, 0) ? 0 : Marshal.GetLastWin32Error();
  }

  // Every generic credential's names: target, user and comment. Never a value.
  public static List<string[]> List() {
    List<string[]> items = new List<string[]>();
    int count;
    IntPtr p;
    if (!CredEnumerate(null, 0, out count, out p)) {
      int err = Marshal.GetLastWin32Error();
      if (err == NOT_FOUND) return items;
      throw new System.ComponentModel.Win32Exception(err);
    }
    try {
      for (int i = 0; i < count; i++) {
        IntPtr one = Marshal.ReadIntPtr(p, i * IntPtr.Size);
        CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(one, typeof(CREDENTIAL));
        if (c.Type == GENERIC) items.Add(new string[] { c.TargetName ?? "", c.UserName ?? "", c.Comment ?? "" });
      }
    } finally {
      CredFree(p);
    }
    return items;
  }
}
'@

$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$utf16 = New-Object System.Text.UnicodeEncoding($false, $false, $true)

function ToHex([byte[]]$bytes) {
  if (-not $bytes) { return '' }
  return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}
function FromHex([string]$hex) {
  if ($hex -notmatch '^(?:[0-9A-Fa-f]{2})*$') { Fail 2 'stdin is not hex' }
  $bytes = New-Object byte[] ($hex.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
  return , $bytes
}

# A value's bytes as text. The mod and cmdkey write UTF-16LE; Git Credential
# Manager and some other tools write UTF-8. UTF-16LE text that holds any
# ASCII has a zero byte at an odd offset, which UTF-8 text never does. $null
# when the bytes are neither.
function Decode([byte[]]$b) {
  if ($b.Length -eq 0) { return '' }
  $isWide = $false
  if ($b.Length % 2 -eq 0) {
    for ($i = 1; $i -lt $b.Length; $i += 2) { if ($b[$i] -eq 0) { $isWide = $true; break } }
  }
  $text = $null
  if ($isWide) { try { $text = $utf16.GetString($b) } catch {} }
  if ($null -eq $text) { try { $t = $utf8.GetString($b); if (-not $t.Contains([char]0)) { $text = $t } } catch {} }
  if ($null -eq $text -and $b.Length % 2 -eq 0) { try { $text = $utf16.GetString($b) } catch {} }
  # Some writers count the terminating NUL into the value
  if ($null -ne $text) { $text = $text.TrimEnd([char]0) }
  return $text
}

# UTF-16LE as cmdkey writes it; a value too long for that in UTF-8, which
# holds an ASCII value in half the bytes
function Encode([string]$text) {
  $wide = $utf16.GetBytes($text)
  if ($wide.Length -le [SecretBoxCred]::MAX_BLOB) { return , $wide }
  $narrow = $utf8.GetBytes($text)
  if ($narrow.Length -le [SecretBoxCred]::MAX_BLOB) { return , $narrow }
  Fail 4 "the value is $($narrow.Length) bytes; Credential Manager holds at most $([SecretBoxCred]::MAX_BLOB)"
}

function WriteOut([string]$text) {
  $bytes = $utf8.GetBytes($text)
  $out = [Console]::OpenStandardOutput()
  $out.Write($bytes, 0, $bytes.Length)
  $out.Flush()
}

$value = $null
if ($Stdin) {
  $lines = [Console]::In.ReadToEnd() -split "`r?`n"
  $Service = $utf8.GetString((FromHex $lines[0]))
  $Account = if ($lines.Length -gt 1) { $utf8.GetString((FromHex $lines[1])) } else { '' }
  if ($Command -eq 'set') {
    if ($lines.Length -lt 3) { Fail 2 'set needs the value on the third line of stdin' }
    $value = $utf8.GetString((FromHex $lines[2]))
  }
}

# The item named, when its account matches the one asked for (any, when none is)
function Find {
  $user = $null
  $blob = $null
  $err = [SecretBoxCred]::Read($Service, [ref]$user, [ref]$blob)
  if ($err -eq [SecretBoxCred]::NOT_FOUND) { return @{ code = 44 } }
  if ($err -ne 0) { return @{ code = 1; why = "Credential Manager error $err" } }
  if ($Account -and $user -cne $Account) { return @{ code = 44; user = $user } }
  return @{ code = 0; user = $user; blob = $blob }
}

function NeedService {
  if (-not $Service) { Fail 2 "$Command needs -Service" }
  if ($Service -match '[\x00-\x1f\x7f]' -or $Account -match '[\x00-\x1f\x7f]') { Fail 2 'a name holds a control character' }
}

try {
  switch ($Command) {
    'get' {
      NeedService
      $item = Find
      if ($item.code -eq 44) { Fail 44 "no credential with the service '$Service'$(if ($Account) { " and account '$Account'" })" }
      if ($item.code -ne 0) { Fail 1 $item.why }
      $text = Decode $item.blob
      if ($null -eq $text) { Fail 3 "the value of '$Service' is not text" }
      if ($text -notmatch '^[\x20-\x7e]*$') { Fail 3 "the value of '$Service' holds a newline, a tab or a non-ASCII character, so it is not printed; store it base64-encoded instead" }
      WriteOut $text
    }
    'read' {
      NeedService
      $item = Find
      if ($item.code -ne 0) { if ($item.why) { [Console]::Error.WriteLine("credman: $($item.why)") }; exit $item.code }
      $text = Decode $item.blob
      $kind = if ($null -eq $text) { 'bytes' } else { 'text' }
      $hex = if ($null -eq $text) { ToHex $item.blob } else { ToHex $utf8.GetBytes($text) }
      WriteOut "ok $(ToHex $utf8.GetBytes($item.user)) $kind $hex`n"
    }
    'exists' {
      NeedService
      $item = Find
      if ($item.code -eq 1) { Fail 1 $item.why }
      exit $item.code
    }
    'set' {
      NeedService
      if ($null -eq $value) { Fail 2 'set takes its value on stdin: use -Stdin' }
      if (-not $Account) { Fail 2 'set needs an account' }
      $item = Find
      if ($item.code -eq 1) { Fail 1 $item.why }
      if ($item.user -and $item.user -cne $Account -and -not $Force) { Fail 5 "the service '$Service' is held under the account '$($item.user)'; Credential Manager keeps one account per service" }
      $err = [SecretBoxCred]::Write($Service, $Account, $Comment, (Encode $value))
      if ($err -ne 0) { Fail 1 "Credential Manager error $err" }
    }
    'add' {
      NeedService
      if (-not $Account) { $Account = $env:USERNAME }
      if ([Console]::IsInputRedirected) { Fail 6 'add prompts for the value, so run it in your own terminal window, not through Claude or with !' }
      $item = Find
      if ($item.code -eq 1) { Fail 1 $item.why }
      if ($item.user -and $item.user -cne $Account -and -not $Force) { Fail 5 "the service '$Service' is held under the account '$($item.user)'; add -Force to replace it" }
      $secure = Read-Host -AsSecureString "Value for $Service (account $Account; typing is hidden)"
      $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
      try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
      if (-not $plain) { Fail 2 'no value given; nothing was saved' }
      $err = [SecretBoxCred]::Write($Service, $Account, $Comment, (Encode $plain))
      $plain = $null
      if ($err -ne 0) { Fail 1 "Credential Manager error $err" }
      [Console]::Error.WriteLine("credman: saved '$Service' (account $Account)")
    }
    'delete' {
      NeedService
      $item = Find
      if ($item.code -ne 0) { if ($item.why) { Fail 1 $item.why }; Fail 44 "no credential with the service '$Service'" }
      $err = [SecretBoxCred]::Delete($Service)
      if ($err -ne 0) { Fail 1 "Credential Manager error $err" }
    }
    'list' {
      $sb = New-Object System.Text.StringBuilder
      foreach ($i in [SecretBoxCred]::List()) {
        [void]$sb.Append("$(ToHex $utf8.GetBytes($i[0])) $(ToHex $utf8.GetBytes($i[1])) $(ToHex $utf8.GetBytes($i[2]))`n")
      }
      WriteOut $sb.ToString()
    }
    default { Fail 2 'usage: credman.ps1 get|exists|add|delete -Service NAME [-Account NAME], list, or read|set -Stdin' }
  }
} catch {
  # The exception's own text, never a value: no value is part of any message here
  Fail 1 ($_.Exception.Message -replace '[\r\n]+', ' ')
}
exit 0
