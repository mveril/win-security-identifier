# Emits canonical-cased DOMAIN\Name and SID as compact JSON (UTF-8)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$acct = $wi.Name  # or: $wi.User.Translate([System.Security.Principal.NTAccount]).Value
[pscustomobject]@{ sid = $wi.User.Value; account = $acct } | ConvertTo-Json -Compress
