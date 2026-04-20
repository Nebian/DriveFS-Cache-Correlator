# Run locally on your own machine to generate a clipboard-ready command
$scriptPath = ".\drive_detections.ps1"
$scriptText = Get-Content $scriptPath -Raw

$bytes = [Text.Encoding]::UTF8.GetBytes($scriptText)
$ms = New-Object IO.MemoryStream
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
$gz.Write($bytes, 0, $bytes.Length)
$gz.Close()

$b64 = [Convert]::ToBase64String($ms.ToArray())

$cmd = @"
`$b64 = '$b64'
`$tmp = Join-Path `$env:TEMP 'drive_detections.ps1'
`$raw = [Convert]::FromBase64String(`$b64)
`$in  = New-Object IO.MemoryStream(,`$raw)
`$gz  = New-Object IO.Compression.GZipStream(`$in, [IO.Compression.CompressionMode]::Decompress)
`$sr  = New-Object IO.StreamReader(`$gz, [Text.Encoding]::UTF8)
[IO.File]::WriteAllText(`$tmp, `$sr.ReadToEnd(), [Text.Encoding]::UTF8)
& powershell -NoProfile -ExecutionPolicy Bypass -File `$tmp
"@

Set-Clipboard $cmd