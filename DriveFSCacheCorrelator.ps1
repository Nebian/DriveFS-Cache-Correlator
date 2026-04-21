param(
    [string]$Path,
    [UInt64]$Filename
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Output ""
    $scriptName = Split-Path -Leaf $PSCommandPath
    Write-Output ("Usage: .\{0} -Path <sqlite_db_path> -Filename <cache_id>" -f $scriptName)
    Write-Output ""
}

function Write-VerticalResults {
    param([object[]]$InputObject)

    if (-not $InputObject) {
        return
    }

    $index = 0
    foreach ($row in $InputObject) {
        $index++
        Write-Output ("[{0}]" -f $index)
        foreach ($prop in $row.PSObject.Properties) {
            Write-Output ("{0}: {1}" -f $prop.Name, $prop.Value)
        }
        Write-Output ""
    }
}

function Read-At {
    param(
        [System.IO.FileStream]$Stream,
        [long]$Offset,
        [int]$Count
    )

    $buffer = New-Object byte[] $Count
    [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)

    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($buffer, $read, $Count - $read)
        if ($n -le 0) {
            throw "Unexpected EOF at offset $Offset"
        }
        $read += $n
    }
    
    return , $buffer
}

function Get-Slice {
    param(
        [byte[]]$Data,
        [int]$Offset,
        [int]$Length
    )

    $slice = New-Object byte[] $Length
    [System.Buffer]::BlockCopy($Data, $Offset, $slice, 0, $Length)
    return , $slice
}

function ConvertTo-ByteArray {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [byte[]]) {
        return , $Value
    }

    if ($Value -is [System.Array]) {
        try {
            return , ([byte[]]$Value)
        }
        catch {
            return $null
        }
    }

    return $null
}

function Read-BEUInt16 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )
    return (([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1])
}

function Read-BEUInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )
    return (
        (([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        ([uint32]$Bytes[$Offset + 3]))
    )
}

function Read-LEUInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )
    return (
        ([uint32]$Bytes[$Offset] -bor
        ([uint32]$Bytes[$Offset + 1] -shl 8) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 3] -shl 24))
    )
}

function Read-WalChecksumUInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [bool]$ChecksumBigEndian
    )

    if ($ChecksumBigEndian) {
        return [uint32](Read-BEUInt32 -Bytes $Bytes -Offset $Offset)
    }

    return [uint32](Read-LEUInt32 -Bytes $Bytes -Offset $Offset)
}

function Add-UInt32Wrap {
    param(
        [UInt64[]]$Values
    )

    [UInt64]$sum = 0
    foreach ($value in $Values) {
        $sum += [UInt64]$value
    }

    return [uint32]($sum % 0x100000000)
}

function Update-WalChecksum {
    param(
        [byte[]]$Bytes,
        [uint32]$S0 = 0,
        [uint32]$S1 = 0,
        [bool]$ChecksumBigEndian
    )

    if (($Bytes.Length % 8) -ne 0) {
        throw "WAL checksum input length must be a multiple of 8 bytes"
    }

    $sum0 = [uint32]$S0
    $sum1 = [uint32]$S1

    for ($i = 0; $i -lt $Bytes.Length; $i += 8) {
        $x0 = [uint32](Read-WalChecksumUInt32 -Bytes $Bytes -Offset $i -ChecksumBigEndian:$ChecksumBigEndian)
        $x1 = [uint32](Read-WalChecksumUInt32 -Bytes $Bytes -Offset ($i + 4) -ChecksumBigEndian:$ChecksumBigEndian)

        $sum0 = Add-UInt32Wrap -Values @([UInt64]$sum0, [UInt64]$x0, [UInt64]$sum1)
        $sum1 = Add-UInt32Wrap -Values @([UInt64]$sum1, [UInt64]$x1, [UInt64]$sum0)
    }

    return [pscustomobject]@{
        S0 = $sum0
        S1 = $sum1
    }
}

function Initialize-WalOverlay {
    param([string]$DatabasePath)

    $walPath = "$DatabasePath-wal"
    if (-not (Test-Path -LiteralPath $walPath -PathType Leaf)) {
        return
    }

    $walFs = [System.IO.File]::Open(
        $walPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )

    try {
        if ($walFs.Length -lt 32) {
            return
        }

        $walHeader = Read-At -Stream $walFs -Offset 0 -Count 32
        $magic = [uint32](Read-BEUInt32 -Bytes $walHeader -Offset 0)

        if ($magic -ne 0x377F0682 -and $magic -ne 0x377F0683) {
            return
        }

        $checksumBigEndian = ($magic -eq 0x377F0683)
        $walPageSize = [int](Read-BEUInt32 -Bytes $walHeader -Offset 8)
        if ($walPageSize -le 0) {
            return
        }

        if ($walPageSize -ne $script:PageSize) {
            return
        }

        $salt1 = [uint32](Read-BEUInt32 -Bytes $walHeader -Offset 16)
        $salt2 = [uint32](Read-BEUInt32 -Bytes $walHeader -Offset 20)
        $headerChecksum1 = [uint32](Read-BEUInt32 -Bytes $walHeader -Offset 24)
        $headerChecksum2 = [uint32](Read-BEUInt32 -Bytes $walHeader -Offset 28)

        $checksumState = Update-WalChecksum -Bytes (Get-Slice -Data $walHeader -Offset 0 -Length 24) -ChecksumBigEndian:$checksumBigEndian
        if ($checksumState.S0 -ne $headerChecksum1 -or $checksumState.S1 -ne $headerChecksum2) {
            return
        }

        $frameSize = 24 + $walPageSize
        if ($frameSize -le 24) {
            return
        }

        $frames = New-Object System.Collections.Generic.List[object]
        $lastCommitFrameIndex = 0
        $frameIndex = 0
        $frameOffset = 32

        while (($frameOffset + $frameSize) -le $walFs.Length) {
            $frameIndex++

            $frameHeader = Read-At -Stream $walFs -Offset $frameOffset -Count 24
            $pageData = Read-At -Stream $walFs -Offset ($frameOffset + 24) -Count $walPageSize

            $pageNumber = [int](Read-BEUInt32 -Bytes $frameHeader -Offset 0)
            $databaseSizeAfterCommit = [uint32](Read-BEUInt32 -Bytes $frameHeader -Offset 4)
            $frameSalt1 = [uint32](Read-BEUInt32 -Bytes $frameHeader -Offset 8)
            $frameSalt2 = [uint32](Read-BEUInt32 -Bytes $frameHeader -Offset 12)
            $frameChecksum1 = [uint32](Read-BEUInt32 -Bytes $frameHeader -Offset 16)
            $frameChecksum2 = [uint32](Read-BEUInt32 -Bytes $frameHeader -Offset 20)

            if ($frameSalt1 -ne $salt1 -or $frameSalt2 -ne $salt2) {
                break
            }

            $checksumState = Update-WalChecksum -Bytes (Get-Slice -Data $frameHeader -Offset 0 -Length 8) -S0 $checksumState.S0 -S1 $checksumState.S1 -ChecksumBigEndian:$checksumBigEndian
            $checksumState = Update-WalChecksum -Bytes $pageData -S0 $checksumState.S0 -S1 $checksumState.S1 -ChecksumBigEndian:$checksumBigEndian

            if ($checksumState.S0 -ne $frameChecksum1 -or $checksumState.S1 -ne $frameChecksum2) {
                break
            }

            $frames.Add([pscustomobject]@{
                FrameIndex = $frameIndex
                PageNumber = $pageNumber
                PageData   = [byte[]]$pageData
                DbSize     = $databaseSizeAfterCommit
            })

            if ($databaseSizeAfterCommit -ne 0) {
                $lastCommitFrameIndex = $frameIndex
            }

            $frameOffset += $frameSize
        }

        if ($lastCommitFrameIndex -le 0) {
            return
        }

        foreach ($frame in $frames) {
            if ($frame.FrameIndex -gt $lastCommitFrameIndex) {
                break
            }

            $script:WalPageCache[[int]$frame.PageNumber] = [byte[]]$frame.PageData
        }
    }
    finally {
        $walFs.Dispose()
    }
}

function Read-SignedBE {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [int]$Length
    )

    if ($Length -le 0) { return 0 }

    $tmp = Get-Slice -Data $Bytes -Offset $Offset -Length $Length

    switch ($Length) {
        1 { return [sbyte]$tmp[0] }
        2 {
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($tmp) }
            return [BitConverter]::ToInt16($tmp, 0)
        }
        3 {
            $sign = if (($tmp[0] -band 0x80) -ne 0) { 0xFF } else { 0x00 }
            $full = [byte[]]@($sign) + $tmp
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($full) }
            return [BitConverter]::ToInt32($full, 0)
        }
        4 {
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($tmp) }
            return [BitConverter]::ToInt32($tmp, 0)
        }
        6 {
            $sign = if (($tmp[0] -band 0x80) -ne 0) { 0xFF } else { 0x00 }
            $full = [byte[]]@($sign, $sign) + $tmp
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($full) }
            return [BitConverter]::ToInt64($full, 0)
        }
        8 {
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($tmp) }
            return [BitConverter]::ToInt64($tmp, 0)
        }
        default {
            throw "Unsupported integer length: $Length"
        }
    }
}

function Read-Varint {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )

    [UInt64]$value = 0

    for ($i = 0; $i -lt 8; $i++) {
        [UInt64]$b = [UInt64]$Bytes[$Offset.Value]
        $Offset.Value++

        if ($b -lt 0x80) {
            $value = ($value -shl 7) -bor $b
            return $value
        }

        $value = ($value -shl 7) -bor ($b -band 0x7F)
    }

    [UInt64]$b9 = [UInt64]$Bytes[$Offset.Value]
    $Offset.Value++
    $value = ($value -shl 8) -bor $b9
    return $value
}

function Get-Page {
    param([int]$PageNumber)

    if ($script:WalPageCache.ContainsKey($PageNumber)) {
        return , $script:WalPageCache[$PageNumber]
    }

    if ($script:PageCache.ContainsKey($PageNumber)) {
        return , $script:PageCache[$PageNumber]
    }

    $offset = [long](($PageNumber - 1) * $script:PageSize)
    $page = Read-At -Stream $script:Fs -Offset $offset -Count $script:PageSize
    $script:PageCache[$PageNumber] = $page
    return , $page
}

function Get-TableLeafCellPayload {
    param(
        [int]$PageNumber,
        [byte[]]$PageBytes,
        [int]$CellOffset
    )

    $off = [ref]$CellOffset
    [UInt64]$payloadLength = Read-Varint -Bytes $PageBytes -Offset $off
    [UInt64]$rowid = Read-Varint -Bytes $PageBytes -Offset $off

    $U = $script:UsableSize
    $X = $U - 35
    $M = [math]::Floor((($U - 12) * 32) / 255) - 23

    if ($payloadLength -le $X) {
        $local = [int]$payloadLength
    }
    else {
        $K = $M + (($payloadLength - $M) % ($U - 4))
        if ($K -le $X) {
            $local = [int]$K
        }
        else {
            $local = [int]$M
        }
    }

    $payload = New-Object System.Collections.Generic.List[byte]
    if ($local -gt 0) {
        $payload.AddRange((Get-Slice -Data $PageBytes -Offset $off.Value -Length $local))
    }

    if ($payloadLength -gt $local) {
        $overflowPage = [int](Read-BEUInt32 -Bytes $PageBytes -Offset ($off.Value + $local))
        [int64]$remaining = [int64]$payloadLength - $local

        while ($overflowPage -ne 0 -and $remaining -gt 0) {
            $ov = Get-Page -PageNumber $overflowPage
            $nextOverflow = [int](Read-BEUInt32 -Bytes $ov -Offset 0)
            $chunkLen = [int][Math]::Min($remaining, $U - 4)

            if ($chunkLen -gt 0) {
                $payload.AddRange((Get-Slice -Data $ov -Offset 4 -Length $chunkLen))
            }

            $remaining -= $chunkLen
            $overflowPage = $nextOverflow
        }
    }

    return [pscustomobject]@{
        RowId   = [UInt64]$rowid
        Payload = [byte[]]$payload.ToArray()
    }
}

function ConvertFrom-SqliteRecord {
    param([byte[]]$Payload)

    $off = [ref]0
    [UInt64]$headerSize = Read-Varint -Bytes $Payload -Offset $off

    $serials = New-Object System.Collections.Generic.List[UInt64]
    while ($off.Value -lt $headerSize) {
        $serials.Add((Read-Varint -Bytes $Payload -Offset $off))
    }

    $bodyOffset = [int]$headerSize
    $values = New-Object System.Collections.Generic.List[object]

    foreach ($serial in $serials) {
        switch ($serial) {
            0 { $values.Add($null) }
            1 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 1))
                $bodyOffset += 1
            }
            2 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 2))
                $bodyOffset += 2
            }
            3 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 3))
                $bodyOffset += 3
            }
            4 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 4))
                $bodyOffset += 4
            }
            5 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 6))
                $bodyOffset += 6
            }
            6 {
                $values.Add((Read-SignedBE -Bytes $Payload -Offset $bodyOffset -Length 8))
                $bodyOffset += 8
            }
            7 {
                $raw = Get-Slice -Data $Payload -Offset $bodyOffset -Length 8
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($raw) }
                $values.Add([BitConverter]::ToDouble($raw, 0))
                $bodyOffset += 8
            }
            8 { $values.Add(0) }
            9 { $values.Add(1) }
            default {
                if ($serial -ge 12) {
                    if (($serial % 2) -eq 0) {
                        $len = [int](($serial - 12) / 2)
                        [byte[]]$blobBytes = Get-Slice -Data $Payload -Offset $bodyOffset -Length $len
                        $values.Add($blobBytes)
                        $bodyOffset += $len
                    }
                    else {
                        $len = [int](($serial - 13) / 2)
                        $txtBytes = Get-Slice -Data $Payload -Offset $bodyOffset -Length $len
                        $values.Add([System.Text.Encoding]::UTF8.GetString($txtBytes))
                        $bodyOffset += $len
                    }
                }
                else {
                    throw "Unsupported serial type: $serial"
                }
            }
        }
    }

    return , $values.ToArray()
}

function Get-SqliteSchemaRows {
    param([int]$PageNumber)

    if ($script:VisitedPages.Contains($PageNumber)) {
        return @()
    }
    [void]$script:VisitedPages.Add($PageNumber)

    $page = Get-Page -PageNumber $PageNumber
    $hdrOffset = if ($PageNumber -eq 1) { 100 } else { 0 }
    $pageType = $page[$hdrOffset]

    $rows = New-Object System.Collections.Generic.List[object]

    switch ($pageType) {
        0x05 {
            $cellCount = Read-BEUInt16 -Bytes $page -Offset ($hdrOffset + 3)
            $rightMost = [int](Read-BEUInt32 -Bytes $page -Offset ($hdrOffset + 8))
            $ptrBase = $hdrOffset + 12

            for ($i = 0; $i -lt $cellCount; $i++) {
                $cellPtr = Read-BEUInt16 -Bytes $page -Offset ($ptrBase + ($i * 2))
                $leftChild = [int](Read-BEUInt32 -Bytes $page -Offset $cellPtr)
                $rows.AddRange((Get-SqliteSchemaRows -PageNumber $leftChild))
            }

            $rows.AddRange((Get-SqliteSchemaRows -PageNumber $rightMost))
        }

        0x0D {
            $cellCount = Read-BEUInt16 -Bytes $page -Offset ($hdrOffset + 3)
            $ptrBase = $hdrOffset + 8

            for ($i = 0; $i -lt $cellCount; $i++) {
                $cellPtr = Read-BEUInt16 -Bytes $page -Offset ($ptrBase + ($i * 2))
                $cell = Get-TableLeafCellPayload -PageNumber $PageNumber -PageBytes $page -CellOffset $cellPtr
                $cols = ConvertFrom-SqliteRecord -Payload $cell.Payload

                if ($cols.Length -ge 5) {
                    $rows.Add([pscustomobject]@{
                            type     = $cols[0]
                            name     = $cols[1]
                            tbl_name = $cols[2]
                            rootpage = $cols[3]
                            sql      = $cols[4]
                            rowid    = $cell.RowId
                            page     = $PageNumber
                            cell     = $cellPtr
                        })
                }
            }
        }

        default {
            throw ("Unexpected sqlite_schema page type 0x{0:X2} at page {1}" -f $pageType, $PageNumber)
        }
    }

    return , $rows.ToArray()
}

function Get-TablePageHeaderOffset {
    param([int]$PageNumber)

    if ($PageNumber -eq 1) {
        return 100
    }

    return 0
}

function Get-TableLeafCells {
    param([int]$PageNumber)

    $page = Get-Page -PageNumber $PageNumber
    $hdrOffset = Get-TablePageHeaderOffset -PageNumber $PageNumber
    $pageType = $page[$hdrOffset]

    $rows = New-Object System.Collections.Generic.List[object]

    switch ($pageType) {
        0x05 {
            $cellCount = Read-BEUInt16 -Bytes $page -Offset ($hdrOffset + 3)
            $rightMost = [int](Read-BEUInt32 -Bytes $page -Offset ($hdrOffset + 8))
            $ptrBase = $hdrOffset + 12

            for ($i = 0; $i -lt $cellCount; $i++) {
                $cellPtr = Read-BEUInt16 -Bytes $page -Offset ($ptrBase + ($i * 2))
                $leftChild = [int](Read-BEUInt32 -Bytes $page -Offset $cellPtr)
                $rows.AddRange((Get-TableLeafCells -PageNumber $leftChild))
            }

            $rows.AddRange((Get-TableLeafCells -PageNumber $rightMost))
        }

        0x0D {
            $cellCount = Read-BEUInt16 -Bytes $page -Offset ($hdrOffset + 3)
            $ptrBase = $hdrOffset + 8

            for ($i = 0; $i -lt $cellCount; $i++) {
                $cellPtr = Read-BEUInt16 -Bytes $page -Offset ($ptrBase + ($i * 2))
                $cell = Get-TableLeafCellPayload -PageNumber $PageNumber -PageBytes $page -CellOffset $cellPtr
                $rows.Add([pscustomobject]@{
                        PageNumber = $PageNumber
                        CellOffset = $cellPtr
                        RowId      = [UInt64]$cell.RowId
                        Payload     = [byte[]]$cell.Payload
                    })
            }
        }

        default {
            throw ("Unexpected table b-tree page type 0x{0:X2} at page {1}" -f $pageType, $PageNumber)
        }
    }

    return , $rows.ToArray()
}

function ConvertTo-ProtobufVarint {
    param([UInt64]$Value)

    $bytes = New-Object System.Collections.Generic.List[byte]
    [UInt64]$remaining = $Value

    do {
        [byte]$b = [byte]($remaining -band 0x7F)
        $remaining = $remaining -shr 7

        if ($remaining -ne 0) {
            $b = [byte]($b -bor 0x80)
        }

        $bytes.Add($b)
    } while ($remaining -ne 0)

    return , ([byte[]]$bytes.ToArray())
}

function Get-ContentEntryPrefix {
    param([UInt64]$CacheId)

    $field1Tag = [byte]0x08
    $encoded = ConvertTo-ProtobufVarint -Value $CacheId
    return , ([byte[]]@($field1Tag) + $encoded)
}

function Test-ByteArrayStartsWith {
    param(
        [byte[]]$Data,
        [byte[]]$Prefix
    )

    if ($null -eq $Data -or $null -eq $Prefix) {
        return $false
    }

    if ($Data.Length -lt $Prefix.Length) {
        return $false
    }

    for ($i = 0; $i -lt $Prefix.Length; $i++) {
        if ($Data[$i] -ne $Prefix[$i]) {
            return $false
        }
    }

    return $true
}

function Resolve-TableRoots {
    param(
        [object[]]$SchemaRows,
        [string[]]$Names
    )

    $resolved = New-Object 'System.Collections.Generic.Dictionary[string, object]'

    foreach ($name in $Names) {
        $row = $SchemaRows |
        Where-Object { $_.type -eq 'table' -and $_.name -eq $name } |
        Select-Object -First 1

        if ($null -ne $row) {
            $resolved[$name] = $row
        }
    }

    return $resolved
}

function Get-ItemPropertiesMatches {
    param(
        [int]$RootPage,
        [byte[]]$TargetPrefix
    )

    $matchRows = New-Object System.Collections.Generic.List[object]

    foreach ($leafCell in (Get-TableLeafCells -PageNumber $RootPage)) {
        $cols = ConvertFrom-SqliteRecord -Payload $leafCell.Payload

        if ($cols.Length -lt 4) {
            continue
        }

        $itemStableId = $cols[0]
        $key = $cols[1]
        $value = $cols[2]
        $valueType = $cols[3]

        if ($key -ne 'content-entry') {
            continue
        }

        $valueBytes = ConvertTo-ByteArray -Value $value
        if ($null -eq $valueBytes) {
            continue
        }

        if (-not (Test-ByteArrayStartsWith -Data $valueBytes -Prefix $TargetPrefix)) {
            continue
        }

        $matchRows.Add([pscustomobject]@{
                item_stable_id = [Int64]$itemStableId
                value_type     = $valueType
                property_page  = $leafCell.PageNumber
                property_cell  = ('0x{0:X}' -f $leafCell.CellOffset)
            })
    }

    return , $matchRows.ToArray()
}

function Get-ItemsByStableId {
    param(
        [int]$RootPage,
        [Int64[]]$StableIds
    )

    $wanted = New-Object 'System.Collections.Generic.HashSet[Int64]'
    foreach ($stableId in $StableIds) {
        [void]$wanted.Add([Int64]$stableId)
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($leafCell in (Get-TableLeafCells -PageNumber $RootPage)) {
        $stableId = [Int64]$leafCell.RowId
        if (-not $wanted.Contains($stableId)) {
            continue
        }

        $cols = ConvertFrom-SqliteRecord -Payload $leafCell.Payload
        if ($cols.Length -lt 18) {
            continue
        }

        $rows.Add([pscustomobject]@{
                stable_id     = $stableId
                id            = $cols[1]
                modified_date = $cols[8]
                file_size     = $cols[11]
                local_title   = $cols[13]
                items_page    = $leafCell.PageNumber
                items_cell    = ('0x{0:X}' -f $leafCell.CellOffset)
            })
    }

    return , $rows.ToArray()
}

$script:PageCache = New-Object 'System.Collections.Generic.Dictionary[int, byte[]]'
$script:WalPageCache = New-Object 'System.Collections.Generic.Dictionary[int, byte[]]'
$script:VisitedPages = New-Object 'System.Collections.Generic.HashSet[int]'

if ([string]::IsNullOrWhiteSpace($Path) -or -not $PSBoundParameters.ContainsKey('Filename')) {
    Show-Usage
    return
}

$script:Fs = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::ReadWrite
)

try {
    $header = Read-At -Stream $script:Fs -Offset 0 -Count 100

    $sig = [System.Text.Encoding]::ASCII.GetString($header[0..15])
    if (-not $sig.StartsWith("SQLite format 3")) {
        throw "Not a SQLite 3 database"
    }

    $script:PageSize = Read-BEUInt16 -Bytes $header -Offset 16
    if ($script:PageSize -eq 1) {
        $script:PageSize = 65536
    }

    $reserved = [int]$header[20]
    $script:UsableSize = $script:PageSize - $reserved

    Initialize-WalOverlay -DatabasePath $Path

    $schemaRows = Get-SqliteSchemaRows -PageNumber 1

    $neededTables = Resolve-TableRoots -SchemaRows $schemaRows -Names @('item_properties', 'items')
        foreach ($requiredName in @('item_properties', 'items')) {
            if (-not $neededTables.ContainsKey($requiredName)) {
                throw "Required table '$requiredName' not found in sqlite_schema"
            }
        }

    $targetPrefix = Get-ContentEntryPrefix -CacheId $Filename
    $propertyMatches = Get-ItemPropertiesMatches -RootPage ([int]$neededTables['item_properties'].rootpage) -TargetPrefix $targetPrefix

    if (-not $propertyMatches) {
        Write-Output ""
        Write-Output ("No item_properties rows matched content-entry prefix for cache ID {0}." -f $Filename)
        return
    }

    $stableIds = $propertyMatches |
    Select-Object -ExpandProperty item_stable_id -Unique

    $itemsRows = Get-ItemsByStableId -RootPage ([int]$neededTables['items'].rootpage) -StableIds $stableIds
    $itemsByStableId = @{}
    foreach ($item in $itemsRows) {
        $itemsByStableId[[Int64]$item.stable_id] = $item
    }

    $final = foreach ($match in $propertyMatches) {
        $item = $itemsByStableId[[Int64]$match.item_stable_id]

        [pscustomobject]@{
            stable_id     = [Int64]$match.item_stable_id
            id            = if ($null -ne $item) { $item.id } else { $null }
            modified_date = if ($null -ne $item) { $item.modified_date } else { $null }
            local_title   = if ($null -ne $item) { $item.local_title } else { $null }
            file_size     = if ($null -ne $item) { $item.file_size } else { $null }
        }
    }

    Write-Output ""
    Write-Output ("Matches for cache ID {0}" -f $Filename)
    Write-VerticalResults -InputObject ($final | Sort-Object stable_id, id, local_title)
}
finally {
    $script:Fs.Dispose()
}
