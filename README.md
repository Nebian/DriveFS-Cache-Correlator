# DriveFS-Cache-Correlator
PowerShell script that maps Google DriveFS cached files back to their original names and metadata without external dependencies, helping investigations and alert triage.

## Usage
```powershell
.\drivefs_cache_correlator.ps1 -Path <sqlite_db_path> -Filename <cache_id>
```
## How it works

The script reconstructs the current SQLite view from the main database and its WAL, then searches `item_properties` for `content-entry` blobs whose protobuf field 1 matches the target cache ID. The matched `item_stable_id` values are then joined against `items` to retrieve file metadata.

```text
INPUT:
    database path
    cache ID

OPEN main database

IF sibling WAL exists:
    parse WAL
    overlay newer pages on top of main DB pages

READ sqlite_schema
FIND root pages for:
    - item_properties
    - items

BUILD protobuf prefix for target cache ID

SCAN item_properties:
    for each row:
        if key != "content-entry":
            skip
        if value blob does not start with target prefix:
            skip
        store item_stable_id

SCAN items:
    for each row:
        if stable_id is not in matched item_stable_id set:
            skip
        extract file metadata

PRINT final results
```
## Pseudocode
```text
START

1. Validate input
    if Path is missing or Filename is missing:
        print usage
        stop

2. Open the main SQLite database file

3. Read and validate the SQLite header
    read first 100 bytes
    verify signature starts with "SQLite format 3"
    read page size
    calculate usable page size

4. Look for a sibling WAL file
    expected path = database path + "-wal"

5. If WAL exists:
    parse WAL header
    parse WAL frames
    verify frames/checksums
    keep the newest committed version of each page
    build an in-memory page overlay:
        page number -> latest page bytes from WAL

6. Define page reader behavior
    when a page is requested:
        if WAL overlay contains that page:
            return WAL version
        else:
            return page from main database file

7. Read sqlite_schema manually
    walk its b-tree recursively
    decode schema records
    find root pages for:
        - item_properties
        - items

8. Build the target protobuf prefix
    prefix = 0x08 + protobuf-varint(Filename)

    example:
        Filename = 172
        protobuf-varint(172) = AC 01
        target prefix = 08 AC 01

9. Scan item_properties manually
    walk the item_properties b-tree recursively

    for each row:
        decode SQLite record
        extract:
            item_stable_id
            key
            value
            value_type

        if key != "content-entry":
            skip row

        convert value into raw byte array
        if value is not a valid byte array:
            skip row

        if value does NOT start with target prefix:
            skip row

        add item_stable_id to matched stable_id list

10. If no matched stable_id values were found:
    print:
        no item_properties rows matched content-entry prefix for cache ID X
    stop

11. Remove duplicate stable_id values
    build unique stable_id set

12. Scan items manually
    walk the items b-tree recursively

    for each row:
        read rowid
        note:
            in this table, rowid = stable_id
        decode SQLite record
        extract:
            id
            modified_date
            local_title
            file_size

        if rowid is not in the matched stable_id set:
            skip row

        store item metadata keyed by stable_id

13. Join the results
    for each matched stable_id:
        look up metadata from items
        build output object:
            stable_id
            id
            modified_date
            local_title
            file_size

14. Sort results for readability

15. Print results vertically
    one record block at a time

END
```
## Why WAL matters

Google Drive for desktop’s SQLite database may use Write-Ahead Logging (WAL). In that mode, recent changes are not written immediately into the main metadata_sqlite_db file. Instead, they may exist only in the sibling metadata_sqlite_db-wal file until a checkpoint merges them back into the main database.

This matters because a parser that reads only the main database file can miss newer rows, newer page versions, or recently updated metadata. In practice, that can produce false negatives: a cache entry may be visible in SQLite-aware tools, but not visible to a raw parser that ignores the WAL.

To avoid that problem, this script checks for a sibling -wal file and uses it as an overlay on top of the main database pages. When a page exists in the WAL, the WAL version is treated as the current one. When it does not, the script falls back to the page stored in the main database. This allows the script to reconstruct a more accurate view of the database state at the time of analysis.

## Limitations

This script is designed for a specific forensic use case and makes some deliberate assumptions.

It focuses on correlating cache IDs through item_properties.key = 'content-entry' and then enriching the result from items. It is not a general-purpose SQLite parser and it does not attempt to fully interpret every table, record type, or protobuf structure in the database.

The matching logic is intentionally optimized: it checks whether the content-entry blob starts with the protobuf field-1 prefix for the target cache ID. This is efficient and sufficient for the current workflow, but it is not the same as performing a full semantic decode of every protobuf blob.

The script also depends on the observed schema and data layout remaining compatible with the current Google Drive for desktop version. If Google changes the table structure, protobuf layout, page usage, or cache correlation method, the script may require updates.

Although WAL is supported, the script still works as a manual parser rather than a full SQLite engine. It is intended for controlled analysis of this specific database family, not for perfect emulation of every SQLite feature or edge case.

Finally, the results should be treated as strong correlation evidence within the analyzed database state, not as a timeless truth. Cache contents and metadata can change over time, and the script reflects what is present in the database snapshot and WAL state available at the moment of parsing.
