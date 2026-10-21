Garnet 2.2.1-dwti.4 for Windows x64

Project-patched Microsoft Garnet v2.2.1. Requires .NET 10.
Install the complete net10.0 runtime. Replacing only the executable does not
install the persistence fixes. Source identity and file hashes are recorded
in garnet-build.json. The upstream MIT license is LICENSE.txt.

Includes the existing broker, disconnect, transaction and AOF commit fixes.
Resets serialized object length for every record and writes the explicit Null
marker for null object values. Does not change the object serialization format.

Legacy zero-length objects are rejected unless recovery can verify a later
valid same-key version through the rebuilt index. Only those superseded
records are retired in recovery memory. Unknown or unregistered object types,
truncated objects and unverified empty latest values still stop recovery.
Recovery honors both the lower and upper bounds of partial pages.

No queue clearing, database restoration or recovery bypass is included.
This archive contains runtime files only, without server data or tests.
