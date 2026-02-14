# Repository Contract Index: QUIC_CRYPTO_TLS Component

## Component Overview
**Source File**: `src/core/crypto_tls.c`  
**Header Files**: `src/core/transport_params.h`, `src/core/crypto.h`  
**Purpose**: Processes TLS-specific data structures for QUIC protocol, including:
- Decoding ALPN list and SNI from Client Hello
- Reading and writing QUIC transport parameter extension
- Parsing TLS handshake messages

## Public API Inventory

### 1. QuicTpIdIsReserved
**Signature**: `BOOLEAN QuicTpIdIsReserved(_In_ QUIC_VAR_INT ID)`  
**Purpose**: Checks if a transport parameter ID is reserved per QUIC spec  
**Preconditions**:
- None (pure function)
**Postconditions**:
- Returns TRUE if `(ID % 31) == 27`, FALSE otherwise
**Contract**: Reserved IDs follow pattern "31 * N + 27" for integer N
**Thread-safety**: Thread-safe (no state)

### 2. QuicCryptoTlsReadSniExtension
**Signature**: `QUIC_STATUS QuicCryptoTlsReadSniExtension(_In_ QUIC_CONNECTION* Connection, _In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint16_t BufferLength, _Inout_ QUIC_NEW_CONNECTION_INFO* Info)`  
**Purpose**: Parses SNI (Server Name Indication) extension from TLS ClientHello  
**Preconditions**:
- `Connection` must not be NULL
- `Buffer` must be valid for `BufferLength` bytes
- `Info` must be a valid pointer
- Buffer must contain well-formed SNI extension per TLS spec
**Postconditions**:
- On success: `Info->ServerName` points to first hostname in list, `Info->ServerNameLength` set
- Returns `QUIC_STATUS_SUCCESS` on valid SNI
- Returns `QUIC_STATUS_INVALID_PARAMETER` on malformed data
**Error cases**:
- BufferLength < 2 bytes (minimum header)
- Name list length < 3 bytes
- Truncated name data
**Side effects**: Updates `Info` structure (borrowed pointers into `Buffer`)
**Thread-safety**: Caller must ensure exclusive access to `Info`

### 3. QuicCryptoTlsReadAlpnExtension
**Signature**: `QUIC_STATUS QuicCryptoTlsReadAlpnExtension(_In_ QUIC_CONNECTION* Connection, _In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint16_t BufferLength, _Inout_ QUIC_NEW_CONNECTION_INFO* Info)`  
**Purpose**: Parses ALPN (Application-Layer Protocol Negotiation) extension  
**Preconditions**:
- `Connection` must not be NULL
- `Buffer` must be valid for `BufferLength` bytes
- `Info` must be a valid pointer
- Buffer must contain protocol list with at least 1 protocol (1-255 bytes each)
**Postconditions**:
- On success: `Info->ClientAlpnList` points to protocol list, `Info->ClientAlpnListLength` set
- Returns `QUIC_STATUS_SUCCESS` on valid ALPN
- Returns `QUIC_STATUS_INVALID_PARAMETER` on malformed data
**Error cases**:
- BufferLength < 4 bytes (min: 2-byte list length + 1-byte proto len + 1-byte proto)
- Protocol list length mismatch
- Truncated protocol data
**Side effects**: Updates `Info` structure (borrowed pointers into `Buffer`)

### 4. QuicCryptoTlsReadExtensions
**Signature**: `QUIC_STATUS QuicCryptoTlsReadExtensions(_In_ QUIC_CONNECTION* Connection, _In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint16_t BufferLength, _Inout_ QUIC_NEW_CONNECTION_INFO* Info)`  
**Purpose**: Parses TLS extensions list, extracting SNI, ALPN, and QUIC transport parameters  
**Preconditions**:
- `Connection` must not be NULL with valid `Stats.QuicVersion`
- `Buffer` must be valid for `BufferLength` bytes
- `Info` must be valid
**Postconditions**:
- Extracts SNI, ALPN, and transport parameters
- Returns `QUIC_STATUS_INVALID_PARAMETER` if transport parameters missing or duplicate extensions found
- Updates `Connection->PeerTransportParams` on success
**Error cases**:
- Duplicate SNI/ALPN/TP extensions
- Missing QUIC transport parameters extension
- Malformed extension structure (length mismatches)

### 5. QuicCryptoTlsReadClientHello
**Signature**: `QUIC_STATUS QuicCryptoTlsReadClientHello(_In_ QUIC_CONNECTION* Connection, _In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength, _Inout_ QUIC_NEW_CONNECTION_INFO* Info)`  
**Purpose**: Parses complete TLS ClientHello message  
**Preconditions**:
- `Connection`, `Buffer`, `Info` must be valid
- Buffer must contain complete ClientHello per TLS 1.3 spec
**Postconditions**:
- Validates version >= TLS 1.0
- Parses random, session ID, cipher suites, compression methods
- Calls `QuicCryptoTlsReadExtensions` for extension list
- Returns `QUIC_STATUS_SUCCESS` even if no extensions present
**Error cases**:
- TLS version < 0x0301
- Malformed random/sessionID/ciphersuites/compression
- Invalid extension list

### 6. QuicCryptoTlsReadInitial
**Signature**: `QUIC_STATUS QuicCryptoTlsReadInitial(_In_ QUIC_CONNECTION* Connection, _In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength, _Inout_ QUIC_NEW_CONNECTION_INFO* Info)`  
**Purpose**: Reads TLS Initial packet, expecting ClientHello message(s)  
**Preconditions**:
- Valid `Connection`, `Buffer`, `Info`
- Buffer may contain partial data
**Postconditions**:
- Returns `QUIC_STATUS_PENDING` if data incomplete
- Returns `QUIC_STATUS_INVALID_PARAMETER` if not ClientHello or missing ALPN
- Logs warning if SNI missing (but still succeeds)
- Processes multiple messages in buffer
**Error cases**:
- First message not ClientHello (type != 0x01)
- Missing ALPN extension (mandatory)
- Incomplete message (returns PENDING, not error)

### 7. QuicCryptoTlsReadClientRandom
**Signature**: `QUIC_STATUS QuicCryptoTlsReadClientRandom(_In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength, _Inout_ QUIC_TLS_SECRETS* TlsSecrets)`  
**Purpose**: Extracts 32-byte client random from TLS handshake  
**Preconditions**:
- Buffer must have at least `TLS_MESSAGE_HEADER_LENGTH + 2 + 32` bytes
- `TlsSecrets` must be valid
**Postconditions**:
- Copies 32 bytes to `TlsSecrets->ClientRandom`
- Sets `TlsSecrets->IsSet.ClientRandom = TRUE`
- Always returns `QUIC_STATUS_SUCCESS`
**Contract**: Caller guarantees sufficient buffer size (asserted, not checked)

### 8. QuicCryptoTlsGetCompleteTlsMessagesLength
**Signature**: `uint32_t QuicCryptoTlsGetCompleteTlsMessagesLength(_In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength)`  
**Purpose**: Calculates total length of complete TLS messages in buffer  
**Preconditions**:
- `Buffer` must be valid for `BufferLength` bytes
**Postconditions**:
- Returns cumulative length of complete messages (stops at first incomplete)
- Returns 0 if first message incomplete
**Contract**: Used for framing/buffering logic

### 9. QuicCryptoTlsEncodeTransportParameters
**Signature**: `const uint8_t* QuicCryptoTlsEncodeTransportParameters(_In_opt_ QUIC_CONNECTION* Connection, _In_ BOOLEAN IsServerTP, _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams, _In_opt_ const QUIC_PRIVATE_TRANSPORT_PARAMETER* TestParam, _Out_ uint32_t* TPLen)`  
**Purpose**: Allocates and encodes QUIC transport parameters into wire format  
**Preconditions**:
- `TransportParams` must be valid
- `TPLen` must be valid output pointer
- All enabled flags must have valid corresponding field values
- Server-only flags (ORIGINAL_DESTINATION_CID, STATELESS_RESET_TOKEN, etc.) only set when `IsServerTP == TRUE`
**Postconditions**:
- Returns allocated buffer (caller must free with `CXPLAT_FREE(..., QUIC_POOL_TLS_TRANSPARAMS)`)
- Returns NULL on allocation failure
- `*TPLen` set to buffer length (including CxPlatTlsTPHeaderSize)
**Ownership**: Caller owns returned buffer, must free
**Thread-safety**: Thread-safe (no shared state)

### 10. QuicCryptoTlsDecodeTransportParameters
**Signature**: `BOOLEAN QuicCryptoTlsDecodeTransportParameters(_In_opt_ QUIC_CONNECTION* Connection, _In_ BOOLEAN IsServerTP, _In_reads_(TPLen) const uint8_t* TPBuf, _In_ uint16_t TPLen, _Inout_ QUIC_TRANSPORT_PARAMETERS* TransportParams)`  
**Purpose**: Decodes wire-format transport parameters into struct  
**Preconditions**:
- `TPBuf` must be valid for `TPLen` bytes
- `TransportParams` must be valid
- If `TransportParams->VersionInfo` is non-NULL, it will be freed first
**Postconditions**:
- On success: `TransportParams` populated, returns TRUE
- On failure: `TransportParams` zeroed, returns FALSE
- Sets default values for optional parameters not present
- Allocates `VersionInfo` buffer if version negotiation extension present (caller must call cleanup)
**Error cases**:
- Duplicate parameter IDs (for first 64 IDs)
- Invalid parameter lengths
- Server-only parameters sent by client
- Client-only parameters sent by server
- VarInt decode failures
**Ownership**: May allocate `VersionInfo` - caller must call `QuicCryptoTlsCleanupTransportParameters`

### 11. QuicCryptoTlsCopyTransportParameters
**Signature**: `QUIC_STATUS QuicCryptoTlsCopyTransportParameters(_In_ const QUIC_TRANSPORT_PARAMETERS* Source, _In_ QUIC_TRANSPORT_PARAMETERS* Destination)`  
**Purpose**: Deep copies transport parameters, including allocated buffers  
**Preconditions**:
- `Source` and `Destination` must be valid
**Postconditions**:
- On success: `Destination` is deep copy, returns `QUIC_STATUS_SUCCESS`
- On failure: returns `QUIC_STATUS_OUT_OF_MEMORY`
- Allocates `VersionInfo` if present in Source
**Ownership**: Caller must call `QuicCryptoTlsCleanupTransportParameters` on Destination

### 12. QuicCryptoTlsCleanupTransportParameters
**Signature**: `void QuicCryptoTlsCleanupTransportParameters(_In_ QUIC_TRANSPORT_PARAMETERS* TransportParams)`  
**Purpose**: Frees allocated memory within transport parameters struct  
**Preconditions**:
- `TransportParams` must be valid
**Postconditions**:
- Frees `VersionInfo` if allocated
- Clears `QUIC_TP_FLAG_VERSION_NEGOTIATION` flag
- Sets `VersionInfo` to NULL and `VersionInfoLength` to 0
**Ownership**: Frees owned memory, struct itself remains valid

## Type Invariants

### QUIC_TRANSPORT_PARAMETERS
**Invariants**:
- If `Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION`, then `VersionInfo` is either NULL or points to allocated buffer of `VersionInfoLength` bytes
- `MaxUdpPayloadSize` >= 1200 and <= 65527 when set
- `AckDelayExponent` <= 20 when set
- `MaxAckDelay` <= 2^14 when set
- Connection ID lengths <= 20 bytes
- Server-only flags only set in server TPs
- All varint fields are valid QUIC varints

### QUIC_NEW_CONNECTION_INFO
**Invariants**:
- `ServerName` and `ClientAlpnList` are borrowed pointers (lifetime tied to source buffer)
- Lengths match actual data pointed to

## Environment Invariants
- Memory allocation via `CXPLAT_ALLOC_NONPAGED` may fail
- `QUIC_POOL_TLS_TRANSPARAMS` and `QUIC_POOL_VERSION_INFO` are valid pool tags
- Trace events (QuicTraceEvent, QuicTraceLogConnVerbose) are safe to call
- VarInt encoding/decoding functions (`QuicVarIntEncode`, `QuicVarIntDecode`, `QuicVarIntSize`) are available

## State Machine
No explicit state machine in this component - functions are primarily stateless parsers and encoders. State is maintained in `QUIC_CONNECTION` and `QUIC_TRANSPORT_PARAMETERS` structures passed in.

## Dependency Map
- **crypto_tls.c** depends on:
  - `QuicVarIntEncode/Decode/Size` (varint.c)
  - `CxPlatCopyMemory`, `CxPlatZeroMemory` (platform layer)
  - `CXPLAT_ALLOC_NONPAGED`, `CXPLAT_FREE` (platform layer)
  - `QuicTraceEvent`, `QuicTraceLogConnVerbose/Warning` (logging)
  - `QuicCidBufToStr` (cid.h)
  - `CxPlatTlsTPHeaderSize` (platform TLS)

- **Calls within crypto_tls.c**:
  - `QuicCryptoTlsReadInitial` → `QuicCryptoTlsReadClientHello` → `QuicCryptoTlsReadExtensions` → `QuicCryptoTlsReadSniExtension` / `QuicCryptoTlsReadAlpnExtension` / `QuicCryptoTlsDecodeTransportParameters`

## Key Testing Considerations
1. **Boundary values**: Min/max lengths for all fields
2. **Error paths**: All parse error branches must be tested
3. **Encode/decode round-trip**: Ensure symmetry
4. **Edge cases**: Empty lists, minimal valid data, maximum valid data
5. **Duplicate detection**: Transport parameter duplicate IDs
6. **Server vs Client**: Different behaviors for IsServerTP flag
7. **Version handling**: Draft-29 vs final version extension types
8. **Memory safety**: All allocations, frees, and cleanup paths
