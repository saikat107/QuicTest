# Repository Contract Index for QUIC_API Component

## Source Files
- **Implementation**: `src/core/api.c` (2063 lines)
- **Header**: `src/core/api.h`
- **Public Include**: `src/inc/msquic.h`

## Component Overview
The QUIC_API component implements the public-facing MsQuic API functions defined in the QUIC_API_TABLE. These functions provide the interface for:
- Connection management (open, close, start, shutdown)
- Stream management (open, close, send, receive)
- Configuration and parameter management
- Resumption tickets and datagrams

## Public API Inventory

### Connection APIs

#### 1. `MsQuicConnectionOpen`
**Signature**: 
```c
QUIC_STATUS MsQuicConnectionOpen(
    HQUIC RegistrationHandle,
    QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    void* Context,
    HQUIC* NewConnection)
```

**Purpose**: Opens a new QUIC connection on the current partition

**Preconditions**:
- `RegistrationHandle` must be a valid registration handle (non-NULL, type==QUIC_HANDLE_TYPE_REGISTRATION)
- `Handler` must be non-NULL
- `NewConnection` must be non-NULL
- MsQuic library must be initialized

**Postconditions**:
- On success: Returns QUIC_STATUS_SUCCESS, `*NewConnection` points to new connection handle
- On failure: Returns error code, connection not allocated

**Side Effects**:
- Allocates connection object
- Adds reference to registration
- Assigns to current partition's worker

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle, NULL Handler, or NULL NewConnection
- `QUIC_STATUS_OUT_OF_MEMORY`: Allocation failure

**Thread Safety**: Can be called at DISPATCH_LEVEL, internally synchronized

**Resource Ownership**: Caller owns returned connection handle, must call MsQuicConnectionClose to free

---

#### 2. `MsQuicConnectionOpenInPartition`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionOpenInPartition(
    HQUIC RegistrationHandle,
    uint16_t PartitionIndex,
    QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    void* Context,
    HQUIC* NewConnection)
```

**Purpose**: Opens a new QUIC connection on a specific partition (hard partitioning)

**Preconditions**:
- Same as MsQuicConnectionOpen
- `PartitionIndex` < MsQuicLib.PartitionCount

**Postconditions**: Same as MsQuicConnectionOpen

**Side Effects**: Same as MsQuicConnectionOpen, but assigns to specified partition

**Error Codes**: Same as MsQuicConnectionOpen, plus partition index validation

**Platform Notes**: Hard partitioning only supported on Linux (non-IO_URING, non-XDP)

---

#### 3. `MsQuicConnectionClose`
**Signature**:
```c
void MsQuicConnectionClose(HQUIC Handle)
```

**Purpose**: Closes a connection handle and releases resources

**Preconditions**:
- `Handle` must be a valid connection handle (type==CONNECTION_CLIENT or CONNECTION_SERVER)
- Must be called at PASSIVE_LEVEL
- Handle must not already be closed

**Postconditions**:
- Connection handle is closed
- All resources freed (eventually, after worker processes close operation)
- Handle becomes invalid

**Side Effects**:
- Queues close operation to worker
- May wait on completion event if not called from worker thread and not async
- Releases handle owner reference

**Thread Safety**: 
- If called from worker thread: executes inline
- If called from app thread: queues operation and waits for completion
- Async mode: queues operation but doesn't wait

**Resource Ownership**: Frees the connection handle memory

---

#### 4. `MsQuicConnectionShutdown`
**Signature**:
```c
void MsQuicConnectionShutdown(
    HQUIC Handle,
    QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    QUIC_UINT62 ErrorCode)
```

**Purpose**: Initiates graceful or abortive shutdown of a connection

**Preconditions**:
- `Handle` must be valid connection or stream handle
- `ErrorCode` <= QUIC_UINT62_MAX (0x3FFFFFFFFFFFFFFF)
- Connection must not be freed

**Postconditions**:
- Shutdown operation queued
- Connection begins shutdown sequence

**Side Effects**:
- Queues high-priority shutdown operation
- May use backup operation if allocation fails

**Error Handling**: Silently fails if handle invalid or already shutting down

**Thread Safety**: Can be called at DISPATCH_LEVEL, operation is queued

---

#### 5. `MsQuicConnectionStart`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionStart(
    HQUIC Handle,
    HQUIC ConfigHandle,
    QUIC_ADDRESS_FAMILY Family,
    const char* ServerName,
    uint16_t ServerPort)
```

**Purpose**: Starts a client connection to a server

**Preconditions**:
- `Handle` must be valid connection or stream handle
- If connection handle: must be client connection
- `ConfigHandle` must be valid configuration with SecurityConfig set
- `ServerPort` != 0
- `Family` must be UNSPEC, INET, or INET6
- If `ServerName` provided: length <= QUIC_MAX_SNI_LENGTH
- Connection must not already be started or closed locally
- Either `ServerName` provided OR remote address already set

**Postconditions**:
- Returns QUIC_STATUS_PENDING on success
- Connection start operation queued
- Configuration reference added

**Side Effects**:
- Allocates copy of ServerName
- Queues start operation
- Begins connection handshake

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid config, NULL ServerName when required, invalid family, server port 0, server connection
- `QUIC_STATUS_INVALID_STATE`: Already started or closed
- `QUIC_STATUS_OUT_OF_MEMORY`: Allocation failure
- `QUIC_STATUS_PENDING`: Success

---

#### 6. `MsQuicConnectionSetConfiguration`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionSetConfiguration(
    HQUIC Handle,
    HQUIC ConfigHandle)
```

**Purpose**: Sets configuration on a server connection (for accepted connections)

**Preconditions**:
- `Handle` must be valid connection or stream handle
- If connection: must be server connection
- `ConfigHandle` must be valid configuration with SecurityConfig
- Connection must not already have configuration set

**Postconditions**:
- Returns QUIC_STATUS_PENDING on success
- Configuration set operation queued
- Configuration reference added

**Side Effects**:
- Queues set configuration operation
- Enables handshake to proceed on server

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid config, NULL SecurityConfig, client connection
- `QUIC_STATUS_INVALID_STATE`: Configuration already set
- `QUIC_STATUS_OUT_OF_MEMORY`: Operation allocation failure
- `QUIC_STATUS_PENDING`: Success

---

#### 7. `MsQuicConnectionSendResumptionTicket`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionSendResumptionTicket(
    HQUIC Handle,
    QUIC_SEND_RESUMPTION_FLAGS Flags,
    uint16_t DataLength,
    const uint8_t* ResumptionData)
```

**Purpose**: Sends a resumption ticket to the client (server-side 0-RTT)

**Preconditions**:
- `Handle` must be valid connection or stream handle
- Must be server connection
- `DataLength` <= QUIC_MAX_RESUMPTION_APP_DATA_LENGTH
- If `DataLength` > 0: `ResumptionData` must be non-NULL
- `Flags` <= QUIC_SEND_RESUMPTION_FLAG_FINAL
- Connection must be connected and handshake complete
- Resumption must be enabled

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- Resumption ticket operation queued

**Side Effects**:
- Allocates copy of resumption data
- Queues send operation
- Ticket will be encrypted and sent to client

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid data length, NULL data when length > 0, invalid flags, client connection
- `QUIC_STATUS_INVALID_STATE`: Not connected, handshake incomplete, resumption disabled
- `QUIC_STATUS_OUT_OF_MEMORY`: Allocation failure
- `QUIC_STATUS_SUCCESS`: Success

---

### Stream APIs

#### 8. `MsQuicStreamOpen`
**Signature**:
```c
QUIC_STATUS MsQuicStreamOpen(
    HQUIC Handle,
    QUIC_STREAM_OPEN_FLAGS Flags,
    QUIC_STREAM_CALLBACK_HANDLER Handler,
    void* Context,
    HQUIC* NewStream)
```

**Purpose**: Opens a new stream on a connection

**Preconditions**:
- `Handle` must be valid connection or stream handle
- `Handler` must be non-NULL
- `NewStream` must be non-NULL
- Connection must not be freed or handle closed

**Postconditions**:
- On success: Returns QUIC_STATUS_SUCCESS, `*NewStream` points to new stream
- On failure: Returns error code

**Side Effects**:
- Allocates stream object
- Adds stream to connection's stream set
- May trigger flow control updates

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: NULL NewStream, NULL Handler, invalid handle
- `QUIC_STATUS_OUT_OF_MEMORY`: Stream allocation failure
- `QUIC_STATUS_ABORTED`: Connection shutting down

---

#### 9. `MsQuicStreamClose`
**Signature**:
```c
void MsQuicStreamClose(HQUIC Handle)
```

**Purpose**: Closes a stream handle

**Preconditions**:
- `Handle` must be valid stream handle
- Must be called at PASSIVE_LEVEL

**Postconditions**:
- Stream handle closed
- Resources released

**Side Effects**:
- Queues stream close operation
- Waits for completion if not on worker thread
- Releases handle owner reference

**Thread Safety**: Similar to ConnectionClose - inline on worker, queued otherwise

---

#### 10. `MsQuicStreamStart`
**Signature**:
```c
QUIC_STATUS MsQuicStreamStart(
    HQUIC Handle,
    QUIC_STREAM_START_FLAGS Flags)
```

**Purpose**: Starts a stream (makes it ready to send/receive)

**Preconditions**:
- `Handle` must be valid stream handle
- Stream must not be freed or handle closed
- Must not already be started

**Postconditions**:
- Returns QUIC_STATUS_PENDING on success
- Stream start operation queued

**Side Effects**:
- Queues stream start operation
- Stream will be assigned stream ID
- Flow control initialized

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle
- `QUIC_STATUS_INVALID_STATE`: Already started, connection closed
- `QUIC_STATUS_OUT_OF_MEMORY`: Operation allocation failure
- `QUIC_STATUS_PENDING`: Success

---

#### 11. `MsQuicStreamShutdown`
**Signature**:
```c
QUIC_STATUS MsQuicStreamShutdown(
    HQUIC Handle,
    QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    QUIC_UINT62 ErrorCode)
```

**Purpose**: Shuts down send and/or receive direction of a stream

**Preconditions**:
- `Handle` must be valid stream handle
- `ErrorCode` <= QUIC_UINT62_MAX
- Stream must not be freed or handle closed

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- Shutdown operation queued

**Side Effects**:
- Queues stream shutdown operation
- Will send FIN or RESET_STREAM as appropriate

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle, error code out of range
- `QUIC_STATUS_OUT_OF_MEMORY`: Operation allocation failure
- `QUIC_STATUS_SUCCESS`: Success

---

#### 12. `MsQuicStreamSend`
**Signature**:
```c
QUIC_STATUS MsQuicStreamSend(
    HQUIC Handle,
    const QUIC_BUFFER* const Buffers,
    uint32_t BufferCount,
    QUIC_SEND_FLAGS Flags,
    void* ClientSendContext)
```

**Purpose**: Sends data on a stream

**Preconditions**:
- `Handle` must be valid stream handle
- `Buffers` must be non-NULL
- `BufferCount` > 0
- Stream must not be freed or handle closed
- Stream must be started

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS/PENDING on success
- Send operation queued

**Side Effects**:
- Allocates send request
- Queues data to send buffer
- May trigger packet sending

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle, NULL buffers, zero count
- `QUIC_STATUS_INVALID_STATE`: Send direction closed
- `QUIC_STATUS_OUT_OF_MEMORY`: Send request allocation failure

---

#### 13. `MsQuicStreamReceiveComplete`
**Signature**:
```c
void MsQuicStreamReceiveComplete(
    HQUIC Handle,
    uint64_t BufferLength)
```

**Purpose**: Completes processing of received data, returning flow control credit

**Preconditions**:
- `Handle` must be valid stream handle
- Stream must have received data of `BufferLength`
- Must have outstanding receive indication

**Postconditions**:
- Flow control credits returned
- Receive operation queued

**Side Effects**:
- Queues receive complete operation
- Updates flow control window
- May send MAX_STREAM_DATA frame

---

#### 14. `MsQuicStreamReceiveSetEnabled`
**Signature**:
```c
QUIC_STATUS MsQuicStreamReceiveSetEnabled(
    HQUIC Stream,
    BOOLEAN IsEnabled)
```

**Purpose**: Enables or disables receive callbacks for a stream

**Preconditions**:
- `Stream` must be valid stream handle
- Stream must not be freed or closed

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- Receive enable state queued

**Side Effects**:
- Queues receive set enabled operation
- Controls whether receive callbacks are delivered

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle
- `QUIC_STATUS_OUT_OF_MEMORY`: Operation allocation failure

---

#### 15. `MsQuicStreamProvideReceiveBuffers`
**Signature**:
```c
QUIC_STATUS MsQuicStreamProvideReceiveBuffers(
    HQUIC Handle,
    uint32_t BufferCount,
    const QUIC_BUFFER* Buffers)
```

**Purpose**: Provides application-owned buffers for zero-copy receive

**Preconditions**:
- `Handle` must be valid stream handle
- `BufferCount` > 0
- `Buffers` must be non-NULL and valid

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- Buffers registered for receive

**Side Effects**:
- Queues receive buffers operation
- Received data will be placed directly in provided buffers

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle, NULL buffers, zero count
- `QUIC_STATUS_OUT_OF_MEMORY`: Operation allocation failure

---

### Parameter APIs

#### 16. `MsQuicSetParam`
**Signature**:
```c
QUIC_STATUS MsQuicSetParam(
    HQUIC Handle,
    uint32_t Param,
    uint32_t BufferLength,
    const void* Buffer)
```

**Purpose**: Sets a parameter on a QUIC object

**Preconditions**:
- If non-global param: `Handle` must be valid
- `Buffer` must be non-NULL (usually)
- `BufferLength` must match expected size for param
- Must be called at PASSIVE_LEVEL

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- Parameter value updated

**Side Effects**:
- Depends on specific parameter
- May trigger configuration changes, resource allocation, protocol actions

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid param ID, wrong buffer size, NULL buffer
- `QUIC_STATUS_INVALID_STATE`: Param cannot be set in current state
- Various param-specific errors

---

#### 17. `MsQuicGetParam`
**Signature**:
```c
QUIC_STATUS MsQuicGetParam(
    HQUIC Handle,
    uint32_t Param,
    uint32_t* BufferLength,
    void* Buffer)
```

**Purpose**: Gets a parameter value from a QUIC object

**Preconditions**:
- If non-global param: `Handle` must be valid
- `BufferLength` must be non-NULL
- Must be called at PASSIVE_LEVEL

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS on success
- `*BufferLength` updated with actual size
- `Buffer` filled with parameter value (if provided and large enough)

**Side Effects**: None (read-only)

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid param ID, NULL BufferLength
- `QUIC_STATUS_BUFFER_TOO_SMALL`: Buffer too small for param value
- `QUIC_STATUS_INVALID_STATE`: Param not available in current state

---

### Datagram API

#### 18. `MsQuicDatagramSend`
**Signature**:
```c
QUIC_STATUS MsQuicDatagramSend(
    HQUIC Handle,
    const QUIC_BUFFER* const Buffers,
    uint32_t BufferCount,
    QUIC_SEND_FLAGS Flags,
    void* ClientSendContext)
```

**Purpose**: Sends an unreliable datagram on a connection

**Preconditions**:
- `Handle` must be valid connection or stream handle
- `Buffers` must be non-NULL
- `BufferCount` > 0
- Connection must support datagrams (negotiated)

**Postconditions**:
- Returns QUIC_STATUS_SUCCESS/PENDING on success
- Datagram queued for sending

**Side Effects**:
- Allocates datagram send request
- Queues datagram for transmission
- Best-effort delivery (may be dropped)

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle, NULL buffers
- `QUIC_STATUS_INVALID_STATE`: Datagrams not enabled
- `QUIC_STATUS_OUT_OF_MEMORY`: Allocation failure

---

### Validation Completion APIs

#### 19. `MsQuicConnectionResumptionTicketValidationComplete`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionResumptionTicketValidationComplete(
    HQUIC Handle,
    BOOLEAN Result)
```

**Purpose**: Completes async validation of a resumption ticket (server-side)

**Preconditions**:
- `Handle` must be valid connection handle
- Must be server connection
- Must have outstanding resumption validation request

**Postconditions**:
- Resumption validation completed
- Connection proceeds or rejects 0-RTT based on Result

**Side Effects**:
- Queues validation complete operation
- May accept or reject 0-RTT data

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle

---

#### 20. `MsQuicConnectionCertificateValidationComplete`
**Signature**:
```c
QUIC_STATUS MsQuicConnectionCertificateValidationComplete(
    HQUIC Handle,
    BOOLEAN Result,
    QUIC_TLS_ALERT_CODES TlsAlert)
```

**Purpose**: Completes async validation of a peer certificate

**Preconditions**:
- `Handle` must be valid connection handle
- Must have outstanding certificate validation request

**Postconditions**:
- Certificate validation completed
- Connection proceeds or fails based on Result

**Side Effects**:
- Queues validation complete operation
- May continue or abort handshake

**Error Codes**:
- `QUIC_STATUS_INVALID_PARAMETER`: Invalid handle

---

## Type/Object Invariants

### QUIC_CONNECTION State Machine

**States** (inferred from code):
1. **Created**: Connection allocated, not started
2. **Started**: Client connection started, handshake in progress
3. **Connected**: Handshake complete, data can flow
4. **ShuttingDown**: Graceful shutdown initiated
5. **Closed**: Connection closed, resources being released
6. **Freed**: Connection object freed

**State Transitions**:
- Created → Started: `MsQuicConnectionStart` (client)
- Created → Connected: `MsQuicConnectionSetConfiguration` + handshake (server)
- Started → Connected: Handshake completes
- Any → ShuttingDown: `MsQuicConnectionShutdown`
- Any → Closed: `MsQuicConnectionClose` or error
- Closed → Freed: After all operations complete

**State Invariants**:
- In **Created**: ClientCallbackHandler set, Configuration may be NULL
- In **Started**: Configuration != NULL (client), State.Started = TRUE
- In **Connected**: State.Connected = TRUE, Crypto.TlsState.HandshakeComplete = TRUE
- In **Closed**: State.HandleClosed = TRUE, no new operations accepted
- In **Freed**: State.Freed = TRUE, handle invalid

**Key Flags**:
- `State.Started`: Connection handshake initiated
- `State.Connected`: Handshake complete
- `State.HandleClosed`: Application closed handle
- `State.ClosedLocally`: Local shutdown initiated
- `State.ClosedRemotely`: Remote shutdown received
- `State.Freed`: Memory freed
- `State.HandleShutdown`: Shutdown in progress
- `State.ResumptionEnabled`: 0-RTT resumption available

---

### QUIC_STREAM State Machine

**States**:
1. **Created**: Stream allocated, not started
2. **Started**: Stream ID assigned, ready for I/O
3. **SendShutdown**: Send direction closed (FIN sent)
4. **ReceiveShutdown**: Receive direction closed
5. **Closed**: Both directions closed
6. **Freed**: Stream object freed

**State Transitions**:
- Created → Started: `MsQuicStreamStart`
- Started → SendShutdown: `MsQuicStreamShutdown` (send) or `MsQuicStreamSend` with FIN
- Started → ReceiveShutdown: `MsQuicStreamShutdown` (receive) or FIN received
- Any → Closed: Both directions shut down
- Closed → Freed: After all operations complete

**Key Flags**:
- `Flags.Started`: Stream is started
- `Flags.HandleClosed`: Application closed handle
- `Flags.SendShutdown`: Send direction shut down
- `Flags.ReceiveShutdown`: Receive direction shut down

---

### QUIC_REGISTRATION
**Invariants**:
- `Handle.Type == QUIC_HANDLE_TYPE_REGISTRATION`
- Maintains list of configurations and connections
- Must be open before creating connections

---

### QUIC_CONFIGURATION
**Invariants**:
- `Handle.Type == QUIC_HANDLE_TYPE_CONFIGURATION`
- Must have SecurityConfig loaded before starting connection
- Contains ALPN buffers, settings, credentials

---

## Environment Invariants

1. **Initialization**: `MsQuic` global API table must be initialized before calling any API
2. **Threading**: Most APIs can be called at DISPATCH_LEVEL except Close, SetParam, GetParam (PASSIVE_LEVEL)
3. **Worker Thread**: Operations are processed on worker threads in the partition
4. **Operation Queue**: All state-changing operations go through operation queue for serialization
5. **Reference Counting**: All handles use reference counting; close decrements final ref
6. **Memory Pools**: Uses tagged memory pools (QUIC_POOL_*) for allocation tracking
7. **Locking**: No application-visible locks; internal synchronization via workers

---

## Key Dependencies

### Internal Functions Called by Public APIs:
- `QuicConnAlloc`: Allocates connection object
- `QuicConnRelease`: Releases connection reference
- `QuicConnQueueOper`: Queues operation to worker
- `QuicConnCloseHandle`: Internal close logic
- `QuicStreamAlloc`: Allocates stream object
- `QuicConfigurationAddRef`: Adds config reference
- `QuicLibraryGetCurrentPartition`: Gets current partition

### Platform Abstractions (CxPlat):
- `CxPlatEventInitialize/Set/WaitForever`: Event synchronization
- `CxPlatCopyMemory`: Memory operations
- `CXPLAT_ALLOC_NONPAGED/CXPLAT_FREE`: Memory allocation
- `CxPlatCurThreadID`: Thread ID retrieval

---

## Contract Notes

1. **Handle Validation**: All public APIs validate handle types using IS_*_HANDLE macros
2. **Defensive Programming**: `_Pre_defensive_` annotations indicate validation of untrusted inputs
3. **Async Operations**: Most operations return immediately after queuing (QUIC_STATUS_PENDING)
4. **Completion Callbacks**: App notified via callbacks, not return values
5. **Error Handling**: Invalid inputs return error; internal errors may assert in debug builds
6. **Memory Ownership**: 
   - Handles: App owns, must close
   - Buffers passed to send: MsQuic copies or retains until send complete
   - Received data: App must call ReceiveComplete to return buffers
7. **No Precondition Violations in Tests**: Tests must not pass NULL where required, invalid handles, wrong handle types, or violate state machine transitions

---

## Coverage Strategy

To achieve 100% coverage of api.c:

1. **Positive Paths**: Test successful execution of each public API
2. **Parameter Validation**: Test each validation check (NULL params, invalid types, out-of-range values)
3. **State Validation**: Test invalid state transitions (e.g., start already-started connection)
4. **Memory Paths**: Test allocation failure paths where possible
5. **Handle Type Variations**: Test APIs that accept connection OR stream handle
6. **Threading Paths**: Test worker thread vs app thread execution (for Close)
7. **Edge Cases**: Empty buffers, boundary values, special flags
8. **Integration Scenarios**: Multi-step scenarios (open→start→send→close)

All tests must use only public APIs and respect contracts.
