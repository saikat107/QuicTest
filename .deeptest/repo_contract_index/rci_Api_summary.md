# Repository Contract Index: Api Component

## Source: `src/core/api.c` (2063 lines)
## Header: `src/core/api.h` (354 lines)

## Public API Inventory

| # | Function | Lines | Summary |
|---|----------|-------|---------|
| 1 | `QuicConnectionOpenInPartition` | 33-104 | Internal: Allocate and initialize a new client connection in a specific partition |
| 2 | `MsQuicConnectionOpen` | 106-125 | Open a new client connection using current partition |
| 3 | `MsQuicConnectionOpenInPartition` | 127-147 | Open a new client connection in a specific partition (public API wrapper) |
| 4 | `MsQuicConnectionClose` | 149-258 | Close a connection handle (sync blocking or async via worker) |
| 5 | `MsQuicConnectionShutdown` | 260-328 | Shutdown a connection (or via stream handle). Queues operation |
| 6 | `MsQuicConnectionStart` | 330-473 | Start a client connection to a server |
| 7 | `MsQuicConnectionSetConfiguration` | 475-564 | Set configuration on a server-side connection |
| 8 | `MsQuicConnectionSendResumptionTicket` | 566-676 | Send a resumption ticket from server to client |
| 9 | `MsQuicStreamOpen` | 678-746 | Open a new stream on a connection (or via stream handle) |
| 10 | `MsQuicStreamClose` | 748-855 | Close a stream handle |
| 11 | `MsQuicStreamStart` | 857-940 | Start a stream (queue operation to worker) |
| 12 | `MsQuicStreamShutdown` | 942-1061 | Shutdown a stream in specified direction(s) |
| 13 | `MsQuicStreamSend` | 1063-1269 | Send data on a stream |
| 14 | `MsQuicStreamReceiveSetEnabled` | 1271-1338 | Enable/disable receive processing on a stream |
| 15 | `MsQuicStreamReceiveComplete` | 1340-1438 | Complete a receive operation on a stream |
| 16 | `MsQuicStreamProvideReceiveBuffers` | 1440-1590 | Provide app-owned receive buffers |
| 17 | `MsQuicSetParam` | 1592-1715 | Set a parameter on a handle |
| 18 | `MsQuicGetParam` | 1717-1841 | Get a parameter from a handle |
| 19 | `MsQuicDatagramSend` | 1843-1917 | Send a datagram on a connection |
| 20 | `MsQuicConnectionResumptionTicketValidationComplete` | 1919-1992 | Complete resumption ticket validation |
| 21 | `MsQuicConnectionCertificateValidationComplete` | 1994-2063 | Complete certificate validation |

## Handle Routing Pattern

Many APIs accept both connection and stream handles via `IS_CONN_HANDLE`/`IS_STREAM_HANDLE` macros:
- ConnectionShutdown, StreamOpen, ConnectionSetConfiguration, SendResumptionTicket,
  ResumptionTicketValidationComplete, CertificateValidationComplete
- Stream handles extract the parent connection: `Connection = Stream->Connection`

## Key Contracts

1. **Handle Type Validation**: All APIs validate handle type; invalid types return `QUIC_STATUS_INVALID_PARAMETER`
2. **NULL Parameter Checks**: NULL required params return `QUIC_STATUS_INVALID_PARAMETER`  
3. **Client vs Server**: Several APIs are server-only (SetConfiguration, SendResumptionTicket, ResumptionTicketValidation)
4. **Worker Thread Execution**: Many APIs have inline (worker thread) vs queued (non-worker) paths
5. **Debug Assertions**: `CXPLAT_DBG_ASSERT`/`QUIC_CONN_VERIFY` crash in debug builds on certain invalid inputs
6. **Synchronous Blocking**: SetParam/GetParam on connection/stream handles block via `CxPlatEventWaitForever`

## Coverage Analysis (74.2%)

**Covered (591/796 lines):**
- All parameter validation paths
- Client-side API usage patterns
- Handle routing (connection + stream handles)
- SetParam/GetParam with global, registration, configuration, listener, connection, stream handles
- Priority queue paths for Set/GetParam
- Stream lifecycle (open, start, send, shutdown, close)
- DatagramSend validation and queueing

**Contract-Unreachable from Test Harness (205 lines):**
- OOM/allocation failure paths (~60 lines) - require fault injection
- Worker thread inline paths (~50 lines) - require worker thread context
- Server-side connection paths (~55 lines) - require server connection handle
- Remote close paths (~10 lines) - require actual remote peer
- Debug assertion paths (~5 lines) - crash in debug builds
- Synchronous blocking paths (~15 lines) - hang on CxPlatEventWaitForever
