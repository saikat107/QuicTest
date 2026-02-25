# Test Reflection: Api Component (Updated)

## Summary
- **Component**: Api (src/core/api.c)
- **Tests**: 176 passing
- **Coverage**: 84.0% (669/796 lines)
- **Contract-unreachable remaining**: 127 lines

## Coverage Breakdown of Remaining Uncovered Lines

### OOM/Allocation Failure Paths (70 lines)
These paths require malloc/pool allocation to fail. Not testable without fault injection.
- Line 79: MsQuicConnectionOpen - QuicConnAlloc failure
- Lines 421-464: MsQuicConnectionStart - server name alloc + operation alloc failure
- Lines 628-667: MsQuicConnectionSendResumptionTicket - data copy + operation alloc failure
- Line 732: MsQuicStreamOpen - QuicStreamInitialize failure
- Lines 903-909: MsQuicStreamStart - operation alloc failure
- Lines 1027-1033: MsQuicStreamShutdown - operation alloc failure
- Lines 1128-1134: MsQuicStreamSend - SendRequest pool alloc failure
- Lines 1213-1245: MsQuicStreamSend - operation alloc + BackUpOper emergency
- Lines 1305-1311: MsQuicStreamReceiveSetEnabled - operation alloc failure
- Lines 1515-1522: MsQuicStreamProvideReceiveBuffers - chunk pool alloc failure
- Lines 1539-1547: MsQuicStreamProvideReceiveBuffers - operation alloc failure
- Lines 1896-1897: MsQuicDatagramSend - SendRequest alloc failure
- Lines 2036-2042: MsQuicCertificateValidationComplete - operation alloc failure

### Server Success-Queue Paths (21 lines)
These paths require a fully established server-side connection (real TLS handshake).
- Lines 533-554: MsQuicConnectionSetConfiguration - server config success + queue
- Lines 1964-1982: MsQuicResumptionTicketValidationComplete - success + queue

### Debug Assertion Paths (10 lines)
These paths trigger CXPLAT_FRE_ASSERT or QUIC_CONN_VERIFY in debug builds.
- Line 188: MsQuicConnectionClose - worker-thread close after HandleClosed
- Lines 292-293: MsQuicConnectionShutdown - ErrorCode > QUIC_UINT62_MAX
- Lines 304-310: MsQuicConnectionShutdown - BackUpOper path (OOM prerequisite)
- Line 789: MsQuicStreamClose - worker-thread close after HandleClosed

### StreamProvideReceiveBuffers (26 lines)
Complex callback-context paths requiring PeerStreamStartEventActive or real app-owned buffer setup.
- Lines 1490-1498: PeerStreamStartEventActive inline path
- Lines 1512-1534: Chunk allocation + inline execution
- Lines 1549-1582: Queued path + error cleanup

## Mock-Based Test Categories Added

### Worker-Thread Inline Tests (12 tests)
- SetParam/GetParam on connection/stream with WorkerThreadID = CxPlatCurThreadID()
- SetParam/GetParam with HIGH_PRIORITY flag on worker thread
- ConnectionClose inline (QuicConnCloseHandle)
- ConnectionClose with CloseAsync=TRUE
- StreamClose inline (QuicStreamClose)
- StreamShutdown with INLINE flag on worker thread
- StreamSend with SendBufferingEnabled=FALSE on worker thread

### ClosedRemotely/ClosedLocally Tests (5 tests)
- StreamOpen/StreamStart/StreamSend on ClosedRemotely connection
- StreamOpen on ClosedLocally connection
- ConnectionStart on ClosedLocally connection

### Server-Type Error Path Tests (8 tests)
- ConnectionSetConfig: NULL SecurityConfig, already-configured
- SendResumptionTicket: not-ResumeEnabled, not-Connected, not-HandshakeComplete
- ResumeTicketValidation: HandshakeComplete, SessionResumed
- CertValidation: invalid TlsAlert

### Stream State Manipulation Tests (5 tests)
- StreamSend with SendEnabled=FALSE
- StreamStart with Started=TRUE
- ConnectionStart with Started=TRUE
- StreamReceiveComplete canary overflow + BackUpOperUsed
- StreamReceiveComplete with RECEIVE_CALL_ACTIVE_FLAG

## Bug Reports
No bugs discovered. All test failures were due to debug assertions triggered by
violated internal invariants, which is expected behavior in debug builds.
