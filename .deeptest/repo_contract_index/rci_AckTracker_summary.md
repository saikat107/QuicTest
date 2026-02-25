# Repository Contract Index: AckTracker Component

## Public API Inventory

### 1. QuicAckTrackerInitialize(Tracker)
- **Signature**: `void QuicAckTrackerInitialize(QUIC_ACK_TRACKER* Tracker)`
- **Declared in**: `src/core/ack_tracker.h:66-68`
- **Summary**: Initializes the two QUIC_RANGE structures (PacketNumbersReceived, PacketNumbersToAck)
- **Preconditions**: Tracker must point to valid memory. Tracker should not be already initialized.
- **Postconditions**: Both ranges initialized with max alloc sizes. Other fields unchanged.
- **Side effects**: None
- **Error contract**: None (void return)
- **Thread-safety**: Not thread-safe

### 2. QuicAckTrackerUninitialize(Tracker)
- **Signature**: `void QuicAckTrackerUninitialize(QUIC_ACK_TRACKER* Tracker)`
- **Declared in**: `src/core/ack_tracker.h:75-77`
- **Summary**: Frees memory allocated by the two QUIC_RANGE structures
- **Preconditions**: Tracker must have been initialized via QuicAckTrackerInitialize
- **Postconditions**: Both ranges freed
- **Side effects**: Frees heap memory
- **Error contract**: None (void return)
- **Thread-safety**: Not thread-safe

### 3. QuicAckTrackerReset(Tracker)
- **Signature**: `void QuicAckTrackerReset(QUIC_ACK_TRACKER* Tracker)`
- **Declared in**: `src/core/ack_tracker.h:84-86`
- **Summary**: Resets all tracker state to initial values
- **Preconditions**: Tracker must have been initialized
- **Postconditions**: All counters zeroed, flags cleared, ECN zeroed, ranges reset
- **Side effects**: None (just state reset)
- **Error contract**: None
- **Thread-safety**: Not thread-safe

### 4. QuicAckTrackerAddPacketNumber(Tracker, PacketNumber)
- **Signature**: `BOOLEAN QuicAckTrackerAddPacketNumber(QUIC_ACK_TRACKER* Tracker, uint64_t PacketNumber)`
- **Declared in**: `src/core/ack_tracker.h:93-96`
- **Summary**: Adds a packet number to the duplicate detection range. Returns TRUE if duplicate.
- **Preconditions**: Tracker must be initialized
- **Postconditions**: PacketNumber added to PacketNumbersReceived range
- **Return**: TRUE if packet is a duplicate (already in range or alloc failure), FALSE if new
- **Error contract**: Returns TRUE on allocation failure (treats as duplicate)
- **Thread-safety**: Not thread-safe

### 5. QuicAckTrackerDidHitReorderingThreshold(Tracker, ReorderingThreshold)
- **Signature**: `BOOLEAN QuicAckTrackerDidHitReorderingThreshold(QUIC_ACK_TRACKER* Tracker, uint8_t ReorderingThreshold)`
- **Declared in**: `src/core/ack_tracker.h:98-102`
- **Summary**: Checks if reordering threshold has been hit per draft-ietf-quic-frequence-10 §6.2
- **Preconditions**: Tracker must be initialized, PacketNumbersToAck should have entries
- **Return**: TRUE if reordering exceeds threshold, FALSE otherwise
- **Key logic**: Returns FALSE if threshold==0 or fewer than 2 ranges. Iterates ranges to find smallest missing packet after LargestReported.
- **Thread-safety**: Not thread-safe (read-only but not const in signature)

### 6. QuicAckTrackerAckPacket(Tracker, PacketNumber, RecvTimeUs, ECN, AckType)
- **Signature**: `void QuicAckTrackerAckPacket(QUIC_ACK_TRACKER* Tracker, uint64_t PacketNumber, uint64_t RecvTimeUs, CXPLAT_ECN_TYPE ECN, QUIC_ACK_TYPE AckType)`
- **Declared in**: `src/core/ack_tracker.h:115-121`
- **Summary**: Adds packet to acknowledgment range and manages ACK timing/flags
- **Preconditions**: Tracker must be embedded in QUIC_PACKET_SPACE with valid Connection. PacketNumber <= QUIC_VAR_INT_MAX. Must be non-duplicate (caller checks).
- **Postconditions**: PacketNumber added to PacketNumbersToAck. ECN counters updated. ACK flags or timer set on Connection.
- **Side effects**: May set QUIC_CONN_SEND_FLAG_ACK on Connection.Send, start delayed ACK timer, or call QuicConnTransportError on alloc failure.
- **Error contract**: On allocation failure, calls QuicConnTransportError (fatal for connection)
- **Thread-safety**: Not thread-safe

### 7. QuicAckTrackerAckFrameEncode(Tracker, Builder)
- **Signature**: `BOOLEAN QuicAckTrackerAckFrameEncode(QUIC_ACK_TRACKER* Tracker, QUIC_PACKET_BUILDER* Builder)`
- **Declared in**: `src/core/ack_tracker.h:129-132`
- **Summary**: Encodes current ACK state into a QUIC ACK frame
- **Preconditions**: QuicAckTrackerHasPacketsToAck(Tracker) must be TRUE. Builder must be properly initialized.
- **Return**: TRUE if encode succeeded, FALSE if not enough room
- **Postconditions**: On success: AlreadyWrittenAckFrame=TRUE, LargestPacketNumberAcknowledged updated, AckElicitingPacketsToAcknowledge cleared.
- **Side effects**: Modifies Builder state (DatagramLength, Metadata)
- **Thread-safety**: Not thread-safe

### 8. QuicAckTrackerOnAckFrameAcked(Tracker, LargestAckedPacketNumber)
- **Signature**: `void QuicAckTrackerOnAckFrameAcked(QUIC_ACK_TRACKER* Tracker, uint64_t LargestAckedPacketNumber)`
- **Declared in**: `src/core/ack_tracker.h:139-142`
- **Summary**: Handles acknowledgment of a previously-sent ACK frame. Removes ranges <= LargestAckedPacketNumber.
- **Preconditions**: Tracker must be embedded in QUIC_PACKET_SPACE with valid Connection.
- **Postconditions**: PacketNumbersToAck min raised to LargestAckedPacketNumber+1.
- **Side effects**: May clear AckElicitingPacketsToAcknowledge and update Send state.
- **Thread-safety**: Not thread-safe

### 9. QuicAckTrackerHasPacketsToAck(Tracker) [inline]
- **Signature**: `BOOLEAN QuicAckTrackerHasPacketsToAck(const QUIC_ACK_TRACKER* Tracker)`
- **Declared in**: `src/core/ack_tracker.h:151-158`
- **Summary**: Returns TRUE if there are unacknowledged packets that need a new ACK frame.
- **Logic**: !AlreadyWrittenAckFrame && PacketNumbersToAck size != 0
- **Thread-safety**: Not thread-safe (read-only)

## Type/Object Invariants

### QUIC_ACK_TRACKER
- PacketNumbersReceived: Valid QUIC_RANGE with max alloc QUIC_MAX_RANGE_DUPLICATE_PACKETS (4096)
- PacketNumbersToAck: Valid QUIC_RANGE with max alloc QUIC_MAX_RANGE_ACK_PACKETS (2048)
- LargestPacketNumberAcknowledged: Updated only by AckFrameEncode
- LargestPacketNumberRecvTime: Set when receiving the new largest packet
- AckElicitingPacketsToAcknowledge: Count of ACK-eliciting packets not yet ACKed
- AlreadyWrittenAckFrame: TRUE after encoding, FALSE when new packet received
- NonZeroRecvECN: TRUE once any non-zero ECN type is seen
- ReceivedECN: Running counters per ECN type

### State Machine
- **Empty**: No packets received. HasPacketsToAck = FALSE.
- **Receiving**: Packets added via AckPacket. HasPacketsToAck = TRUE (AlreadyWrittenAckFrame = FALSE).
- **Written**: AckFrameEncode called. AlreadyWrittenAckFrame = TRUE. HasPacketsToAck = FALSE.
- **Acked**: OnAckFrameAcked called. Ranges trimmed.

Transitions:
- Empty -> Receiving: AckPacket(non-dup)
- Receiving -> Written: AckFrameEncode
- Written -> Receiving: AckPacket(new packet)
- Written/Receiving -> Acked: OnAckFrameAcked
- Acked -> Receiving: AckPacket(new packet)
- Any -> Empty: Reset

## Environment Invariants
- MsQuicLib must be initialized (MsQuicLibraryLoad + MsQuicAddRef)
- For AckPacket/OnAckFrameAcked/AckFrameEncode: Tracker must be embedded in QUIC_PACKET_SPACE via CXPLAT_CONTAINING_RECORD
- Connection.Send must be properly set up for QuicSendSetSendFlag/QuicSendUpdateAckState calls

## Dependency Map
- QuicAckTrackerInitialize -> QuicRangeInitialize (x2)
- QuicAckTrackerUninitialize -> QuicRangeUninitialize (x2)
- QuicAckTrackerReset -> QuicRangeReset (x2)
- QuicAckTrackerAddPacketNumber -> QuicRangeAddRange
- QuicAckTrackerDidHitReorderingThreshold -> QuicRangeSize, QuicRangeGetMax, QuicRangeGet, QuicRangeGetHigh
- QuicAckTrackerAckPacket -> QuicRangeGetMaxSafe, QuicRangeAddValue, QuicRangeGetMax, QuicAckTrackerDidHitReorderingThreshold, QuicSendSetSendFlag, QuicSendStartDelayedAckTimer, QuicSendValidate, QuicConnTransportError
- QuicAckTrackerAckFrameEncode -> CxPlatTimeUs64, CxPlatTimeDiff64, QuicTimestampFrameEncode, QuicAckFrameEncode, QuicSendUpdateAckState, QuicPacketBuilderAddFrame
- QuicAckTrackerOnAckFrameAcked -> QuicRangeSetMin, QuicAckTrackerHasPacketsToAck, QuicSendUpdateAckState
