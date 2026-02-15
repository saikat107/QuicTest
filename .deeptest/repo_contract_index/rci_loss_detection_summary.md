# Repository Contract Index - QUIC Loss Detection

## Component: QUIC-LOSS-DETECTION
**Source**: `src/core/loss_detection.c`  
**Header**: `src/core/loss_detection.h`

---

## Public API Inventory

### 1. `QuicLossDetectionInitialize`
**Signature**: `void QuicLossDetectionInitialize(_Inout_ QUIC_LOSS_DETECTION* LossDetection)`

**Purpose**: Initializes a QUIC_LOSS_DETECTION structure for a new connection

**Preconditions**:
- `LossDetection` must be non-NULL and point to valid memory
- Must be called before any other loss detection operations

**Postconditions**:
- `SentPackets` list is empty (NULL)
- `LostPackets` list is empty (NULL)
- All counters zeroed (PacketsInFlight, TotalBytesSent, TotalBytesAcked, etc.)
- Tail pointers properly initialized

**Side Effects**: Modifies LossDetection structure in-place

**Thread Safety**: Not thread-safe; caller must synchronize

---

### 2. `QuicLossDetectionUninitialize`
**Signature**: `void QuicLossDetectionUninitialize(_In_ QUIC_LOSS_DETECTION* LossDetection)`

**Purpose**: Cleans up loss detection state, discarding all tracked packets

**Preconditions**:
- `LossDetection` must be initialized via `QuicLossDetectionInitialize`
- Must be embedded in a valid QUIC_CONNECTION structure (required for QuicLossDetectionGetConnection)

**Postconditions**:
- All SentPackets are discarded and freed
- All LostPackets are discarded and freed
- Frames in packets are retransmitted or released

**Side Effects**:
- Calls QuicLossDetectionOnPacketDiscarded for each packet
- Frees packet metadata
- May trigger frame retransmission

---

### 3. `QuicLossDetectionReset`
**Signature**: `void QuicLossDetectionReset(_In_ QUIC_LOSS_DETECTION* LossDetection)`

**Purpose**: Resets loss detection state, cancelling timer and retransmitting all outstanding packets

**Preconditions**:
- `LossDetection` must be initialized
- Must be embedded in a valid QUIC_CONNECTION

**Postconditions**:
- Loss detection timer cancelled
- All internal counters reset to zero
- All packets retransmitted
- SentPackets and LostPackets lists cleared

**Side Effects**:
- Cancels QUIC_CONN_TIMER_LOSS_DETECTION timer
- Calls QuicLossDetectionRetransmitFrames for all packets

---

### 4. `QuicLossDetectionDiscardPackets`
**Signature**: `void QuicLossDetectionDiscardPackets(_In_ QUIC_LOSS_DETECTION* LossDetection, _In_ QUIC_PACKET_KEY_TYPE KeyType)`

**Purpose**: Discards all packets of a specific key type when that encryption level is no longer needed

**Preconditions**:
- `LossDetection` must be initialized
- `KeyType` must be valid (QUIC_PACKET_KEY_INITIAL, HANDSHAKE, 0_RTT, or 1_RTT)

**Postconditions**:
- All packets with matching KeyType removed from SentPackets
- All packets with matching KeyType removed from LostPackets
- Congestion control updated for lost data

**Side Effects**:
- Updates PacketsInFlight counter
- May trigger congestion control adjustments

---

### 5. `QuicLossDetectionOnZeroRttRejected`
**Signature**: `void QuicLossDetectionOnZeroRttRejected(_In_ QUIC_LOSS_DETECTION* LossDetection)`

**Purpose**: Handles rejection of 0-RTT data by discarding all 0-RTT packets

**Preconditions**:
- `LossDetection` must be initialized
- Typically called when server rejects 0-RTT

**Postconditions**:
- All 0-RTT packets discarded
- Frames from 0-RTT packets marked for retransmission in 1-RTT

---

### 6. `QuicLossDetectionUpdateTimer`
**Signature**: `void QuicLossDetectionUpdateTimer(_In_ QUIC_LOSS_DETECTION* LossDetection, _In_ BOOLEAN ExecuteImmediatelyIfNecessary)`

**Purpose**: Updates/rearms the loss detection timer based on current state

**Preconditions**:
- `LossDetection` must be initialized
- Connection must have valid Path with SmoothedRtt != 0 (when packets are outstanding)

**Postconditions**:
- Timer set appropriately (RACK, PROBE, or INITIAL timer)
- Timer cancelled if no outstanding packets or connection closed
- If `ExecuteImmediatelyIfNecessary` is TRUE and timer expired, processes immediately

**Timer Types**:
- **RACK Timer**: Set when packet with later ack exists, fires after TIME_REORDER_THRESHOLD
- **PROBE Timer**: Set when no later ack exists, uses PTO calculation
- **INITIAL Timer**: Used before first RTT sample available

---

### 7. `QuicLossDetectionComputeProbeTimeout`
**Signature**: `uint64_t QuicLossDetectionComputeProbeTimeout(_In_ QUIC_LOSS_DETECTION* LossDetection, _In_ const QUIC_PATH* Path, _In_ uint32_t Count)`

**Purpose**: Computes Probe Timeout (PTO) value in microseconds

**Preconditions**:
- `Path->SmoothedRtt` must be non-zero (ASSERT if violated)
- `LossDetection` and `Path` must be non-NULL

**Returns**: PTO value in microseconds

**Formula**: `(SmoothedRtt + 4*RttVariance + MaxAckDelay) * Count`

---

### 8. `QuicLossDetectionOnPacketSent`
**Signature**: `void QuicLossDetectionOnPacketSent(_In_ QUIC_LOSS_DETECTION* LossDetection, _In_ QUIC_PATH* Path, _In_ QUIC_SENT_PACKET_METADATA* SentPacket)`

**Purpose**: Called when a packet is sent; tracks it for loss detection

**Preconditions**:
- `SentPacket->FrameCount` must be non-zero (ASSERT if violated)
- `SentPacket` contains temporary metadata that caller will release
- Must be embedded in valid QUIC_CONNECTION

**Postconditions**:
- Packet metadata copied and added to SentPackets tail
- If ack-eliciting: PacketsInFlight incremented
- TotalBytesSent updated
- Congestion control notified
- If allocation fails: frames immediately marked for retransmission

**Side Effects**:
- Allocates permanent packet metadata from pool
- Updates statistics
- May trigger idle timeout reset
- May mark connection as app-limited

---

### 9. `QuicLossDetectionProcessAckFrame`
**Signature**: `BOOLEAN QuicLossDetectionProcessAckFrame(_In_ QUIC_LOSS_DETECTION* LossDetection, _In_ QUIC_PATH* Path, _In_ QUIC_RX_PACKET* Packet, _In_ QUIC_ENCRYPT_LEVEL EncryptLevel, _In_ QUIC_FRAME_TYPE FrameType, _In_ uint16_t BufferLength, _In_reads_bytes_(BufferLength) const uint8_t* Buffer, _Inout_ uint16_t* Offset, _Out_ BOOLEAN* InvalidFrame)`

**Purpose**: Processes an ACK frame from peer, acknowledging sent packets and detecting losses

**Preconditions**:
- All pointers must be non-NULL
- `Buffer` must contain valid ACK frame data at `*Offset`
- `BufferLength` must be sufficient

**Returns**: 
- TRUE if frame processed successfully
- FALSE on error (check `*InvalidFrame` to determine if frame was corrupt)

**Postconditions**:
- Acknowledged packets removed from SentPackets
- `*Offset` advanced past ACK frame
- `*InvalidFrame` set appropriately
- Lost packets detected and handled
- LargestAck updated if new maximum acknowledged
- Congestion control notified of acks and losses

**Error Contracts**:
- Returns FALSE with `*InvalidFrame = TRUE` if frame is malformed
- Returns FALSE with `*InvalidFrame = FALSE` on other processing errors

---

### 10. `QuicLossDetectionProcessTimerOperation`
**Signature**: `void QuicLossDetectionProcessTimerOperation(_In_ QUIC_LOSS_DETECTION* LossDetection)`

**Purpose**: Called when loss detection timer fires; sends probes or detects losses

**Preconditions**:
- `LossDetection` must be initialized
- Typically called from timer callback

**Postconditions**:
- Lost packets detected and handled (RACK timer case)
- Probe packets scheduled (PROBE timer case)
- ProbeCount incremented or reset as appropriate
- Timer re-armed via QuicLossDetectionUpdateTimer

**Side Effects**:
- May schedule probe packets (calls QuicLossDetectionScheduleProbe)
- May detect and handle losses (calls QuicLossDetectionDetectAndHandleLostPackets)
- Updates ProbeCount

---

## Type/Object Invariants

### QUIC_LOSS_DETECTION Structure

**Object Invariants** (must hold for valid instance):
1. `SentPackets` list is ordered by ascending packet number (with handshake exception)
2. `LostPackets` list is ordered by ascending packet number (with handshake exception)
3. `SentPacketsTail` always points to address of last Next pointer in SentPackets
4. `LostPacketsTail` always points to address of last Next pointer in LostPackets
5. `PacketsInFlight` equals count of IsAckEliciting packets in SentPackets
6. `LargestSentPacketNumber` >= all packet numbers in SentPackets
7. If `LargestAck` > 0, then `LargestAckEncryptLevel` is valid
8. `TotalBytesSent` >= `TotalBytesAcked`
9. All packet metadata in lists has `Freed` flag = FALSE (debug builds)

**Lifetime Invariants**:
- Must call `QuicLossDetectionInitialize` before use
- Must call `QuicLossDetectionUninitialize` before free
- Must be embedded in QUIC_CONNECTION structure (required by GetConnection macro)

---

### QUIC_SENT_PACKET_METADATA Structure

**Object Invariants**:
1. `FrameCount` <= QUIC_MAX_FRAMES_PER_PACKET (12)
2. If `Flags.IsAckEliciting`, packet must be counted in LossDetection->PacketsInFlight
3. If `Flags.HasLastAckedPacketInfo`, LastAckedPacketInfo fields are valid
4. `PacketNumber` is unique per connection
5. `SentTime` is monotonically increasing (generally) within same key type

---

## State Machine

### Loss Detection States (Implicit)

The loss detection module doesn't have explicit states, but operates in different modes:

**Mode 1: No Outstanding Packets**
- Invariant: `PacketsInFlight == 0`, `SentPackets` empty or only non-ack-eliciting
- Transitions:
  - `OnPacketSent(ack-eliciting)` → Mode 2

**Mode 2: Outstanding Packets, No RTT Sample**
- Invariant: `Path->GotFirstRttSample == FALSE`
- Timer: INITIAL timer (uses InitialRtt estimate)
- Transitions:
  - Receive ACK with RTT sample → Mode 3 or 4
  - All packets acknowledged → Mode 1

**Mode 3: Outstanding Packets with RACK Opportunity**
- Invariant: Oldest ack-eliciting packet has `PacketNumber < LargestAck`
- Timer: RACK timer (time-based reordering detection)
- Transitions:
  - RACK timer fires → detect losses → possibly Mode 4 or 1
  - Packet acknowledged → may stay in Mode 3 or go to Mode 4

**Mode 4: Outstanding Packets, No RACK Opportunity**
- Invariant: All outstanding packets sent after `LargestAck` OR no ack yet
- Timer: PROBE timer (PTO-based)
- Transitions:
  - PROBE timer fires → schedule probes, increment ProbeCount
  - Packet acknowledged → reset ProbeCount, may go to Mode 3 or 1

**State Transition Diagram**:
```
                    ┌─────────────────┐
                    │ Mode 1: No Pkts │
                    │  Outstanding    │
                    └────────┬────────┘
                             │
          Send ack-eliciting │
                             ↓
                    ┌─────────────────┐
                    │ Mode 2: No RTT  │
             ┌─────▶│     Sample      │
             │      └────────┬────────┘
             │               │
             │ Recv ACK      │ First RTT sample
             │ (all acked)   ↓
             │      ┌─────────────────┐
             │      │ Mode 3: RACK    │◀────┐
             │      │  Opportunity    │     │
             │      └────────┬────────┘     │
             │               │               │
             │ RACK timer /  │ Oldest pkt   │ ACK arrives
             │ All acked     │ > LargestAck │ (new RACK opp)
             │               ↓               │
             │      ┌─────────────────┐     │
             └──────│ Mode 4: PROBE   │─────┘
                    │     Timer       │
                    └─────────────────┘
                         │
                         │ PROBE timer
                         └──► Send probes, increment ProbeCount
```

---

## Environment Invariants

### Global/Module State
1. **Initialization Requirement**: Connection's SentPacketPool must be initialized before calling OnPacketSent
2. **Memory Allocation**: Packet metadata allocated from SentPacketPool; if allocation fails, frames immediately retransmitted
3. **Timer Management**: Only one QUIC_CONN_TIMER_LOSS_DETECTION timer per connection
4. **Connection Closure**: Timer must be cancelled when connection closes

### Locking Discipline
- Loss detection is single-threaded within a connection's execution context
- All operations assume caller holds connection lock (implicit)
- No internal locking required

### Resource Ownership
- **Packet Metadata**: Allocated by OnPacketSent, owned by loss detection until:
  - Acknowledged → freed in ProcessAckFrame
  - Lost → moved to LostPackets temporarily, then freed
  - Discarded → freed in Uninitialize/Reset/DiscardPackets
- **Frames**: Ownership passed to retransmission logic when packet lost/discarded

---

## Dependency Map

### Key Dependencies

**Internal (within loss_detection.c)**:
- `QuicLossDetectionRetransmitFrames`: Marks frames for retransmission (private)
- `QuicLossDetectionOnPacketDiscarded`: Handles packet cleanup (private)
- `QuicLossDetectionDetectAndHandleLostPackets`: RACK/FACK loss detection (private)
- `QuicLossDetectionScheduleProbe`: Schedules probe packets (private)
- `QuicLossDetectionOldestOutstandingPacket`: Finds oldest ack-eliciting packet (private)

**External Dependencies**:
- `QUIC_CONNECTION`: Parent structure, accessed via QuicLossDetectionGetConnection
- `QuicConnTimerSet/Cancel`: Timer management
- `QuicCongestionControl*`: Congestion control notifications
- `QuicSentPacketPoolGetPacketMetadata`: Packet metadata allocation
- `QuicSentPacketMetadataReleaseFrames`: Frame cleanup
- `QuicStreamOnLoss/OnAck`: Stream-specific callbacks
- `QuicCryptoOnLoss`: Crypto frame callbacks

### Call Relationships

**Entry Points** (called by connection layer):
1. `Initialize` → called at connection creation
2. `Uninitialize` → called at connection cleanup
3. `Reset` → called on connection reset
4. `OnPacketSent` → called by send path after packet transmission
5. `ProcessAckFrame` → called by receive path when ACK frame received
6. `ProcessTimerOperation` → called by timer callback
7. `DiscardPackets` → called when encryption level discarded
8. `OnZeroRttRejected` → called when 0-RTT rejected
9. `UpdateTimer` → called after state changes
10. `ComputeProbeTimeout` → utility function

**Outbound Calls** (to other modules):
- Connection: Timer operations, idle timeout, statistics
- Congestion Control: OnDataSent, OnDataAcknowledged, OnDataLost, OnDataInvalidated
- Streams: OnLoss, OnAck callbacks per frame
- Crypto: OnLoss callback for CRYPTO frames
- Packet Pool: Allocate/free metadata

---

## Contract-Reachable Coverage Goals

All public functions should be fully testable through the public API by:
1. Creating a mock QUIC_CONNECTION with embedded QUIC_LOSS_DETECTION
2. Simulating packet send operations via `OnPacketSent`
3. Simulating ACK reception via `ProcessAckFrame`
4. Triggering timer operations via `ProcessTimerOperation` or `UpdateTimer(TRUE)`
5. Testing lifecycle via `Initialize`, `Reset`, `Uninitialize`
6. Testing special cases via `DiscardPackets`, `OnZeroRttRejected`

All internal functions are exercised transitively through public API scenarios.

**Expected Coverage**: 100% of lines in loss_detection.c should be reachable through realistic scenarios that respect the contract.
