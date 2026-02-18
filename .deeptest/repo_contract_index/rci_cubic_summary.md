# Repository Contract Index: CUBIC Congestion Control Component

## Component Overview
**Source File**: `src/core/cubic.c`  
**Header File**: `src/core/cubic.h`  
**Purpose**: Implementation of CUBIC congestion control algorithm (RFC 8312) for QUIC protocol

## Public API Functions

### 1. CubicCongestionControlInitialize
**Signature**: `void CubicCongestionControlInitialize(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ const QUIC_SETTINGS_INTERNAL* Settings)`  
**Summary**: Initializes the CUBIC congestion control state machine and sets up function pointers  
**Preconditions**:
- `Cc` must be non-null and point to valid memory
- `Settings` must be non-null with valid InitialWindowPackets and SendIdleTimeoutMs
- Connection structure must be properly initialized (accessible via QuicCongestionControlGetConnection)
- Connection->Paths[0] must be initialized with a valid MTU

**Postconditions**:
- All 17 function pointers in Cc are set to CUBIC implementations
- SlowStartThreshold set to UINT32_MAX
- CongestionWindow initialized based on MTU and InitialWindowPackets
- BytesInFlightMax set to CongestionWindow / 2
- HyStart state initialized to HYSTART_NOT_STARTED
- All state flags (IsInRecovery, HasHadCongestionEvent, etc.) set to FALSE

**Thread Safety**: Must be called at DISPATCH_LEVEL or lower (IRQL annotation)

### 2. CubicCongestionControlCanSend
**Signature**: `BOOLEAN CubicCongestionControlCanSend(_In_ QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Determines if more data can be sent based on congestion window and exemptions  
**Preconditions**: Cc must be initialized via CubicCongestionControlInitialize  
**Postconditions**: Returns TRUE if BytesInFlight < CongestionWindow OR Exemptions > 0  
**Side Effects**: None (read-only)

### 3. CubicCongestionControlSetExemption
**Signature**: `void CubicCongestionControlSetExemption(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ uint8_t NumPackets)`  
**Summary**: Sets the number of packets that can be sent ignoring congestion window  
**Preconditions**: Cc must be initialized  
**Postconditions**: Cubic->Exemptions = NumPackets  
**Use Case**: Allows sending probe packets for loss recovery

### 4. CubicCongestionControlReset
**Signature**: `void CubicCongestionControlReset(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ BOOLEAN FullReset)`  
**Summary**: Resets congestion control state to initial conditions  
**Preconditions**: Cc must be initialized  
**Postconditions**:
- SlowStartThreshold reset to UINT32_MAX
- CongestionWindow reset to InitialWindowPackets * MTU
- HyStart state reset to HYSTART_NOT_STARTED
- IsInRecovery and HasHadCongestionEvent set to FALSE
- If FullReset: BytesInFlight reset to 0

### 5. CubicCongestionControlGetSendAllowance
**Signature**: `uint32_t CubicCongestionControlGetSendAllowance(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ uint64_t TimeSinceLastSend, _In_ BOOLEAN TimeSinceLastSendValid)`  
**Summary**: Calculates how many bytes can be sent, considering pacing if enabled  
**Preconditions**: Cc must be initialized  
**Returns**:
- 0 if BytesInFlight >= CongestionWindow (CC blocked)
- (CongestionWindow - BytesInFlight) if not pacing
- Paced allowance based on RTT if pacing enabled and conditions met

**Pacing Conditions**: PacingEnabled=TRUE, GotFirstRttSample=TRUE, SmoothedRtt >= QUIC_MIN_PACING_RTT, TimeSinceLastSendValid=TRUE

### 6. CubicCongestionControlOnDataSent
**Signature**: `void CubicCongestionControlOnDataSent(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ uint32_t NumRetransmittableBytes)`  
**Summary**: Called when data is sent; updates BytesInFlight and decrements exemptions  
**Preconditions**: Cc must be initialized  
**Postconditions**:
- BytesInFlight += NumRetransmittableBytes
- BytesInFlightMax updated if BytesInFlight exceeds it
- LastSendAllowance adjusted by NumRetransmittableBytes
- Exemptions decremented if > 0

### 7. CubicCongestionControlOnDataInvalidated
**Signature**: `BOOLEAN CubicCongestionControlOnDataInvalidated(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ uint32_t NumRetransmittableBytes)`  
**Summary**: Called when sent data is invalidated (e.g., dropped from send buffer); decrements BytesInFlight  
**Preconditions**: BytesInFlight >= NumRetransmittableBytes  
**Postconditions**: BytesInFlight -= NumRetransmittableBytes  
**Returns**: TRUE if transitioned from blocked to unblocked state

### 8. CubicCongestionControlOnDataAcknowledged
**Signature**: `BOOLEAN CubicCongestionControlOnDataAcknowledged(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ const QUIC_ACK_EVENT* AckEvent)`  
**Summary**: Core CUBIC logic; adjusts congestion window on ACK based on slow start vs congestion avoidance  
**Preconditions**:
- Cc must be initialized
- AckEvent must be non-null with valid fields (TimeNow, LargestAck, NumRetransmittableBytes, SmoothedRtt)
- BytesInFlight >= AckEvent->NumRetransmittableBytes

**Postconditions**:
- BytesInFlight decremented by BytesAcked
- If in recovery and LargestAck > RecoverySentPacketNumber: exit recovery
- If in slow start (CW < SSThresh): CW grows by BytesAcked / CWndSlowStartGrowthDivisor
- If in congestion avoidance: CW grows via CUBIC formula (t-K)^3 or AIMD
- CongestionWindow capped at 2 * BytesInFlightMax
- HyStart++ logic applied if enabled

**Returns**: TRUE if transitioned from blocked to unblocked

### 9. CubicCongestionControlOnDataLost
**Signature**: `void CubicCongestionControlOnDataLost(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ const QUIC_LOSS_EVENT* LossEvent)`  
**Summary**: Handles packet loss; triggers congestion event if loss is after recovery  
**Preconditions**:
- Cc must be initialized
- LossEvent must be valid with LargestPacketNumberLost, LargestSentPacketNumber, NumRetransmittableBytes
- BytesInFlight >= LossEvent->NumRetransmittableBytes

**Postconditions**:
- If loss after last congestion event: triggers CubicCongestionControlOnCongestionEvent
- BytesInFlight -= NumRetransmittableBytes
- RecoverySentPacketNumber = LargestSentPacketNumber
- HyStart state transitions to HYSTART_DONE

### 10. CubicCongestionControlOnEcn
**Signature**: `void CubicCongestionControlOnEcn(_In_ QUIC_CONGESTION_CONTROL* Cc, _In_ const QUIC_ECN_EVENT* EcnEvent)`  
**Summary**: Handles ECN congestion signal; treats as congestion event  
**Preconditions**: Cc initialized, EcnEvent valid  
**Postconditions**: Triggers CubicCongestionControlOnCongestionEvent with Ecn=TRUE

### 11. CubicCongestionControlOnSpuriousCongestionEvent
**Signature**: `BOOLEAN CubicCongestionControlOnSpuriousCongestionEvent(_In_ QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Reverts congestion window changes if congestion event was spurious  
**Preconditions**: Cc initialized  
**Postconditions**: If IsInRecovery=TRUE: restores prev state (WindowPrior, WindowMax, KCubic, SlowStartThreshold, CongestionWindow, AimdWindow)  
**Returns**: FALSE if not in recovery; TRUE if reverted and became unblocked

### 12. CubicCongestionControlLogOutFlowStatus
**Signature**: `void CubicCongestionControlLogOutFlowStatus(_In_ const QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Logs current congestion control statistics  
**Preconditions**: Cc initialized  
**Side Effects**: Emits trace event with BytesInFlight, CongestionWindow, connection flow control, RTT

### 13. CubicCongestionControlGetExemptions
**Signature**: `uint8_t CubicCongestionControlGetExemptions(_In_ const QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Returns current exemptions count  
**Preconditions**: Cc initialized  
**Returns**: Cubic->Exemptions

### 14. CubicCongestionControlGetBytesInFlightMax
**Signature**: `uint32_t CubicCongestionControlGetBytesInFlightMax(_In_ const QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Returns maximum BytesInFlight observed  
**Returns**: Cubic->BytesInFlightMax

### 15. CubicCongestionControlGetCongestionWindow
**Signature**: `uint32_t CubicCongestionControlGetCongestionWindow(_In_ const QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Returns current congestion window size  
**Returns**: Cubic->CongestionWindow

### 16. CubicCongestionControlIsAppLimited
**Signature**: `BOOLEAN CubicCongestionControlIsAppLimited(_In_ const QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Checks if application is limiting send rate  
**Returns**: Always FALSE (not implemented for CUBIC)

### 17. CubicCongestionControlSetAppLimited
**Signature**: `void CubicCongestionControlSetAppLimited(_In_ struct QUIC_CONGESTION_CONTROL* Cc)`  
**Summary**: Marks connection as app-limited  
**Side Effects**: None (not implemented for CUBIC)

### 18. CubicCongestionControlGetNetworkStatistics
**Signature**: `void CubicCongestionControlGetNetworkStatistics(_In_ const QUIC_CONNECTION* Connection, _In_ const QUIC_CONGESTION_CONTROL* Cc, _Out_ QUIC_NETWORK_STATISTICS* NetworkStatistics)`  
**Summary**: Populates network statistics structure  
**Preconditions**: All parameters non-null  
**Postconditions**: NetworkStatistics filled with BytesInFlight, PostedBytes, IdealBytes, SmoothedRTT, CongestionWindow, Bandwidth

## Internal Helper Functions (NOT PUBLIC - DO NOT TEST DIRECTLY)

### CubeRoot (static/private utility)
- Computes integer cube root for CUBIC formula  
- **DO NOT CALL DIRECTLY IN TESTS** - private implementation detail

### QuicConnLogCubic (internal logging)
- Logs CUBIC state to trace system  
- **DO NOT CALL DIRECTLY** - internal helper

### CubicCongestionHyStartChangeState (internal state machine)
- Manages HyStart++ state transitions  
- **DO NOT CALL DIRECTLY** - internal to congestion avoidance logic

### CubicCongestionHyStartResetPerRttRound (internal)
- Resets per-RTT-round HyStart counters  
- **DO NOT CALL DIRECTLY**

### CubicCongestionControlUpdateBlockedState (internal)
- Updates blocked/unblocked state and notifies connection  
- **DO NOT CALL DIRECTLY**

### CubicCongestionControlOnCongestionEvent (internal)
- Core congestion event handler (loss or ECN)  
- **DO NOT CALL DIRECTLY** - invoked via OnDataLost/OnEcn

## CUBIC State Machine

```
┌──────────────────┐
│ INITIALIZATION   │
│  (Initialize)    │
└────────┬─────────┘
         │
         v
┌────────────────────┐      HyStart++ enabled
│  SLOW START        │◄─────────────────────────┐
│  HyStart=NOT_START │                          │
│  CW < SSThresh     │                          │
└────┬──────┬────────┘                          │
     │      │                                    │
     │      │ RTT inflation detected            │
     │      └──────────────────┐                │
     │                         v                │
     │              ┌────────────────────┐      │
     │              │ CONSERVATIVE       │      │
     │              │ SLOW START         │      │
     │              │ HyStart=ACTIVE     │      │
     │ SSThresh     │ Growth divisor > 1 │      │
     │ reached OR   └──────────┬─────────┘      │
     │ HyStart exit            │                │
     v                         │ CSS rounds     │
┌────────────────────┐         │ complete       │
│ CONGESTION         │◄────────┘                │
│ AVOIDANCE          │                          │
│ HyStart=DONE       │                          │
│ CW >= SSThresh     │                          │
│ (CUBIC/AIMD)       │                          │
└────┬──────┬────────┘                          │
     │      │                                    │
     │      │ Loss or ECN event                 │
     │      v                                    │
     │  ┌───────────────────┐                   │
     │  │ IN RECOVERY       │                   │
     │  │ IsInRecovery=TRUE │                   │
     │  │ CW reduced        │                   │
     │  └────┬──────┬───────┘                   │
     │       │      │                            │
     │       │      └─ Spurious? ───────────────┘
     │       │         (Revert state)
     │       │ ACK > RecoverySentPacketNumber
     │       v
     │  [Exit Recovery]
     │       │
     └───────┘

PERSISTENT CONGESTION:
  Loss detected + PersistentCongestion=TRUE
  → CW reset to 2*MTU (minimum)
  → SSThresh, WindowMax, KCubic updated
```

## Object Invariants

### QUIC_CONGESTION_CONTROL_CUBIC Invariants

**Always true for a valid CUBIC instance**:
1. `CongestionWindow > 0` (always at least 2*MTU after persistent congestion)
2. `BytesInFlight <= BytesInFlightMax`
3. `InitialWindowPackets > 0`
4. `SendIdleTimeoutMs >= 0`
5. `SlowStartThreshold >= CongestionWindow` OR `SlowStartThreshold == UINT32_MAX`
6. If `HasHadCongestionEvent == TRUE`, then `RecoverySentPacketNumber` is valid
7. If `IsInRecovery == TRUE`, then `HasHadCongestionEvent == TRUE`
8. If `TimeOfLastAckValid == TRUE`, then `TimeOfLastAck` is valid
9. HyStartState ∈ {HYSTART_NOT_STARTED, HYSTART_ACTIVE, HYSTART_DONE}
10. `Exemptions <= 255` (uint8_t)
11. If `IsInPersistentCongestion == TRUE`, then `IsInRecovery == TRUE`

**State-specific invariants**:

**Slow Start State** (CongestionWindow < SlowStartThreshold):
- HyStartState ∈ {HYSTART_NOT_STARTED, HYSTART_ACTIVE}
- CWndSlowStartGrowthDivisor >= 1
- If HyStart enabled and ACTIVE: ConservativeSlowStartRounds > 0

**Congestion Avoidance State** (CongestionWindow >= SlowStartThreshold):
- HyStartState == HYSTART_DONE
- TimeOfCongAvoidStart is valid
- AimdWindow > 0
- KCubic, WindowMax, WindowPrior set appropriately after first congestion event

**Recovery State** (IsInRecovery == TRUE):
- RecoverySentPacketNumber is valid and > 0
- HasHadCongestionEvent == TRUE
- Prev* fields (PrevCongestionWindow, PrevSlowStartThreshold, etc.) hold state before congestion event

## Environment Invariants

1. **Connection Initialization**: Connection structure accessible via `QuicCongestionControlGetConnection(Cc)` must be fully initialized
2. **Path Initialization**: Connection->Paths[0] must be initialized with valid MTU before calling Initialize
3. **Thread Safety**: All public functions annotated with IRQL requirements; must respect Windows kernel IRQL levels
4. **Memory Safety**: Cc pointer must remain valid for lifetime of congestion control usage
5. **Event Sequencing**: OnDataSent must be called before OnDataAcknowledged/OnDataLost for the same packet
6. **Trace System**: QuicTrace framework must be initialized for logging functions

## Key Dependencies

### Required Headers/Modules
- `precomp.h` - Platform abstraction and common definitions
- `cubic.h` - Public CUBIC API declarations
- `congestion_control.h` - Event structures (QUIC_ACK_EVENT, QUIC_LOSS_EVENT, QUIC_ECN_EVENT)
- `connection.h` - QUIC_CONNECTION structure (via QuicCongestionControlGetConnection)
- `send.h` - Send buffer interactions (QuicSendBufferConnectionAdjust)
- Platform layer: CxPlatTimeUs64, CxPlatTimeDiff64, CxPlatZeroMemory

### Function Call Relationships
- **Initialize** → calls internal state reset helpers
- **OnDataAcknowledged** → calls CanSend, UpdateBlockedState, HyStart helpers
- **OnDataLost** → calls OnCongestionEvent, UpdateBlockedState
- **OnEcn** → calls OnCongestionEvent, UpdateBlockedState
- **OnSpuriousCongestionEvent** → calls UpdateBlockedState
- **UpdateBlockedState** (internal) → calls CanSend, connection flow control APIs
- **OnCongestionEvent** (internal) → updates window, calls HyStartChangeState

## Test Reflection Document
Location: `.deeptest/repo_contract_index/test_reflection_cubic.md`  
Purpose: Tracks each new test, its scenario, contract reasoning, and expected coverage impact
