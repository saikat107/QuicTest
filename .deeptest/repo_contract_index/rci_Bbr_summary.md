# BBR Congestion Control - Repository Contract Index Summary

## Public API Inventory

### BbrCongestionControlInitialize
- **Signature:** `void BbrCongestionControlInitialize(QUIC_CONGESTION_CONTROL* Cc, const QUIC_SETTINGS_INTERNAL* Settings)`
- **Declared in:** `src/core/bbr.h`
- **Summary:** Initializes BBR congestion control state, sets function pointers, initializes filters.
- **Preconditions:** `Cc` must be embedded in a valid `QUIC_CONNECTION` structure (for CXPLAT_CONTAINING_RECORD). Settings must be non-null.
- **Postconditions:** Cc populated with BBR function pointers. State in STARTUP, no bytes in flight.

### Via Function Pointer Table (QUIC_CONGESTION_CONTROL vtable):
All the following are accessed through function pointers set during Initialize:

| Function | Signature | Description |
|---|---|---|
| CanSend | `BOOLEAN (Cc)` | Returns TRUE if BytesInFlight < CongestionWindow or Exemptions > 0 |
| SetExemption | `void (Cc, NumPackets)` | Sets number of exempted packets |
| Reset | `void (Cc, FullReset)` | Resets BBR state. FullReset zeroes BytesInFlight |
| GetSendAllowance | `uint32_t (Cc, TimeSinceLastSend, Valid)` | Returns bytes allowed to send with pacing |
| GetCongestionWindow | `uint32_t (Cc)` | Returns effective cwnd (min of cwnd/recovery, or min in ProbeRTT) |
| OnDataSent | `void (Cc, NumBytes)` | Increments BytesInFlight, decrements Exemptions, tracks max |
| OnDataInvalidated | `BOOLEAN (Cc, NumBytes)` | Decrements BytesInFlight, returns unblock state |
| OnDataAcknowledged | `BOOLEAN (Cc, AckEvent)` | Core ACK processing: bandwidth estimation, state transitions |
| OnDataLost | `void (Cc, LossEvent)` | Handles packet loss: enters recovery, updates recovery window |
| OnSpuriousCongestionEvent | `BOOLEAN (Cc)` | Always returns FALSE (no-op in BBR) |
| SetAppLimited | `void (Cc)` | Marks bandwidth filter as app-limited if BytesInFlight <= cwnd |
| IsAppLimited | `BOOLEAN (Cc)` | Returns BandwidthFilter.AppLimited |
| GetExemptions | `uint8_t (Cc)` | Returns Exemptions count |
| GetBytesInFlightMax | `uint32_t (Cc)` | Returns BytesInFlightMax |
| LogOutFlowStatus | `void (Cc)` | Logs connection flow stats |
| GetNetworkStatistics | `void (Connection, Cc, Stats)` | Fills QUIC_NETWORK_STATISTICS |

## State Machine

```
STARTUP --[BtlbwFound]--> DRAIN --[BytesInFlight <= TargetCwnd]--> PROBE_BW
STARTUP --[RttSampleExpired && !ExitingQuiescence]--> PROBE_RTT
DRAIN --[RttSampleExpired && !ExitingQuiescence]--> PROBE_RTT  
PROBE_BW --[RttSampleExpired && !ExitingQuiescence]--> PROBE_RTT
PROBE_RTT --[BtlbwFound && ProbeRttComplete]--> PROBE_BW
PROBE_RTT --[!BtlbwFound && ProbeRttComplete]--> STARTUP
```

### Recovery States:
```
NOT_RECOVERY --[loss]--> CONSERVATIVE --[new round]--> GROWTH --[end of recovery ACK]--> NOT_RECOVERY
```

## Environment Invariants
- `Cc` must be embedded in `QUIC_CONNECTION` (CXPLAT_CONTAINING_RECORD macro)
- Connection.Paths[0].Mtu must be set for DatagramPayloadSize calculation
- BytesInFlight must always be >= bytes being subtracted (assert-guarded)
