# Test Reflection: AckTracker Component

## Test Summary

43 tests generated for `ack_tracker.c`, achieving **97.9%** line coverage.
The remaining 2 uncovered lines (200-201) are the `QuicConnTransportError` allocation-failure 
path which requires OOM to trigger and is contract-unreachable in normal testing.
`ack_tracker.h` (inline `QuicAckTrackerHasPacketsToAck`) is at 100%.

### Test 1: InitializeAndUninitialize
- **Scenario**: Allocate tracker, initialize, verify ranges empty, uninitialize.
- **Target APIs**: QuicAckTrackerInitialize, QuicAckTrackerUninitialize
- **Coverage**: Lines 47-58, 60-68
- **Non-redundancy**: Foundation test for tracker lifecycle.

### Test 2: ResetClearsAllState
- **Scenario**: Set non-default values, reset, verify everything zeroed.
- **Target APIs**: QuicAckTrackerReset
- **Coverage**: Lines 70-84

### Tests 3-4: AddPacketNumberDetectsDuplicates, AddPacketNumberOutOfOrder
- **Target APIs**: QuicAckTrackerAddPacketNumber
- **Coverage**: Lines 86-97

### Test 5: HasPacketsToAckFlag
- **Target APIs**: QuicAckTrackerHasPacketsToAck (inline)
- **Coverage**: ack_tracker.h lines 155-157

### Tests 6-12: ReorderingThreshold* (7 tests)
- **Target APIs**: QuicAckTrackerDidHitReorderingThreshold
- **Scenarios**: Zero threshold, single range, gap detection, below threshold, 
  LargestAcked shifting, multiple gaps, LargestReported clamping.
- **Coverage**: Lines 103-164 (complete)

### Tests 13-22: AckPacket* (10 tests)
- **Target APIs**: QuicAckTrackerAckPacket
- **Scenarios**: Non-ACK-eliciting, immediate ACK (MaxAckDelayMs=0), ACK_IMMEDIATE type,
  packet tolerance, skip when ACK queued, reordering detection, RecvTime updates,
  ECN handling, clearing AlreadyWrittenAckFrame, reordering-triggered immediate ACK.
- **Coverage**: Lines 166-283 (except 200-201 OOM path)

### Tests 23-27: OnAckFrameAcked* (5 tests)
- **Target APIs**: QuicAckTrackerOnAckFrameAcked
- **Scenarios**: Remove old packets, remove all, clear AckEliciting counter,
  preserve newer packets, packet zero edge case.
- **Coverage**: Lines 338-367

### Tests 28-35: AckFrameEncode* (8 tests)
- **Target APIs**: QuicAckTrackerAckFrameEncode
- **Scenarios**: Basic encode, insufficient space, ECN, clear counter, gaps,
  timestamp encoding, timestamp insufficient space, encode-then-new-packet.
- **Coverage**: Lines 286-336 (complete)

### Tests 36-43: Lifecycle/Integration (8 tests)
- Full lifecycle, multiple cycles, contiguous merge, reverse order merge,
  reset after receiving, mixed ECN accumulation, large values, packet zero.
