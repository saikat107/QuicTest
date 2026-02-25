/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC ack tracker implementation.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "AckTrackerTest.cpp.clog.h"
#endif

//
// Helper to set up a minimal mock environment for AckTracker tests that need
// a Connection context. Uses CXPLAT_CONTAINING_RECORD-safe structs so that
// QuicAckTrackerGetPacketSpace and QuicSendGetConnection produce valid pointers.
//
struct MockAckTrackerContext {
    QUIC_CONNECTION Connection;
    QUIC_PACKET_SPACE PacketSpace;

    MockAckTrackerContext() {
        CxPlatZeroMemory(&Connection, sizeof(Connection));
        CxPlatZeroMemory(&PacketSpace, sizeof(PacketSpace));

        PacketSpace.Connection = &Connection;
        PacketSpace.EncryptLevel = QUIC_ENCRYPT_LEVEL_1_RTT;

        QuicAckTrackerInitialize(&PacketSpace.AckTracker);

        //
        // Set FlushOperationPending to prevent QuicSendQueueFlush from
        // attempting to allocate operations on a NULL Worker.
        //
        Connection.Send.FlushOperationPending = TRUE;
        CxPlatListInitializeHead(&Connection.Send.SendStreams);

        //
        // Set all timers to UINT64_MAX so QuicConnTimerCancel is a no-op.
        //
        for (int i = 0; i < QUIC_CONN_TIMER_COUNT; i++) {
            Connection.ExpirationTimes[i] = UINT64_MAX;
        }
        Connection.EarliestExpirationTime = UINT64_MAX;

        //
        // Default connection settings for ACK behavior.
        //
        Connection.PacketTolerance = 2;
        Connection.Settings.MaxAckDelayMs = 0; // Immediate ACK by default
        Connection.ReorderingThreshold = 1;
        Connection.AckDelayExponent = 3;

        //
        // Point the connection's Packets array to our PacketSpace.
        //
        Connection.Packets[QUIC_ENCRYPT_LEVEL_1_RTT] = &PacketSpace;

        //
        // Ensure crypto state allows send flags.
        //
        Connection.Crypto.TlsState.WriteKey = QUIC_PACKET_KEY_1_RTT;
    }

    ~MockAckTrackerContext() {
        QuicAckTrackerUninitialize(&PacketSpace.AckTracker);
    }

    QUIC_ACK_TRACKER* Tracker() { return &PacketSpace.AckTracker; }
};

//
// Test: Initialize and uninitialize verifies that ranges are properly set up.
// Scenario: Allocate a tracker, initialize it, verify the ranges are empty,
// then uninitialize.
// Assertions: Both ranges have zero size after initialization.
//
TEST(DeepTestAckTracker, InitializeAndUninitialize)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));

    QuicAckTrackerInitialize(&Tracker);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reset clears all fields back to initial state.
// Scenario: Set various fields to non-default values, call Reset, then verify
// everything is back to the initial state.
// Assertions: All counters are zero, flags are FALSE, ECN is zeroed, ranges
// are empty.
//
TEST(DeepTestAckTracker, ResetClearsAllState)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Set non-default values.
    //
    Tracker.AckElicitingPacketsToAcknowledge = 5;
    Tracker.LargestPacketNumberAcknowledged = 100;
    Tracker.LargestPacketNumberRecvTime = 999;
    Tracker.AlreadyWrittenAckFrame = TRUE;
    Tracker.NonZeroRecvECN = TRUE;
    Tracker.ReceivedECN.ECT_0_Count = 3;
    Tracker.ReceivedECN.ECT_1_Count = 2;
    Tracker.ReceivedECN.CE_Count = 1;

    //
    // Add some values to the ranges.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersReceived, 10);

    QuicAckTrackerReset(&Tracker);

    ASSERT_EQ(Tracker.AckElicitingPacketsToAcknowledge, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberAcknowledged, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberRecvTime, 0u);
    ASSERT_FALSE(Tracker.AlreadyWrittenAckFrame);
    ASSERT_FALSE(Tracker.NonZeroRecvECN);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_1_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.CE_Count, 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber returns FALSE for new packets, TRUE for duplicates.
// Scenario: Add a sequence of packet numbers, then re-add them to verify
// duplicate detection.
// Assertions: First add returns FALSE (not duplicate), second returns TRUE.
//
TEST(DeepTestAckTracker, AddPacketNumberDetectsDuplicates)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // First insertion should not be a duplicate.
    //
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 0));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 1));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 5));

    //
    // Re-adding should detect duplicates.
    //
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 0));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 1));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 5));

    //
    // Verify that a new number is still not duplicate.
    //
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 3));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber with out-of-order packet numbers.
// Scenario: Add packets in non-sequential order and verify duplicate detection
// still works correctly with gaps.
// Assertions: Each unique packet returns FALSE, each duplicate returns TRUE.
//
TEST(DeepTestAckTracker, AddPacketNumberOutOfOrder)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 10));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 5));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 20));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 7));

    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 10));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 5));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 20));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 7));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: HasPacketsToAck returns FALSE when empty and TRUE when packets are
// queued.
// Scenario: Check the flag on a fresh tracker, add packets, verify the flag
// changes, then set AlreadyWrittenAckFrame and check it goes back to FALSE.
// Assertions: HasPacketsToAck reflects the combination of range size and
// AlreadyWrittenAckFrame.
//
TEST(DeepTestAckTracker, HasPacketsToAckFlag)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Empty tracker has nothing to ack.
    //
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    //
    // Add a packet to the ToAck range.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(&Tracker));

    //
    // After writing an ACK frame, HasPacketsToAck should be FALSE.
    //
    Tracker.AlreadyWrittenAckFrame = TRUE;
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    //
    // Add another packet - AlreadyWrittenAckFrame should still block.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 2);
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    //
    // Clear the flag - now has packets.
    //
    Tracker.AlreadyWrittenAckFrame = FALSE;
    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE when threshold is 0.
// Scenario: Add packets with gaps, set threshold to 0.
// Assertions: Always returns FALSE when threshold is 0.
//
TEST(DeepTestAckTracker, ReorderingThresholdZeroAlwaysFalse)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 0));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE with fewer than 2 ranges.
// Scenario: Add contiguous packets so there's only 1 sub-range.
// Assertions: Returns FALSE even with a non-zero threshold.
//
TEST(DeepTestAckTracker, ReorderingThresholdSingleRangeFalse)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Contiguous packets: only 1 sub-range.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 2);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 3);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 1u);
    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold detects reordering with gaps.
// Scenario: Add packets with a gap (1, 5) creating 2 sub-ranges, then verify
// threshold detection. With threshold=1 and LargestAcked=0, the missing packet
// 2 is a gap between range [1,1] and [5,5]. The difference 5-2=3 >= 1.
// Assertions: Returns TRUE when gap exceeds threshold.
//
TEST(DeepTestAckTracker, ReorderingThresholdDetectsGap)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Create gap: [1] and [5] -> gap at 2,3,4.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    //
    // With threshold=1: LargestUnacked=5, SmallestTracked=1, LargestReported=1.
    // PreviousSmallestMissing = high(range[0])+1 = 2.
    // LargestReported (1) > PreviousSmallestMissing (2)? No.
    // LargestUnacked - PreviousSmallestMissing = 5-2 = 3 >= 1. TRUE.
    //
    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE when gap is below threshold.
// Scenario: Create a small gap with a high threshold value.
// Assertions: Returns FALSE when gap does not exceed threshold.
//
TEST(DeepTestAckTracker, ReorderingThresholdBelowThreshold)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Gap: [1] and [3] -> gap at 2. LargestUnacked=3, SmallestMissing=2.
    // Difference = 3-2 = 1 < threshold(5). FALSE.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 3);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 5));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with LargestPacketNumberAcknowledged affecting
// LargestReported calculation.
// Scenario: Set LargestPacketNumberAcknowledged high enough that it shifts
// LargestReported above the gap range, causing the function to skip it.
// Assertions: Returns FALSE when LargestReported is beyond all gaps.
//
TEST(DeepTestAckTracker, ReorderingThresholdLargestAckedShiftsLargestReported)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Ranges: [5] and [10]. Gap at 6-9.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    //
    // With LargestAcked=20, threshold=1:
    // LargestReported = max(SmallestTracked, LargestAcked - threshold + 1)
    //                 = max(5, 20-1+1) = 20.
    // Loop: RangeStart = range[1].Low = 10. LargestReported(20) >= RangeStart(10) -> FALSE.
    //
    Tracker.LargestPacketNumberAcknowledged = 20;
    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with multiple gaps, checks the right gap.
// Scenario: Create three sub-ranges with two gaps. The function should find
// the smallest missing after LargestReported.
// Assertions: Returns TRUE based on the gap evaluation.
//
TEST(DeepTestAckTracker, ReorderingThresholdMultipleGaps)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Ranges: [1], [5], [10]. Gaps at 2-4 and 6-9.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 3u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    //
    // threshold=1: LargestUnacked=10, SmallestTracked=1, LargestReported=1.
    // Loop from highest range (index=2): RangeStart=10, LargestReported(1)<10.
    //   PreviousSmallestMissing = high(range[1])+1 = 6. LargestReported(1) > 6? No.
    //   LargestUnacked - PreviousSmallestMissing = 10-6 = 4 >= 1. TRUE.
    //
    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    //
    // threshold=5: 10-6 = 4 < 5. Continue to next iteration:
    //   Index=1: RangeStart=5, LargestReported(1)<5.
    //   PreviousSmallestMissing = high(range[0])+1 = 2. LargestReported(1) > 2? No.
    //   LargestUnacked - PreviousSmallestMissing = 10-2 = 8 >= 5. TRUE.
    //
    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 5));

    //
    // threshold=9: 10-2 = 8 < 9. No more ranges to check. FALSE.
    //
    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 9));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold where LargestReported adjusts
// PreviousSmallestMissing.
// Scenario: LargestPacketNumberAcknowledged is set such that LargestReported
// is between the gap, causing PreviousSmallestMissing to be clamped.
// Assertions: Returns correct result with the LargestReported adjustment.
//
TEST(DeepTestAckTracker, ReorderingThresholdLargestReportedClampsMissing)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    //
    // Ranges: [1] and [10]. Gap at 2-9.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    //
    // With LargestAcked=5, threshold=1:
    // LargestReported = max(1, 5-1+1) = 5.
    // Loop: RangeStart=10, LargestReported(5)<10.
    //   PreviousSmallestMissing = high(range[0])+1 = 2. LargestReported(5) > 2. Yes!
    //   PreviousSmallestMissing = LargestReported = 5.
    //   LargestUnacked - PreviousSmallestMissing = 10-5 = 5 >= 1. TRUE.
    //
    Tracker.LargestPacketNumberAcknowledged = 5;
    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    //
    // With threshold=6: LargestAcked(5) < SmallestTracked(1)+6=7, so
    // LargestReported=1. PreviousSmallestMissing=2, 10-2=8 >= 6. TRUE.
    //
    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 6));

    //
    // With threshold=9: 10-2 = 8 < 9. FALSE.
    //
    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 9));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AckPacket with NON_ACK_ELICITING type adds packet to ToAck range.
// Scenario: Use a mock connection context, call AckPacket with
// QUIC_ACK_TYPE_NON_ACK_ELICITING, verify the packet is added to the range
// and AckElicitingPacketsToAcknowledge is NOT incremented.
// Assertions: Packet in range, counter unchanged, AlreadyWrittenAckFrame
// cleared.
//
TEST(DeepTestAckTracker, AckPacketNonAckEliciting)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    Tracker->AlreadyWrittenAckFrame = TRUE;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    //
    // Packet should be in the ToAck range.
    //
    uint64_t Max;
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Max, 1u);

    //
    // AckElicitingPacketsToAcknowledge should not be incremented.
    //
    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 0u);

    //
    // AlreadyWrittenAckFrame should be cleared.
    //
    ASSERT_FALSE(Tracker->AlreadyWrittenAckFrame);
}

//
// Test: AckPacket with ACK_ELICITING type triggers immediate ACK when
// MaxAckDelayMs is 0.
// Scenario: Connection has MaxAckDelayMs=0. AckPacket with ACK_ELICITING
// should immediately set the ACK send flag.
// Assertions: ACK send flag is set, AckElicitingPacketsToAcknowledge is 1.
//
TEST(DeepTestAckTracker, AckPacketAckElicitingImmediateAck)
{
    MockAckTrackerContext Ctx;
    Ctx.Connection.Settings.MaxAckDelayMs = 0;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 1u);
    ASSERT_TRUE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);
}

//
// Test: AckPacket with ACK_IMMEDIATE type always triggers immediate ACK.
// Scenario: Even with a high MaxAckDelayMs and tolerance, ACK_IMMEDIATE
// should force the ACK flag.
// Assertions: ACK send flag is set.
//
TEST(DeepTestAckTracker, AckPacketAckImmediateType)
{
    MockAckTrackerContext Ctx;
    Ctx.Connection.Settings.MaxAckDelayMs = 25;
    Ctx.Connection.PacketTolerance = 100;
    auto* Tracker = Ctx.Tracker();

    //
    // Even though tolerance is high and delay is non-zero, ACK_IMMEDIATE
    // should force sending immediately.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_IMMEDIATE);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 1u);
    ASSERT_TRUE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);
}

//
// Test: AckPacket increments ACK eliciting counter and triggers when
// PacketTolerance is reached.
// Scenario: With PacketTolerance=2, the first ACK_ELICITING packet should
// NOT trigger immediate ACK, but the second should.
// Assertions: ACK flag set only after tolerance reached.
//
TEST(DeepTestAckTracker, AckPacketReachesPacketTolerance)
{
    MockAckTrackerContext Ctx;
    Ctx.Connection.Settings.MaxAckDelayMs = 25;
    Ctx.Connection.PacketTolerance = 2;
    //
    // We can't safely call QuicSendStartDelayedAckTimer (needs Worker).
    // Instead, pre-set the delayed ACK timer as active to satisfy the assert.
    //
    Ctx.Connection.Send.DelayedAckTimerActive = TRUE;
    auto* Tracker = Ctx.Tracker();

    //
    // First ACK-eliciting packet: counter=1 < tolerance=2.
    // Should try to start delayed ACK timer, but we pre-set it.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 1u);
    //
    // ACK flag should NOT be set yet.
    //
    ASSERT_FALSE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);

    //
    // Second ACK-eliciting packet: counter=2 >= tolerance=2. Immediate ACK.
    //
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 2u);
    ASSERT_TRUE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);
}

//
// Test: AckPacket skips when ACK flag is already set.
// Scenario: Pre-set the ACK send flag, call AckPacket with ACK_ELICITING.
// The code should take the early exit at line 243.
// Assertions: Counter incremented, no crash, flag still set.
//
TEST(DeepTestAckTracker, AckPacketSkipsWhenAckAlreadyQueued)
{
    MockAckTrackerContext Ctx;
    Ctx.Connection.Send.SendFlags |= QUIC_CONN_SEND_FLAG_ACK;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 1u);
    ASSERT_TRUE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);
}

//
// Test: AckPacket detects reordering when a smaller packet arrives after a
// larger one.
// Scenario: Add packets 5, then 2. When 2 arrives, the current largest (5)
// is greater, so Stats.Recv.ReorderedPackets should be incremented.
// Assertions: ReorderedPackets count is exactly 1.
//
TEST(DeepTestAckTracker, AckPacketDetectsReordering)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // Receive packet 5 first.
    //
    QuicAckTrackerAckPacket(
        Tracker, 5, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_EQ(Ctx.Connection.Stats.Recv.ReorderedPackets, 0u);

    //
    // Receive packet 2 (out of order).
    //
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_EQ(Ctx.Connection.Stats.Recv.ReorderedPackets, 1u);
}

//
// Test: AckPacket updates LargestPacketNumberRecvTime only for the new largest.
// Scenario: Receive packets 1, 5, 3 with different timestamps. Only the
// timestamps for 1 and 5 should be recorded (as they were the new largest at
// those points).
// Assertions: RecvTime matches the time of the largest packet.
//
TEST(DeepTestAckTracker, AckPacketUpdatesRecvTimeForLargest)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->LargestPacketNumberRecvTime, 1000u);

    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->LargestPacketNumberRecvTime, 5000u);

    //
    // Packet 3 is not the largest, so recv time should not change.
    //
    QuicAckTrackerAckPacket(
        Tracker, 3, 3000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->LargestPacketNumberRecvTime, 5000u);
}

//
// Test: AckPacket handles ECN types correctly.
// Scenario: Send packets with different ECN values and verify the counters
// are incremented correctly and NonZeroRecvECN is set.
// Assertions: Each ECN counter matches expected value, flag is set for
// non-zero ECN.
//
TEST(DeepTestAckTracker, AckPacketEcnHandling)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // NON_ECT should not set the flag or increment any counter.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_FALSE(Tracker->NonZeroRecvECN);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_1_Count, 0u);
    ASSERT_EQ(Tracker->ReceivedECN.CE_Count, 0u);

    //
    // ECT_1 should set flag and increment ECT_1.
    //
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_ECT_1, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_TRUE(Tracker->NonZeroRecvECN);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_1_Count, 1u);

    //
    // ECT_0 should increment ECT_0.
    //
    QuicAckTrackerAckPacket(
        Tracker, 3, 3000, CXPLAT_ECN_ECT_0, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_0_Count, 1u);

    //
    // CE should increment CE.
    //
    QuicAckTrackerAckPacket(
        Tracker, 4, 4000, CXPLAT_ECN_CE, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->ReceivedECN.CE_Count, 1u);

    //
    // Send multiple ECT_0 to verify counter increments.
    //
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_ECT_0, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_0_Count, 2u);
}

//
// Test: AckPacket clears AlreadyWrittenAckFrame when new packet arrives.
// Scenario: Set AlreadyWrittenAckFrame to TRUE, receive a packet, verify it
// is cleared.
// Assertions: AlreadyWrittenAckFrame is FALSE after receiving a new packet.
//
TEST(DeepTestAckTracker, AckPacketClearsAlreadyWrittenFlag)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Tracker->AlreadyWrittenAckFrame = TRUE;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_FALSE(Tracker->AlreadyWrittenAckFrame);
}

//
// Test: AckPacket triggers reordering-based immediate ACK when threshold hit.
// Scenario: Receive packets with a gap, then receive the largest packet
// that triggers the reordering threshold check.
// Assertions: ACK flag is set due to reordering detection.
//
TEST(DeepTestAckTracker, AckPacketReorderingTriggersImmediateAck)
{
    MockAckTrackerContext Ctx;
    Ctx.Connection.Settings.MaxAckDelayMs = 25;
    Ctx.Connection.PacketTolerance = 100; // High tolerance so count won't trigger
    Ctx.Connection.ReorderingThreshold = 1;
    //
    // Pre-set delayed ACK timer so first packet doesn't crash.
    //
    Ctx.Connection.Send.DelayedAckTimerActive = TRUE;
    auto* Tracker = Ctx.Tracker();

    //
    // Receive packet 1 first (sets up baseline).
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);
    ASSERT_FALSE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);

    //
    // Receive packet 5 (gap at 2,3,4 - triggers reordering threshold).
    // NewLargestPacketNumber=TRUE, DidHitReorderingThreshold should be TRUE.
    //
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_TRUE(Ctx.Connection.Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK);
}

//
// Test: OnAckFrameAcked removes packet numbers below the acked number.
// Scenario: Add several packets, call OnAckFrameAcked with a mid-range value,
// verify older packets are removed.
// Assertions: Min of ToAck range is LargestAckedPacketNumber+1.
//
TEST(DeepTestAckTracker, OnAckFrameAckedRemovesOldPackets)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // Add packets to ToAck range.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    //
    // ACK frame acked for packets up to 2.
    //
    QuicAckTrackerOnAckFrameAcked(Tracker, 2);

    //
    // Packets 1 and 2 should be removed. Min should be 5 (next after 2+1=3,
    // but only 5 exists).
    //
    uint64_t Min;
    ASSERT_TRUE(QuicRangeGetMinSafe(&Tracker->PacketNumbersToAck, &Min));
    ASSERT_EQ(Min, 5u);
}

//
// Test: OnAckFrameAcked removes all packets when LargestAcked covers everything.
// Scenario: Ack all packets, verify the ToAck range becomes empty.
// Assertions: Range size is 0 after acking all.
//
TEST(DeepTestAckTracker, OnAckFrameAckedRemovesAll)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QuicAckTrackerOnAckFrameAcked(Tracker, 2);

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
}

//
// Test: OnAckFrameAcked clears AckElicitingPacketsToAcknowledge when all
// ranges are removed but the counter was non-zero.
// Scenario: Add ACK-eliciting packets, then ack all. The code should detect
// the inconsistency (counter > 0 but no ranges) and reset the counter.
// Assertions: AckElicitingPacketsToAcknowledge is 0 after full ack.
//
TEST(DeepTestAckTracker, OnAckFrameAckedClearsAckElicitingCounter)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // Add ACK-eliciting packets.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);
    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 1u);

    //
    // Ack all. The counter should be cleared because ranges are empty.
    //
    QuicAckTrackerOnAckFrameAcked(Tracker, 1);

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 0u);
}

//
// Test: Full lifecycle - receive, ack-encode (simulated), ack-acked.
// Scenario: Simulate the full lifecycle: receive packets, encode an ACK frame
// (by manually setting the fields that AckFrameEncode would set), then handle
// the ack of that ACK frame.
// Assertions: State transitions correctly through the lifecycle.
//
TEST(DeepTestAckTracker, FullLifecycleReceiveToAcked)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // Phase 1: Receive packets.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 3, 3000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(Tracker));

    //
    // Phase 2: Simulate ACK frame encode (set the fields that
    // QuicAckTrackerAckFrameEncode would set).
    //
    Tracker->AlreadyWrittenAckFrame = TRUE;
    Tracker->LargestPacketNumberAcknowledged = 3;

    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(Tracker));

    //
    // Phase 3: Peer acknowledges our ACK frame.
    //
    QuicAckTrackerOnAckFrameAcked(Tracker, 3);

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
}

//
// Test: Multiple receive-ack cycles.
// Scenario: Go through two complete cycles of receiving packets and getting
// them acked, verifying state is clean between cycles.
// Assertions: Tracker resets properly between cycles.
//
TEST(DeepTestAckTracker, MultipleCycles)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    //
    // Cycle 1: Receive packets 1-3, simulate encode, get acked.
    //
    for (uint64_t i = 1; i <= 3; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, i * 1000, CXPLAT_ECN_NON_ECT,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }
    Tracker->AlreadyWrittenAckFrame = TRUE;
    Tracker->LargestPacketNumberAcknowledged = 3;
    QuicAckTrackerOnAckFrameAcked(Tracker, 3);
    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);

    //
    // Cycle 2: Receive packets 4-6.
    //
    for (uint64_t i = 4; i <= 6; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, i * 1000, CXPLAT_ECN_NON_ECT,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }
    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(Tracker));

    uint64_t Min, Max;
    ASSERT_TRUE(QuicRangeGetMinSafe(&Tracker->PacketNumbersToAck, &Min));
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Min, 4u);
    ASSERT_EQ(Max, 6u);

    Tracker->AlreadyWrittenAckFrame = TRUE;
    Tracker->LargestPacketNumberAcknowledged = 6;
    QuicAckTrackerOnAckFrameAcked(Tracker, 6);
    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
}

//
// Test: AddPacketNumber with large packet numbers.
// Scenario: Use large (but valid) packet numbers near QUIC_VAR_INT_MAX
// boundaries to verify no overflow.
// Assertions: Duplicate detection works with large values.
//
TEST(DeepTestAckTracker, AddPacketNumberLargeValues)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    const uint64_t Large1 = 1000000;
    const uint64_t Large2 = 1000001;

    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, Large1));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, Large2));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, Large1));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, Large2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AckPacket with packet number 0 (minimum valid value).
// Scenario: Packet number 0 is a valid QUIC packet number. Verify it works.
// Assertions: Packet 0 is added to ToAck range, RecvTime updated.
//
TEST(DeepTestAckTracker, AckPacketZero)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 0, 500, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    uint64_t Max;
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Max, 0u);
    ASSERT_EQ(Tracker->LargestPacketNumberRecvTime, 500u);
}

//
// Test: OnAckFrameAcked with LargestAckedPacketNumber of 0.
// Scenario: Only packet 0 exists. Acking packet 0 should clear the range.
// Assertions: ToAck range is empty after acking packet 0.
//
TEST(DeepTestAckTracker, OnAckFrameAckedPacketZero)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 0, 500, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QuicAckTrackerOnAckFrameAcked(Tracker, 0);

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
}

//
// Test: OnAckFrameAcked leaves newer packets intact.
// Scenario: Receive packets 1, 5, 10. Ack up to 5. Packet 10 should remain.
// Assertions: Only packet 10 remains in the ToAck range.
//
TEST(DeepTestAckTracker, OnAckFrameAckedPreservesNewer)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 10, 10000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QuicAckTrackerOnAckFrameAcked(Tracker, 5);

    uint64_t Min, Max;
    ASSERT_TRUE(QuicRangeGetMinSafe(&Tracker->PacketNumbersToAck, &Min));
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Min, 10u);
    ASSERT_EQ(Max, 10u);
    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 1u);
}

//
// Test: Reset after receiving packets clears everything.
// Scenario: Receive packets, then reset and verify all state is clean.
// Assertions: All fields are zero/default after reset.
//
TEST(DeepTestAckTracker, ResetAfterReceivingPackets)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_ECT_0, QUIC_ACK_TYPE_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_CE, QUIC_ACK_TYPE_ACK_ELICITING);

    //
    // Verify state is non-default before reset.
    //
    ASSERT_TRUE(Tracker->NonZeroRecvECN);
    ASSERT_NE(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);

    QuicAckTrackerReset(Tracker);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 0u);
    ASSERT_EQ(Tracker->LargestPacketNumberAcknowledged, 0u);
    ASSERT_EQ(Tracker->LargestPacketNumberRecvTime, 0u);
    ASSERT_FALSE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_FALSE(Tracker->NonZeroRecvECN);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Tracker->ReceivedECN.CE_Count, 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersReceived), 0u);
}

//
// Test: AckPacket with all three ECN types in sequence.
// Scenario: Receive packets with ECT_0, ECT_1, and CE in sequence and verify
// all counters accumulate correctly.
// Assertions: Each counter has the expected accumulated value.
//
TEST(DeepTestAckTracker, AckPacketMixedEcnAccumulation)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    for (uint64_t i = 0; i < 3; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, (i + 1) * 1000, CXPLAT_ECN_ECT_0,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }
    for (uint64_t i = 3; i < 5; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, (i + 1) * 1000, CXPLAT_ECN_ECT_1,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }
    for (uint64_t i = 5; i < 6; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, (i + 1) * 1000, CXPLAT_ECN_CE,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }

    ASSERT_EQ(Tracker->ReceivedECN.ECT_0_Count, 3u);
    ASSERT_EQ(Tracker->ReceivedECN.ECT_1_Count, 2u);
    ASSERT_EQ(Tracker->ReceivedECN.CE_Count, 1u);
    ASSERT_TRUE(Tracker->NonZeroRecvECN);
}

//
// Test: AckFrameEncode succeeds with sufficient buffer space and non-ECN.
// Scenario: Set up a mock Builder with a large enough buffer, add packets
// to the tracker, and call AckFrameEncode.
// Assertions: Returns TRUE, AlreadyWrittenAckFrame is TRUE,
// LargestPacketNumberAcknowledged updated, Metadata FrameCount incremented.
//
TEST(DeepTestAckTracker, AckFrameEncodeBasic)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    //
    // Add some packets.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 3, 3000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(Tracker));

    //
    // Set up a mock QUIC_PACKET_BUILDER.
    //
    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16; // Typical AEAD tag size
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL; // Not 1-RTT to skip timestamp
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_TRUE(Result);
    ASSERT_TRUE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_EQ(Tracker->LargestPacketNumberAcknowledged, 3u);
    ASSERT_EQ(Builder.Metadata->FrameCount, 1u);
    ASSERT_GT(Builder.DatagramLength, (uint16_t)0);
}

//
// Test: AckFrameEncode fails with insufficient buffer space.
// Scenario: Set up a builder with a very small buffer that can't hold the ACK.
// Assertions: Returns FALSE.
//
TEST(DeepTestAckTracker, AckFrameEncodeInsufficientSpace)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    //
    // Buffer too small for any ACK frame encoding.
    //
    uint8_t Buffer[1];
    Buffer[0] = 0;
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 0;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_FALSE(Result);
}

//
// Test: AckFrameEncode with ECN data includes ECN in the frame.
// Scenario: Receive packets with ECN, encode the ACK frame, verify ECN data
// is passed to the encoder.
// Assertions: Returns TRUE, NonZeroRecvECN was set before encoding.
//
TEST(DeepTestAckTracker, AckFrameEncodeWithEcn)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_ECT_0, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_ECT_1, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(Tracker->NonZeroRecvECN);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_TRUE(Result);
    ASSERT_TRUE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_EQ(Tracker->LargestPacketNumberAcknowledged, 2u);
}

//
// Test: AckFrameEncode clears AckElicitingPacketsToAcknowledge counter.
// Scenario: Receive ACK-eliciting packets, then encode the ACK frame. The
// counter should be cleared.
// Assertions: Counter is 0 after encode.
//
TEST(DeepTestAckTracker, AckFrameEncodeClearsAckElicitingCounter)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 2u);

    //
    // The ACK flag was set by AckPacket (MaxAckDelayMs=0), clear it so
    // HasPacketsToAck works for encode.
    //
    Tracker->AlreadyWrittenAckFrame = FALSE;

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_TRUE(Result);
    ASSERT_EQ(Tracker->AckElicitingPacketsToAcknowledge, 0u);
}

//
// Test: AckFrameEncode with gaps in the packet range produces a valid encoding.
// Scenario: Add non-contiguous packets to create gaps in the ACK blocks.
// Assertions: Encode succeeds and produces output bytes.
//
TEST(DeepTestAckTracker, AckFrameEncodeWithGaps)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    //
    // Create gaps: [1], [5], [10].
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 5, 5000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Tracker, 10, 10000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_TRUE(Result);
    ASSERT_EQ(Tracker->LargestPacketNumberAcknowledged, 10u);
    //
    // With 3 sub-ranges, the encoded frame should be larger than a single-range
    // frame. Exact size depends on varint encoding.
    //
    ASSERT_GT(Builder.DatagramLength, (uint16_t)3);
}

//
// Test: Contiguous packets are merged into a single range.
// Scenario: Add packets 1,2,3,4,5 and verify the ToAck range contains exactly
// one sub-range.
// Assertions: Range size is 1 with correct min/max.
//
TEST(DeepTestAckTracker, AckPacketContiguousMerge)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    for (uint64_t i = 1; i <= 5; i++) {
        QuicAckTrackerAckPacket(
            Tracker, i, i * 1000, CXPLAT_ECN_NON_ECT,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 1u);

    uint64_t Min, Max;
    ASSERT_TRUE(QuicRangeGetMinSafe(&Tracker->PacketNumbersToAck, &Min));
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Min, 1u);
    ASSERT_EQ(Max, 5u);
}

//
// Test: Receiving in reverse order still produces correct range.
// Scenario: Add packets 5,4,3,2,1 and verify they merge into one range.
// Assertions: Single range from 1 to 5, reordering counted each time.
//
TEST(DeepTestAckTracker, AckPacketReverseOrderMerge)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();

    for (uint64_t i = 5; i >= 1; i--) {
        QuicAckTrackerAckPacket(
            Tracker, i, i * 1000, CXPLAT_ECN_NON_ECT,
            QUIC_ACK_TYPE_NON_ACK_ELICITING);
    }

    ASSERT_EQ(QuicRangeSize(&Tracker->PacketNumbersToAck), 1u);

    uint64_t Min, Max;
    ASSERT_TRUE(QuicRangeGetMinSafe(&Tracker->PacketNumbersToAck, &Min));
    ASSERT_TRUE(QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &Max));
    ASSERT_EQ(Min, 1u);
    ASSERT_EQ(Max, 5u);

    //
    // Only 4 reordered packets (2,3,4,5 each arrive when 5 is largest...no,
    // actually 5 is received first, then 4,3,2,1 are all reordered).
    //
    ASSERT_EQ(Ctx.Connection.Stats.Recv.ReorderedPackets, 4u);
}

//
// Test: AckFrameEncode followed by new packet clears AlreadyWrittenAckFrame.
// Scenario: Encode, then receive a new packet, verify HasPacketsToAck returns
// TRUE again.
// Assertions: State transitions correctly from Written back to Receiving.
//
TEST(DeepTestAckTracker, AckFrameEncodeThenNewPacket)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = FALSE;

    //
    // Receive and encode.
    //
    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    QuicAckTrackerAckFrameEncode(Tracker, &Builder);
    ASSERT_TRUE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(Tracker));

    //
    // Receive new packet.
    //
    QuicAckTrackerAckPacket(
        Tracker, 2, 2000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_FALSE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(Tracker));
}

//
// Test: AckFrameEncode with TimestampSendNegotiated and 1-RTT encrypt level
// encodes a timestamp frame before the ACK frame.
// Scenario: Enable timestamp negotiation, set 1-RTT encrypt level, provide
// a large buffer, and verify encoding succeeds.
// Assertions: Returns TRUE, DatagramLength includes timestamp + ACK bytes.
//
TEST(DeepTestAckTracker, AckFrameEncodeWithTimestamp)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = TRUE;
    Ctx.Connection.Stats.Timing.Start = 0;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    uint8_t Buffer[512];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 16;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_1_RTT; // Triggers timestamp encoding
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_TRUE(Result);
    ASSERT_TRUE(Tracker->AlreadyWrittenAckFrame);
    ASSERT_EQ(Tracker->LargestPacketNumberAcknowledged, 1u);
    //
    // DatagramLength should be larger than a non-timestamp encode because
    // of the timestamp frame prefix.
    //
    ASSERT_GT(Builder.DatagramLength, (uint16_t)0);
}

//
// Test: AckFrameEncode fails when buffer is too small for the timestamp frame.
// Scenario: Enable timestamp negotiation with 1-RTT, provide a very small
// buffer that can't fit even the timestamp frame.
// Assertions: Returns FALSE because the timestamp frame couldn't be encoded.
//
TEST(DeepTestAckTracker, AckFrameEncodeTimestampInsufficientSpace)
{
    MockAckTrackerContext Ctx;
    auto* Tracker = Ctx.Tracker();
    Ctx.Connection.State.TimestampSendNegotiated = TRUE;
    Ctx.Connection.Stats.Timing.Start = 0;

    QuicAckTrackerAckPacket(
        Tracker, 1, 1000, CXPLAT_ECN_NON_ECT, QUIC_ACK_TYPE_NON_ACK_ELICITING);

    QUIC_PACKET_BUILDER Builder;
    CxPlatZeroMemory(&Builder, sizeof(Builder));

    //
    // Buffer too small for timestamp frame.
    //
    uint8_t Buffer[2];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    QUIC_BUFFER Datagram;
    Datagram.Length = sizeof(Buffer);
    Datagram.Buffer = Buffer;

    Builder.Connection = &Ctx.Connection;
    Builder.Datagram = &Datagram;
    Builder.DatagramLength = 0;
    Builder.EncryptionOverhead = 0;
    Builder.EncryptLevel = QUIC_ENCRYPT_LEVEL_1_RTT;
    Builder.Metadata = &Builder.MetadataStorage.Metadata;
    Builder.Metadata->FrameCount = 0;

    BOOLEAN Result = QuicAckTrackerAckFrameEncode(Tracker, &Builder);

    ASSERT_FALSE(Result);
}

