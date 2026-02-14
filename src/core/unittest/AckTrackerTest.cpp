/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC_ACK_TRACKER component.

--*/

#include "main.h"

//
// Note: Tests for QuicAckTrackerAckPacket, QuicAckTrackerAckFrameEncode, and
// QuicAckTrackerOnAckFrameAcked require full QUIC_CONNECTION embedding and are
// tested in the integration test suite. These unit tests focus on the standalone
// functions that don't require connection context.
//

//
// Test: Initialize and uninitialize ACK tracker.
// Scenario: Basic lifecycle - initialize a tracker and verify it starts empty,
// then uninitialize and clean up.
// Assertions: Verify ranges are empty after initialization.
//
TEST(AckTrackerTest, InitializeUninitialize)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    // Verify tracker starts empty
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reset ACK tracker to initial state.
// Scenario: Add some packets, then reset and verify all state is cleared.
// Assertions: All fields reset to zero/FALSE, ranges empty.
//
TEST(AckTrackerTest, Reset)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    // Add some state
    QuicRangeAddValue(&Tracker.PacketNumbersReceived, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    Tracker.AckElicitingPacketsToAcknowledge = 5;
    Tracker.LargestPacketNumberAcknowledged = 10;
    Tracker.LargestPacketNumberRecvTime = 100;
    Tracker.AlreadyWrittenAckFrame = TRUE;
    Tracker.NonZeroRecvECN = TRUE;
    Tracker.ReceivedECN.ECT_0_Count = 3;
    
    // Reset
    QuicAckTrackerReset(&Tracker);
    
    // Verify all fields are reset
    ASSERT_EQ(Tracker.AckElicitingPacketsToAcknowledge, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberAcknowledged, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberRecvTime, 0u);
    ASSERT_FALSE(Tracker.AlreadyWrittenAckFrame);
    ASSERT_FALSE(Tracker.NonZeroRecvECN);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_1_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.CE_Count, 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Add a new packet number and check for duplicates.
// Scenario: Add packet 100, verify it's not a duplicate. Add it again, verify it IS a duplicate.
// Assertions: First add returns FALSE (not duplicate), second add returns TRUE (duplicate).
//
TEST(AckTrackerTest, AddPacketNumber_NewPacket)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    // Add packet 100 - should not be a duplicate
    BOOLEAN IsDuplicate = QuicAckTrackerAddPacketNumber(&Tracker, 100);
    ASSERT_FALSE(IsDuplicate);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 1u);
    
    // Add packet 100 again - should be a duplicate
    IsDuplicate = QuicAckTrackerAddPacketNumber(&Tracker, 100);
    ASSERT_TRUE(IsDuplicate);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 1u);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Add multiple distinct packet numbers.
// Scenario: Add packets 1, 2, 3 in order. Verify none are duplicates.
// Assertions: All return FALSE (not duplicate), range size grows.
//
TEST(AckTrackerTest, AddPacketNumber_MultiplePackets)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 1));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 2));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 3));
    
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 1u); // Contiguous range
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Add out-of-order packet numbers.
// Scenario: Add packets 10, 5, 15. Verify none are duplicates.
// Assertions: All return FALSE, ranges created appropriately.
//
TEST(AckTrackerTest, AddPacketNumber_OutOfOrder)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 10));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 5));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 15));
    
    // Should have 3 separate ranges
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 3u);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reordering threshold check with zero threshold.
// Scenario: Call DidHitReorderingThreshold with threshold=0. Should always return FALSE.
// Assertions: Returns FALSE regardless of state.
//
TEST(AckTrackerTest, ReorderingThreshold_Disabled)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 100);
    Tracker.LargestPacketNumberAcknowledged = 50;
    
    // Reordering threshold of 0 disables the check
    BOOLEAN Hit = QuicAckTrackerDidHitReorderingThreshold(&Tracker, 0);
    ASSERT_FALSE(Hit);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reordering threshold check with single range.
// Scenario: Only one range present. Should return FALSE (no gaps).
// Assertions: Returns FALSE.
//
TEST(AckTrackerTest, ReorderingThreshold_SingleRange)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 100);
    Tracker.LargestPacketNumberAcknowledged = 50;
    
    // Single range - no reordering
    BOOLEAN Hit = QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3);
    ASSERT_FALSE(Hit);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reordering threshold check with gap exceeding threshold.
// Scenario: Ranges [5-5] and [20-20], LargestAcked=10, threshold=3.
// Gap between 5 and 20 is 14, which exceeds threshold. Should return TRUE.
// Assertions: Returns TRUE.
//
TEST(AckTrackerTest, ReorderingThreshold_ExceedsThreshold)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 20);
    Tracker.LargestPacketNumberAcknowledged = 10;
    
    // Gap between smallest missing (6) and largest unacked (20) is 14 >= threshold (3)
    BOOLEAN Hit = QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3);
    ASSERT_TRUE(Hit);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reordering threshold check with gap below threshold.
// Scenario: Ranges [10-10] and [12-12], LargestAcked=8, threshold=3.
// Gap between 10 and 12 is 1, which doesn't exceed threshold. Should return FALSE.
// Assertions: Returns FALSE.
//
TEST(AckTrackerTest, ReorderingThreshold_BelowThreshold)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 12);
    Tracker.LargestPacketNumberAcknowledged = 8;
    
    // Gap is small, doesn't exceed threshold
    BOOLEAN Hit = QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3);
    ASSERT_FALSE(Hit);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Check if tracker has packets to ACK.
// Scenario: Initially empty, add packet, check again, write ACK frame flag, check again.
// Assertions: FALSE when empty, TRUE when packets present and not written, FALSE after written.
//
TEST(AckTrackerTest, HasPacketsToAck)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    // Initially no packets to ACK
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));
    
    // Add a packet - need to reset AlreadyWrittenAckFrame first
    Tracker.AlreadyWrittenAckFrame = FALSE;
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(&Tracker));
    
    // Mark ACK frame as written
    Tracker.AlreadyWrittenAckFrame = TRUE;
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: OnAckFrameAcked removes packet numbers.
// Scenario: Add packets 1-10, simulate acknowledgment. Verify min value advances.
// Assertions: Min packet number advances after QuicRangeSetMin.
// Note: This tests the core logic of removing acknowledged packets.
//
TEST(AckTrackerTest, OnAckFrameAcked_RemovesPackets)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    // Add packets 1-10
    BOOLEAN Unused;
    QuicRangeAddRange(&Tracker.PacketNumbersToAck, 1, 10, &Unused);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 1u);
    
    // Simulate what OnAckFrameAcked does: remove packets <= 5
    QuicRangeSetMin(&Tracker.PacketNumbersToAck, 6);
    
    // Should have packets 6-10 remaining
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 1u);
    uint64_t MinRemaining = QuicRangeGetMin(&Tracker.PacketNumbersToAck);
    ASSERT_EQ(MinRemaining, 6u);
    
    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: OnAckFrameAcked removes all packets.
// Scenario: Add packets, simulate acknowledgment of all packets.
// Assertions: PacketNumbersToAck becomes empty.
//
TEST(AckTrackerTest, OnAckFrameAcked_RemovesAll)
{
    QUIC_ACK_TRACKER Tracker;
    QuicAckTrackerInitialize(&Tracker);
    
    BOOLEAN Unused;
    QuicRangeAddRange(&Tracker.PacketNumbersToAck, 1, 5, &Unused);
    
    // Remove all packets
    QuicRangeSetMin(&Tracker.PacketNumbersToAck, 11);
    
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    
    QuicAckTrackerUninitialize(&Tracker);
}
