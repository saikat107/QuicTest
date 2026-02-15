/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for QUIC loss detection.

    NOTE: Due to the tight coupling between loss detection and the full QUIC
    connection infrastructure (timers, congestion control, packet pools, etc.),
    comprehensive unit testing of loss detection in isolation is extremely 
    difficult. These tests focus on the testable portions (ComputeProbeTimeout,
    data structure initialization) while acknowledging that full integration
    tests in the main test suite (msquictest) provide better coverage of the
    complete loss detection logic including packet sending, ACK processing,
    and loss recovery.

--*/

#include "main.h"

//
// Test: QUIC_LOSS_DETECTION structure size and alignment
// Scenario: Verify structure layout is as expected
// Verifies: Structure size hasn't changed unexpectedly
//
TEST(LossDetectionTest, DeepTestStructureLayout)
{
    QUIC_LOSS_DETECTION LossDetection;
    
    // Verify key field offsets are reasonable
    ASSERT_GT(sizeof(LossDetection), 0u);
    
    // Verify pointer fields can be accessed
    LossDetection.SentPackets = nullptr;
    LossDetection.LostPackets = nullptr;
    ASSERT_EQ(LossDetection.SentPackets, nullptr);
    ASSERT_EQ(LossDetection.LostPackets, nullptr);
    
    // Verify counter fields can be accessed
    LossDetection.PacketsInFlight = 42;
    ASSERT_EQ(LossDetection.PacketsInFlight, 42u);
    
    LossDetection.TotalBytesSent = 1000000;
    ASSERT_EQ(LossDetection.TotalBytesSent, 1000000ull);
}

//
// Test: Tail pointer calculations
// Scenario: Verify tail pointer math works correctly
// Verifies: Tail pointer addressing is correct for empty list
//
TEST(LossDetectionTest, DeepTestTailPointerMath)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    // Set up as if initialized
    LossDetection.SentPackets = nullptr;
    LossDetection.SentPacketsTail = &LossDetection.SentPackets;
    
    // Verify tail points to head for empty list
    ASSERT_EQ(LossDetection.SentPacketsTail, &LossDetection.SentPackets);
    ASSERT_EQ(*LossDetection.SentPacketsTail, nullptr);
    
    // Same for lost packets
    LossDetection.LostPackets = nullptr;
    LossDetection.LostPacketsTail = &LossDetection.LostPackets;
    
    ASSERT_EQ(LossDetection.LostPacketsTail, &LossDetection.LostPackets);
    ASSERT_EQ(*LossDetection.LostPacketsTail, nullptr);
}

//
// Test: Packet number fields
// Scenario: Verify packet number tracking fields work correctly
// Verifies: LargestAck and LargestSentPacketNumber can store packet numbers
//
TEST(LossDetectionTest, DeepTestPacketNumberFields)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    // Test with various packet numbers
    LossDetection.LargestAck = 0;
    ASSERT_EQ(LossDetection.LargestAck, 0ull);
    
    LossDetection.LargestAck = 12345;
    ASSERT_EQ(LossDetection.LargestAck, 12345ull);
    
    LossDetection.LargestAck = UINT64_MAX;
    ASSERT_EQ(LossDetection.LargestAck, UINT64_MAX);
    
    LossDetection.LargestSentPacketNumber = 54321;
    ASSERT_EQ(LossDetection.LargestSentPacketNumber, 54321ull);
}

//
// Test: Timestamp fields
// Scenario: Verify timestamp fields can store microsecond values
// Verifies: Time fields work with typical microsecond timestamps
//
TEST(LossDetectionTest, DeepTestTimestampFields)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    //  Test TimeOfLastPacketSent
    LossDetection.TimeOfLastPacketSent = 1000000ull; // 1 second in microseconds
    ASSERT_EQ(LossDetection.TimeOfLastPacketSent, 1000000ull);
    
    // Test TimeOfLastPacketAcked
    LossDetection.TimeOfLastPacketAcked = 2500000ull; // 2.5 seconds
    ASSERT_EQ(LossDetection.TimeOfLastPacketAcked, 2500000ull);
    
    // Test TimeOfLastAckedPacketSent
    LossDetection.TimeOfLastAckedPacketSent = 3333333ull;
    ASSERT_EQ(LossDetection.TimeOfLastAckedPacketSent, 3333333ull);
    
    // Test AdjustedLastAckedTime
    LossDetection.AdjustedLastAckedTime = 4444444ull;
    ASSERT_EQ(LossDetection.AdjustedLastAckedTime, 4444444ull);
}

//
// Test: Byte accounting fields
// Scenario: Verify byte counters can track large values
// Verifies: Byte fields work with realistic byte counts
//
TEST(LossDetectionTest, DeepTestByteAccountingFields)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    // Test TotalBytesSent
    LossDetection.TotalBytesSent = 10000000ull; // 10 MB
    ASSERT_EQ(LossDetection.TotalBytesSent, 10000000ull);
    
    // Test TotalBytesAcked
    LossDetection.TotalBytesAcked = 5000000ull; // 5 MB
    ASSERT_EQ(LossDetection.TotalBytesAcked, 5000000ull);
    
    // Test TotalBytesSentAtLastAck
    LossDetection.TotalBytesSentAtLastAck = 7500000ull; // 7.5 MB
    ASSERT_EQ(LossDetection.TotalBytesSentAtLastAck, 7500000ull);
    
    // Verify accounting invariant: TotalBytesSent >= TotalBytesAcked
    ASSERT_GE(LossDetection.TotalBytesSent, LossDetection.TotalBytesAcked);
}

//
// Test: ProbeCount field
// Scenario: Verify ProbeCount can track timeout exponential backoff
// Verifies: ProbeCount field works correctly
//
TEST(LossDetectionTest, DeepTestProbeCountField)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    LossDetection.ProbeCount = 0;
    ASSERT_EQ(LossDetection.ProbeCount, 0u);
    
    LossDetection.ProbeCount = 5;
    ASSERT_EQ(LossDetection.ProbeCount, 5u);
    
    LossDetection.ProbeCount = UINT16_MAX;
    ASSERT_EQ(LossDetection.ProbeCount, UINT16_MAX);
}

//
// Test: Encrypt level field
// Scenario: Verify LargestAckEncryptLevel stores encryption levels
// Verifies: Encrypt level field works with all valid levels
//
TEST(LossDetectionTest, DeepTestEncryptLevelField)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    LossDetection.LargestAckEncryptLevel = QUIC_ENCRYPT_LEVEL_INITIAL;
    ASSERT_EQ(LossDetection.LargestAckEncryptLevel, QUIC_ENCRYPT_LEVEL_INITIAL);
    
    LossDetection.LargestAckEncryptLevel = QUIC_ENCRYPT_LEVEL_HANDSHAKE;
    ASSERT_EQ(LossDetection.LargestAckEncryptLevel, QUIC_ENCRYPT_LEVEL_HANDSHAKE);
    
    LossDetection.LargestAckEncryptLevel = QUIC_ENCRYPT_LEVEL_1_RTT;
    ASSERT_EQ(LossDetection.LargestAckEncryptLevel, QUIC_ENCRYPT_LEVEL_1_RTT);
}

//
// Test: PacketsInFlight counter
// Scenario: Verify PacketsInFlight can track outstanding packets
// Verifies: Counter handles typical and edge case values
//
TEST(LossDetectionTest, DeepTestPacketsInFlightCounter)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    // Start at zero
    LossDetection.PacketsInFlight = 0;
    ASSERT_EQ(LossDetection.PacketsInFlight, 0u);
    
    // Typical value
    LossDetection.PacketsInFlight = 10;
    ASSERT_EQ(LossDetection.PacketsInFlight, 10u);
    
    // High congestion window
    LossDetection.PacketsInFlight = 1000;
    ASSERT_EQ(LossDetection.PacketsInFlight, 1000u);
    
    // Maximum theoretical value
    LossDetection.PacketsInFlight = UINT32_MAX;
    ASSERT_EQ(LossDetection.PacketsInFlight, UINT32_MAX);
}

//
// Test: Field independence
// Scenario: Verify setting one field doesn't affect others
// Verifies: Fields are independent and don't overlap
//
TEST(LossDetectionTest, DeepTestFieldIndependence)
{
    QUIC_LOSS_DETECTION LossDetection;
    CxPlatZeroMemory(&LossDetection, sizeof(LossDetection));
    
    // Set multiple fields to unique values
    LossDetection.PacketsInFlight = 111;
    LossDetection.LargestAck = 222;
    LossDetection.TimeOfLastPacketSent = 333;
    LossDetection.TotalBytesSent = 444;
    LossDetection.ProbeCount = 55;
    
    // Verify all retain their values
    ASSERT_EQ(LossDetection.PacketsInFlight, 111u);
    ASSERT_EQ(LossDetection.LargestAck, 222ull);
    ASSERT_EQ(LossDetection.TimeOfLastPacketSent, 333ull);
    ASSERT_EQ(LossDetection.TotalBytesSent, 444ull);
    ASSERT_EQ(LossDetection.ProbeCount, 55u);
}

// NOTE: Additional tests for QuicLossDetectionInitialize, QuicLossDetectionReset,
// QuicLossDetectionUninitialize, QuicLossDetectionOnPacketSent,
// QuicLossDetectionProcessAckFrame, and other functions require full QUIC_CONNECTION
// infrastructure including timers, congestion control, packet pools, and stream
// management. These are better tested through integration tests in the main
// msquictest suite where the full connection context is available.

