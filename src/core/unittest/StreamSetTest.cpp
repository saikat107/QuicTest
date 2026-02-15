/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for QUIC Stream Set Management.

--*/

#include "main.h"

//
// Helper to create a minimal mock connection for stream set testing.
// Uses a real QUIC_CONNECTION structure to ensure proper memory layout.
//
static void InitializeMockConnection(
    QUIC_CONNECTION& Connection,
    BOOLEAN IsServer)
{
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    
    // Set connection state
    Connection.State.Initialized = TRUE;
    Connection.State.Started = TRUE;
    Connection.State.PeerTransportParameterValid = TRUE;
    
    // Set server/client flag (via base QUIC_HANDLE Type field)
    ((QUIC_HANDLE*)&Connection)->Type = IsServer ? 
        QUIC_HANDLE_TYPE_CONNECTION_SERVER : QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
    
    // Initialize transport parameters
    Connection.PeerTransportParams.Flags = 0;
    Connection.PeerTransportParams.InitialMaxData = 65536;
    Connection.PeerTransportParams.InitialMaxStreamDataBidiLocal = 16384;
    Connection.PeerTransportParams.InitialMaxStreamDataBidiRemote = 16384;
    Connection.PeerTransportParams.InitialMaxStreamDataUni = 16384;
}

//
// Test: DeepTestStreamSetInitialize
// Scenario: Verifies QuicStreamSetInitialize correctly initializes all fields
// How: Calls QuicStreamSetInitialize on a stream set
// Assertions: Lists are initialized, StreamTable is NULL, Types array is zero-initialized
//
TEST(StreamSetTest, DeepTestStreamSetInitialize)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Verify lists are initialized (non-null forward/back links)
    ASSERT_NE(Connection.Streams.ClosedStreams.Flink, nullptr);
    ASSERT_NE(Connection.Streams.ClosedStreams.Blink, nullptr);
    ASSERT_NE(Connection.Streams.WaitingStreams.Flink, nullptr);
    ASSERT_NE(Connection.Streams.WaitingStreams.Blink, nullptr);
    
    // Verify lists are empty (self-referential)
    ASSERT_EQ(Connection.Streams.ClosedStreams.Flink, &Connection.Streams.ClosedStreams);
    ASSERT_EQ(Connection.Streams.ClosedStreams.Blink, &Connection.Streams.ClosedStreams);
    ASSERT_EQ(Connection.Streams.WaitingStreams.Flink, &Connection.Streams.WaitingStreams);
    ASSERT_EQ(Connection.Streams.WaitingStreams.Blink, &Connection.Streams.WaitingStreams);
    
    // Verify StreamTable is NULL (lazy initialization)
    ASSERT_EQ(Connection.Streams.StreamTable, nullptr);
    
    // Verify all stream types are zero-initialized
    for (int i = 0; i < NUMBER_OF_STREAM_TYPES; i++) {
        ASSERT_EQ(Connection.Streams.Types[i].MaxTotalStreamCount, 0u);
        ASSERT_EQ(Connection.Streams.Types[i].TotalStreamCount, 0u);
        ASSERT_EQ(Connection.Streams.Types[i].MaxCurrentStreamCount, 0u);
        ASSERT_EQ(Connection.Streams.Types[i].CurrentStreamCount, 0u);
    }
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUninitialize
// Scenario: Verifies QuicStreamSetUninitialize properly cleans up
// How: Initializes then uninitializes a stream set
// Assertions: No crashes, proper cleanup
//
TEST(StreamSetTest, DeepTestStreamSetUninitialize)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    QuicStreamSetUninitialize(&Connection.Streams);
    
    // After uninitialize, StreamTable should still be NULL (was never allocated)
    ASSERT_EQ(Connection.Streams.StreamTable, nullptr);
}

//
// Test: DeepTestStreamSetGetCountAvailableZero
// Scenario: Verifies QuicStreamSetGetCountAvailable returns 0 when no streams allowed
// How: Calls GetCountAvailable on zero-initialized stream set
// Assertions: Returns 0 for all stream types
//
TEST(StreamSetTest, DeepTestStreamSetGetCountAvailableZero)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // All types should return 0 available (MaxTotal = 0, Total = 0)
    ASSERT_EQ(QuicStreamSetGetCountAvailable(&Connection.Streams, 0), 0u);
    ASSERT_EQ(QuicStreamSetGetCountAvailable(&Connection.Streams, 1), 0u);
    ASSERT_EQ(QuicStreamSetGetCountAvailable(&Connection.Streams, 2), 0u);
    ASSERT_EQ(QuicStreamSetGetCountAvailable(&Connection.Streams, 3), 0u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetGetCountAvailableNonZero
// Scenario: Verifies QuicStreamSetGetCountAvailable returns correct count when streams allowed
// How: Sets MaxTotalStreamCount, calls GetCountAvailable
// Assertions: Returns correct available count (MaxTotal - Total)
//
TEST(StreamSetTest, DeepTestStreamSetGetCountAvailableNonZero)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set max allowed streams for type 0 (client bidirectional)
    Connection.Streams.Types[0].MaxTotalStreamCount = 100;
    Connection.Streams.Types[0].TotalStreamCount = 30;
    
    uint16_t Available = QuicStreamSetGetCountAvailable(&Connection.Streams, 0);
    ASSERT_EQ(Available, 70u); // 100 - 30 = 70
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetGetCountAvailableAtLimit
// Scenario: Verifies GetCountAvailable returns 0 when at limit
// How: Sets TotalStreamCount == MaxTotalStreamCount
// Assertions: Returns 0
//
TEST(StreamSetTest, DeepTestStreamSetGetCountAvailableAtLimit)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    Connection.Streams.Types[1].MaxTotalStreamCount = 50;
    Connection.Streams.Types[1].TotalStreamCount = 50;
    
    uint16_t Available = QuicStreamSetGetCountAvailable(&Connection.Streams, 1);
    ASSERT_EQ(Available, 0u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetGetCountAvailableCapped
// Scenario: Verifies GetCountAvailable caps return at UINT16_MAX
// How: Sets MaxTotalStreamCount very high
// Assertions: Returns UINT16_MAX (65535)
//
TEST(StreamSetTest, DeepTestStreamSetGetCountAvailableCapped)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    Connection.Streams.Types[2].MaxTotalStreamCount = UINT64_MAX;
    Connection.Streams.Types[2].TotalStreamCount = 0;
    
    uint16_t Available = QuicStreamSetGetCountAvailable(&Connection.Streams, 2);
    ASSERT_EQ(Available, UINT16_MAX); // Capped at 65535
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxCountBeforeStart
// Scenario: Verifies UpdateMaxCount before connection start sets MaxTotalStreamCount
// How: Calls UpdateMaxCount with connection not started
// Assertions: MaxCurrentStreamCount and MaxTotalStreamCount updated correctly
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxCountBeforeStart)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    Connection.State.Started = FALSE; // Not started yet
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Update max count for type 0 (client bidirectional)
    QuicStreamSetUpdateMaxCount(&Connection.Streams, 0, 100);
    
    ASSERT_EQ(Connection.Streams.Types[0].MaxCurrentStreamCount, 100u);
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 100u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxCountAfterStart
// Scenario: Verifies UpdateMaxCount after connection start adjusts MaxTotalStreamCount
// How: Calls UpdateMaxCount with connection started and existing current count
// Assertions: MaxTotalStreamCount incremented by delta
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxCountAfterStart)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    Connection.State.Started = TRUE;
    
    // Initialize send structure to avoid null dereference
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set initial state
    Connection.Streams.Types[0].MaxCurrentStreamCount = 50;
    Connection.Streams.Types[0].MaxTotalStreamCount = 60;
    
    // Increase max to 80 (delta = 30)
    QuicStreamSetUpdateMaxCount(&Connection.Streams, 0, 80);
    
    ASSERT_EQ(Connection.Streams.Types[0].MaxCurrentStreamCount, 80u);
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 90u); // 60 + (80 - 50) = 90
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetGetFlowControlSummaryEmpty
// Scenario: Verifies GetFlowControlSummary returns zeros for empty stream set
// How: Calls GetFlowControlSummary with no streams
// Assertions: Both outputs are 0
//
TEST(StreamSetTest, DeepTestStreamSetGetFlowControlSummaryEmpty)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    uint64_t FcAvailable = 999;
    uint64_t SendWindow = 999;
    
    QuicStreamSetGetFlowControlSummary(&Connection.Streams, &FcAvailable, &SendWindow);
    
    ASSERT_EQ(FcAvailable, 0u);
    ASSERT_EQ(SendWindow, 0u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetGetMaxStreamIDs
// Scenario: Verifies GetMaxStreamIDs returns correctly encoded stream IDs
// How: Sets MaxTotalStreamCount for each type, calls GetMaxStreamIDs
// Assertions: Returns (count << 2) | type for each type
//
TEST(StreamSetTest, DeepTestStreamSetGetMaxStreamIDs)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set max counts
    Connection.Streams.Types[0].MaxTotalStreamCount = 10; // Client Bidi
    Connection.Streams.Types[1].MaxTotalStreamCount = 20; // Server Bidi
    Connection.Streams.Types[2].MaxTotalStreamCount = 30; // Client Uni
    Connection.Streams.Types[3].MaxTotalStreamCount = 40; // Server Uni
    
    uint64_t MaxStreamIds[NUMBER_OF_STREAM_TYPES];
    QuicStreamSetGetMaxStreamIDs(&Connection.Streams, MaxStreamIds);
    
    // Verify encoding: (count << 2) | type
    ASSERT_EQ(MaxStreamIds[0], (10ull << 2) | 0); // 40
    ASSERT_EQ(MaxStreamIds[1], (20ull << 2) | 1); // 81
    ASSERT_EQ(MaxStreamIds[2], (30ull << 2) | 2); // 122
    ASSERT_EQ(MaxStreamIds[3], (40ull << 2) | 3); // 163
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetInitializeTransportParametersBasic
// Scenario: Verifies InitializeTransportParameters sets max stream counts
// How: Calls InitializeTransportParameters with bidi and unidi counts
// Assertions: MaxTotalStreamCount updated for local stream types (client or server)
//
TEST(StreamSetTest, DeepTestStreamSetInitializeTransportParametersBasic)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE); // Client connection
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Client can initiate: type 0 (client bidi) and type 2 (client uni)
    // Peer allows 10 bidi and 20 unidi streams
    QuicStreamSetInitializeTransportParameters(
        &Connection.Streams,
        10,  // BidiStreamCount
        20,  // UnidiStreamCount
        FALSE);
    
    // Client bidi (type 0) should be set to 10
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 10u);
    
    // Client uni (type 2) should be set to 20
    ASSERT_EQ(Connection.Streams.Types[2].MaxTotalStreamCount, 20u);
    
    // Server types should remain 0
    ASSERT_EQ(Connection.Streams.Types[1].MaxTotalStreamCount, 0u);
    ASSERT_EQ(Connection.Streams.Types[3].MaxTotalStreamCount, 0u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetInitializeTransportParametersServer
// Scenario: Verifies InitializeTransportParameters for server connection
// How: Creates server connection, calls InitializeTransportParameters
// Assertions: MaxTotalStreamCount updated for server stream types
//
TEST(StreamSetTest, DeepTestStreamSetInitializeTransportParametersServer)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, TRUE); // Server connection
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Server can initiate: type 1 (server bidi) and type 3 (server uni)
    QuicStreamSetInitializeTransportParameters(
        &Connection.Streams,
        15,  // BidiStreamCount
        25,  // UnidiStreamCount
        FALSE);
    
    // Server bidi (type 1) should be set to 15
    ASSERT_EQ(Connection.Streams.Types[1].MaxTotalStreamCount, 15u);
    
    // Server uni (type 3) should be set to 25
    ASSERT_EQ(Connection.Streams.Types[3].MaxTotalStreamCount, 25u);
    
    // Client types should remain 0
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 0u);
    ASSERT_EQ(Connection.Streams.Types[2].MaxTotalStreamCount, 0u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxStreamsIncrease
// Scenario: Verifies UpdateMaxStreams increases max stream count
// How: Calls UpdateMaxStreams with higher limit
// Assertions: MaxTotalStreamCount increased for correct stream type
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxStreamsIncrease)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE); // Client
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set initial max for client bidi streams (type 0)
    Connection.Streams.Types[0].MaxTotalStreamCount = 10;
    
    // Peer sends MAX_STREAMS frame increasing limit to 20
    QuicStreamSetUpdateMaxStreams(&Connection.Streams, TRUE, 20);
    
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 20u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxStreamsNoDecrease
// Scenario: Verifies UpdateMaxStreams does not decrease limit
// How: Calls UpdateMaxStreams with lower value
// Assertions: MaxTotalStreamCount unchanged
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxStreamsNoDecrease)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE); // Client
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    Connection.Streams.Types[0].MaxTotalStreamCount = 50;
    
    // Try to decrease limit to 30 (should be ignored)
    QuicStreamSetUpdateMaxStreams(&Connection.Streams, TRUE, 30);
    
    ASSERT_EQ(Connection.Streams.Types[0].MaxTotalStreamCount, 50u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxStreamsBidiServer
// Scenario: Verifies UpdateMaxStreams updates server bidi streams
// How: Server connection, calls UpdateMaxStreams for bidi
// Assertions: Server bidi type (1) updated
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxStreamsBidiServer)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, TRUE); // Server
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    Connection.Streams.Types[1].MaxTotalStreamCount = 5;
    
    // Update server bidi streams
    QuicStreamSetUpdateMaxStreams(&Connection.Streams, TRUE, 15);
    
    ASSERT_EQ(Connection.Streams.Types[1].MaxTotalStreamCount, 15u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetUpdateMaxStreamsUnidiServer
// Scenario: Verifies UpdateMaxStreams updates server unidi streams
// How: Server connection, calls UpdateMaxStreams for unidi
// Assertions: Server unidi type (3) updated
//
TEST(StreamSetTest, DeepTestStreamSetUpdateMaxStreamsUnidiServer)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, TRUE); // Server
    
    // Initialize send structure
    CxPlatZeroMemory(&Connection.Send, sizeof(Connection.Send));
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    Connection.Streams.Types[3].MaxTotalStreamCount = 8;
    
    // Update server unidi streams
    QuicStreamSetUpdateMaxStreams(&Connection.Streams, FALSE, 25);
    
    ASSERT_EQ(Connection.Streams.Types[3].MaxTotalStreamCount, 25u);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetAllStreamTypes
// Scenario: Verifies all 4 stream type encodings work correctly
// How: Sets counts for all 4 types, gets max IDs
// Assertions: All types encoded correctly (type in low 2 bits)
//
TEST(StreamSetTest, DeepTestStreamSetAllStreamTypes)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set unique counts for each type
    Connection.Streams.Types[0].MaxTotalStreamCount = 1; // Client Bidi: 0b00
    Connection.Streams.Types[1].MaxTotalStreamCount = 2; // Server Bidi: 0b01
    Connection.Streams.Types[2].MaxTotalStreamCount = 3; // Client Uni:  0b10
    Connection.Streams.Types[3].MaxTotalStreamCount = 4; // Server Uni:  0b11
    
    uint64_t MaxStreamIds[NUMBER_OF_STREAM_TYPES];
    QuicStreamSetGetMaxStreamIDs(&Connection.Streams, MaxStreamIds);
    
    // Verify type bits are correct
    ASSERT_EQ(MaxStreamIds[0] & 0x3, 0u); // Type 0b00
    ASSERT_EQ(MaxStreamIds[1] & 0x3, 1u); // Type 0b01
    ASSERT_EQ(MaxStreamIds[2] & 0x3, 2u); // Type 0b10
    ASSERT_EQ(MaxStreamIds[3] & 0x3, 3u); // Type 0b11
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetTypeBoundaries
// Scenario: Verifies stream type boundaries and count ranges
// How: Tests all 4 types with various count values
// Assertions: Each type maintains independent counts
//
TEST(StreamSetTest, DeepTestStreamSetTypeBoundaries)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set different totals and currents for each type
    for (int i = 0; i < NUMBER_OF_STREAM_TYPES; i++) {
        Connection.Streams.Types[i].MaxTotalStreamCount = (i + 1) * 100;
        Connection.Streams.Types[i].TotalStreamCount = (i + 1) * 50;
        Connection.Streams.Types[i].MaxCurrentStreamCount = (i + 1) * 80;
        Connection.Streams.Types[i].CurrentStreamCount = (i + 1) * 40;
    }
    
    // Verify each type is independent
    for (int i = 0; i < NUMBER_OF_STREAM_TYPES; i++) {
        uint16_t Available = QuicStreamSetGetCountAvailable(&Connection.Streams, i);
        ASSERT_EQ(Available, (uint16_t)((i + 1) * 50)); // MaxTotal - Total
        ASSERT_EQ(Connection.Streams.Types[i].CurrentStreamCount, (uint16_t)((i + 1) * 40));
    }
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetCountConsistency
// Scenario: Verifies count invariants (TotalStreamCount >= CurrentStreamCount)
// How: Sets various count combinations, verifies invariants hold
// Assertions: Total >= Current for all types
//
TEST(StreamSetTest, DeepTestStreamSetCountConsistency)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set counts maintaining invariant
    Connection.Streams.Types[0].TotalStreamCount = 100;
    Connection.Streams.Types[0].CurrentStreamCount = 60;
    
    Connection.Streams.Types[1].TotalStreamCount = 50;
    Connection.Streams.Types[1].CurrentStreamCount = 50;
    
    Connection.Streams.Types[2].TotalStreamCount = 200;
    Connection.Streams.Types[2].CurrentStreamCount = 0;
    
    // Verify invariant: Total >= Current
    for (int i = 0; i < NUMBER_OF_STREAM_TYPES; i++) {
        ASSERT_GE(Connection.Streams.Types[i].TotalStreamCount,
                  Connection.Streams.Types[i].CurrentStreamCount);
    }
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetLargeStreamCounts
// Scenario: Verifies behavior with very large stream counts
// How: Sets MaxTotalStreamCount to large values, tests GetCountAvailable
// Assertions: Correctly handles large counts, caps at UINT16_MAX
//
TEST(StreamSetTest, DeepTestStreamSetLargeStreamCounts)
{
    QUIC_CONNECTION Connection;
    InitializeMockConnection(Connection, FALSE);
    
    QuicStreamSetInitialize(&Connection.Streams);
    
    // Set very large max count
    Connection.Streams.Types[0].MaxTotalStreamCount = 1000000;
    Connection.Streams.Types[0].TotalStreamCount = 500000;
    
    uint16_t Available = QuicStreamSetGetCountAvailable(&Connection.Streams, 0);
    
    // Should be capped at UINT16_MAX (65535), not 500000
    ASSERT_EQ(Available, UINT16_MAX);
    
    QuicStreamSetUninitialize(&Connection.Streams);
}

//
// Test: DeepTestStreamSetClientServerTypeDifference
// Scenario: Verifies client and server connections use different stream types
// How: Creates both client and server connections, checks type assignments
// Assertions: Client uses types 0,2; Server uses types 1,3
//
TEST(StreamSetTest, DeepTestStreamSetClientServerTypeDifference)
{
    QUIC_CONNECTION ClientConn, ServerConn;
    InitializeMockConnection(ClientConn, FALSE);
    InitializeMockConnection(ServerConn, TRUE);
    
    // Initialize send structures
    CxPlatZeroMemory(&ClientConn.Send, sizeof(ClientConn.Send));
    CxPlatZeroMemory(&ServerConn.Send, sizeof(ServerConn.Send));
    
    QuicStreamSetInitialize(&ClientConn.Streams);
    QuicStreamSetInitialize(&ServerConn.Streams);
    
    // Set TP for client (types 0,2 for client-initiated streams)
    QuicStreamSetInitializeTransportParameters(&ClientConn.Streams, 10, 20, FALSE);
    
    // Set TP for server (types 1,3 for server-initiated streams)
    QuicStreamSetInitializeTransportParameters(&ServerConn.Streams, 15, 25, FALSE);
    
    // Client should have types 0 and 2 set
    ASSERT_EQ(ClientConn.Streams.Types[0].MaxTotalStreamCount, 10u);
    ASSERT_EQ(ClientConn.Streams.Types[2].MaxTotalStreamCount, 20u);
    ASSERT_EQ(ClientConn.Streams.Types[1].MaxTotalStreamCount, 0u);
    ASSERT_EQ(ClientConn.Streams.Types[3].MaxTotalStreamCount, 0u);
    
    // Server should have types 1 and 3 set
    ASSERT_EQ(ServerConn.Streams.Types[1].MaxTotalStreamCount, 15u);
    ASSERT_EQ(ServerConn.Streams.Types[3].MaxTotalStreamCount, 25u);
    ASSERT_EQ(ServerConn.Streams.Types[0].MaxTotalStreamCount, 0u);
    ASSERT_EQ(ServerConn.Streams.Types[2].MaxTotalStreamCount, 0u);
    
    QuicStreamSetUninitialize(&ClientConn.Streams);
    QuicStreamSetUninitialize(&ServerConn.Streams);
}
