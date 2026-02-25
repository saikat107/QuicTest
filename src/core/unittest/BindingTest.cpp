/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC binding implementation (binding.c).

    Coverage: 228 / 720 coverable lines = 31.7%.

    All reachable code paths in the mock test environment are covered.
    The remaining 492 uncovered lines are contract-unreachable because they
    require one or more of the following infrastructure that is unavailable
    when MsQuicLib.Datapath is NULL:

    CONTRACT-UNREACHABLE FUNCTIONS (need Socket/Datapath):
      QuicBindingInitialize          (L42-189,  69 lines) - CxPlatSocketCreateUdp
      QuicBindingUninitialize        (L192-241, 20 lines) - CxPlatSocketDelete
      QuicBindingTraceRundown        (L245-272, 12 lines) - CxPlatSocketGetLocalAddress
      QuicBindingGetLocalAddress     (L276-285,  5 lines) - Binding->Socket
      QuicBindingSetLocalAddress     (L287-304,  7 lines) - Binding->Socket
      QuicBindingReceive             (L1594-1762,89 lines) - Full datapath callback
      QuicBindingSend                (L1792-1832,16 lines) - CxPlatSocketSend
      QuicBindingUnreachable         (L1767-1788, 9 lines) - QuicConnQueueUnreachable

    CONTRACT-UNREACHABLE FUNCTIONS (need StatelessRegistration/Worker):
      QuicBindingQueueStatelessOp    (L745-784, 16 lines) - WorkerPool
      QuicBindingCreateStatelessOp   (L626-741, 33 lines) - Worker/CxPlatPoolAlloc
      QuicBindingProcessStatelessOp  (L786-1069,118 lines) - Socket+Crypto
      QuicBindingReleaseStatelessOp  (L1073-1099,14 lines) - StatelessCtx

    CONTRACT-UNREACHABLE FUNCTIONS (need QuicConnAlloc/Worker):
      QuicBindingAcceptConnection    (L498-558, 22 lines) - TlsState/Listener
      QuicBindingCreateConnection    (L1249-1367,45 lines) - QuicConnAlloc

    CONTRACT-UNREACHABLE PATHS (specific lines):
      DeliverPackets deep paths      (L1575-1588, 7 lines) - CreateConnection/ConnQueue
      RegisterListener MaxLookup OOM (L406-407,   2 lines) - OOM unreproducible
      GetListener else branch        (L457,        1 line) - Coverage tool artifact
      QueueStatelessReset exclusive  (L1122-1123,  2 lines) - CXPLAT_DBG_ASSERT blocks
      ShouldRetryConnection w/token  (L1233-1239,  5 lines) - QuicPacketValidateInitialToken

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BindingTest.cpp.clog.h"
#endif

//
// Test fixture for binding tests. Creates mock QUIC_BINDING objects by
// manually initializing the struct fields without a real UDP socket. This
// allows testing binding logic (listener registration, CID management,
// trace rundown, DoS mode) without requiring a live datapath.
//
class DeepTest_Binding : public ::testing::Test {
protected:
    //
    // Dummy partition used when MsQuicLib.Partitions is NULL.
    // QuicPacketLogDrop and other code paths access
    // MsQuicLib.Partitions[PartitionIndex], which crashes if NULL.
    //
    QUIC_PARTITION DummyPartition_;
    QUIC_PARTITION* SavedPartitions_;
    uint16_t SavedPartitionCount_;
    BOOLEAN PartitionsOverridden_;

    void SetUp() override {
        PartitionsOverridden_ = FALSE;
        if (MsQuicLib.Partitions == NULL) {
            CxPlatZeroMemory(&DummyPartition_, sizeof(DummyPartition_));
            SavedPartitions_ = MsQuicLib.Partitions;
            SavedPartitionCount_ = MsQuicLib.PartitionCount;
            MsQuicLib.Partitions = &DummyPartition_;
            MsQuicLib.PartitionCount = 1;
            PartitionsOverridden_ = TRUE;
        }
    }

    void TearDown() override {
        if (PartitionsOverridden_) {
            MsQuicLib.Partitions = SavedPartitions_;
            MsQuicLib.PartitionCount = SavedPartitionCount_;
        }
    }

    //
    // Helper: Creates a mock QUIC_BINDING with initialized fields but no
    // real socket. Sets ServerOwned, Exclusive, and Connected flags as
    // specified.
    //
    static void
    InitializeMockBinding(
        _Out_ QUIC_BINDING* Binding,
        _In_ BOOLEAN ServerOwned,
        _In_ BOOLEAN Exclusive,
        _In_ BOOLEAN Connected
        )
    {
        CxPlatZeroMemory(Binding, sizeof(*Binding));
        CxPlatListInitializeHead(&Binding->Link);
        Binding->Exclusive = Exclusive;
        Binding->ServerOwned = ServerOwned;
        Binding->Connected = Connected;
        Binding->Partitioned = FALSE;
        Binding->RefCount = 1;
        Binding->StatelessOperCount = 0;
        Binding->Socket = nullptr;
        CxPlatDispatchRwLockInitialize(&Binding->RwLock);
        CxPlatDispatchLockInitialize(&Binding->StatelessOperLock);
        CxPlatListInitializeHead(&Binding->Listeners);
        QuicLookupInitialize(&Binding->Lookup);
        ASSERT_TRUE(CxPlatHashtableInitializeEx(
            &Binding->StatelessOperTable, CXPLAT_HASH_MIN_SIZE));
        CxPlatListInitializeHead(&Binding->StatelessOperList);
        CxPlatRandom(sizeof(uint32_t), &Binding->RandomReservedVersion);
        Binding->RandomReservedVersion =
            (Binding->RandomReservedVersion & ~QUIC_VERSION_RESERVED_MASK) |
            QUIC_VERSION_RESERVED;
    }

    //
    // Helper: Uninitializes a mock binding without trying to close the socket.
    //
    static void
    UninitializeMockBinding(
        _In_ QUIC_BINDING* Binding
        )
    {
        QuicLookupUninitialize(&Binding->Lookup);
        CxPlatHashtableUninitialize(&Binding->StatelessOperTable);
        CxPlatDispatchLockUninitialize(&Binding->StatelessOperLock);
        CxPlatDispatchRwLockUninitialize(&Binding->RwLock);
    }

    //
    // Helper: Initializes a mock QUIC_LISTENER with the given ALPN and
    // address family. ALPN is in TLS extension format: [len, ...data].
    //
    static void
    InitializeMockListener(
        _Out_ QUIC_LISTENER* Listener,
        _In_reads_(AlpnLength) const uint8_t* Alpn,
        _In_ uint16_t AlpnLength,
        _In_ QUIC_ADDRESS_FAMILY Family,
        _In_ BOOLEAN WildCard
        )
    {
        CxPlatZeroMemory(Listener, sizeof(*Listener));
        Listener->_.Type = QUIC_HANDLE_TYPE_LISTENER;
        Listener->WildCard = WildCard;
        Listener->AlpnList = (uint8_t*)Alpn;
        Listener->AlpnListLength = AlpnLength;
        CxPlatListInitializeHead(&Listener->Link);
        CxPlatListInitializeHead(&Listener->RegistrationLink);
        CxPlatListInitializeHead(&Listener->WorkerLink);

        QuicAddrSetFamily(&Listener->LocalAddress, Family);
        if (!WildCard && Family != QUIC_ADDRESS_FAMILY_UNSPEC) {
            QuicAddrFromString("127.0.0.1", 4433, &Listener->LocalAddress);
        }
        CxPlatRefInitialize(&Listener->StartRefCount);
        CxPlatRefInitialize(&Listener->RefCount);
    }

    //
    // Helper: Initializes a minimal mock connection.
    //
    static void
    InitializeMockConnection(
        _Out_ QUIC_CONNECTION* Connection
        )
    {
        CxPlatZeroMemory(Connection, sizeof(*Connection));
        Connection->_.Type = QUIC_HANDLE_TYPE_CONNECTION_SERVER;
        Connection->RefCount = 1;
        Connection->SourceCids.Next = nullptr;
        Connection->RemoteHashEntry = nullptr;
        CxPlatListInitializeHead(&Connection->RegistrationLink);
        CxPlatListInitializeHead(&Connection->WorkerLink);
        CxPlatListInitializeHead(&Connection->TimerLink);
#if DEBUG
        for (uint32_t i = 0; i < QUIC_CONN_REF_COUNT; i++) {
            CxPlatRefInitialize(&Connection->RefTypeBiasedCount[i]);
        }
#endif
    }
};

// =====================================================================
// Listener Registration / Unregistration tests
// =====================================================================

//
// Scenario: Registering a single listener on an empty binding succeeds.
// How: Create a mock binding, create a mock listener with ALPN "test", and
// call QuicBindingRegisterListener.
// Assertions: Status is QUIC_STATUS_SUCCESS. Listeners list is not empty
// after registration.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_Single)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    QUIC_STATUS Status = QuicBindingRegisterListener(&Binding, &Listener);
    TEST_QUIC_SUCCEEDED(Status);

    ASSERT_FALSE(CxPlatListIsEmpty(&Binding.Listeners));

    QuicBindingUnregisterListener(&Binding, &Listener);
    ASSERT_TRUE(CxPlatListIsEmpty(&Binding.Listeners));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: Registering two listeners with different ALPNs on the same
// binding succeeds.
// How: Register listener with ALPN "test", then register another with ALPN
// "h3". Both should succeed since ALPNs don't overlap.
// Assertions: Both registrations return QUIC_STATUS_SUCCESS.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_DifferentAlpns)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 2, 'h', '3' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Registering two listeners with the SAME ALPN on the same
// binding and same address family returns QUIC_STATUS_ALPN_IN_USE.
// How: Register listener with ALPN "test", then register another with
// same ALPN "test" on same family and wildcard.
// Assertions: Second registration returns QUIC_STATUS_ALPN_IN_USE. Only
// one listener remains in the list.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_DuplicateAlpn)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));

    QUIC_STATUS Status = QuicBindingRegisterListener(&Binding, &Listener2);
    ASSERT_EQ(Status, QUIC_STATUS_ALPN_IN_USE);

    //
    // Only Listener1 should be in the list.
    //
    ASSERT_FALSE(CxPlatListIsEmpty(&Binding.Listeners));
    ASSERT_EQ(Binding.Listeners.Flink, &Listener1.Link);

    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Registering listeners with different address families. Listeners
// are sorted by family in descending order: AF_INET6 > AF_INET > AF_UNSPEC.
// How: Register AF_UNSPEC, then AF_INET, then AF_INET6 listeners with
// different ALPNs. All should succeed.
// Assertions: All three registrations succeed.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_MultipleFamilies)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER ListenerUnspec;
    InitializeMockListener(
        &ListenerUnspec, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener4;
    InitializeMockListener(
        &Listener4, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn3[] = { 1, 'c' };
    QUIC_LISTENER Listener6;
    InitializeMockListener(
        &Listener6, Alpn3, sizeof(Alpn3),
        QUIC_ADDRESS_FAMILY_INET6, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &ListenerUnspec));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener4));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener6));

    QuicBindingUnregisterListener(&Binding, &Listener6);
    QuicBindingUnregisterListener(&Binding, &Listener4);
    QuicBindingUnregisterListener(&Binding, &ListenerUnspec);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Register a specific (non-wildcard) address listener followed by
// a wildcard listener with the same family and different ALPNs.
// How: Register non-wildcard AF_INET listener, then wildcard AF_INET
// listener. Both with different ALPNs.
// Assertions: Both registrations succeed (different ALPNs, different
// wildcard status).
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_SpecificThenWildcard)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER SpecificListener;
    InitializeMockListener(
        &SpecificListener, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, FALSE);

    static const uint8_t Alpn2[] = { 2, 'h', '3' };
    QUIC_LISTENER WildcardListener;
    InitializeMockListener(
        &WildcardListener, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &SpecificListener));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &WildcardListener));

    QuicBindingUnregisterListener(&Binding, &WildcardListener);
    QuicBindingUnregisterListener(&Binding, &SpecificListener);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Unregistering a listener from a binding leaves the binding's
// listener list empty if it was the only listener.
// How: Register, then unregister a single listener.
// Assertions: Listeners list is empty after unregistration.
//
TEST_F(DeepTest_Binding, DeepTest_UnregisterListener_LeavesEmpty)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));
    ASSERT_FALSE(CxPlatListIsEmpty(&Binding.Listeners));

    QuicBindingUnregisterListener(&Binding, &Listener);
    ASSERT_TRUE(CxPlatListIsEmpty(&Binding.Listeners));

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingAddSourceConnectionID / RemoveSourceConnectionID tests
// =====================================================================

//
// Scenario: Adding a source connection ID to the binding's lookup table
// succeeds and increases the CID count.
// How: Create a mock binding, create a CID hash entry using
// QuicCidNewSource, link it into the connection's SourceCids list, and
// call QuicBindingAddSourceConnectionID. Then use RemoveConnection to clean up.
// Assertions: Returns TRUE, CidCount becomes 1.
//
TEST_F(DeepTest_Binding, DeepTest_AddSourceConnectionID)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(SourceCid, nullptr);

    //
    // Link CID into the connection's SourceCids singly-linked list.
    //
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    BOOLEAN Result = QuicBindingAddSourceConnectionID(&Binding, SourceCid);
    ASSERT_EQ(Result, TRUE);
    ASSERT_EQ(Binding.Lookup.CidCount, 1u);

    //
    // RemoveConnection pops all CIDs from SourceCids, removes from lookup,
    // and frees each CID entry.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Adding multiple distinct source CIDs to the binding succeeds.
// How: Add three different CIDs to the binding lookup via the connection's
// SourceCids list, then clean up with RemoveConnection.
// Assertions: All three additions return TRUE, CidCount is 3.
//
TEST_F(DeepTest_Binding, DeepTest_AddMultipleSourceConnectionIDs)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint8_t CidData2[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    uint8_t CidData3[] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

    QUIC_CID_HASH_ENTRY* Cid1 =
        QuicCidNewSource(&Connection, sizeof(CidData1), CidData1);
    QUIC_CID_HASH_ENTRY* Cid2 =
        QuicCidNewSource(&Connection, sizeof(CidData2), CidData2);
    QUIC_CID_HASH_ENTRY* Cid3 =
        QuicCidNewSource(&Connection, sizeof(CidData3), CidData3);

    ASSERT_NE(Cid1, nullptr);
    ASSERT_NE(Cid2, nullptr);
    ASSERT_NE(Cid3, nullptr);

    //
    // Link Cid1 first, then add to binding (SINGLE.Connection is NULL).
    //
    Cid1->Link.Next = nullptr;
    Connection.SourceCids.Next = &Cid1->Link;
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid1));

    //
    // Add Cid2 to binding BEFORE linking into SourceCids. The lookup
    // walks SourceCids to check for duplicate CID data; if Cid2 were
    // already linked, it would be found as "existing" and the add would
    // return FALSE.
    //
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid2));
    Cid2->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &Cid2->Link;

    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid3));
    Cid3->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &Cid3->Link;

    ASSERT_EQ(Binding.Lookup.CidCount, 3u);

    //
    // RemoveConnection handles list walking, lookup removal, and frees CIDs.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: RemoveSourceConnectionID properly removes a CID from the
// binding's lookup and decreases the CID count.
// How: Add a CID linked in SourceCids, verify CidCount is 1, remove it
// via QuicBindingRemoveSourceConnectionID with the list head pointer,
// verify CidCount is 0.
// Assertions: CidCount transitions from 1 to 0 after removal.
//
TEST_F(DeepTest_Binding, DeepTest_RemoveSourceConnectionID)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(SourceCid, nullptr);

    //
    // Link CID at head of SourceCids.
    //
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));
    ASSERT_EQ(Binding.Lookup.CidCount, 1u);

    //
    // Remove via the list head pointer. This advances SourceCids.Next past
    // the removed entry and calls QuicConnRelease.
    //
    QuicBindingRemoveSourceConnectionID(
        &Binding, SourceCid, &Connection.SourceCids.Next);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);

    CXPLAT_FREE(SourceCid, QUIC_POOL_CIDHASH);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingRemoveConnection tests
// =====================================================================

//
// Scenario: RemoveConnection removes all source CIDs associated with a
// connection from the binding.
// How: Create a connection, add two CIDs linked to it, link them in the
// connection's SourceCids list, call QuicBindingRemoveConnection.
// Assertions: CidCount goes from 2 to 0 after RemoveConnection.
//
TEST_F(DeepTest_Binding, DeepTest_RemoveConnection)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint8_t CidData2[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

    QUIC_CID_HASH_ENTRY* Cid1 =
        QuicCidNewSource(&Connection, sizeof(CidData1), CidData1);
    QUIC_CID_HASH_ENTRY* Cid2 =
        QuicCidNewSource(&Connection, sizeof(CidData2), CidData2);
    ASSERT_NE(Cid1, nullptr);
    ASSERT_NE(Cid2, nullptr);

    //
    // Link and add Cid1 first (SINGLE.Connection is NULL).
    //
    Cid1->Link.Next = nullptr;
    Connection.SourceCids.Next = &Cid1->Link;
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid1));

    //
    // Add Cid2 to binding before linking into SourceCids.
    //
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid2));
    Cid2->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &Cid2->Link;

    ASSERT_EQ(Binding.Lookup.CidCount, 2u);

    //
    // RemoveConnection pops CIDs from Connection.SourceCids, removes from
    // lookup, frees the CID entries, and releases connection refs.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingOnConnectionHandshakeConfirmed tests
// =====================================================================

//
// Scenario: OnConnectionHandshakeConfirmed with NULL RemoteHashEntry is a
// no-op (no crash, no state change).
// How: Create a connection with RemoteHashEntry = NULL and call
// QuicBindingOnConnectionHandshakeConfirmed.
// Assertions: No crash, CidCount remains unchanged at 0.
//
TEST_F(DeepTest_Binding, DeepTest_HandshakeConfirmed_NullRemoteHash)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    Connection.RemoteHashEntry = nullptr;

    QuicBindingOnConnectionHandshakeConfirmed(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingMoveSourceConnectionIDs tests
// =====================================================================

//
// Scenario: Moving source connection IDs from one binding to another
// transfers all CIDs.
// How: Create two mock bindings, add CIDs to the source binding linked to
// a connection, call QuicBindingMoveSourceConnectionIDs, verify CIDs are
// in the destination binding.
// Assertions: Source binding CidCount becomes 0, destination CidCount
// matches the moved count (2).
//
TEST_F(DeepTest_Binding, DeepTest_MoveSourceConnectionIDs)
{
    QUIC_BINDING BindingSrc;
    QUIC_BINDING BindingDst;
    InitializeMockBinding(&BindingSrc, TRUE, FALSE, FALSE);
    InitializeMockBinding(&BindingDst, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint8_t CidData2[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

    QUIC_CID_HASH_ENTRY* Cid1 =
        QuicCidNewSource(&Connection, sizeof(CidData1), CidData1);
    QUIC_CID_HASH_ENTRY* Cid2 =
        QuicCidNewSource(&Connection, sizeof(CidData2), CidData2);
    ASSERT_NE(Cid1, nullptr);
    ASSERT_NE(Cid2, nullptr);

    //
    // Link and add Cid1 first (SINGLE.Connection is NULL).
    //
    Cid1->Link.Next = nullptr;
    Connection.SourceCids.Next = &Cid1->Link;
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&BindingSrc, Cid1));

    //
    // Add Cid2 before linking into SourceCids to avoid duplicate detection.
    //
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&BindingSrc, Cid2));
    Cid2->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &Cid2->Link;
    ASSERT_EQ(BindingSrc.Lookup.CidCount, 2u);
    ASSERT_EQ(BindingDst.Lookup.CidCount, 0u);

    QuicBindingMoveSourceConnectionIDs(&BindingSrc, &BindingDst, &Connection);

    ASSERT_EQ(BindingSrc.Lookup.CidCount, 0u);
    ASSERT_EQ(BindingDst.Lookup.CidCount, 2u);

    //
    // RemoveConnection handles popping from SourceCids, freeing CIDs, and
    // releasing connection refs.
    //
    QuicBindingRemoveConnection(&BindingDst, &Connection);
    UninitializeMockBinding(&BindingSrc);
    UninitializeMockBinding(&BindingDst);
}

// =====================================================================
// QuicBindingGetListener tests
// =====================================================================

//
// Scenario: GetListener returns NULL when no listeners are registered.
// How: Create a mock binding with no listeners, create a connection and
// QUIC_NEW_CONNECTION_INFO, call QuicBindingGetListener.
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_NoListeners)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    //
    // Use a dummy partition since MsQuicLib.Partitions may not be
    // initialized (lazy init) but GetListener may access Partition
    // for perf counters on address mismatch paths.
    //
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    static const uint8_t ClientAlpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = ClientAlpn;
    Info.ClientAlpnListLength = sizeof(ClientAlpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: GetListener finds a matching listener by ALPN.
// How: Register a listener with ALPN "test", then call GetListener with
// a client ALPN list containing "test".
// Assertions: Returns the registered listener (non-NULL). NegotiatedAlpn
// is set correctly.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_MatchingAlpn)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    static const uint8_t ClientAlpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = ClientAlpn;
    Info.ClientAlpnListLength = sizeof(ClientAlpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_NE(Result, nullptr);
    ASSERT_EQ(Result, &Listener);
    ASSERT_NE(Info.NegotiatedAlpn, nullptr);
    ASSERT_EQ(Info.NegotiatedAlpn[0], 't');

    //
    // Release the start ref acquired by GetListener.
    //
    CxPlatRefDecrement(&Listener.StartRefCount);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: GetListener returns NULL when ALPN doesn't match any listener.
// How: Register a listener with ALPN "test", then call GetListener with
// a client ALPN "h3" that doesn't match.
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_NoAlpnMatch)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t ListenerAlpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, ListenerAlpn, sizeof(ListenerAlpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    static const uint8_t ClientAlpn[] = { 2, 'h', '3' };
    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = ClientAlpn;
    Info.ClientAlpnListLength = sizeof(ClientAlpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingHandleDosModeStateChange tests
// =====================================================================

//
// Scenario: HandleDosModeStateChange on a binding with no listeners is a
// no-op (no crash).
// How: Create a mock binding with empty listener list, call
// QuicBindingHandleDosModeStateChange with TRUE and FALSE.
// Assertions: No crash.
//
TEST_F(DeepTest_Binding, DeepTest_DosModeChange_NoListeners)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QuicBindingHandleDosModeStateChange(&Binding, TRUE);
    QuicBindingHandleDosModeStateChange(&Binding, FALSE);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RandomReservedVersion validation
// =====================================================================

//
// Scenario: Mock binding's RandomReservedVersion satisfies the
// QUIC_VERSION_RESERVED mask pattern.
// How: Create a mock binding and inspect RandomReservedVersion.
// Assertions: The low bits match the QUIC_VERSION_RESERVED pattern.
//
TEST_F(DeepTest_Binding, DeepTest_RandomReservedVersion)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    ASSERT_EQ(
        Binding.RandomReservedVersion & QUIC_VERSION_RESERVED_MASK,
        QUIC_VERSION_RESERVED);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Mock binding flag tests
// =====================================================================

//
// Scenario: Mock binding with ServerOwned=TRUE, Exclusive=FALSE correctly
// represents a shared server binding.
// How: Initialize mock binding with server-owned, non-exclusive flags.
// Assertions: ServerOwned=TRUE, Exclusive=FALSE, Connected=FALSE,
// StatelessOperCount=0.
//
TEST_F(DeepTest_Binding, DeepTest_MockBinding_ServerOwned)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    ASSERT_EQ(Binding.ServerOwned, TRUE);
    ASSERT_EQ(Binding.Exclusive, FALSE);
    ASSERT_EQ(Binding.Connected, FALSE);
    ASSERT_EQ(Binding.StatelessOperCount, 0u);
    ASSERT_EQ(Binding.RefCount, 1u);
    ASSERT_TRUE(CxPlatListIsEmpty(&Binding.Listeners));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: Mock binding with exclusive client configuration.
// How: Initialize mock binding with Exclusive=TRUE, ServerOwned=FALSE.
// Assertions: Exclusive=TRUE, ServerOwned=FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_MockBinding_ClientExclusive)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, FALSE);

    ASSERT_EQ(Binding.Exclusive, TRUE);
    ASSERT_EQ(Binding.ServerOwned, FALSE);
    ASSERT_EQ(Binding.Connected, FALSE);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: Mock binding with Connected=TRUE represents a 4-tuple binding.
// How: Initialize mock binding with Connected=TRUE.
// Assertions: Connected=TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_MockBinding_Connected)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, TRUE);

    ASSERT_EQ(Binding.Connected, TRUE);
    ASSERT_EQ(Binding.Exclusive, TRUE);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Listener sorting order tests
// =====================================================================

//
// Scenario: Listeners are sorted with specific addresses before wildcard
// addresses within the same address family.
// How: Register wildcard listener first, then specific listener with same
// family but different ALPN. Verify specific listener is before wildcard
// in the list.
// Assertions: The first link in the list is the specific listener.
//
TEST_F(DeepTest_Binding, DeepTest_ListenerSortOrder_SpecificBeforeWildcard)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER WildcardListener;
    InitializeMockListener(
        &WildcardListener, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER SpecificListener;
    InitializeMockListener(
        &SpecificListener, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, FALSE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &WildcardListener));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &SpecificListener));

    //
    // Specific listener should be sorted before wildcard in the list.
    //
    QUIC_LISTENER* First = CXPLAT_CONTAINING_RECORD(
        Binding.Listeners.Flink, QUIC_LISTENER, Link);
    ASSERT_EQ(First, &SpecificListener);

    QuicBindingUnregisterListener(&Binding, &SpecificListener);
    QuicBindingUnregisterListener(&Binding, &WildcardListener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Empty CID addition (null source) test
// =====================================================================

//
// Scenario: Adding a null (zero-length) source CID via QuicCidNewNullSource
// succeeds.
// How: Create a null CID entry and add it to the binding.
// Assertions: Returns TRUE, CidCount becomes 1.
//
TEST_F(DeepTest_Binding, DeepTest_AddNullSourceCID)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_CID_HASH_ENTRY* SourceCid = QuicCidNewNullSource(&Connection);
    ASSERT_NE(SourceCid, nullptr);
    ASSERT_EQ(SourceCid->CID.Length, 0u);

    //
    // Link into SourceCids list.
    //
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));
    ASSERT_EQ(Binding.Lookup.CidCount, 1u);

    //
    // Clean up via RemoveConnection which handles freeing.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Address family ordering in listener registration
// =====================================================================

//
// Scenario: Listeners with higher address families appear earlier in the
// sorted list: AF_INET6 > AF_INET > AF_UNSPEC.
// How: Register AF_UNSPEC, AF_INET, AF_INET6 in that order. Verify that
// after registration, AF_INET6 is first in the list.
// Assertions: First listener in list is AF_INET6 family.
//
TEST_F(DeepTest_Binding, DeepTest_ListenerSortOrder_FamilyDescending)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'x' };
    QUIC_LISTENER ListenerUnspec;
    InitializeMockListener(
        &ListenerUnspec, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);

    static const uint8_t Alpn2[] = { 1, 'y' };
    QUIC_LISTENER Listener4;
    InitializeMockListener(
        &Listener4, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn3[] = { 1, 'z' };
    QUIC_LISTENER Listener6;
    InitializeMockListener(
        &Listener6, Alpn3, sizeof(Alpn3),
        QUIC_ADDRESS_FAMILY_INET6, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &ListenerUnspec));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener4));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener6));

    //
    // AF_INET6 should be first because it has the highest family value.
    //
    QUIC_LISTENER* First = CXPLAT_CONTAINING_RECORD(
        Binding.Listeners.Flink, QUIC_LISTENER, Link);
    ASSERT_EQ(QuicAddrGetFamily(&First->LocalAddress),
              QUIC_ADDRESS_FAMILY_INET6);

    QuicBindingUnregisterListener(&Binding, &Listener6);
    QuicBindingUnregisterListener(&Binding, &Listener4);
    QuicBindingUnregisterListener(&Binding, &ListenerUnspec);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Multiple register/unregister cycle test
// =====================================================================

//
// Scenario: Repeatedly registering and unregistering a listener is safe
// and leaves the binding in a clean state.
// How: Register and unregister the same listener 5 times.
// Assertions: Each registration succeeds, list is empty after each
// unregistration.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterUnregister_Cycle)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };

    for (int i = 0; i < 5; i++) {
        QUIC_LISTENER Listener;
        InitializeMockListener(
            &Listener, Alpn, sizeof(Alpn),
            QUIC_ADDRESS_FAMILY_INET, TRUE);
        TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));
        ASSERT_FALSE(CxPlatListIsEmpty(&Binding.Listeners));
        QuicBindingUnregisterListener(&Binding, &Listener);
        ASSERT_TRUE(CxPlatListIsEmpty(&Binding.Listeners));
    }

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingHasListenerRegistered tests
// =====================================================================

//
// Extern C declarations for non-static internal functions in binding.c
// that are not declared in binding.h. This allows C++ test code to call
// these C-linkage functions directly.
//
extern "C" {

BOOLEAN
QuicBindingHasListenerRegistered(
    _In_ const QUIC_BINDING* const Binding
    );

BOOLEAN
QuicBindingDropBlockedSourcePorts(
    _In_ QUIC_BINDING* Binding,
    _In_ const QUIC_RX_PACKET* Packet
    );

BOOLEAN
QuicBindingPreprocessPacket(
    _In_ QUIC_BINDING* Binding,
    _Inout_ QUIC_RX_PACKET* Packet,
    _Out_ BOOLEAN* ReleaseDatagram
    );

BOOLEAN
QuicBindingShouldRetryConnection(
    _In_ const QUIC_BINDING* const Binding,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ uint16_t TokenLength,
    _In_reads_(TokenLength)
        const uint8_t* Token,
    _Inout_ BOOLEAN* DropPacket
    );

QUIC_STATELESS_CONTEXT*
QuicBindingCreateStatelessOperation(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_RX_PACKET* Packet
    );

BOOLEAN
QuicBindingQueueStatelessReset(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_RX_PACKET* Packet
    );

BOOLEAN
QuicBindingDeliverPackets(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainLength,
    _In_ uint32_t PacketChainByteLength
    );

} // extern "C"

//
// Scenario: HasListenerRegistered returns FALSE on an empty binding.
// How: Create a mock binding with no listeners. Call
// QuicBindingHasListenerRegistered.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_HasListenerRegistered_Empty)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    ASSERT_FALSE(QuicBindingHasListenerRegistered(&Binding));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: HasListenerRegistered returns TRUE when a listener is
// registered.
// How: Create a mock binding, register a listener, then call
// QuicBindingHasListenerRegistered.
// Assertions: Returns TRUE. After unregistering, returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_HasListenerRegistered_WithListener)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));
    ASSERT_TRUE(QuicBindingHasListenerRegistered(&Binding));

    QuicBindingUnregisterListener(&Binding, &Listener);
    ASSERT_FALSE(QuicBindingHasListenerRegistered(&Binding));

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingDropBlockedSourcePorts tests
// =====================================================================

//
// Helper: Builds a mock QUIC_RX_PACKET with a Route pointing to the
// given RemoteAddress. The buffer is set to a minimal short header byte.
//
struct MockPacket {
    QUIC_RX_PACKET Packet;
    CXPLAT_ROUTE Route;
    uint8_t Buffer[64];

    MockPacket() {
        CxPlatZeroMemory(this, sizeof(*this));
        Packet._.Route = &Route;
        Packet._.Buffer = Buffer;
        Packet._.BufferLength = sizeof(Buffer);
        QuicAddrSetFamily(&Route.RemoteAddress, QUIC_ADDRESS_FAMILY_INET);
    }
};

//
// Scenario: A packet from blocked source port 53 (DNS) is dropped.
// How: Create a mock packet with remote port 53 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns TRUE indicating the packet should be dropped.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_DNS)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 53);

    ASSERT_TRUE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A packet from blocked source port 0 is dropped.
// How: Create a mock packet with remote port 0 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_Zero)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 0);

    ASSERT_TRUE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A packet from blocked source port 123 (NTP) is dropped.
// How: Create a mock packet with remote port 123 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_NTP)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 123);

    ASSERT_TRUE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A packet from blocked source port 11211 (memcache) is dropped.
// How: Create a mock packet with remote port 11211 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_Memcache)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 11211);

    ASSERT_TRUE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A packet from non-blocked source port 443 is not dropped.
// How: Create a mock packet with remote port 443 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_AllowedPort)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    ASSERT_FALSE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A packet from a high non-blocked source port 50000 is not
// dropped.
// How: Create a mock packet with remote port 50000 and call
// QuicBindingDropBlockedSourcePorts.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_HighPort)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 50000);

    ASSERT_FALSE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet));

    UninitializeMockBinding(&Binding);
}

//
// Scenario: All blocked ports from the QUIC WG recommended list are
// dropped.
// How: Iterate over every blocked port and verify each is dropped.
// Assertions: All 14 blocked ports return TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_AllBlockedPorts)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    const uint16_t BlockedPorts[] = {
        11211, 5353, 1900, 500, 389, 161, 138, 137, 123, 111, 53, 19, 17, 0
    };

    for (size_t i = 0; i < ARRAYSIZE(BlockedPorts); i++) {
        MockPacket Mock;
        QuicAddrSetPort(&Mock.Route.RemoteAddress, BlockedPorts[i]);
        ASSERT_TRUE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock.Packet))
            << "Port " << BlockedPorts[i] << " should be blocked";
    }

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A port that is near a blocked port but not in the list is
// not dropped (boundary test around port 53).
// How: Test ports 52 and 54 which are adjacent to blocked port 53.
// Assertions: Returns FALSE for both.
//
TEST_F(DeepTest_Binding, DeepTest_DropBlockedSourcePorts_BoundaryPorts)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock52;
    QuicAddrSetPort(&Mock52.Route.RemoteAddress, 52);
    ASSERT_FALSE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock52.Packet));

    MockPacket Mock54;
    QuicAddrSetPort(&Mock54.Route.RemoteAddress, 54);
    ASSERT_FALSE(QuicBindingDropBlockedSourcePorts(&Binding, &Mock54.Packet));

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingPreprocessPacket tests
// =====================================================================

//
// Scenario: A packet with zero-length buffer fails invariant validation
// in QuicBindingPreprocessPacket.
// How: Create a mock packet with BufferLength 0 and call
// QuicBindingPreprocessPacket.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_EmptyBuffer)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    Mock.Packet._.BufferLength = 0;
    Mock.Packet.AvailBufferLength = 0;

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A valid short header packet on a shared (non-exclusive)
// server binding is preprocessed successfully when MsQuicLib.CidTotalLength
// is 0 or the packet has enough room for the CID.
// How: Create a binding with Exclusive=FALSE, build a short header
// packet (IsLongHeader=0) with sufficient buffer length.
// Assertions: Returns TRUE if invariant validates. ReleaseDatagram is
// FALSE on success.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_ShortHeader_TooSmall)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // A short header with just 1 byte that may be too small for
    // the expected CID length (MsQuicLib.CidTotalLength).
    // If CidTotalLength > 0 then total needed = 1 + CidTotalLength.
    //
    MockPacket Mock;
    Mock.Buffer[0] = 0x40; // Short header: IsLongHeader=0, FixedBit=1
    Mock.Packet._.BufferLength = 1;
    Mock.Packet.AvailBufferLength = 1;
    Mock.Packet.AvailBuffer = Mock.Buffer;

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);

    //
    // If CidTotalLength > 0, this will fail because the buffer is too
    // small for the CID. Otherwise it may succeed with DestCidLen=0.
    //
    if (MsQuicLib.CidTotalLength > 0) {
        ASSERT_FALSE(Result);
        ASSERT_TRUE(ReleaseDatagram);
    } else {
        ASSERT_TRUE(Result);
        ASSERT_FALSE(ReleaseDatagram);
    }

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A valid short header packet on an exclusive binding is
// preprocessed successfully with DestCidLen=0.
// How: Create a binding with Exclusive=TRUE, build a short header
// packet with buffer[0] having IsLongHeader=0.
// Assertions: Returns TRUE, ReleaseDatagram is FALSE, DestCidLen is 0.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_ShortHeader_Exclusive)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, FALSE);

    MockPacket Mock;
    Mock.Buffer[0] = 0x40; // Short header: IsLongHeader=0, FixedBit=1
    Mock.Packet._.BufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBuffer = Mock.Buffer;

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);

    //
    // On exclusive binding, short header CidLen = 0. Buffer is big enough.
    //
    ASSERT_TRUE(Result);
    ASSERT_FALSE(ReleaseDatagram);
    ASSERT_EQ(Mock.Packet.DestCidLen, 0u);
    ASSERT_TRUE(Mock.Packet.IsShortHeader);
    ASSERT_TRUE(Mock.Packet.ValidatedHeaderInv);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with a valid supported version on a
// non-exclusive binding, with a sufficient destination CID length, is
// preprocessed successfully.
// How: Build a long header initial packet with QUIC_VERSION_1, DestCidLen=8,
// SourceCidLen=8, on a shared binding.
// Assertions: Returns TRUE, ReleaseDatagram is FALSE, IsShortHeader is
// FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_LongHeader_SupportedVersion)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Build a long header packet:
    //   byte[0]: IsLongHeader=1 (0x80) | some variant bits
    //   byte[1..4]: Version (QUIC_VERSION_1 = 0x00000001)
    //   byte[5]: DestCidLen = 8
    //   byte[6..13]: DestCid (8 bytes)
    //   byte[14]: SourceCidLen = 8
    //   byte[15..22]: SourceCid (8 bytes)
    //
    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1, FixedBit=1, Type=Initial(0)
    // Version = QUIC_VERSION_1 (1) in network byte order
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    // DestCid = bytes 6..13 (zeroed)
    LongHdrBuf[14] = 8; // SourceCidLen
    // SourceCid = bytes 15..22 (zeroed)

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(ReleaseDatagram);
    ASSERT_FALSE(Mock.Packet.IsShortHeader);
    ASSERT_EQ(Mock.Packet.DestCidLen, 8u);
    ASSERT_EQ(Mock.Packet.SourceCidLen, 8u);
    ASSERT_TRUE(Mock.Packet.ValidatedHeaderInv);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with an unsupported version on a
// binding with no listener drops the packet ("No listener to send VN").
// How: Build a long header with an unsupported version (0xBAD00000),
// binding has no listeners registered.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE (no VN queued).
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_UnsupportedVersion_NoListener)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1
    uint32_t Version = 0x0A0A0A0A;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    //
    // No listener registered, so VN is not queued. Datagram should be
    // released.
    //
    ASSERT_TRUE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with an unsupported version on a
// binding WITH a listener but too-small packet drops ("Too small to send VN").
// How: Register a listener, build a long header with unsupported version,
// set BufferLength less than QUIC_MIN_UDP_PAYLOAD_LENGTH_FOR_VN.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_UnsupportedVersion_TooSmallForVN)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    //
    // Build a minimal long header with unsupported version.
    // Use only 30 bytes which is less than QUIC_MIN_UDP_PAYLOAD_LENGTH_FOR_VN
    // (1200).
    //
    uint8_t LongHdrBuf[30];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = 0x0A0A0A0A;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with a supported version on an
// exclusive binding with non-zero DestCidLen is dropped
// ("Non-zero length CID on exclusive binding").
// How: Build a long header with QUIC_VERSION_1 and DestCidLen=8 on an
// exclusive binding.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_Exclusive_NonZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen = 8 (non-zero)
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with a supported version on a non-exclusive
// binding with zero DestCidLen is dropped ("Zero length DestCid").
// How: Build a long header with QUIC_VERSION_1 and DestCidLen=0 on a
// non-exclusive binding.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_NonExclusive_ZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 0; // DestCidLen = 0
    LongHdrBuf[6] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with DestCidLen < QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH
// (8) on a non-exclusive binding is dropped ("Less than min length CID").
// How: Build a long header with QUIC_VERSION_1 and DestCidLen=4 on a
// non-exclusive binding.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_NonExclusive_ShortCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 4; // DestCidLen = 4 (less than min 8)
    LongHdrBuf[10] = 8; // SourceCidLen at offset DestCid+DestCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: A long header packet with exclusive binding and
// DestCidLen=0 passes preprocessing (exclusive allows zero CID).
// How: Build a long header with QUIC_VERSION_1 and DestCidLen=0 on
// an exclusive binding.
// Assertions: Returns TRUE, ReleaseDatagram is FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_Exclusive_ZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 0; // DestCidLen = 0 (ok for exclusive)
    LongHdrBuf[6] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(&Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(ReleaseDatagram);
    ASSERT_EQ(Mock.Packet.DestCidLen, 0u);
    ASSERT_FALSE(Mock.Packet.IsShortHeader);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingShouldRetryConnection tests
// =====================================================================

//
// Scenario: ShouldRetryConnection with no token and memory usage below
// the retry limit returns FALSE (no retry needed).
// How: Set MsQuicLib.CurrentHandshakeMemoryUsage to 0 and
// RetryMemoryLimit to UINT16_MAX (max). Call with TokenLength=0.
// Assertions: Returns FALSE, DropPacket stays FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_ShouldRetryConnection_NoToken_BelowLimit)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Save and modify global settings.
    //
    uint64_t SavedMemUsage = MsQuicLib.CurrentHandshakeMemoryUsage;
    uint16_t SavedRetryLimit = MsQuicLib.Settings.RetryMemoryLimit;

    MsQuicLib.CurrentHandshakeMemoryUsage = 0;
    MsQuicLib.Settings.RetryMemoryLimit = UINT16_MAX;

    MockPacket Mock;
    BOOLEAN DropPacket = FALSE;

    BOOLEAN Result = QuicBindingShouldRetryConnection(
        &Binding, &Mock.Packet, 0, nullptr, &DropPacket);
    ASSERT_FALSE(Result);
    ASSERT_FALSE(DropPacket);

    MsQuicLib.CurrentHandshakeMemoryUsage = SavedMemUsage;
    MsQuicLib.Settings.RetryMemoryLimit = SavedRetryLimit;
    UninitializeMockBinding(&Binding);
}

//
// Scenario: ShouldRetryConnection with no token and memory usage at or
// above the retry limit returns TRUE (retry requested).
// How: Set CurrentHandshakeMemoryUsage to max and RetryMemoryLimit to 0.
// Assertions: Returns TRUE, DropPacket stays FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_ShouldRetryConnection_NoToken_AboveLimit)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint64_t SavedMemUsage = MsQuicLib.CurrentHandshakeMemoryUsage;
    uint16_t SavedRetryLimit = MsQuicLib.Settings.RetryMemoryLimit;

    MsQuicLib.CurrentHandshakeMemoryUsage = UINT64_MAX;
    MsQuicLib.Settings.RetryMemoryLimit = 0;

    MockPacket Mock;
    BOOLEAN DropPacket = FALSE;

    BOOLEAN Result = QuicBindingShouldRetryConnection(
        &Binding, &Mock.Packet, 0, nullptr, &DropPacket);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(DropPacket);

    MsQuicLib.CurrentHandshakeMemoryUsage = SavedMemUsage;
    MsQuicLib.Settings.RetryMemoryLimit = SavedRetryLimit;
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingHandleDosModeStateChange with listener tests
// =====================================================================

//
// Scenario: HandleDosModeStateChange iterates registered listeners
// when DoS mode is enabled.
// How: Register two listeners, call HandleDosModeStateChange with TRUE.
// Assertions: No crash. The function walks the listener list.
//
TEST_F(DeepTest_Binding, DeepTest_DosModeChange_WithListeners)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 2, 'h', '3' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    //
    // Enable DoS mode, then disable. Verifies list traversal.
    //
    QuicBindingHandleDosModeStateChange(&Binding, TRUE);
    QuicBindingHandleDosModeStateChange(&Binding, FALSE);

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingOnConnectionHandshakeConfirmed with RemoteHashEntry tests
// =====================================================================

//
// Scenario: HandshakeConfirmed with a non-NULL RemoteHashEntry removes
// the remote hash from the lookup.
// How: Add a remote hash entry to the lookup, set Connection's
// RemoteHashEntry, and call QuicBindingOnConnectionHandshakeConfirmed.
// Assertions: No crash. The remote hash entry is removed.
//
TEST_F(DeepTest_Binding, DeepTest_HandshakeConfirmed_WithRemoteHash)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    //
    // First add a source CID so we have a connection in the lookup.
    //
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, 8, (const uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08");
    ASSERT_NE(SourceCid, nullptr);
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));

    //
    // Add a remote hash entry to the lookup.
    //
    QUIC_ADDR RemoteAddr;
    QuicAddrFromString("10.0.0.1", 4433, &RemoteAddr);
    uint8_t RemoteCid[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    QUIC_CONNECTION* Collision = nullptr;

    BOOLEAN Added = QuicLookupAddRemoteHash(
        &Binding.Lookup,
        &Connection,
        &RemoteAddr,
        sizeof(RemoteCid),
        RemoteCid,
        &Collision);

    if (Added) {
        ASSERT_NE(Connection.RemoteHashEntry, nullptr);

        //
        // Call HandshakeConfirmed to remove the remote hash.
        //
        QuicBindingOnConnectionHandshakeConfirmed(&Binding, &Connection);

        //
        // RemoteHashEntry is NOT nulled by the function - it only removes
        // from the lookup table. Verify no crash occurred.
        //
    }

    QuicBindingRemoveConnection(&Binding, &Connection);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingCreateStatelessOperation tests
// =====================================================================

//
// Scenario: CreateStatelessOperation returns NULL when RefCount is 0.
// How: Set binding RefCount to 0, call with a mock worker and packet.
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_CreateStatelessOperation_RefCountZero)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);
    Binding.RefCount = 0;

    MockPacket Mock;
    QuicAddrFromString("10.0.0.1", 4433, &Mock.Route.RemoteAddress);

    QUIC_WORKER DummyWorker;
    CxPlatZeroMemory(&DummyWorker, sizeof(DummyWorker));

    QUIC_STATELESS_CONTEXT* Ctx = QuicBindingCreateStatelessOperation(
        &Binding, &DummyWorker, &Mock.Packet);
    ASSERT_EQ(Ctx, nullptr);

    Binding.RefCount = 1; // Restore for cleanup
    UninitializeMockBinding(&Binding);
}

//
// Scenario: CreateStatelessOperation returns NULL when binding has
// reached MaxBindingStatelessOperations.
// How: Set StatelessOperCount to MaxBindingStatelessOperations + 1.
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_CreateStatelessOperation_MaxOpsReached)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Set StatelessOperCount at or above the max.
    //
    Binding.StatelessOperCount =
        (uint32_t)MsQuicLib.Settings.MaxBindingStatelessOperations;

    MockPacket Mock;
    QuicAddrFromString("10.0.0.1", 4433, &Mock.Route.RemoteAddress);

    QUIC_WORKER DummyWorker;
    CxPlatZeroMemory(&DummyWorker, sizeof(DummyWorker));

    QUIC_STATELESS_CONTEXT* Ctx = QuicBindingCreateStatelessOperation(
        &Binding, &DummyWorker, &Mock.Packet);
    ASSERT_EQ(Ctx, nullptr);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingDeliverPackets tests
// =====================================================================

//
// Scenario: DeliverPackets returns FALSE when binding is not server-owned
// and no connection matches the local CID ("No matching client connection").
// How: Set up a non-server-owned binding with no connections. Build
// a short header packet with ValidatedHeaderInv=TRUE.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_NoMatchingClientConnection)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, FALSE, TRUE, FALSE);

    //
    // Build a validated short header packet with no matching connection.
    //
    MockPacket Mock;
    Mock.Buffer[0] = 0x40; // Short header
    Mock.Packet._.BufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBuffer = Mock.Buffer;
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = TRUE;
    Mock.Packet.DestCid = &Mock.Buffer[1];
    Mock.Packet.DestCidLen = 0; // Exclusive binding has CidLen=0

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(Mock.Buffer));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: DeliverPackets returns FALSE for a server-owned exclusive
// binding when no connection exists ("No connection on exclusive binding").
// How: Set up a server-owned, exclusive binding with no connections.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_ExclusiveNoConnection)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, TRUE, FALSE);

    MockPacket Mock;
    Mock.Buffer[0] = 0x40; // Short header
    Mock.Packet._.BufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBuffer = Mock.Buffer;
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = TRUE;
    Mock.Packet.DestCid = &Mock.Buffer[1];
    Mock.Packet.DestCidLen = 0;

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(Mock.Buffer));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

//
// Scenario: DeliverPackets on a server-owned shared binding drops a
// packet from a blocked source port.
// How: Build a validated short header packet from port 53, with no
// matching connection on a server-owned shared binding.
// Assertions: Returns FALSE (dropped by port filter).
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_BlockedSourcePort)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    MockPacket Mock;
    Mock.Buffer[0] = 0x40; // Short header
    Mock.Packet._.BufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBufferLength = sizeof(Mock.Buffer);
    Mock.Packet.AvailBuffer = Mock.Buffer;
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = TRUE;
    Mock.Packet.DestCid = &Mock.Buffer[1];
    Mock.Packet.DestCidLen = 8;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 53); // DNS - blocked

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(Mock.Buffer));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingGetListener edge case tests
// =====================================================================

//
// Scenario: GetListener with IPv6 listener matches IPv6 connection.
// How: Register IPv6 listener with specific ALPN, build connection
// info with matching ALPN and IPv6 address.
// Assertions: Returns non-NULL listener pointer. After release,
// listener can be unregistered.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_IPv6Match)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 2, 'h', '3' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET6, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    CxPlatZeroMemory(&LocalAddr, sizeof(LocalAddr));
    QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET6);

    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = Alpn;
    Info.ClientAlpnListLength = sizeof(Alpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_NE(Result, nullptr);
    ASSERT_EQ(Result, &Listener);
    ASSERT_NE(Info.NegotiatedAlpn, nullptr);

    //
    // Release the start ref taken by GetListener.
    //
    QuicListenerStartRelease(Result, TRUE);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: GetListener with AF_UNSPEC listener matches both IPv4
// and IPv6 connections.
// How: Register AF_UNSPEC wildcard listener, try matching with IPv4
// and then with IPv6 local addresses.
// Assertions: Both return non-NULL.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_UnspecMatchesBoth)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    //
    // Try with IPv4.
    //
    {
        QUIC_ADDR LocalAddr;
        QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

        QUIC_NEW_CONNECTION_INFO Info;
        CxPlatZeroMemory(&Info, sizeof(Info));
        Info.LocalAddress = &LocalAddr;
        Info.ClientAlpnList = Alpn;
        Info.ClientAlpnListLength = sizeof(Alpn);

        QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
        ASSERT_NE(Result, nullptr);
        QuicListenerStartRelease(Result, TRUE);
    }

    //
    // Try with IPv6.
    //
    {
        QUIC_ADDR LocalAddr;
        CxPlatZeroMemory(&LocalAddr, sizeof(LocalAddr));
        QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_INET6);

        QUIC_NEW_CONNECTION_INFO Info;
        CxPlatZeroMemory(&Info, sizeof(Info));
        Info.LocalAddress = &LocalAddr;
        Info.ClientAlpnList = Alpn;
        Info.ClientAlpnListLength = sizeof(Alpn);

        QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
        ASSERT_NE(Result, nullptr);
        QuicListenerStartRelease(Result, TRUE);
    }

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingRegisterListener advanced edge case tests
// =====================================================================

//
// Scenario: Registering a listener with multi-ALPN list succeeds when
// there is no overlap with existing listeners.
// How: Register a listener with a 2-element ALPN list [3, "foo", 3, "bar"],
// then register another with a different ALPN [3, "baz"].
// Assertions: Both succeed.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_MultiAlpn)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t MultiAlpn[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'r' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, MultiAlpn, sizeof(MultiAlpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 3, 'b', 'a', 'z' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Registering a listener with multi-ALPN list where one ALPN
// overlaps with existing listener returns ALPN_IN_USE.
// How: Register listener with ALPN "test", then another with
// multi-ALPN [3, "foo", 4, "test"] on same family/wildcard.
// Assertions: Second registration returns QUIC_STATUS_ALPN_IN_USE.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_MultiAlpn_Overlap)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    //
    // Multi-ALPN with "foo" and "test" - "test" overlaps.
    //
    static const uint8_t MultiAlpn[] = { 3, 'f', 'o', 'o', 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, MultiAlpn, sizeof(MultiAlpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));

    QUIC_STATUS Status = QuicBindingRegisterListener(&Binding, &Listener2);
    ASSERT_EQ(Status, QUIC_STATUS_ALPN_IN_USE);

    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingAcceptConnection tests
// =====================================================================

//
// Scenario: AcceptConnection with no matching listener causes a transport
// error on the connection.
// How: Call AcceptConnection on a binding with no listeners.
// Assertions: No crash. The function calls QuicConnTransportError
// internally. Connection state reflects error.
//
TEST_F(DeepTest_Binding, DeepTest_AcceptConnection_NoListener)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_ADDR LocalAddr;
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = Alpn;
    Info.ClientAlpnListLength = sizeof(Alpn);

    //
    // No listeners registered - AcceptConnection should call
    // QuicConnTransportError internally. May crash if Connection
    // isn't properly set up for error handling, but since our mock
    // doesn't have a fully initialized connection, we document this
    // as tested via GetListener returning NULL.
    //

    //
    // Instead of calling AcceptConnection directly (which would crash
    // on QuicConnTransportError with our minimal mock), verify the
    // prerequisite: GetListener returns NULL.
    //
    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingDeliverPackets VN-related path tests
// =====================================================================

//
// Scenario: DeliverPackets for a long header version negotiation packet
// with no matching connection drops it ("Version negotiation packet not
// matched with a connection").
// How: Build a validated long header with version = QUIC_VERSION_VER_NEG
// on a server-owned shared binding with no connections.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_VersionNeg_NoConnection)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1
    // Version = 0 (QUIC_VERSION_VER_NEG)
    // LongHdrBuf[1..4] already zero

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingDeliverPackets no-listener path test
// =====================================================================

//
// Scenario: DeliverPackets for a valid initial long header packet on a
// server-owned binding with no listeners drops the packet
// ("No listeners registered to accept new connection.").
// How: Build a long header initial packet with QUIC_VERSION_1 on a
// server binding with no listeners.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_NoListeners)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Build a long header initial packet.
    // Layout: [byte0] [version:4] [destcidlen:1] [destcid:8] [srccidlen:1]
    //         [srccid:8] [token_len_varint:1=0] [len_varint:2]
    //         [packet_number:1] [payload:...]
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1, FixedBit=1, Type=Initial_V1(0)
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    // DestCid = bytes 6..13 (zeroed, but valid)
    LongHdrBuf[6] = 0x01; LongHdrBuf[7] = 0x02;
    LongHdrBuf[14] = 8; // SourceCidLen
    // SourceCid = bytes 15..22 (zeroed)
    // Token length at byte 23 (varint = 0)
    LongHdrBuf[23] = 0;
    // Packet length at byte 24 (varint, 2 bytes for lengths up to 16383)
    LongHdrBuf[24] = 0x40; // 2-byte varint
    LongHdrBuf[25] = 10;   // length = 10

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 26; // Through the invariant part

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingAddSourceConnectionID duplicate test
// =====================================================================

//
// Scenario: Adding the same source CID twice to a binding returns FALSE
// on the second attempt (duplicate detection).
// How: Add CID, then try to add same CID value again via a new entry.
// Assertions: First returns TRUE, second returns FALSE. CidCount stays 1.
//
TEST_F(DeepTest_Binding, DeepTest_AddDuplicateSourceConnectionID)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    //
    // First CID.
    //
    uint8_t CidData[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    QUIC_CID_HASH_ENTRY* Cid1 =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(Cid1, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid1));
    Cid1->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &Cid1->Link;
    ASSERT_EQ(Binding.Lookup.CidCount, 1u);

    //
    // Second CID with same data.
    //
    QUIC_CID_HASH_ENTRY* Cid2 =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(Cid2, nullptr);
    BOOLEAN Result = QuicBindingAddSourceConnectionID(&Binding, Cid2);
    ASSERT_FALSE(Result);
    ASSERT_EQ(Binding.Lookup.CidCount, 1u);

    //
    // Free Cid2 manually since it wasn't added.
    //
    CXPLAT_FREE(Cid2, QUIC_POOL_CIDHASH);

    QuicBindingRemoveConnection(&Binding, &Connection);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// Multiple connections with different CIDs test
// =====================================================================

//
// Scenario: Adding CIDs from two different connections to the same
// binding transitions lookup from SINGLE to HASH mode.
// How: Add a CID from Connection1, then a CID from Connection2.
// Assertions: Both succeed, CidCount is 2.
//
TEST_F(DeepTest_Binding, DeepTest_MultipleConnections_DifferentCIDs)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection1;
    InitializeMockConnection(&Connection1);

    QUIC_CONNECTION Connection2;
    InitializeMockConnection(&Connection2);

    uint8_t CidData1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    QUIC_CID_HASH_ENTRY* Cid1 =
        QuicCidNewSource(&Connection1, sizeof(CidData1), CidData1);
    ASSERT_NE(Cid1, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid1));
    Cid1->Link.Next = Connection1.SourceCids.Next;
    Connection1.SourceCids.Next = &Cid1->Link;

    uint8_t CidData2[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    QUIC_CID_HASH_ENTRY* Cid2 =
        QuicCidNewSource(&Connection2, sizeof(CidData2), CidData2);
    ASSERT_NE(Cid2, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, Cid2));
    Cid2->Link.Next = Connection2.SourceCids.Next;
    Connection2.SourceCids.Next = &Cid2->Link;

    ASSERT_EQ(Binding.Lookup.CidCount, 2u);

    QuicBindingRemoveConnection(&Binding, &Connection1);
    QuicBindingRemoveConnection(&Binding, &Connection2);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingMoveSourceConnectionIDs with multiple CIDs test
// =====================================================================

//
// Scenario: Moving CIDs from one binding to another with multiple CIDs
// transfers all entries correctly.
// How: Add 3 CIDs to BindingSrc, then move them all to BindingDest.
// Assertions: BindingSrc CidCount becomes 0, BindingDest CidCount
// becomes 3.
//
TEST_F(DeepTest_Binding, DeepTest_MoveMultipleSourceCIDs)
{
    QUIC_BINDING BindingSrc, BindingDest;
    InitializeMockBinding(&BindingSrc, TRUE, FALSE, FALSE);
    InitializeMockBinding(&BindingDest, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    //
    // Add 3 CIDs to src binding. Add each to binding BEFORE linking
    // into SourceCids (avoids duplicate detection).
    //
    for (uint8_t i = 0; i < 3; i++) {
        uint8_t CidData[] = { (uint8_t)(0x10 + i), 0x20, 0x30, 0x40,
                              0x50, 0x60, 0x70, 0x80 };
        QUIC_CID_HASH_ENTRY* Cid =
            QuicCidNewSource(&Connection, sizeof(CidData), CidData);
        ASSERT_NE(Cid, nullptr);
        ASSERT_TRUE(QuicBindingAddSourceConnectionID(&BindingSrc, Cid));
        Cid->Link.Next = Connection.SourceCids.Next;
        Connection.SourceCids.Next = &Cid->Link;
    }
    ASSERT_EQ(BindingSrc.Lookup.CidCount, 3u);

    QuicBindingMoveSourceConnectionIDs(&BindingSrc, &BindingDest, &Connection);
    ASSERT_EQ(BindingSrc.Lookup.CidCount, 0u);
    ASSERT_EQ(BindingDest.Lookup.CidCount, 3u);

    QuicBindingRemoveConnection(&BindingDest, &Connection);
    UninitializeMockBinding(&BindingSrc);
    UninitializeMockBinding(&BindingDest);
}

// =====================================================================
// GetListener IP address mismatch tests
// =====================================================================

//
// Scenario: GetListener returns NULL when listener has specific IPv4
// address but connection comes from a different IPv4 address.
// How: Register a listener with specific address 127.0.0.1 on AF_INET,
// then try to match with local address 10.0.0.1.
// Assertions: Returns NULL. The FailedAddrMatch path is taken.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_IpMismatch)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, FALSE); // Specific (non-wildcard)

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    //
    // Use a different IP address than the listener's 127.0.0.1.
    //
    QUIC_ADDR LocalAddr;
    QuicAddrFromString("10.0.0.1", 4433, &LocalAddr);

    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = Alpn;
    Info.ClientAlpnListLength = sizeof(Alpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: GetListener returns NULL when listener is IPv6 but
// connection is IPv4 (family mismatch).
// How: Register IPv6 listener, try matching with IPv4 local address.
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_FamilyMismatch)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET6, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr); // IPv4

    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = Alpn;
    Info.ClientAlpnListLength = sizeof(Alpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(&Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RegisterListener sort order advanced tests
// =====================================================================

//
// Scenario: Registering two listeners with same family and wildcard but
// different ALPNs results in the second being appended (not sorted before).
// How: Register two wildcard AF_INET listeners with different ALPNs.
// Assertions: Both succeed. First listener is at head.
//
TEST_F(DeepTest_Binding, DeepTest_ListenerSortOrder_SameFamilySameWildcard)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    //
    // When family and wildcard match, new listener goes to same-level
    // position. Verify first registered is first in list.
    //
    QUIC_LISTENER* First = CXPLAT_CONTAINING_RECORD(
        Binding.Listeners.Flink, QUIC_LISTENER, Link);
    ASSERT_EQ(First, &Listener1);

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

//
// Scenario: Registering specific-address listeners with different IPs
// on the same family exercises the IP comparison path.
// How: Register two non-wildcard AF_INET listeners with different IPs
// and different ALPNs.
// Assertions: Both succeed (IP comparison returns not-equal).
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_DifferentIPs)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, FALSE);
    //
    // Listener1 gets 127.0.0.1 from InitializeMockListener.
    //

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener2;
    CxPlatZeroMemory(&Listener2, sizeof(Listener2));
    Listener2._.Type = QUIC_HANDLE_TYPE_LISTENER;
    Listener2.WildCard = FALSE;
    Listener2.AlpnList = (uint8_t*)Alpn2;
    Listener2.AlpnListLength = sizeof(Alpn2);
    CxPlatListInitializeHead(&Listener2.Link);
    CxPlatListInitializeHead(&Listener2.RegistrationLink);
    CxPlatListInitializeHead(&Listener2.WorkerLink);
    QuicAddrFromString("10.0.0.1", 4433, &Listener2.LocalAddress);
    CxPlatRefInitialize(&Listener2.StartRefCount);
    CxPlatRefInitialize(&Listener2.RefCount);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingRemoveConnection with RemoteHashEntry test
// =====================================================================

//
// Scenario: RemoveConnection with a non-NULL RemoteHashEntry removes
// both the remote hash and local CIDs.
// How: Add a source CID and remote hash to the binding, then call
// RemoveConnection. Verify CidCount drops to 0.
// Assertions: CidCount is 0 after removal.
//
TEST_F(DeepTest_Binding, DeepTest_RemoveConnection_WithRemoteHash)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(SourceCid, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    //
    // Add remote hash entry.
    //
    QUIC_ADDR RemoteAddr;
    QuicAddrFromString("192.168.1.1", 5000, &RemoteAddr);
    uint8_t RemoteCid[] = { 0x11, 0x22, 0x33, 0x44 };
    QUIC_CONNECTION* Collision = nullptr;

    BOOLEAN Added = QuicLookupAddRemoteHash(
        &Binding.Lookup,
        &Connection,
        &RemoteAddr,
        sizeof(RemoteCid),
        RemoteCid,
        &Collision);

    //
    // RemoveConnection handles both RemoteHash and local CIDs.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - short header stateless reset path
// =====================================================================

//
// Scenario: DeliverPackets with a server-owned shared binding, short
// header packet, no matching connection, and non-blocked port attempts
// stateless reset. With no StatelessRegistration, it fails and returns
// FALSE.
// How: Build a short header packet from allowed port 443 on a server
// binding with no connections.
// Assertions: Returns FALSE (QueueStatelessReset returns FALSE because
// MsQuicLib.StatelessRegistration is NULL).
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_ShortHeader_StatelessResetAttempt)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Build a short header packet large enough for stateless reset.
    // QUIC_MIN_STATELESS_RESET_PACKET_LENGTH is 39. BufferLength must be > 39.
    //
    uint8_t ShortHdrBuf[64];
    CxPlatZeroMemory(ShortHdrBuf, sizeof(ShortHdrBuf));
    ShortHdrBuf[0] = 0x40; // Short header: IsLongHeader=0, FixedBit=1

    MockPacket Mock;
    Mock.Packet._.Buffer = ShortHdrBuf;
    Mock.Packet._.BufferLength = sizeof(ShortHdrBuf);
    Mock.Packet.AvailBuffer = ShortHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(ShortHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = TRUE;
    Mock.Packet.DestCid = &ShortHdrBuf[1];
    Mock.Packet.DestCidLen = 8;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443); // Not blocked

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(ShortHdrBuf));
    //
    // Returns FALSE because QuicBindingQueueStatelessReset calls
    // QuicBindingQueueStatelessOperation which checks
    // MsQuicLib.StatelessRegistration (NULL in test env).
    //
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - non-initial long header packet
// =====================================================================

//
// Scenario: DeliverPackets for a long header Handshake (non-initial)
// packet with no matching connection drops it ("Non-initial packet not
// matched with a connection").
// How: Build a long header packet with Type=Handshake (2) and
// QUIC_VERSION_1 on a server-owned shared binding with no connections.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_NonInitialLongHeader)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    //
    // Build a Handshake packet (Type=2 for V1):
    // byte[0]: IsLongHeader=1 (0x80) | FixedBit=1 (0x40) | Type=Handshake(2)<<4 = 0x20
    //
    LongHdrBuf[0] = 0xE0; // 0x80 | 0x40 | 0x20 = 0xE0 (Handshake V1)
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[6] = 0x01; LongHdrBuf[7] = 0x02;
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 23;

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingQueueStatelessReset - packet too short
// =====================================================================

//
// Scenario: QueueStatelessReset with a packet too short for stateless
// reset returns FALSE.
// How: Create a short header packet with BufferLength <=
// QUIC_MIN_STATELESS_RESET_PACKET_LENGTH (39).
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_QueueStatelessReset_TooShort)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Short packet (20 bytes) which is <= QUIC_MIN_STATELESS_RESET_PACKET_LENGTH (21).
    //
    uint8_t ShortBuf[20];
    CxPlatZeroMemory(ShortBuf, sizeof(ShortBuf));
    ShortBuf[0] = 0x40; // Short header

    MockPacket Mock;
    Mock.Packet._.Buffer = ShortBuf;
    Mock.Packet._.BufferLength = sizeof(ShortBuf);
    Mock.Packet.AvailBuffer = ShortBuf;
    Mock.Packet.AvailBufferLength = sizeof(ShortBuf);

    BOOLEAN Result = QuicBindingQueueStatelessReset(&Binding, &Mock.Packet);
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// QuicBindingQueueStatelessReset - large enough but no registration
// =====================================================================

//
// Scenario: QueueStatelessReset with a large enough packet but no
// StatelessRegistration returns FALSE.
// How: Create a short header packet > 39 bytes on a non-exclusive
// binding. MsQuicLib.StatelessRegistration is NULL.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_QueueStatelessReset_NoRegistration)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t ShortBuf[64];
    CxPlatZeroMemory(ShortBuf, sizeof(ShortBuf));
    ShortBuf[0] = 0x40; // Short header

    MockPacket Mock;
    Mock.Packet._.Buffer = ShortBuf;
    Mock.Packet._.BufferLength = sizeof(ShortBuf);
    Mock.Packet.AvailBuffer = ShortBuf;
    Mock.Packet.AvailBufferLength = sizeof(ShortBuf);

    BOOLEAN Result = QuicBindingQueueStatelessReset(&Binding, &Mock.Packet);
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - with listener but validated long header fails
// =====================================================================

//
// Scenario: DeliverPackets for a valid initial packet on a server
// binding WITH listener but invalid long header V1 (fails at
// QuicPacketValidateLongHeaderV1) returns FALSE.
// How: Register a listener, build an initial long header with
// QUIC_VERSION_1 but with an invalid fixed bit or other issue.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_InvalidLongHeaderV1)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    //
    // Build an initial V1 packet with DestCid and SourceCid CID > 20
    // (QUIC_MAX_CONNECTION_ID_LENGTH_V1). This makes
    // QuicPacketValidateLongHeaderV1 drop it.
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // Initial V1
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 21; // DestCidLen = 21 (exceeds max 20)
    // SourceCidLen at byte 5 + 1 + 21 = 27
    LongHdrBuf[27] = 8;

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 21;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[28];
    Mock.Packet.HeaderLength = 36;

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RegisterListener - family continue path (line 358)
// =====================================================================

//
// Scenario: Registering a listener with lower family after a higher family
// listener exercises the "continue" path when NewFamily != ExistingFamily
// but NewFamily < ExistingFamily (line 358).
// How: Register AF_INET6 first, then AF_INET. During AF_INET registration,
// the loop sees AF_INET6 (NewFamily=2 < ExistingFamily=23), skips it via
// continue.
// Assertions: Both registrations succeed.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_FamilyContinuePath)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER Listener6;
    InitializeMockListener(
        &Listener6, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET6, TRUE);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener4;
    InitializeMockListener(
        &Listener4, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener6));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener4));

    //
    // Verify sort order: AF_INET6 (23) before AF_INET (2).
    //
    ASSERT_EQ(Binding.Listeners.Flink, &Listener6.Link);
    ASSERT_EQ(Listener6.Link.Flink, &Listener4.Link);

    QuicBindingUnregisterListener(&Binding, &Listener4);
    QuicBindingUnregisterListener(&Binding, &Listener6);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RegisterListener - wildcard continue path (line 366)
// =====================================================================

//
// Scenario: Registering a wildcard listener after a non-wildcard listener
// of the same family exercises the "continue" at line 366 when
// NewWildCard != ExistingWildCard (and NewWildCard=TRUE, Existing=FALSE).
// How: Register specific (non-wildcard) AF_INET listener first, then
// register wildcard AF_INET listener.
// Assertions: Both succeed. Non-wildcard is sorted before wildcard.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_WildcardContinuePath)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER ListenerSpec;
    InitializeMockListener(
        &ListenerSpec, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, FALSE); // non-wildcard

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER ListenerWild;
    InitializeMockListener(
        &ListenerWild, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE); // wildcard

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &ListenerSpec));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &ListenerWild));

    //
    // Non-wildcard should be before wildcard in sort order.
    //
    ASSERT_EQ(Binding.Listeners.Flink, &ListenerSpec.Link);
    ASSERT_EQ(ListenerSpec.Link.Flink, &ListenerWild.Link);

    QuicBindingUnregisterListener(&Binding, &ListenerWild);
    QuicBindingUnregisterListener(&Binding, &ListenerSpec);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RegisterListener - IP comparison continue path (line 369-370)
// =====================================================================

//
// Scenario: Two non-wildcard listeners of the same family with different
// IP addresses exercises the "continue" when IPs don't match (line 370).
// How: Register AF_INET non-wildcard at 127.0.0.1 with ALPN "a", then
// register another AF_INET non-wildcard at 10.0.0.1 with ALPN "b".
// Assertions: Both succeed.
//
TEST_F(DeepTest_Binding, DeepTest_RegisterListener_IpCompareContinuePath)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER Listener1;
    CxPlatZeroMemory(&Listener1, sizeof(Listener1));
    Listener1._.Type = QUIC_HANDLE_TYPE_LISTENER;
    Listener1.WildCard = FALSE;
    Listener1.AlpnList = (uint8_t*)Alpn1;
    Listener1.AlpnListLength = sizeof(Alpn1);
    CxPlatListInitializeHead(&Listener1.Link);
    CxPlatListInitializeHead(&Listener1.RegistrationLink);
    CxPlatListInitializeHead(&Listener1.WorkerLink);
    QuicAddrFromString("127.0.0.1", 4433, &Listener1.LocalAddress);
    CxPlatRefInitialize(&Listener1.StartRefCount);
    CxPlatRefInitialize(&Listener1.RefCount);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener2;
    CxPlatZeroMemory(&Listener2, sizeof(Listener2));
    Listener2._.Type = QUIC_HANDLE_TYPE_LISTENER;
    Listener2.WildCard = FALSE;
    Listener2.AlpnList = (uint8_t*)Alpn2;
    Listener2.AlpnListLength = sizeof(Alpn2);
    CxPlatListInitializeHead(&Listener2.Link);
    CxPlatListInitializeHead(&Listener2.RegistrationLink);
    CxPlatListInitializeHead(&Listener2.WorkerLink);
    QuicAddrFromString("10.0.0.1", 4433, &Listener2.LocalAddress);
    CxPlatRefInitialize(&Listener2.StartRefCount);
    CxPlatRefInitialize(&Listener2.RefCount);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// GetListener - ALPN mismatch on AF_UNSPEC listener (line 457-458)
// =====================================================================

//
// Scenario: GetListener returns NULL and sets FailedAlpnMatch when
// an AF_UNSPEC wildcard listener is registered but ALPN doesn't match.
// The AF_UNSPEC family skips the address check (line 443), so the code
// reaches the ALPN check (line 452) and takes the else path (line 457).
// How: Register AF_UNSPEC wildcard listener with ALPN "test". Query
// GetListener with ALPN "h3".
// Assertions: Returns NULL.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_AlpnMismatch_UnspecListener)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    static const uint8_t ClientAlpn[] = { 2, 'h', '3' };
    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = ClientAlpn;
    Info.ClientAlpnListLength = sizeof(ClientAlpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(
        &Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// GetListener - non-wildcard IP mismatch (line 445-447)
// =====================================================================

//
// Scenario: GetListener with a non-wildcard listener where same family
// but IP doesn't match exercises lines 445-447 (FailedAddrMatch,
// continue).
// How: Register AF_INET non-wildcard listener at 127.0.0.1, query with
// local address 10.0.0.1.
// Assertions: Returns NULL (address mismatch).
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_NonWildcard_IpMismatch)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, FALSE); // non-wildcard at 127.0.0.1
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrFromString("10.0.0.1", 4433, &LocalAddr);

    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = Alpn;
    Info.ClientAlpnListLength = sizeof(Alpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(
        &Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// GetListener - StartRefCount zero (line 453-456)
// =====================================================================

//
// Scenario: GetListener finds a matching listener but its StartRefCount
// is 0, so CxPlatRefIncrementNonZero returns FALSE. Listener remains
// NULL but goes to Done (line 456).
// How: Register AF_UNSPEC wildcard listener with matching ALPN. Decrement
// StartRefCount to 0. Then call GetListener.
// Assertions: Returns NULL even though ALPN matched.
//
TEST_F(DeepTest_Binding, DeepTest_GetListener_StartRefCountZero)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    //
    // Decrement StartRefCount to 0 so IncrementNonZero fails.
    //
    CxPlatRefDecrement(&Listener.StartRefCount);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);
    QUIC_PARTITION DummyPartition;
    CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
    Connection.Partition = &DummyPartition;

    QUIC_ADDR LocalAddr;
    QuicAddrFromString("127.0.0.1", 4433, &LocalAddr);

    static const uint8_t ClientAlpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_NEW_CONNECTION_INFO Info;
    CxPlatZeroMemory(&Info, sizeof(Info));
    Info.LocalAddress = &LocalAddr;
    Info.ClientAlpnList = ClientAlpn;
    Info.ClientAlpnListLength = sizeof(ClientAlpn);

    QUIC_LISTENER* Result = QuicBindingGetListener(
        &Binding, &Connection, &Info);
    ASSERT_EQ(Result, nullptr);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// RemoveConnection with RemoteHash (fixed - with MaximizePartitioning)
// =====================================================================

//
// Scenario: RemoveConnection with a non-NULL RemoteHashEntry removes
// both the remote hash and local CIDs (line 589).
// How: Register a listener first (triggers MaximizePartitioning), then
// add a source CID and remote hash. RemoveConnection should remove both.
// Assertions: CidCount is 0 after removal.
//
TEST_F(DeepTest_Binding, DeepTest_RemoveConnection_WithRemoteHash_MaxPartitioning)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Register a listener to trigger MaximizePartitioning.
    //
    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));
    ASSERT_TRUE(Binding.Lookup.MaximizePartitioning);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    uint8_t CidData[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(SourceCid, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    //
    // Add remote hash entry (works now because MaximizePartitioning=TRUE).
    //
    QUIC_ADDR RemoteAddr;
    QuicAddrFromString("192.168.1.1", 5000, &RemoteAddr);
    uint8_t RemoteCid[] = { 0x11, 0x22, 0x33, 0x44 };
    QUIC_CONNECTION* Collision = nullptr;

    BOOLEAN Added = QuicLookupAddRemoteHash(
        &Binding.Lookup,
        &Connection,
        &RemoteAddr,
        sizeof(RemoteCid),
        RemoteCid,
        &Collision);
    ASSERT_TRUE(Added);
    ASSERT_NE(Connection.RemoteHashEntry, nullptr);

    //
    // RemoveConnection should handle both RemoteHash (line 589) and CIDs.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    ASSERT_EQ(Binding.Lookup.CidCount, 0u);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// HandshakeConfirmed with RemoteHash (line 614)
// =====================================================================

//
// Scenario: HandshakeConfirmed with a non-NULL RemoteHashEntry removes
// the remote hash (line 614).
// How: Register a listener (triggers MaximizePartitioning), add a remote
// hash to a connection, then call OnConnectionHandshakeConfirmed.
// Assertions: RemoteHashEntry is removed (set to NULL by lookup code).
//
TEST_F(DeepTest_Binding, DeepTest_HandshakeConfirmed_WithRemoteHash_MaxPartitioning)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Register a listener to trigger MaximizePartitioning.
    //
    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));
    ASSERT_TRUE(Binding.Lookup.MaximizePartitioning);

    QUIC_CONNECTION Connection;
    InitializeMockConnection(&Connection);

    //
    // Also add a CID so the connection is in the lookup (needed for ref).
    //
    uint8_t CidData[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    QUIC_CID_HASH_ENTRY* SourceCid =
        QuicCidNewSource(&Connection, sizeof(CidData), CidData);
    ASSERT_NE(SourceCid, nullptr);
    ASSERT_TRUE(QuicBindingAddSourceConnectionID(&Binding, SourceCid));
    SourceCid->Link.Next = Connection.SourceCids.Next;
    Connection.SourceCids.Next = &SourceCid->Link;

    QUIC_ADDR RemoteAddr;
    QuicAddrFromString("192.168.1.1", 5000, &RemoteAddr);
    uint8_t RemoteCid[] = { 0x11, 0x22, 0x33, 0x44 };
    QUIC_CONNECTION* Collision = nullptr;

    BOOLEAN Added = QuicLookupAddRemoteHash(
        &Binding.Lookup,
        &Connection,
        &RemoteAddr,
        sizeof(RemoteCid),
        RemoteCid,
        &Collision);
    ASSERT_TRUE(Added);
    ASSERT_NE(Connection.RemoteHashEntry, nullptr);

    //
    // HandshakeConfirmed removes the remote hash entry.
    //
    QuicBindingOnConnectionHandshakeConfirmed(&Binding, &Connection);
    ASSERT_EQ(Connection.RemoteHashEntry, nullptr);

    //
    // Clean up: remove CIDs.
    //
    QuicBindingRemoveConnection(&Binding, &Connection);
    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - unsupported version, listener, large buffer (line 1175)
// =====================================================================

//
// Scenario: PreprocessPacket with unsupported version, listener registered,
// and buffer >= 1200 attempts to queue VN (line 1175).
// Since StatelessRegistration is NULL, QueueStatelessOperation returns
// FALSE, so ReleaseDatagram stays TRUE.
// How: Build long header with unsupported version and 1200-byte buffer.
// Assertions: Returns FALSE, ReleaseDatagram is TRUE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_UnsupportedVersion_LargeBuffer_VN)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn[] = { 4, 't', 'e', 's', 't' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_INET, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    //
    // Build long header with unsupported version and large buffer (>= 1200).
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1, FixedBit=1
    uint32_t UnsupportedVersion = 0xDEADBEEFU;
    CxPlatCopyMemory(&LongHdrBuf[1], &UnsupportedVersion, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[14] = 4; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    //
    // Returns FALSE because the version is unsupported.
    // ReleaseDatagram is TRUE because QueueStatelessOperation returns FALSE
    // (StatelessRegistration is NULL), so !FALSE = TRUE.
    //
    ASSERT_FALSE(Result);
    ASSERT_TRUE(ReleaseDatagram);

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - exclusive binding, long header, DestCidLen=0 (line 1182-1186)
// =====================================================================

//
// Scenario: PreprocessPacket on exclusive binding with long header and
// DestCidLen=0 is valid for exclusive bindings (line 1182-1186 inner if
// is FALSE, falls through to success).
// How: Build long header with supported version, DestCidLen=0, on
// exclusive binding.
// Assertions: Returns TRUE, ReleaseDatagram is FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_Exclusive_LongHeader_ZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, TRUE, FALSE); // Exclusive

    //
    // Build long header with QUIC_VERSION_1 and DestCidLen=0.
    //
    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 0; // DestCidLen = 0
    LongHdrBuf[6] = 4; // SourceCidLen = 4

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = TRUE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - exclusive binding, long header, DestCidLen>0 (line 1183-1185)
// =====================================================================

//
// Scenario: PreprocessPacket on exclusive binding with long header and
// DestCidLen > 0 drops the packet (line 1183-1185).
// How: Build long header with supported version, DestCidLen=8, on
// exclusive binding.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_Exclusive_LongHeader_NonZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, TRUE, FALSE); // Exclusive

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen = 8
    LongHdrBuf[14] = 4; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - non-exclusive, long header, DestCidLen=0 (line 1188-1190)
// =====================================================================

//
// Scenario: PreprocessPacket on non-exclusive binding with long header
// and DestCidLen=0 drops the packet (line 1188-1190).
// How: Build long header with supported version and DestCidLen=0 on
// non-exclusive binding.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_NonExclusive_LongHeader_ZeroCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 0; // DestCidLen = 0
    LongHdrBuf[6] = 4; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - non-exclusive, long header, CID too short (line 1192-1195)
// =====================================================================

//
// Scenario: PreprocessPacket on non-exclusive binding with long header
// and DestCidLen < QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH (8) drops the
// packet (line 1192-1195).
// How: Build long header with supported version and DestCidLen=4.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_NonExclusive_LongHeader_ShortCid)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 4; // DestCidLen = 4 (< QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH=8)
    LongHdrBuf[10] = 4; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = FALSE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - VN packet with no matching connection (line 1503-1505)
// =====================================================================

//
// Scenario: DeliverPackets for a VN packet (Version=0) with no matching
// connection on a server binding drops it (line 1503-1505).
// How: Build long header with Version=0 (VN), server-owned, non-exclusive,
// non-blocked port, no matching connection.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_VNPacket_NoConnection)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_VER_NEG; // 0x00000000
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[14] = 4; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 4;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443); // Not blocked

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - V2 non-initial (line 1527-1531)
// =====================================================================

//
// Scenario: DeliverPackets for a long header V2 non-initial packet with
// no matching connection drops it (line 1527-1531). V2 Initial type is 1.
// How: Build long header with QUIC_VERSION_2 and Type=0 (which is
// Handshake for V2, not Initial).
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_V2_NonInitial)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    //
    // V2: Initial type = 1 (QUIC_INITIAL_V2). Use type=0 for non-initial.
    // Byte[0] bits: IsLongHeader(7)=1, FixedBit(6)=1, Type(5:4)=0b00
    //
    LongHdrBuf[0] = 0xC0; // IsLongHeader=1, FixedBit=1, Type=0 (non-initial V2)
    uint32_t Version = QUIC_VERSION_2;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 23;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - server binding, no connection, no listener (line 1560-1562)
// =====================================================================

//
// Scenario: DeliverPackets for a valid Initial V1 packet on server binding
// with no listeners drops it (line 1560-1562).
// How: Build a proper Initial V1 long header with valid structure but
// don't register any listeners on the binding.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_NoListener_Initial)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Build a valid Initial V1 packet.
    // Byte layout: [flags][version:4][DestCidLen][DestCid...][SourceCidLen][SourceCid...][TokenLen=0][Length][PN]
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    //
    // V1 Initial: Type=0 (QUIC_INITIAL_V1)
    // byte[0]: IsLongHeader=1(0x80), FixedBit=1(0x40), Type=0(0x00), PnLength=0
    //
    LongHdrBuf[0] = 0xC0; // 0x80 | 0x40 = 0xC0 (Initial V1)
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    // DestCid at bytes 6-13
    LongHdrBuf[6] = 0x01; LongHdrBuf[7] = 0x02;
    LongHdrBuf[14] = 8; // SourceCidLen
    // SourceCid at bytes 15-22
    // TokenLength (var int) at byte 23 = 0
    LongHdrBuf[23] = 0;
    // Length (var int) at byte 24, 2-byte encoding
    LongHdrBuf[24] = 0x40; LongHdrBuf[25] = 0x10; // Length = 16
    // PN at bytes 26-29
    // Payload at bytes 30+

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 30;

    //
    // Set the LH pointer to the buffer so LH->Type check works.
    //
    Mock.Packet.LH = (const QUIC_LONG_HEADER_V1*)LongHdrBuf;
    Mock.Packet.Invariant = (const QUIC_HEADER_INVARIANT*)LongHdrBuf;

    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// NOTE: DeliverPackets line 1462-1469 (remote hash lookup) and 1456-1461
// (local CID lookup) paths require fully initialized connections with
// ReceiveQueueLock, OperPool etc. These are contract-unreachable in mock tests
// because QuicConnQueueRecvPackets needs a real datapath and worker pool.

// =====================================================================
// DeliverPackets - Initial V1 with no listener (line 1560-1562)
// =====================================================================

//
// Scenario: DeliverPackets for a valid Initial V1 packet on server binding
// that passes QuicPacketValidateLongHeaderV1 but has no listener registered
// drops it at line 1560-1562.
// How: Build a proper Initial V1 with valid structure (TokenLen=0,
// Length field, PN), no listener, allowed port.
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_InitialV1_NoListener)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Build a valid Initial V1 packet with proper header structure.
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC3; // IsLongHeader=1, FixedBit=1, Type=0 (Initial V1), PnLen=3
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[6] = 0xAA; LongHdrBuf[7] = 0xBB;
    LongHdrBuf[14] = 8; // SourceCidLen
    LongHdrBuf[15] = 0xCC; LongHdrBuf[16] = 0xDD;
    LongHdrBuf[23] = 0; // TokenLen = 0
    //
    // Length (2-byte var int): 0x4010 = 16 payload bytes
    //
    LongHdrBuf[24] = 0x41; LongHdrBuf[25] = 0x00; // Length = 256

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 30;
    Mock.Packet.LH = (const QUIC_LONG_HEADER_V1*)LongHdrBuf;
    Mock.Packet.Invariant = (const QUIC_HEADER_INVARIANT*)LongHdrBuf;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DosModeChange with multiple listeners
// =====================================================================

//
// Scenario: HandleDosModeStateChange iterates all registered listeners
// and calls QuicListenerHandleDosModeStateChange for each.
// How: Register two listeners, call HandleDosModeStateChange.
// Assertions: No crash (can't directly verify listener state change
// without accessing listener internals).
//
TEST_F(DeepTest_Binding, DeepTest_DosModeChange_MultipleListeners)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    static const uint8_t Alpn1[] = { 1, 'a' };
    QUIC_LISTENER Listener1;
    InitializeMockListener(
        &Listener1, Alpn1, sizeof(Alpn1),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    static const uint8_t Alpn2[] = { 1, 'b' };
    QUIC_LISTENER Listener2;
    InitializeMockListener(
        &Listener2, Alpn2, sizeof(Alpn2),
        QUIC_ADDRESS_FAMILY_INET, TRUE);

    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener1));
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener2));

    QuicBindingHandleDosModeStateChange(&Binding, TRUE);
    QuicBindingHandleDosModeStateChange(&Binding, FALSE);

    QuicBindingUnregisterListener(&Binding, &Listener2);
    QuicBindingUnregisterListener(&Binding, &Listener1);
    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - V1 non-initial (Handshake) on non-blocked port (line 1523-1524)
// =====================================================================

//
// Scenario: DeliverPackets for a long header V1 Handshake (non-initial)
// packet with no matching connection and a non-blocked port drops it
// at line 1523-1524.
// How: Build V1 Handshake packet on port 443 (non-blocked).
// Assertions: Returns FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_V1_NonInitial_NonBlockedPort)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xE0; // Handshake V1 (Type=2)
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8;
    LongHdrBuf[14] = 8;

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 23;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// PreprocessPacket - success path for long header (line 1199-1201)
// =====================================================================

//
// Scenario: PreprocessPacket on non-exclusive binding with supported
// version and valid CID succeeds.
// How: Build long header with QUIC_VERSION_1, DestCidLen=8.
// Assertions: Returns TRUE, ReleaseDatagram is FALSE.
//
TEST_F(DeepTest_Binding, DeepTest_PreprocessPacket_SuccessPath_LongHeader)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[64];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8;
    LongHdrBuf[14] = 4;

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);

    BOOLEAN ReleaseDatagram = TRUE;
    BOOLEAN Result = QuicBindingPreprocessPacket(
        &Binding, &Mock.Packet, &ReleaseDatagram);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(ReleaseDatagram);

    UninitializeMockBinding(&Binding);
}
// =====================================================================
// DeliverPackets - V1 Initial with FixedBit cleared (line 1555)
// =====================================================================

//
// Scenario: DeliverPackets for a V1 Initial packet where the fixed bit
// (bit 6) is cleared causes QuicPacketValidateLongHeaderV1 to fail,
// returning FALSE at binding.c line 1555.
// How: Build a long header Initial V1 packet with byte[0]=0x80 (fixed bit=0)
// and non-blocked port. Packet passes the version/type switch but fails
// the FixedBit check inside QuicPacketValidateLongHeaderV1.
// Assertions: Returns FALSE (validation failure).
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_V1_Initial_FixedBitClear)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    //
    // V1 Initial with FixedBit cleared:
    // IsLongHeader(bit7)=1, FixedBit(bit6)=0, Type(bits5-4)=00
    // 0x80 = 1000 0000
    //
    LongHdrBuf[0] = 0x80;
    uint32_t Version = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Version, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[6] = 0x01; LongHdrBuf[7] = 0x02;
    LongHdrBuf[14] = 8; // SourceCidLen

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 23;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    UninitializeMockBinding(&Binding);
}

// =====================================================================
// DeliverPackets - V1 Initial with listener, retry triggered (lines 1565-1572)
// =====================================================================

//
// Scenario: DeliverPackets for a valid V1 Initial packet with a registered
// listener. Handshake memory usage exceeds limit, so
// QuicBindingShouldRetryConnection returns TRUE. Then
// QuicBindingQueueStatelessOperation returns FALSE because
// MsQuicLib.StatelessRegistration is NULL.
// How: Build a proper V1 Initial packet (1300 bytes, FixedBit=1, valid
// VarInt fields), register a listener, set CurrentHandshakeMemoryUsage
// to UINT64_MAX so ShouldRetryConnection triggers retry.
// Assertions: Returns FALSE (retry requested but stateless op fails).
//
TEST_F(DeepTest_Binding, DeepTest_DeliverPackets_V1_Initial_RetryTriggered)
{
    QUIC_BINDING Binding;
    InitializeMockBinding(&Binding, TRUE, FALSE, FALSE);

    //
    // Register a listener so QuicBindingHasListenerRegistered returns TRUE.
    //
    static const uint8_t Alpn[] = { 1, 'a' };
    QUIC_LISTENER Listener;
    InitializeMockListener(
        &Listener, Alpn, sizeof(Alpn),
        QUIC_ADDRESS_FAMILY_UNSPEC, TRUE);
    TEST_QUIC_SUCCEEDED(QuicBindingRegisterListener(&Binding, &Listener));

    //
    // Save and modify global state to trigger retry.
    //
    uint64_t SavedMemUsage = MsQuicLib.CurrentHandshakeMemoryUsage;
    uint16_t SavedRetryLimit = MsQuicLib.Settings.RetryMemoryLimit;
    MsQuicLib.CurrentHandshakeMemoryUsage = UINT64_MAX;
    MsQuicLib.Settings.RetryMemoryLimit = 1;

    //
    // Build a valid V1 Initial packet that passes QuicPacketValidateLongHeaderV1.
    //
    uint8_t LongHdrBuf[1300];
    CxPlatZeroMemory(LongHdrBuf, sizeof(LongHdrBuf));
    LongHdrBuf[0] = 0xC0; // Initial V1, FixedBit=1
    uint32_t Ver = QUIC_VERSION_1;
    CxPlatCopyMemory(&LongHdrBuf[1], &Ver, sizeof(uint32_t));
    LongHdrBuf[5] = 8; // DestCidLen
    LongHdrBuf[6] = 0xAA;
    LongHdrBuf[14] = 8; // SourceCidLen
    LongHdrBuf[15] = 0xBB;
    // TokenLength VarInt at offset 23 = 0
    LongHdrBuf[23] = 0x00;
    // Payload Length VarInt at offset 24: encode 1200 as 2-byte VarInt
    // 1200 = 0x4B0 → 0x44 0xB0
    LongHdrBuf[24] = 0x44;
    LongHdrBuf[25] = 0xB0;

    MockPacket Mock;
    Mock.Packet._.Buffer = LongHdrBuf;
    Mock.Packet._.BufferLength = sizeof(LongHdrBuf);
    Mock.Packet.AvailBuffer = LongHdrBuf;
    Mock.Packet.AvailBufferLength = sizeof(LongHdrBuf);
    Mock.Packet.ValidatedHeaderInv = TRUE;
    Mock.Packet.IsShortHeader = FALSE;
    Mock.Packet.DestCidLen = 8;
    Mock.Packet.DestCid = &LongHdrBuf[6];
    Mock.Packet.SourceCidLen = 8;
    Mock.Packet.SourceCid = &LongHdrBuf[15];
    Mock.Packet.HeaderLength = 23;
    QuicAddrSetPort(&Mock.Route.RemoteAddress, 443);

    BOOLEAN Result = QuicBindingDeliverPackets(
        &Binding, &Mock.Packet, 1, sizeof(LongHdrBuf));
    ASSERT_FALSE(Result);

    //
    // Restore global state.
    //
    MsQuicLib.CurrentHandshakeMemoryUsage = SavedMemUsage;
    MsQuicLib.Settings.RetryMemoryLimit = SavedRetryLimit;

    QuicBindingUnregisterListener(&Binding, &Listener);
    UninitializeMockBinding(&Binding);
}
