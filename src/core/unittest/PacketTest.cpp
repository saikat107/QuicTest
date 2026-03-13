/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC packet processing helpers (packet.c).

    Tests cover:
      - QuicPacketValidateInvariant (long/short header, CID caching/matching)
      - QuicPacketValidateLongHeaderV1 (type checks, fixed bit, token, length)
      - QuicPacketValidateShortHeaderV1 (fixed bit, payload length)
      - QuicLongHeaderTypeToStringV1/V2 (string helpers)
      - QuicPacketEncodeRetryV1 (retry packet encoding)
      - QuicPacketLogDrop / QuicPacketLogDropWithValue (logging helpers)

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PacketTest.cpp.clog.h"
#endif

//
// Forward declarations for packet.c functions not in public header.
//
extern "C" {
_Null_terminated_ const char* QuicLongHeaderTypeToStringV1(uint8_t Type);
_Null_terminated_ const char* QuicLongHeaderTypeToStringV2(uint8_t Type);
}

//
// Test fixture that ensures MsQuicLib.Partitions is valid (needed by
// QuicPacketLogDrop which accesses the perf counter via PartitionIndex).
//
class DeepTest_Packet : public ::testing::Test {
protected:
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
    // Helper: Build a minimal QUIC_RX_PACKET wired to a buffer + route.
    //
    static void
    InitRxPacket(
        _Out_ QUIC_RX_PACKET* Packet,
        _In_ const uint8_t* Buffer,
        _In_ uint16_t BufferLength,
        _In_ CXPLAT_ROUTE* Route
        )
    {
        CxPlatZeroMemory(Packet, sizeof(*Packet));
        Packet->AvailBuffer = Buffer;
        Packet->AvailBufferLength = BufferLength;
        Packet->_.Route = Route;
        Packet->_.PartitionIndex = 0;
    }

    //
    // Helper: Build a minimal mock QUIC_BINDING for use as Owner.
    //
    static void
    InitMockBinding(
        _Out_ QUIC_BINDING* Binding
        )
    {
        CxPlatZeroMemory(Binding, sizeof(*Binding));
    }
};

//
// Helper: Write a QUIC version constant into a buffer. Needed because
// QUIC_VERSION_* are #define literals and cannot be addressed with &.
//
static void
WriteVersionToBuffer(
    _Out_writes_(sizeof(uint32_t)) uint8_t* Dest,
    _In_ uint32_t Version
    )
{
    CxPlatCopyMemory(Dest, &Version, sizeof(uint32_t));
}

// =====================================================================
// QuicLongHeaderTypeToStringV1
// =====================================================================

TEST(PacketTest, LongHeaderTypeToStringV1_Initial)
{
    ASSERT_STREQ("I", QuicLongHeaderTypeToStringV1(QUIC_INITIAL_V1));
}

TEST(PacketTest, LongHeaderTypeToStringV1_ZeroRtt)
{
    ASSERT_STREQ("0P", QuicLongHeaderTypeToStringV1(QUIC_0_RTT_PROTECTED_V1));
}

TEST(PacketTest, LongHeaderTypeToStringV1_Handshake)
{
    ASSERT_STREQ("HS", QuicLongHeaderTypeToStringV1(QUIC_HANDSHAKE_V1));
}

TEST(PacketTest, LongHeaderTypeToStringV1_Retry)
{
    ASSERT_STREQ("R", QuicLongHeaderTypeToStringV1(QUIC_RETRY_V1));
}

TEST(PacketTest, LongHeaderTypeToStringV1_Invalid)
{
    ASSERT_STREQ("INVALID", QuicLongHeaderTypeToStringV1(0xFF));
}

// =====================================================================
// QuicLongHeaderTypeToStringV2
// =====================================================================

TEST(PacketTest, LongHeaderTypeToStringV2_Retry)
{
    ASSERT_STREQ("R", QuicLongHeaderTypeToStringV2(QUIC_RETRY_V2));
}

TEST(PacketTest, LongHeaderTypeToStringV2_Initial)
{
    ASSERT_STREQ("I", QuicLongHeaderTypeToStringV2(QUIC_INITIAL_V2));
}

TEST(PacketTest, LongHeaderTypeToStringV2_ZeroRtt)
{
    ASSERT_STREQ("0P", QuicLongHeaderTypeToStringV2(QUIC_0_RTT_PROTECTED_V2));
}

TEST(PacketTest, LongHeaderTypeToStringV2_Handshake)
{
    ASSERT_STREQ("HS", QuicLongHeaderTypeToStringV2(QUIC_HANDSHAKE_V2));
}

TEST(PacketTest, LongHeaderTypeToStringV2_Invalid)
{
    ASSERT_STREQ("INVALID", QuicLongHeaderTypeToStringV2(0xFF));
}

// =====================================================================
// QuicPacketValidateInvariant
// =====================================================================

//
// Empty buffer must be rejected.
//
TEST_F(DeepTest_Packet, ValidateInvariant_EmptyBuffer)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[1] = {0};
    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, 0, &Route);

    ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
}

//
// Short header too small (just the type byte, no CID when shared binding).
//
TEST_F(DeepTest_Packet, ValidateInvariant_ShortHeaderTooSmall)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Short header: IsLongHeader = 0. One byte of just the header byte.
    // When IsBindingShared = TRUE the DestCidLen is MsQuicLib.CidTotalLength,
    // which is > 0 so the buffer is too short.
    //
    uint8_t Buffer[1] = {0x40}; // FixedBit=1, IsLongHeader=0
    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, 1, &Route);

    if (MsQuicLib.CidTotalLength > 0) {
        ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet, TRUE));
    }
}

//
// Valid short header with non-shared binding (DestCidLen = 0).
//
TEST_F(DeepTest_Packet, ValidateInvariant_ShortHeaderNonShared)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Short header: IsLongHeader = 0, FixedBit = 1.
    // With IsBindingShared = FALSE, DestCidLen = 0 so header is just 1 byte.
    //
    uint8_t Buffer[16];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0x40; // FixedBit=1, IsLongHeader=0
    Buffer[1] = 0x01; // Some payload data

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_TRUE(Packet.IsShortHeader);
    ASSERT_TRUE(Packet.ValidatedHeaderInv);
    ASSERT_EQ(Packet.DestCidLen, 0);
    ASSERT_EQ(Packet.SourceCidLen, 0);
}

//
// Long header too small for DestCid length field.
//
TEST_F(DeepTest_Packet, ValidateInvariant_LongHeaderTooSmallForDestCid)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Long header invariant is: 1 byte flags + 4 bytes version +
    // 1 byte DestCidLength = 6 bytes minimum (MIN_INV_LONG_HDR_LENGTH).
    // Supply less than that.
    //
    uint8_t Buffer[5];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0; // IsLongHeader=1, FixedBit=1

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
}

//
// Long header with DestCid extending past buffer.
//
TEST_F(DeepTest_Packet, ValidateInvariant_LongHeaderDestCidTruncated)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Construct a long header with DestCidLength = 8 but only provide
    // enough room for the invariant (no CID bytes).
    //
    uint8_t Buffer[MIN_INV_LONG_HDR_LENGTH]; // 6 bytes
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0; // IsLongHeader=1, FixedBit=1
    // Version at offset 1..4 (left as 0)
    Buffer[5] = 8; // DestCidLength = 8 -> needs 8 more bytes

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
}

//
// Long header with SourceCid extending past buffer.
//
TEST_F(DeepTest_Packet, ValidateInvariant_LongHeaderSourceCidTruncated)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Long header: DestCidLen=0, SourceCidLen=8 but buffer too short.
    // Layout: [flags(1)][version(4)][DestCidLen=0(1)][SourceCidLen=8(1)][...]
    // Total invariant header = 1+4+1+0+1+8 = 15 bytes needed.
    // Supply only 7 bytes.
    //
    uint8_t Buffer[7];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0; // IsLongHeader=1
    // Version at 1..4 = 0
    Buffer[5] = 0;  // DestCidLength = 0
    Buffer[6] = 8;  // SourceCidLength = 8

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
}

//
// Valid long header with zero-length CIDs. First packet (caches CIDs).
//
TEST_F(DeepTest_Packet, ValidateInvariant_LongHeaderValidZeroCids)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Layout: [flags=0xC0][version=4 bytes][DestCidLen=0][SrcCidLen=0]
    // Total = 7 bytes.
    //
    uint8_t Buffer[32];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0; // IsLongHeader=1, FixedBit=1
    Buffer[5] = 0;  // DestCidLength = 0
    Buffer[6] = 0;  // SourceCidLength = 0

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_FALSE(Packet.IsShortHeader);
    ASSERT_TRUE(Packet.ValidatedHeaderInv);
    ASSERT_EQ(Packet.DestCidLen, 0);
    ASSERT_EQ(Packet.SourceCidLen, 0);
}

//
// Valid long header with non-zero CIDs.
//
TEST_F(DeepTest_Packet, ValidateInvariant_LongHeaderWithCids)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // Layout: [flags=0xC0][version(4)][DestCidLen=4][DestCid(4)][SrcCidLen=4][SrcCid(4)]
    // Total = 1 + 4 + 1 + 4 + 1 + 4 = 15 bytes.
    //
    uint8_t Buffer[64];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0;
    // Version at 1..4 = QUIC_VERSION_1
    WriteVersionToBuffer(Buffer + 1, QUIC_VERSION_1);
    Buffer[5] = 4; // DestCidLength
    Buffer[6] = 0xAA; Buffer[7] = 0xBB; Buffer[8] = 0xCC; Buffer[9] = 0xDD; // DestCid
    Buffer[10] = 4; // SourceCidLength
    Buffer[11] = 0x11; Buffer[12] = 0x22; Buffer[13] = 0x33; Buffer[14] = 0x44; // SourceCid

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_FALSE(Packet.IsShortHeader);
    ASSERT_TRUE(Packet.ValidatedHeaderInv);
    ASSERT_EQ(Packet.DestCidLen, 4);
    ASSERT_EQ(Packet.SourceCidLen, 4);
    ASSERT_EQ(memcmp(Packet.DestCid, Buffer + 6, 4), 0);
    ASSERT_EQ(memcmp(Packet.SourceCid, Buffer + 11, 4), 0);
}

//
// Second packet in datagram: DestCid matches (should succeed).
//
TEST_F(DeepTest_Packet, ValidateInvariant_CidMatchSecondPacket)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[64];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0xC0;
    WriteVersionToBuffer(Buffer + 1, QUIC_VERSION_1);
    Buffer[5] = 4; // DestCidLength
    Buffer[6] = 0xAA; Buffer[7] = 0xBB; Buffer[8] = 0xCC; Buffer[9] = 0xDD;
    Buffer[10] = 4; // SourceCidLength
    Buffer[11] = 0x11; Buffer[12] = 0x22; Buffer[13] = 0x33; Buffer[14] = 0x44;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    //
    // First call: caches CIDs.
    //
    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    //
    // Second call: CIDs already cached, should match.
    //
    QUIC_RX_PACKET Packet2;
    InitRxPacket(&Packet2, Buffer, sizeof(Buffer), &Route);
    Packet2.DestCid = Packet.DestCid;
    Packet2.SourceCid = Packet.SourceCid;
    Packet2.DestCidLen = Packet.DestCidLen;
    Packet2.SourceCidLen = Packet.SourceCidLen;

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet2, FALSE));
}

//
// Second packet: DestCid mismatch (should fail).
//
TEST_F(DeepTest_Packet, ValidateInvariant_CidMismatchSecondPacket)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // First packet with CID = {0xAA, 0xBB, 0xCC, 0xDD}.
    //
    uint8_t Buffer1[64];
    CxPlatZeroMemory(Buffer1, sizeof(Buffer1));
    Buffer1[0] = 0xC0;
    WriteVersionToBuffer(Buffer1 + 1, QUIC_VERSION_1);
    Buffer1[5] = 4;
    Buffer1[6] = 0xAA; Buffer1[7] = 0xBB; Buffer1[8] = 0xCC; Buffer1[9] = 0xDD;
    Buffer1[10] = 4;
    Buffer1[11] = 0x11; Buffer1[12] = 0x22; Buffer1[13] = 0x33; Buffer1[14] = 0x44;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer1, sizeof(Buffer1), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    //
    // Second packet with different DestCid = {0xFF, 0xBB, 0xCC, 0xDD}.
    //
    uint8_t Buffer2[64];
    CxPlatZeroMemory(Buffer2, sizeof(Buffer2));
    Buffer2[0] = 0xC0;
    WriteVersionToBuffer(Buffer2 + 1, QUIC_VERSION_1);
    Buffer2[5] = 4;
    Buffer2[6] = 0xFF; Buffer2[7] = 0xBB; Buffer2[8] = 0xCC; Buffer2[9] = 0xDD;
    Buffer2[10] = 4;
    Buffer2[11] = 0x11; Buffer2[12] = 0x22; Buffer2[13] = 0x33; Buffer2[14] = 0x44;

    QUIC_RX_PACKET Packet2;
    InitRxPacket(&Packet2, Buffer2, sizeof(Buffer2), &Route);
    Packet2.DestCid = Packet.DestCid;
    Packet2.SourceCid = Packet.SourceCid;
    Packet2.DestCidLen = Packet.DestCidLen;
    Packet2.SourceCidLen = Packet.SourceCidLen;

    ASSERT_FALSE(QuicPacketValidateInvariant(&Binding, &Packet2, FALSE));
}

// =====================================================================
// QuicPacketValidateShortHeaderV1
// =====================================================================

//
// Valid short header with FixedBit=1 and IgnoreFixedBit=FALSE.
//
TEST_F(DeepTest_Packet, ValidateShortHeaderV1_Valid)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[32];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0x40; // FixedBit=1, IsLongHeader=0

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    //
    // Must validate invariant first.
    //
    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_TRUE(Packet.IsShortHeader);

    ASSERT_TRUE(QuicPacketValidateShortHeaderV1(&Binding, &Packet, FALSE));
    ASSERT_TRUE(Packet.ValidatedHeaderVer);
    ASSERT_EQ(Packet.PayloadLength, (uint16_t)(sizeof(Buffer) - Packet.HeaderLength));
}

//
// Short header with FixedBit=0 and IgnoreFixedBit=FALSE must fail.
//
TEST_F(DeepTest_Packet, ValidateShortHeaderV1_FixedBitZero)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[32];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0x00; // FixedBit=0, IsLongHeader=0

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_TRUE(Packet.IsShortHeader);

    ASSERT_FALSE(QuicPacketValidateShortHeaderV1(&Binding, &Packet, FALSE));
}

//
// Short header with FixedBit=0 but IgnoreFixedBit=TRUE should succeed.
//
TEST_F(DeepTest_Packet, ValidateShortHeaderV1_FixedBitZeroIgnored)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[32];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    Buffer[0] = 0x00; // FixedBit=0, IsLongHeader=0

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_TRUE(Packet.IsShortHeader);

    ASSERT_TRUE(QuicPacketValidateShortHeaderV1(&Binding, &Packet, TRUE));
    ASSERT_TRUE(Packet.ValidatedHeaderVer);
}

// =====================================================================
// QuicPacketValidateLongHeaderV1
// =====================================================================

//
// Valid V1 Handshake long header (non-Initial, so no token field).
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_ValidHandshake)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    //
    // Build a Handshake packet (type=2 for V1).
    // Layout: [LH flags][Version][DestCidLen=4][DestCid(4)][SrcCidLen=4][SrcCid(4)][Length(2-byte varint)][payload...]
    //
    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 1;
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Reserved = 0;
    LH->PnLength = 3;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 4;

    uint8_t* Cursor = LH->DestCid;
    Cursor[0] = 0xD0; Cursor[1] = 0xD1; Cursor[2] = 0xD2; Cursor[3] = 0xD3;
    Cursor += 4;
    *Cursor++ = 4; // SourceCidLength
    Cursor[0] = 0xA0; Cursor[1] = 0xA1; Cursor[2] = 0xA2; Cursor[3] = 0xA3;
    Cursor += 4;

    // Length (2-byte varint) = 32
    uint16_t PayloadLen = 32;
    *Cursor++ = (uint8_t)(0x40 | ((PayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(PayloadLen & 0xFF);

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + PayloadLen;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, TotalLen, &Route);

    //
    // First validate invariant.
    //
    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));
    ASSERT_FALSE(Packet.IsShortHeader);

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_TRUE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, FALSE));

    ASSERT_TRUE(Packet.ValidatedHeaderVer);
    ASSERT_EQ(TokenLength, 0);
    ASSERT_EQ(Token, nullptr);
    ASSERT_EQ(Packet.PayloadLength, PayloadLen);
}

//
// Long header with FixedBit=0 and IgnoreFixedBit=FALSE must fail.
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_FixedBitZero)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 0; // Invalid
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 0;

    uint8_t* Cursor = LH->DestCid;
    *Cursor++ = 0; // SrcCidLen=0
    uint16_t PayloadLen = 32;
    *Cursor++ = (uint8_t)(0x40 | ((PayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(PayloadLen & 0xFF);

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + PayloadLen;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, TotalLen, &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_FALSE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, FALSE));
}

//
// Long header with FixedBit=0 but IgnoreFixedBit=TRUE should succeed.
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_FixedBitZeroIgnored)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 0;
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 0;

    uint8_t* Cursor = LH->DestCid;
    *Cursor++ = 0; // SrcCidLen=0
    uint16_t PayloadLen = 32;
    *Cursor++ = (uint8_t)(0x40 | ((PayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(PayloadLen & 0xFF);

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + PayloadLen;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, TotalLen, &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_TRUE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, TRUE));
    ASSERT_TRUE(Packet.ValidatedHeaderVer);
}

//
// DestCid > QUIC_MAX_CONNECTION_ID_LENGTH_V1 must fail.
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_DestCidTooLong)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    //
    // DestCidLen = 21 > QUIC_MAX_CONNECTION_ID_LENGTH_V1 (20).
    //
    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 1;
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 21;

    uint8_t* Cursor = LH->DestCid + 21;
    *Cursor++ = 0; // SrcCidLen=0
    uint16_t PayloadLen = 32;
    *Cursor++ = (uint8_t)(0x40 | ((PayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(PayloadLen & 0xFF);

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + PayloadLen;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, TotalLen, &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_FALSE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, FALSE));
}

//
// Disallowed packet type for client (0-RTT from server side) must fail.
// Client cannot receive 0-RTT packets.
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_DisallowedTypeForClient)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 1;
    LH->Type = QUIC_0_RTT_PROTECTED_V1; // Not allowed for client (IsServer=FALSE)
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 0;

    uint8_t* Cursor = LH->DestCid;
    *Cursor++ = 0; // SrcCidLen=0
    uint16_t PayloadLen = 32;
    *Cursor++ = (uint8_t)(0x40 | ((PayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(PayloadLen & 0xFF);

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + PayloadLen;

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, TotalLen, &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_FALSE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, FALSE));
}

//
// Long header with payload length larger than buffer must fail.
//
TEST_F(DeepTest_Packet, ValidateLongHeaderV1_PayloadLengthExceedsBuffer)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[32];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 1;
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 0;

    uint8_t* Cursor = LH->DestCid;
    *Cursor++ = 0; // SrcCidLen=0

    //
    // Encode a large payload length that exceeds buffer.
    //
    uint16_t FakePayloadLen = 1000;
    *Cursor++ = (uint8_t)(0x40 | ((FakePayloadLen >> 8) & 0x3F));
    *Cursor++ = (uint8_t)(FakePayloadLen & 0xFF);

    uint16_t SmallBufferLen = (uint16_t)(Cursor - Buffer) + 4; // Only 4 bytes after header

    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));
    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, SmallBufferLen, &Route);

    ASSERT_TRUE(QuicPacketValidateInvariant(&Binding, &Packet, FALSE));

    const uint8_t* Token = NULL;
    uint16_t TokenLength = 0;
    ASSERT_FALSE(
        QuicPacketValidateLongHeaderV1(
            &Binding, FALSE, &Packet, &Token, &TokenLength, FALSE));
}

// =====================================================================
// QuicPacketEncodeRetryV1
// =====================================================================

//
// Buffer too small for retry packet must return 0.
//
TEST_F(DeepTest_Packet, EncodeRetryV1_BufferTooSmall)
{
    uint8_t DestCid[] = {0xAA, 0xBB};
    uint8_t SourceCid[] = {0xCC, 0xDD};
    uint8_t OrigDestCid[] = {0xEE, 0xFF};
    uint8_t Token[] = {0x01, 0x02, 0x03};
    uint8_t Buffer[4]; // Way too small

    uint16_t Result = QuicPacketEncodeRetryV1(
        QUIC_VERSION_1,
        DestCid, sizeof(DestCid),
        SourceCid, sizeof(SourceCid),
        OrigDestCid, sizeof(OrigDestCid),
        sizeof(Token), Token,
        sizeof(Buffer), Buffer);

    ASSERT_EQ(Result, 0);
}

//
// Valid retry packet encoding for V1.
//
TEST_F(DeepTest_Packet, EncodeRetryV1_ValidV1)
{
    uint8_t DestCid[] = {0xAA, 0xBB};
    uint8_t SourceCid[] = {0xCC, 0xDD};
    uint8_t OrigDestCid[] = {0xEE, 0xFF};
    uint8_t Token[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    uint16_t Result = QuicPacketEncodeRetryV1(
        QUIC_VERSION_1,
        DestCid, sizeof(DestCid),
        SourceCid, sizeof(SourceCid),
        OrigDestCid, sizeof(OrigDestCid),
        sizeof(Token), Token,
        sizeof(Buffer), Buffer);

    //
    // Expected length: MIN_RETRY_HEADER_LENGTH_V1 + DestCidLen + SrcCidLen
    //   + TokenLength + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1
    //
    uint16_t ExpectedLen =
        MIN_RETRY_HEADER_LENGTH_V1 +
        sizeof(DestCid) +
        sizeof(SourceCid) +
        sizeof(Token) +
        QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1;

    ASSERT_EQ(Result, ExpectedLen);

    //
    // Verify the retry header fields.
    //
    QUIC_RETRY_PACKET_V1* Retry = (QUIC_RETRY_PACKET_V1*)Buffer;
    ASSERT_TRUE(Retry->IsLongHeader);
    ASSERT_EQ(Retry->FixedBit, 1);
    ASSERT_EQ(Retry->Type, QUIC_RETRY_V1);
    ASSERT_EQ(Retry->Version, QUIC_VERSION_1);
    ASSERT_EQ(Retry->DestCidLength, sizeof(DestCid));
}

//
// Valid retry packet encoding for V2.
//
TEST_F(DeepTest_Packet, EncodeRetryV1_ValidV2)
{
    uint8_t DestCid[] = {0x01};
    uint8_t SourceCid[] = {0x02};
    uint8_t OrigDestCid[] = {0x03};
    uint8_t Token[] = {0xAA};
    uint8_t Buffer[256];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    uint16_t Result = QuicPacketEncodeRetryV1(
        QUIC_VERSION_2,
        DestCid, sizeof(DestCid),
        SourceCid, sizeof(SourceCid),
        OrigDestCid, sizeof(OrigDestCid),
        sizeof(Token), Token,
        sizeof(Buffer), Buffer);

    ASSERT_NE(Result, 0);

    QUIC_RETRY_PACKET_V1* Retry = (QUIC_RETRY_PACKET_V1*)Buffer;
    ASSERT_TRUE(Retry->IsLongHeader);
    ASSERT_EQ(Retry->Type, QUIC_RETRY_V2);
    ASSERT_EQ(Retry->Version, QUIC_VERSION_2);
}

// =====================================================================
// QuicPacketLogDrop / QuicPacketLogDropWithValue
// =====================================================================

//
// QuicPacketLogDrop with binding (non-connection) ownership path.
//
TEST_F(DeepTest_Packet, LogDrop_Binding)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[16] = {0x40}; // Short header
    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));

    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);
    Packet.AssignedToConnection = FALSE;

    uint64_t DroppedBefore = Binding.Stats.Recv.DroppedPackets;
    QuicPacketLogDrop(&Binding, &Packet, "Test drop reason");
    ASSERT_EQ(Binding.Stats.Recv.DroppedPackets, DroppedBefore + 1);
}

//
// QuicPacketLogDropWithValue with binding ownership path.
//
TEST_F(DeepTest_Packet, LogDropWithValue_Binding)
{
    QUIC_BINDING Binding;
    InitMockBinding(&Binding);

    uint8_t Buffer[16] = {0x40};
    CXPLAT_ROUTE Route;
    CxPlatZeroMemory(&Route, sizeof(Route));

    QUIC_RX_PACKET Packet;
    InitRxPacket(&Packet, Buffer, sizeof(Buffer), &Route);
    Packet.AssignedToConnection = FALSE;

    uint64_t DroppedBefore = Binding.Stats.Recv.DroppedPackets;
    QuicPacketLogDropWithValue(&Binding, &Packet, "Test drop with value", 42);
    ASSERT_EQ(Binding.Stats.Recv.DroppedPackets, DroppedBefore + 1);
}

// =====================================================================
// QuicPacketLogHeader (smoke test - just verify it doesn't crash)
// =====================================================================

TEST_F(DeepTest_Packet, LogHeader_ShortHeader)
{
    uint8_t Buffer[64];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));
    //
    // Build a minimal short header.
    //
    QUIC_SHORT_HEADER_V1* SH = (QUIC_SHORT_HEADER_V1*)Buffer;
    SH->IsLongHeader = FALSE;
    SH->FixedBit = 1;
    SH->SpinBit = 0;
    SH->KeyPhase = 0;

    //
    // Should not crash.
    //
    QuicPacketLogHeader(NULL, TRUE, 0, 1, sizeof(Buffer), Buffer, QUIC_VERSION_1);
}

TEST_F(DeepTest_Packet, LogHeader_LongHeaderHandshake)
{
    uint8_t Buffer[64];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    QUIC_LONG_HEADER_V1* LH = (QUIC_LONG_HEADER_V1*)Buffer;
    LH->IsLongHeader = TRUE;
    LH->FixedBit = 1;
    LH->Type = QUIC_HANDSHAKE_V1;
    LH->Version = QUIC_VERSION_1;
    LH->DestCidLength = 0;

    uint8_t* Cursor = LH->DestCid;
    *Cursor++ = 0; // SrcCidLen=0

    // Length varint = 8
    *Cursor++ = 0x08;

    uint16_t TotalLen = (uint16_t)(Cursor - Buffer) + 8;

    //
    // Should not crash.
    //
    QuicPacketLogHeader(NULL, FALSE, 0, 0, TotalLen, Buffer, QUIC_VERSION_1);
}

TEST_F(DeepTest_Packet, LogHeader_WithConnection)
{
    uint8_t Buffer[64];
    CxPlatZeroMemory(Buffer, sizeof(Buffer));

    //
    // Build a minimal short header.
    //
    QUIC_SHORT_HEADER_V1* SH = (QUIC_SHORT_HEADER_V1*)Buffer;
    SH->IsLongHeader = FALSE;
    SH->FixedBit = 1;
    SH->SpinBit = 0;
    SH->KeyPhase = 0;

    //
    // Create a minimal Connection object to test the non-NULL path.
    //
    QUIC_CONNECTION Connection {};
    Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_SERVER;

    //
    // Should not crash with a valid connection object.
    //
    QuicPacketLogHeader(&Connection, TRUE, 0, 1, sizeof(Buffer), Buffer, QUIC_VERSION_1);
}
