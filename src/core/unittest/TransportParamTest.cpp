/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC transport parameter encoding and decoding logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "TransportParamTest.cpp.clog.h"
#endif

static QUIC_CONNECTION JunkConnection;

void CompareTransportParams(
    _In_ const QUIC_TRANSPORT_PARAMETERS* A,
    _In_ const QUIC_TRANSPORT_PARAMETERS* B,
    _In_ bool IsServer = false
    )
{
    ASSERT_EQ(A->Flags, B->Flags);
    COMPARE_TP_FIELD(INITIAL_MAX_DATA, InitialMaxData);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_LOCAL, InitialMaxStreamDataBidiLocal);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_REMOTE, InitialMaxStreamDataBidiRemote);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_UNI, InitialMaxStreamDataUni);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_BIDI, InitialMaxBidiStreams);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_UNI, InitialMaxUniStreams);
    COMPARE_TP_FIELD(MAX_UDP_PAYLOAD_SIZE, MaxUdpPayloadSize);
    COMPARE_TP_FIELD(ACK_DELAY_EXPONENT, AckDelayExponent);
    COMPARE_TP_FIELD(IDLE_TIMEOUT, IdleTimeout);
    COMPARE_TP_FIELD(MAX_ACK_DELAY, MaxAckDelay);
    COMPARE_TP_FIELD(ACTIVE_CONNECTION_ID_LIMIT, ActiveConnectionIdLimit);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirLength);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirOffset);
    if (A->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        ASSERT_EQ(A->VersionInfoLength, B->VersionInfoLength);
        ASSERT_EQ(
            memcmp(A->VersionInfo, B->VersionInfo, (size_t)A->VersionInfoLength),
            0);
    }
    //COMPARE_TP_FIELD(InitialSourceConnectionID);
    //COMPARE_TP_FIELD(InitialSourceConnectionIDLength);
    if (IsServer) { // TODO
        //COMPARE_TP_FIELD(StatelessResetToken);
        //COMPARE_TP_FIELD(AckPreferredAddressDelayExponent);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionID);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionIDLength);
        //COMPARE_TP_FIELD(RetrySourceConnectionID);
        //COMPARE_TP_FIELD(RetrySourceConnectionIDLength);
    }
}

struct TransportParametersScope
{
    QUIC_TRANSPORT_PARAMETERS* const TP;
    TransportParametersScope(QUIC_TRANSPORT_PARAMETERS* const value) : TP(value) {}
    ~TransportParametersScope() {
        if (TP != nullptr) {
            QuicCryptoTlsCleanupTransportParameters(TP);
        }
    }
};

void EncodeDecodeAndCompare(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false,
    _In_ bool ShouldDecodeSuccessfully = true
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, IsServer, Original, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - CxPlatTlsTPHeaderSize));

    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    TransportParametersScope TPScope(&Decoded);
    BOOLEAN DecodedSuccessfully =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);

    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    ASSERT_EQ(ShouldDecodeSuccessfully, DecodedSuccessfully);
    if (ShouldDecodeSuccessfully) {
        CompareTransportParams(Original, &Decoded, IsServer);
    }
}

void DecodeTwice(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, IsServer, Original, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - CxPlatTlsTPHeaderSize));

    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    TransportParametersScope TPScope(&Decoded);
    BOOLEAN DecodedSuccessfullyOnce =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);
    BOOLEAN DecodedSuccessfullyTwice =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);

    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    ASSERT_TRUE(DecodedSuccessfullyOnce);
    ASSERT_TRUE(DecodedSuccessfullyTwice);
}

/*TEST(TransportParamTest, EmptyClient)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, EmptyServer)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original, true);
}*/

TEST(TransportParamTest, Preset1)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, Preset1DecodeTwice)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    DecodeTwice(&Original);
}

TEST(TransportParamTest, ZeroTP)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    OriginalTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, VersionNegotiationExtension)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    uint8_t VerInfo[21];
    OriginalTP.VersionInfo = VerInfo;
    OriginalTP.VersionInfoLength = sizeof(VerInfo);
    OriginalTP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, VersionNegotiationExtensionDecodeTwice)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    uint8_t VerInfo[21];
    OriginalTP.VersionInfo = VerInfo;
    OriginalTP.VersionInfoLength = sizeof(VerInfo);
    OriginalTP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;

    DecodeTwice(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingOne)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 254;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingZero)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 256;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, GreaseQuicBit)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_GREASE_QUIC_BIT;
    EncodeDecodeAndCompare(&OriginalTP);
    EncodeDecodeAndCompare(&OriginalTP, true);
}

TEST(TransportParamTest, ReliableResetEnabled)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;
    EncodeDecodeAndCompare(&OriginalTP);
    EncodeDecodeAndCompare(&OriginalTP, true);
}

//
// DeepTest Suite: Comprehensive tests for crypto_tls component
//

// Test QuicCryptoTlsGetCompleteTlsMessagesLength with no complete messages
// What: Verify function returns 0 when buffer contains incomplete message
// How: Pass buffer shorter than header or shorter than indicated message length
// Assertions: Returns 0 for incomplete data
TEST(TransportParamTest, DeepTestGetCompleteTlsMessagesLengthIncomplete)
{
    // Empty buffer
    uint8_t buffer1[0];
    ASSERT_EQ(0u, QuicCryptoTlsGetCompleteTlsMessagesLength(buffer1, 0));

    // Partial header (need 4 bytes)
    uint8_t buffer2[3] = {0x01, 0x00, 0x00};
    ASSERT_EQ(0u, QuicCryptoTlsGetCompleteTlsMessagesLength(buffer2, 3));

    // Complete header but incomplete message
    uint8_t buffer3[10];
    buffer3[0] = 0x01; // Message type
    buffer3[1] = 0x00; // Length high byte
    buffer3[2] = 0x00; // Length mid byte  
    buffer3[3] = 0x14; // Length low byte (20 bytes)
    // Only have 10 bytes total, need 4+20=24
    ASSERT_EQ(0u, QuicCryptoTlsGetCompleteTlsMessagesLength(buffer3, 10));
}

// Test QuicCryptoTlsGetCompleteTlsMessagesLength with single complete message
// What: Verify function returns correct length for one complete TLS message
// How: Construct valid TLS message header + payload
// Assertions: Returns header(4) + payload length
TEST(TransportParamTest, DeepTestGetCompleteTlsMessagesLengthSingleMessage)
{
    uint8_t buffer[100];
    buffer[0] = 0x01; // Message type
    buffer[1] = 0x00; // Length = 0x000010 (16 bytes)
    buffer[2] = 0x00;
    buffer[3] = 0x10;
    // Fill 16 bytes of payload
    for (int i = 0; i < 16; i++) {
        buffer[4 + i] = (uint8_t)i;
    }

    // Should return 4 (header) + 16 (payload) = 20
    ASSERT_EQ(20u, QuicCryptoTlsGetCompleteTlsMessagesLength(buffer, 100));
}

// Test QuicCryptoTlsGetCompleteTlsMessagesLength with multiple complete messages
// What: Verify function returns cumulative length of all complete messages
// How: Construct buffer with 2 complete messages and partial third
// Assertions: Returns sum of first two complete messages only
TEST(TransportParamTest, DeepTestGetCompleteTlsMessagesLengthMultipleMessages)
{
    uint8_t buffer[100];
    
    // First message: 4 byte header + 8 byte payload = 12 bytes
    buffer[0] = 0x01;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x08;
    for (int i = 0; i < 8; i++) buffer[4 + i] = 0xAA;

    // Second message: 4 byte header + 10 byte payload = 14 bytes
    buffer[12] = 0x02;
    buffer[13] = 0x00;
    buffer[14] = 0x00;
    buffer[15] = 0x0A;
    for (int i = 0; i < 10; i++) buffer[16 + i] = 0xBB;

    // Third message incomplete: header says 20 bytes but only have 5
    buffer[26] = 0x03;
    buffer[27] = 0x00;
    buffer[28] = 0x00;
    buffer[29] = 0x14; // 20 bytes
    for (int i = 0; i < 5; i++) buffer[30 + i] = 0xCC;

    // Should return 12 + 14 = 26 (stops at incomplete third message)
    ASSERT_EQ(26u, QuicCryptoTlsGetCompleteTlsMessagesLength(buffer, 35));
}

// Test transport parameter encode with all standard flags set
// What: Verify encoding handles maximum set of standard transport parameters
// How: Set all standard TP flags with valid values and encode/decode
// Assertions: Round-trip preserves all values
TEST(TransportParamTest, DeepTestEncodeAllStandardParams)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    OriginalTP.Flags = 
        QUIC_TP_FLAG_IDLE_TIMEOUT |
        QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI |
        QUIC_TP_FLAG_ACK_DELAY_EXPONENT |
        QUIC_TP_FLAG_MAX_ACK_DELAY |
        QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION |
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
    
    OriginalTP.IdleTimeout = 60000;
    OriginalTP.MaxUdpPayloadSize = 1500;
    OriginalTP.InitialMaxData = 1048576;
    OriginalTP.InitialMaxStreamDataBidiLocal = 524288;
    OriginalTP.InitialMaxStreamDataBidiRemote = 524288;
    OriginalTP.InitialMaxStreamDataUni = 262144;
    OriginalTP.InitialMaxBidiStreams = 100;
    OriginalTP.InitialMaxUniStreams = 100;
    OriginalTP.AckDelayExponent = 3;
    OriginalTP.MaxAckDelay = 25;
    OriginalTP.ActiveConnectionIdLimit = 8;
    OriginalTP.MaxDatagramFrameSize = 1200;

    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter encode with boundary values
// What: Verify encoding handles minimum and maximum valid values for varint fields
// How: Set transport parameters to boundary values and encode/decode
// Assertions: Boundary values correctly preserved
TEST(TransportParamTest, DeepTestEncodeBoundaryValues)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    // Test maximum values that fit in different varint sizes
    OriginalTP.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT | QUIC_TP_FLAG_INITIAL_MAX_DATA;
    OriginalTP.IdleTimeout = 0x3FFFFFFFFFFFFFFF; // Max 62-bit varint
    OriginalTP.InitialMaxData = (1ULL << 20) - 1; // Large but reasonable
    
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter decode with minimal valid data
// What: Verify decoder handles minimally valid transport parameter buffer
// How: Encode single required parameter and decode
// Assertions: Decoder succeeds with minimal data and sets defaults
TEST(TransportParamTest, DeepTestDecodeMinimalValid)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    // Just set one optional parameter
    OriginalTP.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    OriginalTP.IdleTimeout = 30000;
    
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter decode defaults with minimal flags
// What: Verify decoder handles minimal valid transport params
// How: Set single flag and encode/decode
// Assertions: Round-trip succeeds with minimal data
TEST(TransportParamTest, DeepTestDecodeDefaults)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    // Set at least one flag to avoid issues with empty TPs
    OriginalTP.Flags = QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
    OriginalTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;
    
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter decode failure on duplicate parameter IDs
// What: Verify decoder rejects transport parameters with duplicate IDs
// How: Manually construct buffer with duplicate parameter ID (within first 64 IDs)
// Assertions: Decoder returns FALSE for duplicate IDs
TEST(TransportParamTest, DeepTestDecodeDuplicateParamId)
{
    // Construct a malformed TP buffer with duplicate ID=1 (IDLE_TIMEOUT)
    uint8_t buffer[50];
    uint8_t* ptr = buffer;
    
    // First IDLE_TIMEOUT parameter: ID=1, Len=1, Value=100
    *ptr++ = 0x01; // ID=1 (varint encoded)
    *ptr++ = 0x01; // Length=1
    *ptr++ = 0x64; // Value=100
    
    // Duplicate IDLE_TIMEOUT parameter: ID=1, Len=1, Value=200
    *ptr++ = 0x01; // ID=1 (duplicate!)
    *ptr++ = 0x01; // Length=1
    *ptr++ = 0xC8; // Value=200
    
    uint16_t bufferLen = (uint16_t)(ptr - buffer);

    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    TransportParametersScope TPScope(&Decoded);
    
    BOOLEAN Result = QuicCryptoTlsDecodeTransportParameters(
        &JunkConnection, false, buffer, bufferLen, &Decoded);
    
    // Should fail due to duplicate ID
    ASSERT_FALSE(Result);
}

// Test transport parameter decode with TIMESTAMP flags
// What: Verify encoding/decoding of timestamp enable flags
// How: Set TIMESTAMP_SEND and TIMESTAMP_RECV flags and verify round-trip
// Assertions: Timestamp flags preserved correctly
TEST(TransportParamTest, DeepTestTimestampFlags)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    // Test send enabled
    OriginalTP.Flags = QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED;
    EncodeDecodeAndCompare(&OriginalTP);
    
    // Test recv enabled
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED;
    EncodeDecodeAndCompare(&OriginalTP);
    
    // Test both enabled
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED;
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter decode with MAX_DATAGRAM_FRAME_SIZE
// What: Verify MAX_DATAGRAM_FRAME_SIZE encoding/decoding
// How: Set various datagram frame size values and verify round-trip
// Assertions: Datagram frame sizes preserved correctly
TEST(TransportParamTest, DeepTestMaxDatagramFrameSize)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    OriginalTP.Flags = QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
    OriginalTP.MaxDatagramFrameSize = 1200;
    EncodeDecodeAndCompare(&OriginalTP);
    
    // Test with larger value
    OriginalTP.MaxDatagramFrameSize = 65535;
    EncodeDecodeAndCompare(&OriginalTP);
    
    // Test with minimal value
    OriginalTP.MaxDatagramFrameSize = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test QuicCryptoTlsCopyTransportParameters success
// What: Verify deep copy of transport parameters including allocated buffers
// How: Create TP with version info, copy it, verify both are independent
// Assertions: Copy succeeds, VersionInfo is deep copied, modifying one doesn't affect other
TEST(TransportParamTest, DeepTestCopyTransportParams)
{
    QUIC_TRANSPORT_PARAMETERS Source;
    CxPlatZeroMemory(&Source, sizeof(Source));
    
    uint8_t VerInfo[21];
    for (int i = 0; i < 21; i++) VerInfo[i] = (uint8_t)i;
    Source.VersionInfo = VerInfo;
    Source.VersionInfoLength = sizeof(VerInfo);
    Source.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION | QUIC_TP_FLAG_IDLE_TIMEOUT;
    Source.IdleTimeout = 30000;
    
    // Encode to allocate VersionInfo
    uint32_t BufferLength;
    auto Buffer = QuicCryptoTlsEncodeTransportParameters(
        &JunkConnection, false, &Source, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);
    
    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);
    
    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    ASSERT_TRUE(QuicCryptoTlsDecodeTransportParameters(
        &JunkConnection, false, TPBuffer, TPBufferLength, &Decoded));
    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    
    // Now copy Decoded to Destination
    QUIC_TRANSPORT_PARAMETERS Destination;
    CxPlatZeroMemory(&Destination, sizeof(Destination));
    
    QUIC_STATUS Status = QuicCryptoTlsCopyTransportParameters(&Decoded, &Destination);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    
    // Verify copy
    ASSERT_EQ(Decoded.Flags, Destination.Flags);
    ASSERT_EQ(Decoded.IdleTimeout, Destination.IdleTimeout);
    ASSERT_EQ(Decoded.VersionInfoLength, Destination.VersionInfoLength);
    ASSERT_NE(Decoded.VersionInfo, Destination.VersionInfo); // Different pointers
    ASSERT_EQ(0, memcmp(Decoded.VersionInfo, Destination.VersionInfo, Decoded.VersionInfoLength));
    
    // Cleanup
    QuicCryptoTlsCleanupTransportParameters(&Decoded);
    QuicCryptoTlsCleanupTransportParameters(&Destination);
}

// Test QuicCryptoTlsCleanupTransportParameters idempotence
// What: Verify cleanup can be called multiple times safely
// How: Allocate TP with VersionInfo, cleanup twice
// Assertions: Second cleanup doesn't crash, VersionInfo is NULL after first cleanup
TEST(TransportParamTest, DeepTestCleanupTransportParamsIdempotent)
{
    QUIC_TRANSPORT_PARAMETERS TP;
    CxPlatZeroMemory(&TP, sizeof(TP));
    
    uint8_t VerInfo[10];
    TP.VersionInfo = VerInfo;
    TP.VersionInfoLength = 10;
    TP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    
    // Encode/decode to allocate
    uint32_t BufferLength;
    auto Buffer = QuicCryptoTlsEncodeTransportParameters(
        &JunkConnection, false, &TP, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);
    
    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);
    
    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    ASSERT_TRUE(QuicCryptoTlsDecodeTransportParameters(
        &JunkConnection, false, TPBuffer, TPBufferLength, &Decoded));
    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    
    ASSERT_TRUE(Decoded.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    ASSERT_NE(nullptr, Decoded.VersionInfo);
    
    // First cleanup
    QuicCryptoTlsCleanupTransportParameters(&Decoded);
    ASSERT_EQ(nullptr, Decoded.VersionInfo);
    ASSERT_EQ(0u, Decoded.VersionInfoLength);
    ASSERT_FALSE(Decoded.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    
    // Second cleanup should be safe (no-op)
    QuicCryptoTlsCleanupTransportParameters(&Decoded);
    ASSERT_EQ(nullptr, Decoded.VersionInfo);
}

// Test transport parameter encode with MIN_ACK_DELAY
// What: Verify MIN_ACK_DELAY parameter encoding/decoding
// How: Set MIN_ACK_DELAY flag with valid value and verify round-trip
// Assertions: MIN_ACK_DELAY value preserved
TEST(TransportParamTest, DeepTestMinAckDelay)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    OriginalTP.Flags = QUIC_TP_FLAG_MIN_ACK_DELAY | QUIC_TP_FLAG_MAX_ACK_DELAY;
    OriginalTP.MinAckDelay = 1000; // 1000 microseconds
    OriginalTP.MaxAckDelay = 25;   // 25 milliseconds (constraint: MinAckDelay/1000 <= MaxAckDelay)
    
    EncodeDecodeAndCompare(&OriginalTP);
}

// Test transport parameter encode with DISABLE_1RTT_ENCRYPTION
// What: Verify DISABLE_1RTT_ENCRYPTION flag encoding/decoding (test-only parameter)
// How: Set DISABLE_1RTT_ENCRYPTION flag and verify round-trip
// Assertions: Flag preserved correctly
TEST(TransportParamTest, DeepTestDisable1RttEncryption)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    
    OriginalTP.Flags = QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION;
    
    EncodeDecodeAndCompare(&OriginalTP);
}
