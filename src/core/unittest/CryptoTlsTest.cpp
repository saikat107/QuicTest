/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC crypto TLS implementation.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CryptoTlsTest.cpp.clog.h"
#endif

//
// Shared mock connection for tests that need a QUIC_CONNECTION*.
//
static QUIC_CONNECTION MockConnection;

//
// RAII scope guard that cleans up transport parameter resources on destruction.
//
struct TPScope {
    QUIC_TRANSPORT_PARAMETERS* TP;
    TPScope(QUIC_TRANSPORT_PARAMETERS* tp) : TP(tp) {}
    ~TPScope() {
        if (TP) {
            QuicCryptoTlsCleanupTransportParameters(TP);
        }
    }
};

//
// Helper: Encodes transport parameters and returns the raw TP buffer (past
// the platform header). Caller must free the base buffer.
//
static const uint8_t*
EncodeTP(
    _In_ const QUIC_TRANSPORT_PARAMETERS* TP,
    _In_ BOOLEAN IsServer,
    _Out_ uint32_t* TotalLen,
    _Out_ uint16_t* TPPayloadLen,
    _Out_ const uint8_t** BasePtr
    )
{
    auto Base = QuicCryptoTlsEncodeTransportParameters(
        &MockConnection, IsServer, TP, NULL, TotalLen);
    if (Base == NULL) return NULL;
    *BasePtr = Base;
    *TPPayloadLen = (uint16_t)(*TotalLen - CxPlatTlsTPHeaderSize);
    return Base + CxPlatTlsTPHeaderSize;
}

// ============================================================================
// QuicCryptoTlsGetCompleteTlsMessagesLength Tests
// ============================================================================

//
// Scenario: Empty buffer yields zero complete messages length.
// How: Call with BufferLength 0.
// Assertions: Returns 0.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_EmptyBuffer)
{
    uint8_t buf[1] = {0};
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 0);
    ASSERT_EQ(result, 0u);
}

//
// Scenario: Buffer too short for a single TLS message header (< 4 bytes).
// How: Call with 3 bytes.
// Assertions: Returns 0.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_TooShortForHeader)
{
    uint8_t buf[3] = {0x01, 0x00, 0x00};
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 3);
    ASSERT_EQ(result, 0u);
}

//
// Scenario: A single complete TLS message of length 5 (header=4 + payload=1).
// How: Construct a buffer with type=0x01, length=0x000001, and 1 byte payload.
// Assertions: Returns 5.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_SingleCompleteMessage)
{
    uint8_t buf[5] = {0x01, 0x00, 0x00, 0x01, 0xAA};
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 5);
    ASSERT_EQ(result, 5u);
}

//
// Scenario: One complete message followed by an incomplete second message.
// How: First message (4+2=6 bytes), then 3 bytes of an incomplete second.
// Assertions: Returns 6 (only the first complete message).
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_OneCompleteOneIncomplete)
{
    uint8_t buf[9] = {
        0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB,  // Complete: 4+2=6
        0x01, 0x00, 0x00                       // Incomplete header data
    };
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 9);
    ASSERT_EQ(result, 6u);
}

//
// Scenario: Two complete messages back-to-back.
// How: Two messages of 4+1=5 bytes each, total 10 bytes.
// Assertions: Returns 10.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_TwoCompleteMessages)
{
    uint8_t buf[10] = {
        0x01, 0x00, 0x00, 0x01, 0xAA,         // msg1: 5 bytes
        0x02, 0x00, 0x00, 0x01, 0xBB           // msg2: 5 bytes
    };
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 10);
    ASSERT_EQ(result, 10u);
}

//
// Scenario: A message with header but claimed length exceeds buffer.
// How: Header claims 100 bytes payload but buffer has only 8.
// Assertions: Returns 0.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_LengthExceedsBuffer)
{
    uint8_t buf[8] = {0x01, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00};
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 8);
    ASSERT_EQ(result, 0u);
}

//
// Scenario: Zero-length payload message (header only, 4 bytes).
// How: Header claims 0 bytes of payload.
// Assertions: Returns 4.
//
TEST(DeepTest_CryptoTls, GetCompleteTlsMessagesLength_ZeroLengthPayload)
{
    uint8_t buf[4] = {0x01, 0x00, 0x00, 0x00};
    uint32_t result = QuicCryptoTlsGetCompleteTlsMessagesLength(buf, 4);
    ASSERT_EQ(result, 4u);
}

// ============================================================================
// QuicCryptoTlsEncodeTransportParameters Tests
// ============================================================================

//
// Scenario: Encode transport parameters with no flags set (minimal encoding).
// How: Zero-initialize TP, call encode.
// Assertions: Returns non-null buffer with non-zero length.
//
TEST(DeepTest_CryptoTls, EncodeTP_NoFlags)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    uint32_t tpLen = 0;
    auto buf = QuicCryptoTlsEncodeTransportParameters(
        &MockConnection, FALSE, &tp, NULL, &tpLen);
    ASSERT_NE(buf, nullptr);
    ASSERT_GT(tpLen, 0u);
    ASSERT_EQ(tpLen, (uint32_t)CxPlatTlsTPHeaderSize);
    CXPLAT_FREE(buf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode with a private test transport parameter.
// How: Set up a QUIC_PRIVATE_TRANSPORT_PARAMETER with known data and encode.
// Assertions: Returns non-null, length includes test param overhead.
//
TEST(DeepTest_CryptoTls, EncodeTP_WithTestParam)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));

    uint8_t testData[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    QUIC_PRIVATE_TRANSPORT_PARAMETER testParam;
    testParam.Type = 0xFF00;
    testParam.Length = sizeof(testData);
    testParam.Buffer = testData;

    uint32_t tpLen = 0;
    auto buf = QuicCryptoTlsEncodeTransportParameters(
        &MockConnection, FALSE, &tp, &testParam, &tpLen);
    ASSERT_NE(buf, nullptr);
    ASSERT_GT(tpLen, (uint32_t)CxPlatTlsTPHeaderSize);
    CXPLAT_FREE(buf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode server-only transport parameters (OriginalDestCID, StatelessResetToken).
// How: Set server-only flags and encode with IsServerTP=TRUE.
// Assertions: Returns non-null, roundtrip decode succeeds with matching values.
//
TEST(DeepTest_CryptoTls, EncodeTP_ServerOnlyParams)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags =
        QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID |
        QUIC_TP_FLAG_STATELESS_RESET_TOKEN |
        QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
    tp.OriginalDestinationConnectionIDLength = 8;
    memset(tp.OriginalDestinationConnectionID, 0xAB, 8);
    memset(tp.StatelessResetToken, 0xCD, QUIC_STATELESS_RESET_TOKEN_LENGTH);
    tp.RetrySourceConnectionIDLength = 4;
    memset(tp.RetrySourceConnectionID, 0xEF, 4);

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, TRUE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);
    ASSERT_GT(payloadLen, (uint16_t)0);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, TRUE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID);
    ASSERT_EQ(decoded.OriginalDestinationConnectionIDLength, (uint8_t)8);
    ASSERT_EQ(memcmp(decoded.OriginalDestinationConnectionID, tp.OriginalDestinationConnectionID, 8), 0);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN);
    ASSERT_EQ(memcmp(decoded.StatelessResetToken, tp.StatelessResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH), 0);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID);
    ASSERT_EQ(decoded.RetrySourceConnectionIDLength, (uint8_t)4);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

// ============================================================================
// QuicCryptoTlsDecodeTransportParameters Tests
// ============================================================================

//
// Scenario: Decode an empty TP buffer (zero length) succeeds with defaults.
// How: Call decode with empty buffer.
// Assertions: Returns TRUE, defaults are set (MaxUdpPayloadSize, etc.).
//
TEST(DeepTest_CryptoTls, DecodeTP_EmptyBuffer)
{
    uint8_t buf[1] = {0};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, 0, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.MaxUdpPayloadSize, (uint64_t)QUIC_TP_MAX_PACKET_SIZE_DEFAULT);
    ASSERT_EQ(decoded.AckDelayExponent, (uint64_t)QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT);
    ASSERT_EQ(decoded.MaxAckDelay, (uint64_t)QUIC_TP_MAX_ACK_DELAY_DEFAULT);
    ASSERT_EQ(decoded.ActiveConnectionIdLimit, (uint64_t)QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT);
}

//
// Scenario: Decode fails when TP buffer is truncated mid-ID.
// How: Provide a single byte (insufficient for var-int ID).
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_TruncatedId)
{
    uint8_t buf[1] = {0x80};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, 1, &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode fails when param length extends past buffer end.
// How: Encode a param with length that goes past the buffer.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_LengthOverflow)
{
    // ID=1 (idle timeout), Length=0x10 but only 2 bytes follow
    uint8_t buf[] = {0x01, 0x10, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode fails on duplicate transport parameter IDs.
// How: Encode idle_timeout twice in the buffer.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_DuplicateId)
{
    // Two idle_timeout (ID=1) params
    uint8_t buf[] = {
        0x01, 0x01, 0x0A,    // ID=1, len=1, value=10
        0x01, 0x01, 0x14     // ID=1, len=1, value=20
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode succeeds for a comprehensive set of all client TP flags.
// How: Encode all client-valid flags, decode, and verify roundtrip.
// Assertions: All flags present with correct values after decode.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_AllClientFlags)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags =
        QUIC_TP_FLAG_IDLE_TIMEOUT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI |
        QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
        QUIC_TP_FLAG_ACK_DELAY_EXPONENT |
        QUIC_TP_FLAG_MAX_ACK_DELAY |
        QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION |
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID |
        QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE |
        QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION |
        QUIC_TP_FLAG_GREASE_QUIC_BIT |
        QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;

    tp.IdleTimeout = 30000;
    tp.InitialMaxData = 1048576;
    tp.InitialMaxStreamDataBidiLocal = 65536;
    tp.InitialMaxStreamDataBidiRemote = 65536;
    tp.InitialMaxStreamDataUni = 65536;
    tp.InitialMaxBidiStreams = 100;
    tp.InitialMaxUniStreams = 100;
    tp.MaxUdpPayloadSize = 1500;
    tp.AckDelayExponent = 10;
    tp.MaxAckDelay = 100;
    tp.ActiveConnectionIdLimit = 4;
    tp.InitialSourceConnectionIDLength = 8;
    memset(tp.InitialSourceConnectionID, 0x42, 8);
    tp.MaxDatagramFrameSize = 1200;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);

    ASSERT_EQ(decoded.IdleTimeout, tp.IdleTimeout);
    ASSERT_EQ(decoded.InitialMaxData, tp.InitialMaxData);
    ASSERT_EQ(decoded.InitialMaxStreamDataBidiLocal, tp.InitialMaxStreamDataBidiLocal);
    ASSERT_EQ(decoded.InitialMaxStreamDataBidiRemote, tp.InitialMaxStreamDataBidiRemote);
    ASSERT_EQ(decoded.InitialMaxStreamDataUni, tp.InitialMaxStreamDataUni);
    ASSERT_EQ(decoded.InitialMaxBidiStreams, tp.InitialMaxBidiStreams);
    ASSERT_EQ(decoded.InitialMaxUniStreams, tp.InitialMaxUniStreams);
    ASSERT_EQ(decoded.MaxUdpPayloadSize, tp.MaxUdpPayloadSize);
    ASSERT_EQ(decoded.AckDelayExponent, tp.AckDelayExponent);
    ASSERT_EQ(decoded.MaxAckDelay, tp.MaxAckDelay);
    ASSERT_EQ(decoded.ActiveConnectionIdLimit, tp.ActiveConnectionIdLimit);
    ASSERT_EQ(decoded.InitialSourceConnectionIDLength, tp.InitialSourceConnectionIDLength);
    ASSERT_EQ(memcmp(decoded.InitialSourceConnectionID, tp.InitialSourceConnectionID, 8), 0);
    ASSERT_EQ(decoded.MaxDatagramFrameSize, tp.MaxDatagramFrameSize);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects server-only params sent by a client (OriginalDestCID).
// How: Encode OriginalDestCID as server, then decode as client (IsServerTP=FALSE).
// Assertions: Decode returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_ServerOnlyParamFromClient)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID;
    tp.OriginalDestinationConnectionIDLength = 8;
    memset(tp.OriginalDestinationConnectionID, 0xAA, 8);

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, TRUE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects stateless_reset_token from a client.
// How: Encode StatelessResetToken as server, decode as client.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_StatelessResetTokenFromClient)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
    memset(tp.StatelessResetToken, 0xCD, QUIC_STATELESS_RESET_TOKEN_LENGTH);

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, TRUE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects retry_source_connection_id from a client.
// How: Encode RetrySourceCID as server, decode as client.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_RetrySourceCIDFromClient)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
    tp.RetrySourceConnectionIDLength = 4;
    memset(tp.RetrySourceConnectionID, 0xEF, 4);

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, TRUE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects MaxUdpPayloadSize below the minimum (1200).
// How: Hand-craft a TP buffer with MaxUdpPayloadSize = 1000.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxUdpPayloadSizeTooSmall)
{
    // ID=3 (max_udp_payload_size), Length=2, Value=1000 (varint: 0x43, 0xE8)
    uint8_t buf[] = {0x03, 0x02, 0x43, 0xE8};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects AckDelayExponent above max (20).
// How: Hand-craft a TP buffer with AckDelayExponent = 21.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_AckDelayExponentTooLarge)
{
    // ID=10 (ack_delay_exponent), Length=1, Value=21
    uint8_t buf[] = {0x0A, 0x01, 0x15};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects MaxAckDelay above max (2^14 - 1 = 16383).
// How: Hand-craft a TP buffer with MaxAckDelay = 16384.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxAckDelayTooLarge)
{
    // ID=11 (max_ack_delay), Length=2, Value=16384 (varint: 0x80, 0x00, 0x40, 0x00 - but 2-byte is 0x40|0x00 0x00)
    // 16384 = 0x4000, varint encoding: 0x80 0x00 0x40 0x00 (4-byte varint)
    // Actually varint 16384: needs 4-byte form: 0x80004000
    uint8_t buf[] = {0x0B, 0x04, 0x80, 0x00, 0x40, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects disable_active_migration with non-zero length.
// How: Hand-craft a TP buffer with disable_active_migration length=1.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_DisableActiveMigrationNonZeroLength)
{
    // ID=12 (disable_active_migration), Length=1, payload=0x00
    uint8_t buf[] = {0x0C, 0x01, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects active_connection_id_limit below minimum (2).
// How: Hand-craft a TP with active_connection_id_limit = 1.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_ActiveCIDLimitBelowMin)
{
    // ID=14 (active_connection_id_limit), Length=1, Value=1
    uint8_t buf[] = {0x0E, 0x01, 0x01};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode correctly handles unknown/reserved TP IDs by ignoring them.
// How: Hand-craft a buffer with a reserved ID (27) plus idle_timeout.
// Assertions: Returns TRUE, idle_timeout is set.
//
TEST(DeepTest_CryptoTls, DecodeTP_UnknownAndReservedIds)
{
    // Reserved ID=27 (31*0+27), Length=2, payload=0x00,0x00
    // Then ID=1 (idle_timeout), Length=1, Value=10
    uint8_t buf[] = {
        0x1B, 0x02, 0x00, 0x00,   // ID=27 (reserved), len=2
        0x01, 0x01, 0x0A           // ID=1 (idle_timeout), len=1, value=10
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);
    ASSERT_EQ(decoded.IdleTimeout, 10u);
}

//
// Scenario: Decode handles preferred_address from server TP without error.
// How: Hand-craft a server TP with preferred_address ID.
// Assertions: Returns TRUE (preferred address is currently a TODO/ignored).
//
TEST(DeepTest_CryptoTls, DecodeTP_PreferredAddressServer)
{
    // ID=13 (preferred_address), Length=2, payload=0x00,0x00
    uint8_t buf[] = {0x0D, 0x02, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, TRUE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
}

//
// Scenario: Decode rejects preferred_address from a client.
// How: Hand-craft preferred_address TP, decode with IsServerTP=FALSE.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_PreferredAddressClient)
{
    uint8_t buf[] = {0x0D, 0x02, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Encode/decode roundtrip with timestamp flags.
// How: Set TIMESTAMP_SEND_ENABLED and TIMESTAMP_RECV_ENABLED, encode, decode.
// Assertions: Timestamp flags preserved through roundtrip.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_TimestampFlags)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode/decode with only TIMESTAMP_SEND_ENABLED.
// How: Set only the send flag, encode, decode.
// Assertions: Send flag preserved, recv flag not set.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_TimestampSendOnly)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_FALSE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode/decode with MinAckDelay.
// How: Set MinAckDelay and MaxAckDelay such that MinAckDelay <= MaxAckDelay*1000.
// Assertions: Roundtrip preserves MinAckDelay value.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_MinAckDelay)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_MIN_ACK_DELAY | QUIC_TP_FLAG_MAX_ACK_DELAY;
    tp.MinAckDelay = 1000;   // 1000 microseconds
    tp.MaxAckDelay = 25;     // 25 milliseconds, so MinAckDelay(1000us) <= MaxAckDelay(25ms=25000us)

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_MIN_ACK_DELAY);
    ASSERT_EQ(decoded.MinAckDelay, 1000u);
    ASSERT_EQ(decoded.MaxAckDelay, 25u);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects MinAckDelay > MaxAckDelay (in us).
// How: Hand-craft raw bytes with min_ack_delay=2000us and max_ack_delay=1ms.
// Assertions: Returns FALSE (min_ack_delay 2000us > max_ack_delay 1ms = 1000us).
//
TEST(DeepTest_CryptoTls, DecodeTP_MinAckDelayExceedsMax)
{
    // max_ack_delay ID=11, len=1, val=1 (1ms)
    // min_ack_delay ID=0xFF04DE1B, 8-byte varint: 0xC0,0x00,0xFF,0x04,0xDE,0x1B,0x00,0x00
    // Wait, 0xFF04DE1B as a varint. The value is 0xFF04DE1B = 4278460955.
    // 8-byte varint: 0xC0 | (val >> 56), ..., but val fits in 32 bits
    // Actually: 8-byte varint for value 0xFF04DE1B:
    //   byte0 = 0xC0 | ((0xFF04DE1B >> 56) & 0x3F) = 0xC0 | 0 = 0xC0
    //   remaining 7 bytes encode 0x00_00_00_FF_04_DE_1B
    uint8_t buf[] = {
        // max_ack_delay: ID=11(0x0B), len=1, val=1
        0x0B, 0x01, 0x01,
        // min_ack_delay: ID=0xFF04DE1B (8-byte varint)
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0x04, 0xDE, 0x1B,
        // len=2, val=2000 (varint: 0x47,0xD0)
        0x02, 0x47, 0xD0
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects disable_1rtt_encryption with non-zero length.
// How: Hand-craft TP with disable_1rtt_encryption length=1.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_Disable1RttEncryptionNonZeroLength)
{
    // ID=0xBAAD (disable_1rtt_encryption), 2-byte varint: 0x40|0xBA, 0xAD => but wait
    // 0xBAAD > 0x3FFF so needs 4-byte varint: 0x80, 0x00, 0xBA, 0xAD
    uint8_t buf[] = {0x80, 0x00, 0xBA, 0xAD, 0x01, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects grease_quic_bit with non-zero length.
// How: Hand-craft TP.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_GreaseQuicBitNonZeroLength)
{
    // ID=0x2AB2 (grease_quic_bit), 2-byte varint: 0x6A, 0xB2
    uint8_t buf[] = {0x6A, 0xB2, 0x01, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects reliable_reset_enabled with non-zero length.
// How: Hand-craft TP.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_ReliableResetNonZeroLength)
{
    // ID=0x17f7586d2cb570, 8-byte varint: 0xC0, 0x17, 0xF7, 0x58, 0x6D, 0x2C, 0xB5, 0x70
    uint8_t buf[] = {0xC0, 0x17, 0xF7, 0x58, 0x6D, 0x2C, 0xB5, 0x70, 0x01, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects timestamp value > 3.
// How: Hand-craft enable_timestamp TP (ID=0x7158) with value=4.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_TimestampValueTooLarge)
{
    // ID=0x7158 = 29016, needs 4-byte varint: 0x80, 0x00, 0x71, 0x58
    // Length=1, Value=4
    uint8_t buf[] = {0x80, 0x00, 0x71, 0x58, 0x01, 0x04};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode handles version_negotiation extension with zero-length data.
// How: Hand-craft TP with version_negotiation ID and empty payload.
// Assertions: Returns TRUE with VERSION_NEGOTIATION flag set, VersionInfo NULL.
//
TEST(DeepTest_CryptoTls, DecodeTP_VersionNegotiationEmpty)
{
    // ID=0x11 (version_negotiation_ext), Length=0
    uint8_t buf[] = {0x11, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    ASSERT_EQ(decoded.VersionInfo, nullptr);
    ASSERT_EQ(decoded.VersionInfoLength, (uint16_t)0);
}

//
// Scenario: Encode/decode roundtrip with version negotiation info.
// How: Set VERSION_NEGOTIATION flag with VersionInfo data.
// Assertions: Roundtrip preserves data, cleanup frees it.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_VersionNegotiation)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    uint8_t verInfo[] = {0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x1D};
    tp.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    tp.VersionInfo = verInfo;
    tp.VersionInfoLength = sizeof(verInfo);

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    ASSERT_EQ(decoded.VersionInfoLength, (uint16_t)sizeof(verInfo));
    ASSERT_NE(decoded.VersionInfo, nullptr);
    ASSERT_EQ(memcmp(decoded.VersionInfo, verInfo, sizeof(verInfo)), 0);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects OriginalDestCID exceeding max CID length (20).
// How: Hand-craft TP with ODCID length = 21.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_OriginalDestCIDTooLong)
{
    // ID=0 (orig_dest_cid), Length=21 (exceeds QUIC_MAX_CONNECTION_ID_LENGTH_V1=20)
    uint8_t buf[23];
    buf[0] = 0x00; // ID=0
    buf[1] = 0x15; // Length=21
    memset(buf + 2, 0xAA, 21);
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, TRUE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects InitialSourceCID exceeding max CID length.
// How: Hand-craft TP with initial_source_cid length = 21.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialSourceCIDTooLong)
{
    // ID=15 (0x0F), Length=21
    uint8_t buf[23];
    buf[0] = 0x0F; // ID=15
    buf[1] = 0x15; // Length=21
    memset(buf + 2, 0xBB, 21);
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode rejects StatelessResetToken with wrong length (!= 16).
// How: Hand-craft TP with token length = 8.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_StatelessResetTokenWrongLength)
{
    // ID=2, Length=8 (should be 16)
    uint8_t buf[10];
    buf[0] = 0x02; // ID=2
    buf[1] = 0x08; // Length=8
    memset(buf + 2, 0xCC, 8);
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, TRUE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode InitialMaxBidiStreams at max valid value.
// How: Encode with InitialMaxBidiStreams = QUIC_TP_MAX_STREAMS_MAX.
// Assertions: Roundtrip succeeds with exact value.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_MaxBidiStreamsAtMax)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
    tp.InitialMaxBidiStreams = QUIC_TP_MAX_STREAMS_MAX;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.InitialMaxBidiStreams, (uint64_t)QUIC_TP_MAX_STREAMS_MAX);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects MinAckDelay exceeding QUIC_TP_MIN_ACK_DELAY_MAX.
// How: Hand-craft raw bytes with min_ack_delay = QUIC_TP_MIN_ACK_DELAY_MAX + 1.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MinAckDelayExceedsAbsoluteMax)
{
    // min_ack_delay ID=0xFF04DE1B (8-byte varint)
    // Value = (1 << 24) = 16777216 as varint (4-byte: 0x81, 0x00, 0x00, 0x00)
    uint8_t buf[] = {
        // min_ack_delay: ID=0xFF04DE1B (8-byte varint)
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0x04, 0xDE, 0x1B,
        // len=4, val=16777216 (0x01000000 as 4-byte varint: 0x81,0x00,0x00,0x00)
        0x04, 0x81, 0x00, 0x00, 0x00
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

// ============================================================================
// QuicCryptoTlsCopyTransportParameters Tests
// ============================================================================

//
// Scenario: Copy transport parameters without VERSION_NEGOTIATION (shallow copy).
// How: Set up TP with basic flags, copy, verify equality.
// Assertions: All fields match after copy.
//
TEST(DeepTest_CryptoTls, CopyTP_BasicNoVersionInfo)
{
    QUIC_TRANSPORT_PARAMETERS src;
    CxPlatZeroMemory(&src, sizeof(src));
    src.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT | QUIC_TP_FLAG_INITIAL_MAX_DATA;
    src.IdleTimeout = 60000;
    src.InitialMaxData = 1048576;

    QUIC_TRANSPORT_PARAMETERS dst;
    CxPlatZeroMemory(&dst, sizeof(dst));
    TPScope scope(&dst);

    QUIC_STATUS status = QuicCryptoTlsCopyTransportParameters(&src, &dst);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_EQ(dst.Flags, src.Flags);
    ASSERT_EQ(dst.IdleTimeout, src.IdleTimeout);
    ASSERT_EQ(dst.InitialMaxData, src.InitialMaxData);
}

//
// Scenario: Copy transport parameters with VERSION_NEGOTIATION (deep copy of VersionInfo).
// How: Set VERSION_NEGOTIATION with VersionInfo data, copy, modify source, verify independence.
// Assertions: Destination has its own copy of VersionInfo.
//
TEST(DeepTest_CryptoTls, CopyTP_WithVersionInfo)
{
    QUIC_TRANSPORT_PARAMETERS src;
    CxPlatZeroMemory(&src, sizeof(src));
    uint8_t verInfo[] = {0x01, 0x02, 0x03, 0x04};
    src.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    src.VersionInfo = (const uint8_t*)CXPLAT_ALLOC_NONPAGED(sizeof(verInfo), QUIC_POOL_VERSION_INFO);
    ASSERT_NE(src.VersionInfo, nullptr);
    CxPlatCopyMemory((uint8_t*)src.VersionInfo, verInfo, sizeof(verInfo));
    src.VersionInfoLength = sizeof(verInfo);
    TPScope srcScope(&src);

    QUIC_TRANSPORT_PARAMETERS dst;
    CxPlatZeroMemory(&dst, sizeof(dst));
    TPScope dstScope(&dst);

    QUIC_STATUS status = QuicCryptoTlsCopyTransportParameters(&src, &dst);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_TRUE(dst.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    ASSERT_NE(dst.VersionInfo, nullptr);
    ASSERT_NE(dst.VersionInfo, src.VersionInfo);
    ASSERT_EQ(dst.VersionInfoLength, src.VersionInfoLength);
    ASSERT_EQ(memcmp(dst.VersionInfo, verInfo, sizeof(verInfo)), 0);
}

// ============================================================================
// QuicCryptoTlsCleanupTransportParameters Tests
// ============================================================================

//
// Scenario: Cleanup with VERSION_NEGOTIATION flag frees VersionInfo and clears flag.
// How: Allocate VersionInfo, set flag, call cleanup.
// Assertions: VersionInfo is NULL, length is 0, flag is cleared.
//
TEST(DeepTest_CryptoTls, CleanupTP_FreesVersionInfo)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION | QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    tp.VersionInfo = (const uint8_t*)CXPLAT_ALLOC_NONPAGED(8, QUIC_POOL_VERSION_INFO);
    ASSERT_NE(tp.VersionInfo, nullptr);
    tp.VersionInfoLength = 8;

    QuicCryptoTlsCleanupTransportParameters(&tp);
    ASSERT_EQ(tp.VersionInfo, nullptr);
    ASSERT_EQ(tp.VersionInfoLength, (uint16_t)0);
    ASSERT_FALSE(tp.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
    ASSERT_TRUE(tp.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);
}

//
// Scenario: Cleanup without VERSION_NEGOTIATION flag is a no-op.
// How: Set TP without version info, call cleanup.
// Assertions: Flags unchanged.
//
TEST(DeepTest_CryptoTls, CleanupTP_NoVersionInfoNoop)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 5000;

    QuicCryptoTlsCleanupTransportParameters(&tp);
    ASSERT_TRUE(tp.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);
    ASSERT_EQ(tp.IdleTimeout, 5000u);
}

// ============================================================================
// QuicCryptoTlsReadInitial Tests
// ============================================================================

//
// Scenario: ReadInitial returns PENDING when buffer is too short for TLS header.
// How: Call with 3 bytes (less than TLS_MESSAGE_HEADER_LENGTH=4).
// Assertions: Returns QUIC_STATUS_PENDING.
//
TEST(DeepTest_CryptoTls, ReadInitial_BufferTooShort)
{
    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    uint8_t buf[3] = {0x01, 0x00, 0x00};
    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, 3, &info);
    ASSERT_EQ(status, QUIC_STATUS_PENDING);
}

//
// Scenario: ReadInitial returns INVALID_PARAMETER for non-ClientHello message type.
// How: Provide a buffer with type byte != 0x01 (e.g., 0x02 ServerHello).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_NotClientHello)
{
    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    uint8_t buf[8] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, 8, &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial returns PENDING when message length exceeds buffer.
// How: Header says 1000 bytes but buffer has only 10.
// Assertions: Returns QUIC_STATUS_PENDING.
//
TEST(DeepTest_CryptoTls, ReadInitial_MessageLengthExceedsBuffer)
{
    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    // Type=0x01 (ClientHello), Length=0x0003E8 (1000)
    uint8_t buf[10] = {0x01, 0x00, 0x03, 0xE8, 0, 0, 0, 0, 0, 0};
    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, 10, &info);
    ASSERT_EQ(status, QUIC_STATUS_PENDING);
}

//
// Scenario: ReadInitial rejects ClientHello with protocol version too low.
// How: Provide ClientHello with version < TLS1_PROTOCOL_VERSION (0x0301).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_VersionTooLow)
{
    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    // ClientHello: type=0x01, length=2, version=0x0200 (too low)
    uint8_t buf[] = {0x01, 0x00, 0x00, 0x02, 0x02, 0x00};
    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, sizeof(buf), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial rejects ClientHello too short for Random field.
// How: Provide version but not enough bytes for 32-byte random.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_TooShortForRandom)
{
    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    // type=0x01, length=4, version=0x0303, then only 2 bytes (need 32)
    uint8_t buf[] = {0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00};
    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, sizeof(buf), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

// ============================================================================
// QuicCryptoTlsReadClientRandom Tests
// ============================================================================

//
// Scenario: ReadClientRandom extracts 32 bytes of random from a valid ClientHello.
// How: Build a buffer with known random bytes at the correct offset.
// Assertions: TlsSecrets.ClientRandom matches, IsSet.ClientRandom = TRUE.
//
TEST(DeepTest_CryptoTls, ReadClientRandom_ValidBuffer)
{
    // Buffer: [type(1)] [length(3)] [version(2)] [random(32)]
    // Total minimum: 4 + 2 + 32 = 38 bytes
    uint8_t buf[38];
    CxPlatZeroMemory(buf, sizeof(buf));
    buf[0] = 0x01; // ClientHello
    buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x22; // length=34
    buf[4] = 0x03; buf[5] = 0x03; // TLS 1.2
    // Fill random with known pattern
    for (int i = 0; i < 32; i++) {
        buf[6 + i] = (uint8_t)(i + 1);
    }

    QUIC_TLS_SECRETS secrets;
    CxPlatZeroMemory(&secrets, sizeof(secrets));

    QUIC_STATUS status = QuicCryptoTlsReadClientRandom(buf, sizeof(buf), &secrets);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_TRUE(secrets.IsSet.ClientRandom);
    for (int i = 0; i < 32; i++) {
        ASSERT_EQ(secrets.ClientRandom[i], (uint8_t)(i + 1));
    }
}

// ============================================================================
// QuicCryptoTlsEncodeTransportParameters - CIBIR encoding roundtrip
// ============================================================================

//
// Scenario: Encode/decode CIBIR encoding with valid values.
// How: Set CibirLength=4, CibirOffset=2, roundtrip.
// Assertions: Values preserved through encode/decode.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_CibirEncoding)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    tp.CibirLength = 4;
    tp.CibirOffset = 2;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_CIBIR_ENCODING);
    ASSERT_EQ(decoded.CibirLength, 4u);
    ASSERT_EQ(decoded.CibirOffset, 2u);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects CIBIR encoding where length+offset exceeds max CID.
// How: Set CibirLength=255, CibirOffset=1 (sum > 255 max CID invariant).
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_CibirEncodingOverflow)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    tp.CibirLength = 255;
    tp.CibirOffset = 1;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode rejects CIBIR encoding where CibirLength=0.
// How: Set CibirLength=0, encode, try to decode.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_CibirEncodingZeroLength)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    tp.CibirLength = 0;
    tp.CibirOffset = 0;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode with truncated var-int length field.
// How: Build buffer where ID is present but length var-int is truncated.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_TruncatedLength)
{
    // ID=1 (idle_timeout), then buffer ends (no length field)
    uint8_t buf[] = {0x01};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Encode with NULL Connection (valid per contract).
// How: Pass NULL for Connection parameter.
// Assertions: Returns non-null buffer.
//
TEST(DeepTest_CryptoTls, EncodeTP_NullConnection)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 30000;

    uint32_t tpLen = 0;
    auto buf = QuicCryptoTlsEncodeTransportParameters(
        NULL, FALSE, &tp, NULL, &tpLen);
    ASSERT_NE(buf, nullptr);
    ASSERT_GT(tpLen, (uint32_t)CxPlatTlsTPHeaderSize);
    CXPLAT_FREE(buf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode with NULL Connection (valid per contract).
// How: Pass NULL for Connection parameter.
// Assertions: Decode succeeds.
//
TEST(DeepTest_CryptoTls, DecodeTP_NullConnection)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 5000;

    uint32_t totalLen = 0;
    auto buf = QuicCryptoTlsEncodeTransportParameters(
        NULL, FALSE, &tp, NULL, &totalLen);
    ASSERT_NE(buf, nullptr);

    auto payload = buf + CxPlatTlsTPHeaderSize;
    uint16_t payloadLen = (uint16_t)(totalLen - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        NULL, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.IdleTimeout, 5000u);

    CXPLAT_FREE(buf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode re-initializes TP by freeing old VersionInfo before decoding.
// How: Pre-set VersionInfo, decode new data, verify old is freed cleanly.
// Assertions: Decode succeeds, no memory leak.
//
TEST(DeepTest_CryptoTls, DecodeTP_ReinitializesVersionInfo)
{
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    decoded.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    decoded.VersionInfo = (const uint8_t*)CXPLAT_ALLOC_NONPAGED(4, QUIC_POOL_VERSION_INFO);
    ASSERT_NE(decoded.VersionInfo, nullptr);
    decoded.VersionInfoLength = 4;
    TPScope scope(&decoded);

    // Decode empty TP - should free old VersionInfo
    uint8_t buf[1] = {0};
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        NULL, FALSE, buf, 0, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.MaxUdpPayloadSize, (uint64_t)QUIC_TP_MAX_PACKET_SIZE_DEFAULT);
}

//
// Scenario: Encode/decode with MaxUdpPayloadSize at boundary values.
// How: Test with minimum (1200) and maximum (65527) values.
// Assertions: Roundtrip preserves exact values.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_MaxUdpPayloadSizeBoundaries)
{
    // Test minimum valid value
    {
        QUIC_TRANSPORT_PARAMETERS tp;
        CxPlatZeroMemory(&tp, sizeof(tp));
        tp.Flags = QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE;
        tp.MaxUdpPayloadSize = QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN;

        uint32_t totalLen = 0;
        uint16_t payloadLen = 0;
        const uint8_t* basePtr = nullptr;
        auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
        ASSERT_NE(payload, nullptr);

        QUIC_TRANSPORT_PARAMETERS decoded;
        CxPlatZeroMemory(&decoded, sizeof(decoded));
        TPScope scope(&decoded);
        BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
            NULL, FALSE, payload, payloadLen, &decoded);
        ASSERT_TRUE(result);
        ASSERT_EQ(decoded.MaxUdpPayloadSize, (uint64_t)QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN);
        CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
    }

    // Test maximum valid value
    {
        QUIC_TRANSPORT_PARAMETERS tp;
        CxPlatZeroMemory(&tp, sizeof(tp));
        tp.Flags = QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE;
        tp.MaxUdpPayloadSize = QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX;

        uint32_t totalLen = 0;
        uint16_t payloadLen = 0;
        const uint8_t* basePtr = nullptr;
        auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
        ASSERT_NE(payload, nullptr);

        QUIC_TRANSPORT_PARAMETERS decoded;
        CxPlatZeroMemory(&decoded, sizeof(decoded));
        TPScope scope(&decoded);
        BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
            NULL, FALSE, payload, payloadLen, &decoded);
        ASSERT_TRUE(result);
        ASSERT_EQ(decoded.MaxUdpPayloadSize, (uint64_t)QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX);
        CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
    }
}

//
// Scenario: Encode/decode with AckDelayExponent at max valid value (20).
// How: Set AckDelayExponent = 20, roundtrip.
// Assertions: Value preserved.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_AckDelayExponentAtMax)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
    tp.AckDelayExponent = QUIC_TP_ACK_DELAY_EXPONENT_MAX;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        NULL, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.AckDelayExponent, (uint64_t)QUIC_TP_ACK_DELAY_EXPONENT_MAX);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode/decode with ActiveConnectionIdLimit at min (2).
// How: Set ActiveConnectionIdLimit = 2, roundtrip.
// Assertions: Value preserved.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_ActiveCIDLimitAtMin)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
    tp.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        NULL, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.ActiveConnectionIdLimit, (uint64_t)QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode/decode with MaxAckDelay at max valid value.
// How: Set MaxAckDelay = QUIC_TP_MAX_ACK_DELAY_MAX, roundtrip.
// Assertions: Value preserved.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_MaxAckDelayAtMax)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_MAX_ACK_DELAY;
    tp.MaxAckDelay = QUIC_TP_MAX_ACK_DELAY_MAX;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        NULL, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.MaxAckDelay, (uint64_t)QUIC_TP_MAX_ACK_DELAY_MAX);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

// ============================================================================
// ClientHello Parsing Tests (ReadInitial -> ReadClientHello -> ReadExtensions)
// ============================================================================

//
// Helper: Builds a minimal valid ClientHello with SNI, ALPN, and QUIC TP extensions.
// The TP extension is encoded from the provided TP parameters.
// Returns a complete TLS record ready for QuicCryptoTlsReadInitial.
//
static void
BuildClientHello(
    _In_opt_ const char* ServerName,
    _In_opt_ const uint8_t* AlpnList,
    _In_ uint16_t AlpnListLen,
    _In_opt_ const uint8_t* TpBuf,
    _In_ uint16_t TpLen,
    _In_ uint16_t TpExtType,
    _Out_ std::vector<uint8_t>& Output
    )
{
    std::vector<uint8_t> chBody;

    // Version: TLS 1.2 (0x0303)
    chBody.push_back(0x03); chBody.push_back(0x03);

    // Random: 32 bytes of zeros
    for (int i = 0; i < 32; i++) chBody.push_back((uint8_t)(i+1));

    // SessionID: length=0
    chBody.push_back(0x00);

    // CipherSuites: length=2, one cipher suite
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01); // TLS_AES_128_GCM_SHA256

    // CompressionMethods: length=1, null compression
    chBody.push_back(0x01); chBody.push_back(0x00);

    // Build extensions
    std::vector<uint8_t> exts;

    // SNI extension (type=0x0000)
    if (ServerName != NULL) {
        uint16_t nameLen = (uint16_t)strlen(ServerName);
        uint16_t listLen = nameLen + 3; // NameType(1) + NameLen(2) + name
        uint16_t extLen = listLen + 2;  // list length field(2) + list

        exts.push_back(0x00); exts.push_back(0x00); // type=SNI
        exts.push_back((uint8_t)(extLen >> 8)); exts.push_back((uint8_t)extLen);
        exts.push_back((uint8_t)(listLen >> 8)); exts.push_back((uint8_t)listLen);
        exts.push_back(0x00); // NameType = host_name
        exts.push_back((uint8_t)(nameLen >> 8)); exts.push_back((uint8_t)nameLen);
        for (uint16_t i = 0; i < nameLen; i++) exts.push_back((uint8_t)ServerName[i]);
    }

    // ALPN extension (type=0x0010)
    if (AlpnList != NULL && AlpnListLen > 0) {
        uint16_t extLen = AlpnListLen + 2; // list length field + data
        exts.push_back(0x00); exts.push_back(0x10); // type=ALPN
        exts.push_back((uint8_t)(extLen >> 8)); exts.push_back((uint8_t)extLen);
        exts.push_back((uint8_t)(AlpnListLen >> 8)); exts.push_back((uint8_t)AlpnListLen);
        for (uint16_t i = 0; i < AlpnListLen; i++) exts.push_back(AlpnList[i]);
    }

    // QUIC Transport Parameters extension
    if (TpBuf != NULL && TpLen > 0) {
        exts.push_back((uint8_t)(TpExtType >> 8)); exts.push_back((uint8_t)TpExtType);
        exts.push_back((uint8_t)(TpLen >> 8)); exts.push_back((uint8_t)TpLen);
        for (uint16_t i = 0; i < TpLen; i++) exts.push_back(TpBuf[i]);
    }

    // Extensions list length
    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8));
    chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    // TLS record header: type=0x01 (ClientHello), length=24-bit
    uint32_t bodyLen = (uint32_t)chBody.size();
    Output.clear();
    Output.push_back(0x01); // ClientHello type
    Output.push_back((uint8_t)(bodyLen >> 16));
    Output.push_back((uint8_t)(bodyLen >> 8));
    Output.push_back((uint8_t)bodyLen);
    Output.insert(Output.end(), chBody.begin(), chBody.end());
}

//
// Scenario: ReadInitial successfully parses a well-formed ClientHello with
// SNI and ALPN extensions and QUIC Transport Parameters.
// How: Build a complete ClientHello with "example.com" SNI, "h3" ALPN, and
//      encoded transport parameters, then call ReadInitial.
// Assertions: Status is SUCCESS, Info has correct SNI, ALPN.
//
TEST(DeepTest_CryptoTls, ReadInitial_ValidClientHelloWithSniAndAlpn)
{
    // Encode transport parameters for QUIC TP extension
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 30000;

    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    // ALPN: "h3" = length(1) + "h3"(2)
    uint8_t alpn[] = {0x02, 'h', '3'};

    std::vector<uint8_t> ch;
    BuildClientHello("example.com", alpn, sizeof(alpn),
                     tpPayload, tpPayloadLen,
                     0x0039, // TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS
                     ch);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1; // Not draft 29

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, ch.data(), (uint32_t)ch.size(), &info);
    TEST_QUIC_SUCCEEDED(status);

    // Verify SNI
    ASSERT_NE(info.ServerName, nullptr);
    ASSERT_EQ(info.ServerNameLength, (uint16_t)11);
    ASSERT_EQ(memcmp(info.ServerName, "example.com", 11), 0);

    // Verify ALPN
    ASSERT_NE(info.ClientAlpnList, nullptr);
    ASSERT_EQ(info.ClientAlpnListLength, (uint16_t)sizeof(alpn));

    // Verify TP decoded into connection
    ASSERT_TRUE(conn.PeerTransportParams.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);
    ASSERT_EQ(conn.PeerTransportParams.IdleTimeout, 30000u);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ReadInitial succeeds with ALPN but no SNI (SNI is optional).
// How: Build ClientHello without SNI extension, only ALPN and TP.
// Assertions: Status is SUCCESS, ServerName is NULL.
//
TEST(DeepTest_CryptoTls, ReadInitial_NoSniPresent)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 5000;

    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    std::vector<uint8_t> ch;
    BuildClientHello(NULL, alpn, sizeof(alpn),
                     tpPayload, tpPayloadLen, 0x0039, ch);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, ch.data(), (uint32_t)ch.size(), &info);
    TEST_QUIC_SUCCEEDED(status);

    ASSERT_EQ(info.ServerName, nullptr);
    ASSERT_NE(info.ClientAlpnList, nullptr);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ReadInitial fails when ALPN extension is missing.
// How: Build ClientHello with only SNI and TP but no ALPN.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER (no ALPN list).
//
TEST(DeepTest_CryptoTls, ReadInitial_MissingAlpn)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 5000;

    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    std::vector<uint8_t> ch;
    BuildClientHello("example.com", NULL, 0,
                     tpPayload, tpPayloadLen, 0x0039, ch);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, ch.data(), (uint32_t)ch.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ReadInitial fails when QUIC TP extension is missing.
// How: Build ClientHello with SNI and ALPN but no transport parameters.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER (no QUIC TP).
//
TEST(DeepTest_CryptoTls, ReadInitial_MissingTransportParameters)
{
    uint8_t alpn[] = {0x02, 'h', '3'};
    std::vector<uint8_t> ch;
    BuildClientHello("example.com", alpn, sizeof(alpn), NULL, 0, 0, ch);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, ch.data(), (uint32_t)ch.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial succeeds with Draft-29 transport parameters extension type.
// How: Build ClientHello using TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT.
// Assertions: Status is SUCCESS with transport parameters decoded.
//
TEST(DeepTest_CryptoTls, ReadInitial_Draft29TransportParameters)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 10000;

    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    std::vector<uint8_t> ch;
    // Use draft TP extension type (0xffa5)
    BuildClientHello("test.com", alpn, sizeof(alpn),
                     tpPayload, tpPayloadLen, 0xffa5, ch);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_DRAFT_29;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, ch.data(), (uint32_t)ch.size(), &info);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_TRUE(conn.PeerTransportParams.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);
    ASSERT_EQ(conn.PeerTransportParams.IdleTimeout, 10000u);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ReadInitial rejects duplicate SNI extension.
// How: Build a ClientHello with two SNI extensions manually.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_DuplicateSniExtension)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    // Build ClientHello body manually with duplicate SNI
    std::vector<uint8_t> chBody;

    // Version
    chBody.push_back(0x03); chBody.push_back(0x03);
    // Random
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    // SessionID
    chBody.push_back(0x00);
    // CipherSuites
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    // CompressionMethods
    chBody.push_back(0x01); chBody.push_back(0x00);

    // Extensions
    std::vector<uint8_t> exts;

    // SNI #1: "a.com"
    const char* name1 = "a.com";
    uint16_t nlen = 5;
    uint16_t llen = nlen + 3;
    uint16_t elen = llen + 2;
    exts.push_back(0x00); exts.push_back(0x00);
    exts.push_back((uint8_t)(elen >> 8)); exts.push_back((uint8_t)elen);
    exts.push_back((uint8_t)(llen >> 8)); exts.push_back((uint8_t)llen);
    exts.push_back(0x00);
    exts.push_back((uint8_t)(nlen >> 8)); exts.push_back((uint8_t)nlen);
    for (int i = 0; i < 5; i++) exts.push_back((uint8_t)name1[i]);

    // SNI #2: "b.com" (duplicate!)
    exts.push_back(0x00); exts.push_back(0x00);
    exts.push_back((uint8_t)(elen >> 8)); exts.push_back((uint8_t)elen);
    exts.push_back((uint8_t)(llen >> 8)); exts.push_back((uint8_t)llen);
    exts.push_back(0x00);
    exts.push_back((uint8_t)(nlen >> 8)); exts.push_back((uint8_t)nlen);
    const char* name2 = "b.com";
    for (int i = 0; i < 5; i++) exts.push_back((uint8_t)name2[i]);

    // ALPN
    uint16_t alpnExtLen = sizeof(alpn) + 2;
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(alpnExtLen >> 8)); exts.push_back((uint8_t)alpnExtLen);
    exts.push_back((uint8_t)(sizeof(alpn) >> 8)); exts.push_back((uint8_t)sizeof(alpn));
    for (size_t i = 0; i < sizeof(alpn); i++) exts.push_back(alpn[i]);

    // QUIC TP
    exts.push_back(0x00); exts.push_back(0x39);
    exts.push_back((uint8_t)(tpPayloadLen >> 8)); exts.push_back((uint8_t)tpPayloadLen);
    for (uint16_t i = 0; i < tpPayloadLen; i++) exts.push_back(tpPayload[i]);

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8)); chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    // TLS record header
    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial rejects duplicate ALPN extension.
// How: Build a ClientHello with two ALPN extensions.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_DuplicateAlpnExtension)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00);
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00);

    std::vector<uint8_t> exts;

    // ALPN #1
    uint16_t alpnExtLen = sizeof(alpn) + 2;
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(alpnExtLen >> 8)); exts.push_back((uint8_t)alpnExtLen);
    exts.push_back((uint8_t)(sizeof(alpn) >> 8)); exts.push_back((uint8_t)sizeof(alpn));
    for (size_t i = 0; i < sizeof(alpn); i++) exts.push_back(alpn[i]);

    // ALPN #2 (duplicate!)
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(alpnExtLen >> 8)); exts.push_back((uint8_t)alpnExtLen);
    exts.push_back((uint8_t)(sizeof(alpn) >> 8)); exts.push_back((uint8_t)sizeof(alpn));
    for (size_t i = 0; i < sizeof(alpn); i++) exts.push_back(alpn[i]);

    // QUIC TP
    exts.push_back(0x00); exts.push_back(0x39);
    exts.push_back((uint8_t)(tpPayloadLen >> 8)); exts.push_back((uint8_t)tpPayloadLen);
    for (uint16_t i = 0; i < tpPayloadLen; i++) exts.push_back(tpPayload[i]);

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8)); chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial rejects duplicate QUIC TP extension.
// How: Build a ClientHello with two QUIC TP extensions.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_DuplicateTransportParametersExtension)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00);
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00);

    std::vector<uint8_t> exts;

    // SNI
    const char* name = "a.com";
    uint16_t nlen = 5, llen = nlen + 3, elen = llen + 2;
    exts.push_back(0x00); exts.push_back(0x00);
    exts.push_back((uint8_t)(elen >> 8)); exts.push_back((uint8_t)elen);
    exts.push_back((uint8_t)(llen >> 8)); exts.push_back((uint8_t)llen);
    exts.push_back(0x00);
    exts.push_back((uint8_t)(nlen >> 8)); exts.push_back((uint8_t)nlen);
    for (int i = 0; i < 5; i++) exts.push_back((uint8_t)name[i]);

    // ALPN
    uint16_t alpnExtLen = sizeof(alpn) + 2;
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(alpnExtLen >> 8)); exts.push_back((uint8_t)alpnExtLen);
    exts.push_back((uint8_t)(sizeof(alpn) >> 8)); exts.push_back((uint8_t)sizeof(alpn));
    for (size_t i = 0; i < sizeof(alpn); i++) exts.push_back(alpn[i]);

    // QUIC TP #1
    exts.push_back(0x00); exts.push_back(0x39);
    exts.push_back((uint8_t)(tpPayloadLen >> 8)); exts.push_back((uint8_t)tpPayloadLen);
    for (uint16_t i = 0; i < tpPayloadLen; i++) exts.push_back(tpPayload[i]);

    // QUIC TP #2 (duplicate!)
    exts.push_back(0x00); exts.push_back(0x39);
    exts.push_back((uint8_t)(tpPayloadLen >> 8)); exts.push_back((uint8_t)tpPayloadLen);
    for (uint16_t i = 0; i < tpPayloadLen; i++) exts.push_back(tpPayload[i]);

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8)); chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial with ClientHello that has SessionID of max length (32).
// How: Build ClientHello with 32-byte session ID.
// Assertions: Parsing succeeds, extensions are read correctly.
//
TEST(DeepTest_CryptoTls, ReadInitial_WithSessionId)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;

    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    // Build ClientHello body with 32-byte session ID
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03); // Version
    for (int i = 0; i < 32; i++) chBody.push_back(0xAA); // Random
    chBody.push_back(32); // SessionID length = 32
    for (int i = 0; i < 32; i++) chBody.push_back(0xBB); // SessionID
    chBody.push_back(0x00); chBody.push_back(0x02); // CipherSuites len
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00); // CompressionMethods

    // Extensions
    std::vector<uint8_t> exts;
    // ALPN
    uint16_t alpnExtLen = sizeof(alpn) + 2;
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(alpnExtLen >> 8)); exts.push_back((uint8_t)alpnExtLen);
    exts.push_back((uint8_t)(sizeof(alpn) >> 8)); exts.push_back((uint8_t)sizeof(alpn));
    for (size_t i = 0; i < sizeof(alpn); i++) exts.push_back(alpn[i]);
    // QUIC TP
    exts.push_back(0x00); exts.push_back(0x39);
    exts.push_back((uint8_t)(tpPayloadLen >> 8)); exts.push_back((uint8_t)tpPayloadLen);
    for (uint16_t i = 0; i < tpPayloadLen; i++) exts.push_back(tpPayload[i]);

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8)); chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;

    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_NE(info.ClientAlpnList, nullptr);
    ASSERT_TRUE(conn.PeerTransportParams.Flags & QUIC_TP_FLAG_IDLE_TIMEOUT);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ReadInitial rejects ClientHello with SessionID > 32 bytes.
// How: Build ClientHello with SessionID length = 33.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SessionIdTooLong)
{
    // Build a minimal buffer: version(2) + random(32) + sessionID_len(1) = 35 bytes
    // Then sessionID_len = 33 which exceeds TLS_SESSION_ID_LENGTH
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(33); // SessionID length > 32
    for (int i = 0; i < 33; i++) chBody.push_back(0);

    // Wrap in TLS header
    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial rejects ClientHello with odd cipher suite length.
// How: Build ClientHello with CipherSuite length = 3 (odd = invalid).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_OddCipherSuiteLength)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x03); // CipherSuites len=3 (odd!)
    chBody.push_back(0x13); chBody.push_back(0x01); chBody.push_back(0x00);

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial rejects ClientHello with CompressionMethod length=0.
// How: Build ClientHello with CompressionMethods length = 0.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER (min length is 1).
//
TEST(DeepTest_CryptoTls, ReadInitial_CompressionMethodLengthZero)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x02); // CipherSuites len=2
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x00); // CompressionMethods len=0 (invalid!)

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial succeeds with no extensions (valid ClientHello).
// How: Build ClientHello with version, random, session, cipher, compression but
//      no extensions at all (BufferLength < sizeof(uint16_t) after compression).
// Assertions: Returns SUCCESS (no extensions is OK, but will fail ALPN check).
//     Actually, the code returns SUCCESS from ReadClientHello when no extensions,
//     but ReadInitial then checks for ALPN and fails.
//
TEST(DeepTest_CryptoTls, ReadInitial_NoExtensions)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x02); // CipherSuites
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00); // CompressionMethods

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    // No ALPN means it fails
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial rejects ClientHello with extension list length mismatch.
// How: Build ClientHello where extension list length exceeds buffer.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_ExtensionListLengthMismatch)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00);
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00);
    // Extensions list length = 1000 but only 2 bytes follow
    chBody.push_back(0x03); chBody.push_back(0xE8); // len=1000
    chBody.push_back(0x00); chBody.push_back(0x00);

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: Decode TP with MaxUdpPayloadSize exceeding max (> 65527).
// How: Hand-craft TP with MaxUdpPayloadSize = 65528.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxUdpPayloadSizeExceedsMax)
{
    // ID=3 (max_udp_payload_size), Length=4, Value=65528
    // 65528 as 4-byte varint: 0x80, 0x00, 0xFF, 0xF8
    uint8_t buf[] = {0x03, 0x04, 0x80, 0x00, 0xFF, 0xF8};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxBidiStreams exceeding max.
// How: Hand-craft TP with bidi streams = QUIC_TP_MAX_STREAMS_MAX + 1.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxBidiStreamsExceedsMax)
{
    // ID=8 (initial_max_streams_bidi), Length=8
    // Value = (1<<60) = 0x1000000000000000 as 8-byte varint
    // 8-byte varint: 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    uint8_t buf[] = {0x08, 0x08, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxUniStreams exceeding max.
// How: Hand-craft TP with uni streams exceeding limit.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxUniStreamsExceedsMax)
{
    // ID=9 (initial_max_streams_uni), Length=8
    // Value = (1<<60) = 0x1000000000000000
    uint8_t buf[] = {0x09, 0x08, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with RetrySourceCID exceeding max length from server.
// How: Hand-craft TP with RetrySourceCID length = 21.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_RetrySourceCIDTooLong)
{
    // ID=16 (0x10), Length=21
    uint8_t buf[23];
    buf[0] = 0x10; // ID=16
    buf[1] = 0x15; // Length=21
    memset(buf + 2, 0xDD, 21);
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, TRUE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

// ============================================================================
// TRY_READ_VAR_INT failure tests: Each TP type with truncated varint payload
// ============================================================================

//
// Scenario: Decode TP with IdleTimeout having zero-length payload (truncated varint).
// How: Hand-craft TP ID=1 (IdleTimeout) with Length=0, no data.
// Assertions: Returns FALSE because QuicVarIntDecode fails on empty payload.
//
TEST(DeepTest_CryptoTls, DecodeTP_IdleTimeoutTruncatedVarint)
{
    uint8_t buf[] = {0x01, 0x00}; // ID=1, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with MaxUdpPayloadSize having zero-length payload.
// How: Hand-craft TP ID=3 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxUdpPayloadSizeTruncatedVarint)
{
    uint8_t buf[] = {0x03, 0x00}; // ID=3, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxData having zero-length payload.
// How: Hand-craft TP ID=4 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxDataTruncatedVarint)
{
    uint8_t buf[] = {0x04, 0x00}; // ID=4, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxStreamDataBidiLocal having zero-length payload.
// How: Hand-craft TP ID=5 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxStreamDataBidiLocalTruncated)
{
    uint8_t buf[] = {0x05, 0x00}; // ID=5, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxStreamDataBidiRemote having zero-length payload.
// How: Hand-craft TP ID=6 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxStreamDataBidiRemoteTruncated)
{
    uint8_t buf[] = {0x06, 0x00}; // ID=6, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxStreamDataUni having zero-length payload.
// How: Hand-craft TP ID=7 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxStreamDataUniTruncated)
{
    uint8_t buf[] = {0x07, 0x00}; // ID=7, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxStreamsBidi having zero-length payload.
// How: Hand-craft TP ID=8 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxStreamsBidiTruncatedVarint)
{
    uint8_t buf[] = {0x08, 0x00}; // ID=8, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with InitialMaxStreamsUni having zero-length payload.
// How: Hand-craft TP ID=9 with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_InitialMaxStreamsUniTruncatedVarint)
{
    uint8_t buf[] = {0x09, 0x00}; // ID=9, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with AckDelayExponent having zero-length payload.
// How: Hand-craft TP ID=10 (0x0a) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_AckDelayExponentTruncatedVarint)
{
    uint8_t buf[] = {0x0a, 0x00}; // ID=10, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with MaxAckDelay having zero-length payload.
// How: Hand-craft TP ID=11 (0x0b) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxAckDelayTruncatedVarint)
{
    uint8_t buf[] = {0x0b, 0x00}; // ID=11, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with ActiveConnectionIdLimit having zero-length payload.
// How: Hand-craft TP ID=14 (0x0e) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_ActiveCIDLimitTruncatedVarint)
{
    uint8_t buf[] = {0x0e, 0x00}; // ID=14, Length=0
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with MaxDatagramFrameSize having zero-length payload.
// How: Hand-craft TP ID=32 (0x20, needs 2-byte varint: 0x40,0x20) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxDatagramFrameSizeTruncatedVarint)
{
    // ID=32 as 2-byte varint: 0x40, 0x20. Length=0.
    uint8_t buf[] = {0x40, 0x20, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with MinAckDelay having zero-length payload.
// How: Hand-craft TP ID=0xFF04DE1B (8-byte varint) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_MinAckDelayTruncatedVarint)
{
    // ID=0xFF04DE1B as 8-byte varint: 0xC0,0x00,0x00,0x00,0xFF,0x04,0xDE,0x1B
    // Length=0
    uint8_t buf[] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0x04, 0xDE, 0x1B, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with Timestamp having zero-length payload.
// How: Hand-craft TP ID=0x7158 (4-byte varint) with Length=0.
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_TimestampTruncatedVarint)
{
    // ID=0x7158 as 4-byte varint: 0x80,0x00,0x71,0x58. Length=0.
    uint8_t buf[] = {0x80, 0x00, 0x71, 0x58, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_FALSE(result);
}

//
// Scenario: Decode TP with unknown non-reserved ID triggers "Unknown ID" path.
// How: Hand-craft TP with ID=0xFE (254). 254 % 31 = 6, not reserved.
//      Length=2, arbitrary data.
// Assertions: Returns TRUE (unknown TPs are ignored), no flags set.
//
TEST(DeepTest_CryptoTls, DecodeTP_UnknownNonReservedId)
{
    // ID=0xFE (254) as 2-byte varint: 0x40, 0xFE. Length=2, data=0x00,0x00.
    uint8_t buf[] = {0x40, 0xFE, 0x02, 0x00, 0x00};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.Flags, (uint32_t)0);
}

// ============================================================================
// ClientHello SNI extension error path tests
// ============================================================================

//
// Helper: Build a ClientHello with a raw SNI extension payload (bypassing
// BuildClientHello's well-formed construction).
//
static void
BuildClientHelloWithRawSniExt(
    _In_ const uint8_t* SniPayload,
    _In_ uint16_t SniPayloadLen,
    _In_ const uint8_t* AlpnList,
    _In_ uint16_t AlpnListLen,
    _In_ const uint8_t* TpBuf,
    _In_ uint16_t TpLen,
    _Out_ std::vector<uint8_t>& Output
    )
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03); // Version
    for (int i = 0; i < 32; i++) chBody.push_back((uint8_t)(i+1)); // Random
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x02); // CipherSuites len=2
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00); // CompressionMethods

    std::vector<uint8_t> exts;

    // SNI extension with raw payload
    exts.push_back(0x00); exts.push_back(0x00); // type=SNI
    exts.push_back((uint8_t)(SniPayloadLen >> 8));
    exts.push_back((uint8_t)SniPayloadLen);
    for (uint16_t i = 0; i < SniPayloadLen; i++) exts.push_back(SniPayload[i]);

    // ALPN extension
    if (AlpnList && AlpnListLen > 0) {
        uint16_t extLen = AlpnListLen + 2;
        exts.push_back(0x00); exts.push_back(0x10);
        exts.push_back((uint8_t)(extLen >> 8));
        exts.push_back((uint8_t)extLen);
        exts.push_back((uint8_t)(AlpnListLen >> 8));
        exts.push_back((uint8_t)AlpnListLen);
        for (uint16_t i = 0; i < AlpnListLen; i++) exts.push_back(AlpnList[i]);
    }

    // TP extension
    if (TpBuf && TpLen > 0) {
        exts.push_back(0x00); exts.push_back(0x39); // type=0x0039
        exts.push_back((uint8_t)(TpLen >> 8));
        exts.push_back((uint8_t)TpLen);
        for (uint16_t i = 0; i < TpLen; i++) exts.push_back(TpBuf[i]);
    }

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8));
    chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    uint32_t bodyLen = (uint32_t)chBody.size();
    Output.clear();
    Output.push_back(0x01);
    Output.push_back((uint8_t)(bodyLen >> 16));
    Output.push_back((uint8_t)(bodyLen >> 8));
    Output.push_back((uint8_t)bodyLen);
    Output.insert(Output.end(), chBody.begin(), chBody.end());
}

//
// Scenario: ReadInitial fails when SNI extension has less than 2 bytes.
// How: Build ClientHello with SNI extension payload of 1 byte (needs >=2 for
//      server name list length). Triggers ReadTlsSni #1.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniTooShortForListLength)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};
    uint8_t sniPayload[] = {0xFF}; // Only 1 byte, need >=2

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial fails when SNI list length < 3.
// How: Build ClientHello with SNI extension payload where the server name list
//      length is 2 (needs >=3 for NameType+HostNameLen). Triggers ReadTlsSni #2.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniListLengthTooSmall)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};
    // SNI: list_length=2 (too small, need >=3), then 2 bytes of data
    uint8_t sniPayload[] = {0x00, 0x02, 0x00, 0x00};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial fails when SNI entry truncated before name length field.
// How: Build ClientHello with SNI extension that has valid list length but
//      only a NameType byte with no room for the 2-byte name length.
//      Triggers ReadTlsSni #3.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniTruncatedBeforeNameLength)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};
    // SNI: list_length=3, NameType=0, but only 1 byte left for name length (needs 2)
    // ExtLen = 4 total. After list_length(2): BufferLength=2.
    // Read NameType(1) => BufferLength=1, < 2 => error #3
    uint8_t sniPayload[] = {0x00, 0x03, 0x00, 0x00};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial fails when SNI name length exceeds remaining buffer.
// How: Build ClientHello with SNI extension where NameLen claims more bytes
//      than available. Triggers ReadTlsSni #4.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniNameLengthExceedsBuffer)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};
    // SNI: list_length=5, NameType=0, NameLen=10 (but only 1 byte follows)
    // ExtLen=6, after list_length(2): BufferLength=4
    // Read NameType(1): BufferLength=3
    // Read NameLen(2): NameLen=10, BufferLength=1, 1 < 10 => error #4
    uint8_t sniPayload[] = {0x00, 0x05, 0x00, 0x00, 0x0A, 0x41};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

// ============================================================================
// ClientHello ALPN extension error path tests
// ============================================================================

//
// Helper: Build a ClientHello with raw ALPN extension payload.
//
static void
BuildClientHelloWithRawAlpnExt(
    _In_ const char* ServerName,
    _In_ const uint8_t* AlpnPayload,
    _In_ uint16_t AlpnPayloadLen,
    _In_ const uint8_t* TpBuf,
    _In_ uint16_t TpLen,
    _Out_ std::vector<uint8_t>& Output
    )
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back((uint8_t)(i+1));
    chBody.push_back(0x00);
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00);

    std::vector<uint8_t> exts;

    // SNI
    if (ServerName) {
        uint16_t nameLen = (uint16_t)strlen(ServerName);
        uint16_t listLen = nameLen + 3;
        uint16_t extLen = listLen + 2;
        exts.push_back(0x00); exts.push_back(0x00);
        exts.push_back((uint8_t)(extLen >> 8)); exts.push_back((uint8_t)extLen);
        exts.push_back((uint8_t)(listLen >> 8)); exts.push_back((uint8_t)listLen);
        exts.push_back(0x00);
        exts.push_back((uint8_t)(nameLen >> 8)); exts.push_back((uint8_t)nameLen);
        for (uint16_t i = 0; i < nameLen; i++) exts.push_back((uint8_t)ServerName[i]);
    }

    // ALPN with raw payload
    exts.push_back(0x00); exts.push_back(0x10);
    exts.push_back((uint8_t)(AlpnPayloadLen >> 8));
    exts.push_back((uint8_t)AlpnPayloadLen);
    for (uint16_t i = 0; i < AlpnPayloadLen; i++) exts.push_back(AlpnPayload[i]);

    // TP
    if (TpBuf && TpLen > 0) {
        exts.push_back(0x00); exts.push_back(0x39);
        exts.push_back((uint8_t)(TpLen >> 8));
        exts.push_back((uint8_t)TpLen);
        for (uint16_t i = 0; i < TpLen; i++) exts.push_back(TpBuf[i]);
    }

    uint16_t extsLen = (uint16_t)exts.size();
    chBody.push_back((uint8_t)(extsLen >> 8));
    chBody.push_back((uint8_t)extsLen);
    chBody.insert(chBody.end(), exts.begin(), exts.end());

    uint32_t bodyLen = (uint32_t)chBody.size();
    Output.clear();
    Output.push_back(0x01);
    Output.push_back((uint8_t)(bodyLen >> 16));
    Output.push_back((uint8_t)(bodyLen >> 8));
    Output.push_back((uint8_t)bodyLen);
    Output.insert(Output.end(), chBody.begin(), chBody.end());
}

//
// Scenario: ReadInitial fails when ALPN extension is too short (<4 bytes).
// How: Build ClientHello with ALPN extension payload of only 3 bytes
//      (needs >=4: 2 for list length + 1 for protocol ID length + 1 for
//      protocol ID byte minimum). Triggers ReadTlsAlpn #1.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_AlpnTooShort)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    // ALPN payload: only 3 bytes (needs uint16 + uint8 + uint8 = 4 minimum)
    uint8_t alpnPayload[] = {0x00, 0x01, 0x02};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawAlpnExt(
        "example.com",
        alpnPayload, sizeof(alpnPayload),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial fails when ALPN list length doesn't match extension size.
// How: Build ClientHello with ALPN extension where the list length field
//      disagrees with the actual extension length. Triggers ReadTlsAlpn #2.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_AlpnLengthMismatch)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    // ALPN: list_length says 10 but actual payload after it is only 3 bytes
    // Total ext payload = 5 bytes, list_length = 0x000A = 10, but only 3 bytes left
    // BufferLength(5) != TlsReadUint16(buf)(10) + 2 => error #2
    uint8_t alpnPayload[] = {0x00, 0x0A, 0x02, 'h', '3'};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawAlpnExt(
        "example.com",
        alpnPayload, sizeof(alpnPayload),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial fails when ALPN entry's protocol ID length exceeds
//      remaining buffer. Triggers ReadTlsAlpn #3.
// How: Build ClientHello with ALPN where individual protocol ID length is
//      larger than the remaining bytes.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_AlpnProtocolLengthExceedsBuffer)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    // ALPN: list_length=3, then protocol ID length=10 but only 2 bytes follow
    // BufferLength = 5, list_length = 3, 5 == 3+2 so #2 passes.
    // After reading list_length: BufferLength=3
    // Protocol ID: Len=10, BufferLength=2, but BufferLength < Len => error #3
    uint8_t alpnPayload[] = {0x00, 0x03, 0x0A, 'h', '3'};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawAlpnExt(
        "example.com",
        alpnPayload, sizeof(alpnPayload),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

// ============================================================================
// Extension parsing error path tests
// ============================================================================

//
// Helper: Build a ClientHello with raw extension bytes (fully manual).
//
static void
BuildClientHelloWithRawExtensions(
    _In_ const uint8_t* ExtPayload,
    _In_ uint16_t ExtPayloadLen,
    _Out_ std::vector<uint8_t>& Output
    )
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back((uint8_t)(i+1));
    chBody.push_back(0x00);
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x01); chBody.push_back(0x00);

    // Extensions list length = ExtPayloadLen
    chBody.push_back((uint8_t)(ExtPayloadLen >> 8));
    chBody.push_back((uint8_t)ExtPayloadLen);
    for (uint16_t i = 0; i < ExtPayloadLen; i++) chBody.push_back(ExtPayload[i]);

    uint32_t bodyLen = (uint32_t)chBody.size();
    Output.clear();
    Output.push_back(0x01);
    Output.push_back((uint8_t)(bodyLen >> 16));
    Output.push_back((uint8_t)(bodyLen >> 8));
    Output.push_back((uint8_t)bodyLen);
    Output.insert(Output.end(), chBody.begin(), chBody.end());
}

//
// Scenario: ReadInitial fails when extension area has fewer than 4 bytes.
// How: Build ClientHello with extension payload of only 3 bytes (need at
//      least 4 for ext type(2) + ext length(2)). Triggers ReadTlsExt #1.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_ExtensionTooShortForHeader)
{
    // Only 3 bytes of extension data
    uint8_t extPayload[] = {0x00, 0x00, 0x00};
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload, sizeof(extPayload), record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails when extension's ExtLen exceeds remaining buffer.
// How: Build ClientHello with an extension header claiming 100 bytes but only
//      2 bytes of data follow. Triggers ReadTlsExt #2.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_ExtensionLengthExceedsBuffer)
{
    // Type=0xFF00 (unknown), Length=100, but only 2 bytes follow
    uint8_t extPayload[] = {0xFF, 0x00, 0x00, 0x64, 0xAA, 0xBB};
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload, sizeof(extPayload), record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails when SNI extension parsing fails and the error
//      propagates through ReadTlsExtensions (line 394).
// How: Build ClientHello with a malformed SNI extension that causes
//      QuicCryptoTlsReadSniExtension to return an error, which ReadTlsExtensions
//      propagates back. Uses empty SNI payload (0 bytes).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniParseFailurePropagation)
{
    // SNI extension with 0 bytes payload - too short to read list length
    uint8_t extPayload[] = {
        0x00, 0x00,  // type = SNI
        0x00, 0x00   // length = 0 (empty payload)
    };
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload, sizeof(extPayload), record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails when ALPN extension parsing fails and the error
//      propagates through ReadTlsExtensions (line 411).
// How: Build ClientHello with valid SNI but a malformed ALPN extension
//      (too short). The ALPN parse error propagates back.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_AlpnParseFailurePropagation)
{
    // SNI(valid) + ALPN(empty payload=0 bytes, too short)
    const char* sni = "test.com";
    uint16_t nameLen = (uint16_t)strlen(sni);
    uint16_t listLen = nameLen + 3;
    uint16_t sniExtLen = listLen + 2;

    std::vector<uint8_t> extPayload;
    // SNI extension
    extPayload.push_back(0x00); extPayload.push_back(0x00); // type=SNI
    extPayload.push_back((uint8_t)(sniExtLen >> 8));
    extPayload.push_back((uint8_t)sniExtLen);
    extPayload.push_back((uint8_t)(listLen >> 8));
    extPayload.push_back((uint8_t)listLen);
    extPayload.push_back(0x00); // NameType
    extPayload.push_back((uint8_t)(nameLen >> 8));
    extPayload.push_back((uint8_t)nameLen);
    for (int i = 0; i < nameLen; i++) extPayload.push_back((uint8_t)sni[i]);

    // ALPN extension with empty payload (too short)
    extPayload.push_back(0x00); extPayload.push_back(0x10); // type=ALPN
    extPayload.push_back(0x00); extPayload.push_back(0x00); // length=0

    uint16_t epLen = (uint16_t)extPayload.size();
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload.data(), epLen, record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails when TP decode fails on non-draft-29 path (line 431).
// How: Build ClientHello with valid SNI/ALPN but the TP extension contains
//      invalid transport parameters (duplicate TP ID).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_TpDecodeFailure)
{
    // Invalid TP buffer: duplicate TP ID=1 (idle_timeout)
    uint8_t invalidTp[] = {
        0x01, 0x01, 0x0A,   // ID=1, Length=1, Value=10
        0x01, 0x01, 0x14    // ID=1 again (duplicate)
    };

    std::vector<uint8_t> extPayload;
    // SNI
    const char* sni = "test.com";
    uint16_t nameLen = (uint16_t)strlen(sni);
    uint16_t listLen = nameLen + 3;
    uint16_t sniExtLen = listLen + 2;
    extPayload.push_back(0x00); extPayload.push_back(0x00);
    extPayload.push_back((uint8_t)(sniExtLen >> 8));
    extPayload.push_back((uint8_t)sniExtLen);
    extPayload.push_back((uint8_t)(listLen >> 8));
    extPayload.push_back((uint8_t)listLen);
    extPayload.push_back(0x00);
    extPayload.push_back((uint8_t)(nameLen >> 8));
    extPayload.push_back((uint8_t)nameLen);
    for (int i = 0; i < nameLen; i++) extPayload.push_back((uint8_t)sni[i]);

    // ALPN
    uint8_t alpnData[] = {0x02, 'h', '3'};
    uint16_t alpnExtLen = sizeof(alpnData) + 2;
    extPayload.push_back(0x00); extPayload.push_back(0x10);
    extPayload.push_back((uint8_t)(alpnExtLen >> 8));
    extPayload.push_back((uint8_t)alpnExtLen);
    extPayload.push_back(0x00); extPayload.push_back((uint8_t)sizeof(alpnData));
    for (auto b : alpnData) extPayload.push_back(b);

    // TP extension (0x0039) with invalid (duplicate ID) payload
    uint16_t tpExtLen = sizeof(invalidTp);
    extPayload.push_back(0x00); extPayload.push_back(0x39);
    extPayload.push_back((uint8_t)(tpExtLen >> 8));
    extPayload.push_back((uint8_t)tpExtLen);
    for (auto b : invalidTp) extPayload.push_back(b);

    uint16_t epLen = (uint16_t)extPayload.size();
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload.data(), epLen, record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails with duplicate TP extension on Draft-29 path.
// How: Build ClientHello with QUIC version DRAFT_29 and two TP extensions
//      with type 0xffa5 (draft-29 TP type). Second one triggers duplicate error (line 439).
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_Draft29DuplicateTP)
{
    // Valid TP payload
    uint8_t tpData[] = {0x01, 0x01, 0x0A}; // ID=1 (idle_timeout), len=1, val=10

    std::vector<uint8_t> extPayload;
    // First draft-29 TP extension (type=0xffa5)
    extPayload.push_back(0xFF); extPayload.push_back(0xA5);
    extPayload.push_back(0x00); extPayload.push_back((uint8_t)sizeof(tpData));
    for (auto b : tpData) extPayload.push_back(b);
    // Second draft-29 TP extension (duplicate)
    extPayload.push_back(0xFF); extPayload.push_back(0xA5);
    extPayload.push_back(0x00); extPayload.push_back((uint8_t)sizeof(tpData));
    for (auto b : tpData) extPayload.push_back(b);

    uint16_t epLen = (uint16_t)extPayload.size();
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload.data(), epLen, record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_DRAFT_29;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial fails when TP decode fails on Draft-29 path (line 452).
// How: Build ClientHello with QUIC version DRAFT_29, with a TP extension
//      containing invalid (duplicate ID) transport parameter data.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_Draft29TpDecodeFailure)
{
    // Invalid TP: duplicate ID
    uint8_t tpData[] = {
        0x01, 0x01, 0x0A,
        0x01, 0x01, 0x14
    };

    std::vector<uint8_t> extPayload;
    // Draft-29 TP extension (type=0xffa5)
    extPayload.push_back(0xFF); extPayload.push_back(0xA5);
    extPayload.push_back(0x00); extPayload.push_back((uint8_t)sizeof(tpData));
    for (auto b : tpData) extPayload.push_back(b);

    uint16_t epLen = (uint16_t)extPayload.size();
    std::vector<uint8_t> record;
    BuildClientHelloWithRawExtensions(extPayload.data(), epLen, record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_DRAFT_29;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial rejects ClientHello when buffer ends before CipherSuite
//      list (ReadTlsClientHello #4 path, line 549).
// How: Build a ClientHello body that has Version(2) + Random(32) + SessionID(1)
//      but only 1 byte where CipherSuite length(2) is expected.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_TruncatedBeforeCipherSuiteLength)
{
    // Minimal body: Version(2) + Random(32) + SessionID_len(1)=0 + 1 byte (not enough for uint16)
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); // Only 1 byte where 2 needed for CipherSuite length

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

// ============================================================================
// Additional coverage and branch tests
// ============================================================================

//
// Scenario: SNI extension with a non-hostname NameType is parsed without error,
//      but Info->ServerName remains NULL because only NameType=0 is recognized.
// How: Build ClientHello with SNI extension containing NameType=1 (unknown).
// Assertions: Returns SUCCESS (SNI is optional), ServerName is NULL.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniWithNonHostnameNameType)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    // SNI payload: list_length=6, then NameType=1 (non-hostname), NameLen=3, name="abc"
    uint8_t sniPayload[] = {
        0x00, 0x06,
        0x01,        // NameType = 1 (NOT host_name)
        0x00, 0x03,
        'a', 'b', 'c'
    };

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_EQ(info.ServerName, nullptr);
    ASSERT_EQ(info.ServerNameLength, (uint16_t)0);
    ASSERT_NE(info.ClientAlpnList, nullptr);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: SNI extension with two entries: first is non-hostname type (ignored),
//      second is hostname type (picked up). Tests loop iteration and Found logic.
// How: Build ClientHello with SNI containing two ServerName entries.
// Assertions: Returns SUCCESS, ServerName matches the hostname entry.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniMultipleEntriesFirstNonHostname)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    uint8_t sniPayload[] = {
        0x00, 0x0D,  // list length = 13
        0x01,        // NameType=1 (non-hostname)
        0x00, 0x03,
        'a', 'b', 'c',
        0x00,        // NameType=0 (host_name)
        0x00, 0x04,
        't', 'e', 's', 't'
    };

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_NE(info.ServerName, nullptr);
    ASSERT_EQ(info.ServerNameLength, (uint16_t)4);
    ASSERT_EQ(memcmp(info.ServerName, "test", 4), 0);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: SNI with two hostname entries: the first is picked, second ignored.
// How: Build ClientHello with two hostname SNI entries.
// Assertions: Returns SUCCESS, ServerName matches the FIRST hostname entry.
//
TEST(DeepTest_CryptoTls, ReadInitial_SniMultipleHostnameEntriesPicksFirst)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    uint8_t alpn[] = {0x02, 'h', '3'};

    uint8_t sniPayload[] = {
        0x00, 0x11,  // list length = 17
        0x00, 0x00, 0x05,
        'f', 'i', 'r', 's', 't',
        0x00, 0x00, 0x06,
        's', 'e', 'c', 'o', 'n', 'd'
    };

    std::vector<uint8_t> record;
    BuildClientHelloWithRawSniExt(
        sniPayload, sizeof(sniPayload),
        alpn, sizeof(alpn),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    TEST_QUIC_SUCCEEDED(status);
    ASSERT_NE(info.ServerName, nullptr);
    ASSERT_EQ(info.ServerNameLength, (uint16_t)5);
    ASSERT_EQ(memcmp(info.ServerName, "first", 5), 0);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
    QuicCryptoTlsCleanupTransportParameters(&conn.PeerTransportParams);
}

//
// Scenario: ALPN with zero-length protocol ID triggers error.
// How: Build ClientHello with ALPN extension containing protocol ID with len=0.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_AlpnZeroLengthProtocolId)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;
    uint32_t tpTotalLen = 0;
    auto tpBuf = QuicCryptoTlsEncodeTransportParameters(NULL, FALSE, &tp, NULL, &tpTotalLen);
    ASSERT_NE(tpBuf, nullptr);
    auto tpPayload = tpBuf + CxPlatTlsTPHeaderSize;
    uint16_t tpPayloadLen = (uint16_t)(tpTotalLen - CxPlatTlsTPHeaderSize);

    // ALPN: list_length=1, one entry with protocol ID length=0
    uint8_t alpnPayload[] = {0x00, 0x01, 0x00};

    std::vector<uint8_t> record;
    BuildClientHelloWithRawAlpnExt(
        "example.com",
        alpnPayload, sizeof(alpnPayload),
        tpPayload, tpPayloadLen,
        record);

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    conn.Stats.QuicVersion = QUIC_VERSION_1;
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);

    CXPLAT_FREE(tpBuf, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Encode/decode with only TIMESTAMP_RECV_ENABLED (value=2).
// How: Set only the recv flag, encode, decode.
// Assertions: Recv flag preserved, send flag not set.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_TimestampRecvOnly)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_FALSE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: ReadInitial with CipherSuite data exceeding remaining buffer.
// How: Build ClientHello where CipherSuites length claims more bytes than remain.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_CipherSuiteDataExceedsBuffer)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x64); // CipherSuites len=100 (even)
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x13); chBody.push_back(0x02);

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial with CompressionMethod data exceeding remaining buffer.
// How: Build ClientHello with CompressionMethods length claiming more bytes.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_CompressionMethodExceedsBuffer)
{
    std::vector<uint8_t> chBody;
    chBody.push_back(0x03); chBody.push_back(0x03);
    for (int i = 0; i < 32; i++) chBody.push_back(0);
    chBody.push_back(0x00); // SessionID len=0
    chBody.push_back(0x00); chBody.push_back(0x02);
    chBody.push_back(0x13); chBody.push_back(0x01);
    chBody.push_back(0x05); // CompressionMethods len=5 but no data follows

    uint32_t bodyLen = (uint32_t)chBody.size();
    std::vector<uint8_t> record;
    record.push_back(0x01);
    record.push_back((uint8_t)(bodyLen >> 16));
    record.push_back((uint8_t)(bodyLen >> 8));
    record.push_back((uint8_t)bodyLen);
    record.insert(record.end(), chBody.begin(), chBody.end());

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(
        &conn, record.data(), (uint32_t)record.size(), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: Encode/decode roundtrip for CIBIR encoding at max boundary.
// How: Set CibirLength + CibirOffset = QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT.
// Assertions: Roundtrip preserves exact values.
//
TEST(DeepTest_CryptoTls, EncodeDecodeTP_CibirEncodingAtMaxBoundary)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    tp.CibirLength = 200;
    tp.CibirOffset = 55;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_CIBIR_ENCODING);
    ASSERT_EQ(decoded.CibirLength, 200u);
    ASSERT_EQ(decoded.CibirOffset, 55u);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Decode TP where CIBIR CibirOffset exceeds max CID length.
// How: Set CibirLength=1 but CibirOffset=255 (sum > 255).
// Assertions: Returns FALSE.
//
TEST(DeepTest_CryptoTls, DecodeTP_CibirOffsetExceedsMax)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    tp.CibirLength = 1;
    tp.CibirOffset = 255;

    uint32_t totalLen = 0;
    uint16_t payloadLen = 0;
    const uint8_t* basePtr = nullptr;
    auto payload = EncodeTP(&tp, FALSE, &totalLen, &payloadLen, &basePtr);
    ASSERT_NE(payload, nullptr);

    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, payload, payloadLen, &decoded);
    ASSERT_FALSE(result);

    CXPLAT_FREE(basePtr, QUIC_POOL_TLS_TRANSPARAMS);
}

//
// Scenario: Cleanup with VERSION_NEGOTIATION flag but NULL VersionInfo pointer.
// How: Set flag but leave VersionInfo as NULL, call cleanup.
// Assertions: No crash, flag is cleared, length is 0.
//
TEST(DeepTest_CryptoTls, CleanupTP_VersionFlagSetButNullPointer)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    tp.VersionInfo = NULL;
    tp.VersionInfoLength = 0;

    QuicCryptoTlsCleanupTransportParameters(&tp);
    ASSERT_EQ(tp.VersionInfo, nullptr);
    ASSERT_EQ(tp.VersionInfoLength, (uint16_t)0);
    ASSERT_FALSE(tp.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION);
}

//
// Scenario: ReadInitial with empty ClientHello body (length=0).
// How: Build a buffer with type=0x01 and length=0.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
TEST(DeepTest_CryptoTls, ReadInitial_EmptyClientHelloBody)
{
    uint8_t buf[] = {0x01, 0x00, 0x00, 0x00};

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, sizeof(buf), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: ReadInitial with version exactly equal to TLS1_PROTOCOL_VERSION.
// How: Build buffer with ClientHello version 0x0301 (minimum acceptable).
// Assertions: Version check passes, fails later for insufficient Random data.
//
TEST(DeepTest_CryptoTls, ReadInitial_VersionExactlyMinimum)
{
    uint8_t buf[] = {0x01, 0x00, 0x00, 0x04, 0x03, 0x01, 0x00, 0x00};

    QUIC_CONNECTION conn;
    CxPlatZeroMemory(&conn, sizeof(conn));
    QUIC_NEW_CONNECTION_INFO info;
    CxPlatZeroMemory(&info, sizeof(info));

    QUIC_STATUS status = QuicCryptoTlsReadInitial(&conn, buf, sizeof(buf), &info);
    ASSERT_EQ(status, QUIC_STATUS_INVALID_PARAMETER);
}

//
// Scenario: Decode TP with MaxUdpPayloadSize at exactly minimum (1200).
// How: Hand-craft TP with value=1200.
// Assertions: Returns TRUE with correct value.
//
TEST(DeepTest_CryptoTls, DecodeTP_MaxUdpPayloadSizeExactlyMin)
{
    uint8_t buf[] = {0x03, 0x02, 0x44, 0xB0};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE);
    ASSERT_EQ(decoded.MaxUdpPayloadSize, 1200u);
}

//
// Scenario: Decode with MinAckDelay exactly equal to MaxAckDelay (in us).
// How: Set min_ack_delay=1000us, max_ack_delay=1ms (=1000us). Boundary.
// Assertions: Returns TRUE (MinAckDelay <= MS_TO_US(MaxAckDelay)).
//
TEST(DeepTest_CryptoTls, DecodeTP_MinAckDelayEqualsMaxInUs)
{
    uint8_t buf[] = {
        0x0B, 0x01, 0x01,
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0x04, 0xDE, 0x1B,
        0x02, 0x43, 0xE8
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_MIN_ACK_DELAY);
    ASSERT_EQ(decoded.MinAckDelay, 1000u);
    ASSERT_EQ(decoded.MaxAckDelay, 1u);
}

//
// Scenario: Decode timestamp value=1 maps to RECV only.
// How: Hand-craft enable_timestamp TP with value=1.
// Assertions: Returns TRUE, only TIMESTAMP_RECV_ENABLED set (1<<24 = 0x01000000).
//
TEST(DeepTest_CryptoTls, DecodeTP_TimestampValueOne)
{
    uint8_t buf[] = {0x80, 0x00, 0x71, 0x58, 0x01, 0x01};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_FALSE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
}

//
// Scenario: Decode timestamp value=2 maps to SEND only.
// How: Hand-craft enable_timestamp TP with value=2.
// Assertions: Returns TRUE, only TIMESTAMP_SEND_ENABLED set (2<<24 = 0x02000000).
//
TEST(DeepTest_CryptoTls, DecodeTP_TimestampValueTwo)
{
    uint8_t buf[] = {0x80, 0x00, 0x71, 0x58, 0x01, 0x02};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_FALSE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
}

//
// Scenario: Decode timestamp value=3 maps to both SEND and RECV.
// How: Hand-craft enable_timestamp TP with value=3.
// Assertions: Returns TRUE, both TIMESTAMP flags set.
//
TEST(DeepTest_CryptoTls, DecodeTP_TimestampValueThree)
{
    uint8_t buf[] = {0x80, 0x00, 0x71, 0x58, 0x01, 0x03};
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    ASSERT_TRUE(result);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);
    ASSERT_TRUE(decoded.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
}

#ifdef DEBUG
//
// Scenario: Decode TP with VersionInfo allocation failure.
// How: Craft TP buffer with VERSION_NEGOTIATION_EXT data, force alloc to fail.
// Assertions: Decode succeeds but VersionInfo is NULL (alloc failed, break).
//
TEST(DeepTest_CryptoTls, DecodeTP_VersionInfoAllocFailure)
{
    // Build TP with version_negotiation_ext (ID=0x11) containing 4 bytes of data.
    // Format: varint ID, varint length, data
    uint8_t buf[] = {
        0x11, 0x04, 0x00, 0x00, 0x00, 0x01  // ID=0x11, len=4, data=4 bytes
    };
    QUIC_TRANSPORT_PARAMETERS decoded;
    CxPlatZeroMemory(&decoded, sizeof(decoded));
    TPScope scope(&decoded);

    CxPlatSetAllocFailDenominator(-1);
    BOOLEAN result = QuicCryptoTlsDecodeTransportParameters(
        &MockConnection, FALSE, buf, sizeof(buf), &decoded);
    CxPlatSetAllocFailDenominator(0);

    // Alloc failure in VERSION_NEGOTIATION_EXT case does a 'break' and
    // continues decoding. The VersionInfo will be NULL.
    ASSERT_TRUE(result);
    ASSERT_EQ(decoded.VersionInfo, nullptr);
}

//
// Scenario: CopyTP with VersionInfo allocation failure.
// How: First encode/decode TPs with VERSION_NEGOTIATION, then force alloc
//      failure during copy.
// Assertions: Copy returns QUIC_STATUS_OUT_OF_MEMORY.
//
TEST(DeepTest_CryptoTls, CopyTP_VersionInfoAllocFailure)
{
    QUIC_TRANSPORT_PARAMETERS source;
    CxPlatZeroMemory(&source, sizeof(source));
    source.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;
    uint8_t versionData[] = {0x00, 0x00, 0x00, 0x01};
    source.VersionInfo = versionData;
    source.VersionInfoLength = sizeof(versionData);

    QUIC_TRANSPORT_PARAMETERS dest;
    CxPlatZeroMemory(&dest, sizeof(dest));

    CxPlatSetAllocFailDenominator(-1);
    QUIC_STATUS status = QuicCryptoTlsCopyTransportParameters(&source, &dest);
    CxPlatSetAllocFailDenominator(0);

    ASSERT_EQ(status, QUIC_STATUS_OUT_OF_MEMORY);
    // Don't cleanup dest since alloc failed - VersionInfo should be NULL
}

//
// Scenario: EncodeTP allocation failure returns NULL.
// How: Force alloc failure during buffer allocation in EncodeTransportParameters.
// Assertions: Returns NULL.
//
TEST(DeepTest_CryptoTls, EncodeTP_AllocFailure)
{
    QUIC_TRANSPORT_PARAMETERS tp;
    CxPlatZeroMemory(&tp, sizeof(tp));
    tp.Flags = QUIC_TP_FLAG_IDLE_TIMEOUT;
    tp.IdleTimeout = 1000;

    uint32_t totalLen = 0;

    CxPlatSetAllocFailDenominator(-1);
    const uint8_t* result = QuicCryptoTlsEncodeTransportParameters(
        NULL, FALSE, &tp, NULL, &totalLen);
    CxPlatSetAllocFailDenominator(0);

    ASSERT_EQ(result, nullptr);
}
#endif // DEBUG
