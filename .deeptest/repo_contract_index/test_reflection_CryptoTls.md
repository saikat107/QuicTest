# Test Reflection: CryptoTls Component

**Final Coverage: 98.00% (638/651 lines) — up from 97.08% baseline**
**Total Tests: 130 (110 original + 20 new)**

## Test 1: ReadInitial_SniWithNonHostnameNameType
- **Scenario**: SNI extension with NameType=1 (non-hostname) is parsed without error but ServerName stays NULL.
- **Primary API**: QuicCryptoTlsReadInitial → QuicCryptoTlsReadSniExtension
- **Contract reasoning**: NameType=1 is not host_name (0x00), so the code skips it. SNI is optional for ServerName extraction. All preconditions maintained via BuildClientHelloWithRawSniExt helper.
- **Coverage impact**: Exercises the `if (NameType != TLS_SNI_TYPE_HOST_NAME)` branch in ReadSniExtension.
- **Non-redundancy**: No existing test sends a non-hostname NameType. All existing SNI tests use NameType=0.

## Test 2: ReadInitial_SniMultipleEntriesFirstNonHostname
- **Scenario**: SNI with two entries: NameType=1 (skipped) then NameType=0 (picked up).
- **Primary API**: QuicCryptoTlsReadSniExtension
- **Contract reasoning**: Tests the SNI loop iteration. First entry is non-hostname and skipped; second is hostname and extracted.
- **Coverage impact**: Exercises the SNI loop with multiple iterations and the Found flag logic.
- **Non-redundancy**: No existing test has multiple SNI entries with mixed types.

## Test 3: ReadInitial_SniMultipleHostnameEntriesPicksFirst
- **Scenario**: Two hostname entries in SNI: verifies the first one is picked.
- **Primary API**: QuicCryptoTlsReadSniExtension
- **Contract reasoning**: Once Found=TRUE is set on first match, subsequent hostname entries are skipped.
- **Coverage impact**: Exercises the `if (Found)` branch in the SNI loop.
- **Non-redundancy**: No existing test has multiple hostname entries.

## Test 4: ReadInitial_AlpnZeroLengthProtocolId
- **Scenario**: ALPN extension with a zero-length protocol ID triggers error.
- **Primary API**: QuicCryptoTlsReadAlpnExtension
- **Contract reasoning**: Zero-length protocol ID is invalid per TLS spec. Contract explicitly rejects this.
- **Coverage impact**: Exercises the `if (ProtocolIdLen == 0)` check in ReadAlpnExtension.
- **Non-redundancy**: No existing test sends a zero-length ALPN protocol ID.

## Test 5: EncodeDecodeTP_TimestampRecvOnly
- **Scenario**: Round-trip encode/decode with only TIMESTAMP_RECV_ENABLED flag.
- **Primary API**: QuicCryptoTlsEncodeTransportParameters, QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: TIMESTAMP_RECV_ENABLED (0x01000000) encodes as wire value 1 (after right-shift by 24). Decode shifts back correctly.
- **Coverage impact**: Exercises the timestamp encoding path with only recv flag set.
- **Non-redundancy**: Existing tests cover both flags together and send-only. This tests recv-only.

## Test 6: ReadInitial_CipherSuiteDataExceedsBuffer
- **Scenario**: CipherSuites length field claims more data than buffer contains.
- **Primary API**: QuicCryptoTlsReadClientHello
- **Contract reasoning**: Buffer overflow check for cipher suites. Length validation is part of the contract.
- **Coverage impact**: Exercises the cipher suite length validation branch.
- **Non-redundancy**: No existing test targets cipher suite length overflow specifically.

## Test 7: ReadInitial_CompressionMethodExceedsBuffer
- **Scenario**: CompressionMethods length claims more data than buffer contains.
- **Primary API**: QuicCryptoTlsReadClientHello
- **Contract reasoning**: Buffer overflow check for compression methods. Length validation is part of contract.
- **Coverage impact**: Exercises the compression methods length validation.
- **Non-redundancy**: No existing test targets compression method length overflow.

## Test 8: EncodeDecodeTP_CibirEncodingAtMaxBoundary
- **Scenario**: CIBIR encoding with large CibirLength and CibirOffset values.
- **Primary API**: QuicCryptoTlsEncodeTransportParameters, QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: CibirLength + CibirOffset within max CID length invariant.
- **Coverage impact**: Exercises CIBIR encode/decode paths with non-trivial values.
- **Non-redundancy**: Existing CIBIR tests use small values. This tests larger boundary values.

## Test 9: DecodeTP_CibirOffsetExceedsMax
- **Scenario**: CIBIR where CibirLength + CibirOffset exceeds max CID length.
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: Decode should fail validation when offset exceeds max.
- **Coverage impact**: Exercises the CIBIR offset validation error path.
- **Non-redundancy**: No existing test triggers the CIBIR offset overflow check.

## Test 10: CleanupTP_VersionFlagSetButNullPointer
- **Scenario**: Cleanup with VERSION_NEGOTIATION flag set but VersionInfo is NULL.
- **Primary API**: QuicCryptoTlsCleanupTransportParameters
- **Contract reasoning**: Cleanup is safe with NULL VersionInfo per contract.
- **Coverage impact**: Exercises the cleanup path where flag is set but no allocation exists.
- **Non-redundancy**: Existing cleanup tests either have no flag or have actual VersionInfo data.

## Test 11: ReadInitial_EmptyClientHelloBody
- **Scenario**: ClientHello with zero-length body fails immediately.
- **Primary API**: QuicCryptoTlsReadInitial → QuicCryptoTlsReadClientHello
- **Contract reasoning**: Body length 0 means insufficient data for version check. Returns INVALID_PARAMETER.
- **Coverage impact**: Exercises the early version check with minimal data.
- **Non-redundancy**: Existing empty tests use completely empty buffer (0 bytes). This has a valid header but zero body.

## Test 12: ReadInitial_VersionExactlyMinimum
- **Scenario**: ClientHello version exactly 0x0301 (TLS 1.0 / minimum accepted).
- **Primary API**: QuicCryptoTlsReadClientHello
- **Contract reasoning**: Version >= TLS1_PROTOCOL_VERSION (0x0301) passes the version check but fails later due to insufficient Random data.
- **Coverage impact**: Exercises the exact boundary of the version check.
- **Non-redundancy**: Existing tests use higher versions; this tests the minimum boundary.

## Test 13: DecodeTP_MaxUdpPayloadSizeExactlyMin
- **Scenario**: Decode TP with MaxUdpPayloadSize = 1200 (exact minimum).
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: 1200 is the minimum valid value (QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN). At-boundary value should succeed.
- **Coverage impact**: Exercises the boundary check `< QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN`.
- **Non-redundancy**: Existing tests test below-minimum. This tests exactly-at-minimum.

## Test 14: DecodeTP_MinAckDelayEqualsMaxInUs
- **Scenario**: MinAckDelay in microseconds equals MaxAckDelay converted to microseconds (boundary condition).
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: MinAckDelay <= MS_TO_US(MaxAckDelay) should pass when equal.
- **Coverage impact**: Exercises the MinAckDelay vs MaxAckDelay boundary check.
- **Non-redundancy**: Existing tests don't test the exact equality boundary.

## Test 15: DecodeTP_TimestampValueOne
- **Scenario**: Decode timestamp wire value 1 maps to RECV_ENABLED only.
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: Wire value 1 << 24 = 0x01000000 = QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED.
- **Coverage impact**: Exercises timestamp decode with specific wire value 1.
- **Non-redundancy**: Existing tests encode with flags, not raw wire values. Tests the shift logic directly.

## Test 16: DecodeTP_TimestampValueTwo
- **Scenario**: Decode timestamp wire value 2 maps to SEND_ENABLED only.
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: Wire value 2 << 24 = 0x02000000 = QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED.
- **Coverage impact**: Exercises timestamp decode with wire value 2.
- **Non-redundancy**: Tests wire-value-to-flag mapping directly.

## Test 17: DecodeTP_TimestampValueThree
- **Scenario**: Decode timestamp wire value 3 maps to both SEND and RECV enabled.
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: Wire value 3 << 24 = 0x03000000 = both flags.
- **Coverage impact**: Exercises timestamp decode with combined wire value 3.
- **Non-redundancy**: Verifies both flags set simultaneously via raw wire value.

## Test 18: DecodeTP_VersionInfoAllocFailure (DEBUG only)
- **Scenario**: Decode TP with VERSION_NEGOTIATION_EXT data when allocation fails.
- **Primary API**: QuicCryptoTlsDecodeTransportParameters
- **Contract reasoning**: Uses CxPlatSetAllocFailDenominator(-1) to force CXPLAT_ALLOC_NONPAGED to return NULL. The decode still returns TRUE (alloc failure does a 'break', not 'goto Exit').
- **Coverage impact**: Covers lines 1847, 1852 (VersionInfo alloc failure path in decode).
- **Non-redundancy**: Only test that exercises the VersionInfo allocation failure path. Quality: 8/10.

## Test 19: CopyTP_VersionInfoAllocFailure (DEBUG only)
- **Scenario**: Copy transport parameters with VERSION_NEGOTIATION flag when allocation fails.
- **Primary API**: QuicCryptoTlsCopyTransportParameters
- **Contract reasoning**: Uses CxPlatSetAllocFailDenominator(-1). Copy returns QUIC_STATUS_OUT_OF_MEMORY.
- **Coverage impact**: Covers lines 2007, 2012 (VersionInfo alloc failure path in copy).
- **Non-redundancy**: Only test that exercises the CopyTP allocation failure. Quality: 8/10.

## Test 20: EncodeTP_AllocFailure (DEBUG only)
- **Scenario**: Encode transport parameters when buffer allocation fails.
- **Primary API**: QuicCryptoTlsEncodeTransportParameters
- **Contract reasoning**: Uses CxPlatSetAllocFailDenominator(-1). Encode returns NULL.
- **Coverage impact**: Covers lines 926, 931 (TP buffer alloc failure path in encode).
- **Non-redundancy**: Only test exercising the encode buffer allocation failure. Quality: 8/10.

---

## Uncovered Lines Analysis (13 lines, 2.00%)

All remaining uncovered lines are truly unreachable through public API:

| Lines | Reason | Category |
|-------|--------|----------|
| 825-826 | PREFERRED_ADDRESS encode (CXPLAT_FRE_ASSERT(FALSE)) | Not implemented |
| 1097-1099 | PREFERRED_ADDRESS encode second path | Not implemented |
| 916, 921 | RequiredTPLen > UINT16_MAX | Mathematically impossible |
| 1266, 1271-1273 | FinalTPLength != RequiredTPLen consistency check | Defensive dead path |
| 1575, 1580 | Duplicate InitialMaxBidiStreams check | **BUG: Dead code** |
