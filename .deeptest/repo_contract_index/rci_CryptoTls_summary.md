# RCI Summary: CryptoTls Component

## Source: `src/core/crypto_tls.c` (2038 lines)
## Header: `src/core/crypto.h` (447 lines)

## Public API Summary (12 functions)

| Function | Purpose |
|----------|---------|
| `QuicTpIdIsReserved` | Check if TP ID is in GREASE range |
| `QuicCryptoTlsReadSniExtension` | Parse TLS SNI extension |
| `QuicCryptoTlsReadAlpnExtension` | Parse TLS ALPN extension |
| `QuicCryptoTlsReadExtensions` | Dispatch all TLS extensions |
| `QuicCryptoTlsReadClientHello` | Parse full ClientHello |
| `QuicCryptoTlsGetCompleteTlsMessagesLength` | Scan for complete TLS messages |
| `QuicCryptoTlsReadInitial` | Entry point for Initial parsing |
| `QuicCryptoTlsReadClientRandom` | Extract ClientRandom bytes |
| `QuicCryptoTlsEncodeTransportParameters` | Encode TPs to wire format |
| `QuicCryptoTlsDecodeTransportParameters` | Decode TPs from wire format |
| `QuicCryptoTlsCopyTransportParameters` | Deep-copy TPs |
| `QuicCryptoTlsCleanupTransportParameters` | Free TP resources |

## Key Type Invariants

**QUIC_TRANSPORT_PARAMETERS**: Flags bitfield controls which fields are valid. When set:
- MaxUdpPayloadSize >= 1200
- Stream limits <= QUIC_TP_MAX_STREAMS_MAX
- ActiveConnectionIdLimit >= 2
- MinAckDelay <= MaxAckDelay * 1000
- CibirLength + CibirOffset <= max CID length

## Coverage Analysis

**Baseline**: 97.08% line coverage (632/651 lines) with 110 existing tests.
**Final**: 98.00% line coverage (638/651 lines) with 130 tests (20 new).

**13 uncovered lines** (all practically unreachable through public API):
- Lines 825-826, 1097-1099: PREFERRED_ADDRESS encoding (FRE_ASSERT(FALSE) - not implemented)
- Lines 916, 921, 926, 931: RequiredTPLen > UINT16_MAX / alloc failure
- Lines 1266, 1271-1273: FinalTPLength != RequiredTPLen defensive assert
- Lines 1575, 1580: **Dead code** (duplicate check - BUG)
- Lines 1847, 1852, 2007, 2012: Allocation failure paths (require mock)

## Bugs Found

### BUG: Dead Code - Duplicate InitialMaxBidiStreams Check
- **Location**: `src/core/crypto_tls.c:1574-1580`
- **Severity**: Low (dead code, no runtime impact)
- **Description**: Lines 1566 and 1574 contain identical checks: `InitialMaxBidiStreams > QUIC_TP_MAX_STREAMS_MAX`. Line 1566 exits on match, making line 1574 unreachable. Likely copy-paste error.

## Test Harness: 130 tests total (110 original + 20 new)
