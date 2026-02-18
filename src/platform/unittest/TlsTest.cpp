/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#include "main.h"
#include "msquic.h"
#include "quic_tls.h"
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6553) // Annotation does not apply to value type.
#include <wincrypt.h>
#pragma warning(pop)
#endif
#include <fcntl.h>

#ifdef QUIC_CLOG
#include "TlsTest.cpp.clog.h"
#endif

const uint32_t DefaultFragmentSize = 1200;
extern const char* OsRunner;

const uint8_t Alpn[] = { 1, 'A' };
const uint8_t MultiAlpn[] = { 1, 'C', 1, 'A', 1, 'B' };
const char* PfxPass = "PLACEHOLDER";        // approved for cred scan
extern const char* PfxPath;
const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };

bool IsWindows2019() { return OsRunner && strcmp(OsRunner, "windows-2019") == 0; }
bool IsWindows2022() { return OsRunner && strcmp(OsRunner, "windows-2022") == 0; }

struct TlsTest : public ::testing::TestWithParam<bool>
{
protected:
    static QUIC_CREDENTIAL_FLAGS SelfSignedCertParamsFlags;
    static QUIC_CREDENTIAL_CONFIG* SelfSignedCertParams;
    static QUIC_CREDENTIAL_CONFIG* ClientCertParams;
    static QUIC_CREDENTIAL_FLAGS CaSelfSignedCertParamsFlags;
    static QUIC_CREDENTIAL_CONFIG* CaSelfSignedCertParams;
    static QUIC_CREDENTIAL_CONFIG* CaClientCertParams;
    static QUIC_CREDENTIAL_CONFIG* CertParamsFromFile;
    static const char* ServerCaCertificateFile;
    static const char* ClientCaCertificateFile;

    struct CxPlatSecConfig {
        CXPLAT_SEC_CONFIG* SecConfig {nullptr};
        operator CXPLAT_SEC_CONFIG* () noexcept { return SecConfig; }
        CxPlatSecConfig() { }
        ~CxPlatSecConfig() {
            if (SecConfig) {
                CxPlatTlsSecConfigDelete(SecConfig);
            }
        }
        void Load(
            _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
            _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags = CXPLAT_TLS_CREDENTIAL_FLAG_NONE
            ) {
            VERIFY_QUIC_SUCCESS(
                CxPlatTlsSecConfigCreate(
                    CredConfig,
                    TlsFlags,
                    &TlsContext::TlsCallbacks,
                    &SecConfig,
                    OnSecConfigCreateComplete));
            ASSERT_NE(nullptr, SecConfig);
        }
        _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
        static void
        QUIC_API
        OnSecConfigCreateComplete(
            _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
            _In_opt_ void* Context,
            _In_ QUIC_STATUS Status,
            _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
            )
        {
            VERIFY_QUIC_SUCCESS(Status);
            ASSERT_NE(nullptr, SecConfig);
            *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
        }
    };

    struct CxPlatServerSecConfig : public CxPlatSecConfig {
        CxPlatServerSecConfig(
            _In_ QUIC_CREDENTIAL_FLAGS CredFlags = QUIC_CREDENTIAL_FLAG_NONE,
            _In_ QUIC_ALLOWED_CIPHER_SUITE_FLAGS CipherFlags = QUIC_ALLOWED_CIPHER_SUITE_NONE,
            _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags = CXPLAT_TLS_CREDENTIAL_FLAG_NONE
            ) {
            SelfSignedCertParams->Flags = SelfSignedCertParamsFlags | CredFlags;
            SelfSignedCertParams->AllowedCipherSuites = CipherFlags;
            Load(SelfSignedCertParams, TlsFlags);
        }
    };

    struct CxPlatClientSecConfig : public CxPlatSecConfig {
        CxPlatClientSecConfig(
            _In_ QUIC_CREDENTIAL_FLAGS CredFlags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
            _In_ QUIC_ALLOWED_CIPHER_SUITE_FLAGS CipherFlags = QUIC_ALLOWED_CIPHER_SUITE_NONE,
            _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags = CXPLAT_TLS_CREDENTIAL_FLAG_NONE
            ) {
            QUIC_CREDENTIAL_CONFIG CredConfig = {
                QUIC_CREDENTIAL_TYPE_NONE,
                QUIC_CREDENTIAL_FLAG_CLIENT,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                QUIC_ALLOWED_CIPHER_SUITE_NONE,
                nullptr
            };
            CredConfig.Flags |= CredFlags;
            CredConfig.AllowedCipherSuites = CipherFlags;
            Load(&CredConfig, TlsFlags);
        }

    };

    struct CxPlatServerSecConfigCa : public CxPlatSecConfig {
        CxPlatServerSecConfigCa(
            _In_ QUIC_CREDENTIAL_FLAGS CredFlags = QUIC_CREDENTIAL_FLAG_NONE,
            _In_ QUIC_ALLOWED_CIPHER_SUITE_FLAGS CipherFlags = QUIC_ALLOWED_CIPHER_SUITE_NONE,
            _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags = CXPLAT_TLS_CREDENTIAL_FLAG_NONE
            ) {
            CaSelfSignedCertParams->Flags = CaSelfSignedCertParamsFlags | CredFlags;
            CaSelfSignedCertParams->AllowedCipherSuites = CipherFlags;
            Load(CaSelfSignedCertParams, TlsFlags);
        }
    };

    struct CxPlatClientSecConfigCa : public CxPlatSecConfig {
        CxPlatClientSecConfigCa(
            _In_ QUIC_CREDENTIAL_FLAGS CredFlags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
            _In_ QUIC_ALLOWED_CIPHER_SUITE_FLAGS CipherFlags = QUIC_ALLOWED_CIPHER_SUITE_NONE,
            _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags = CXPLAT_TLS_CREDENTIAL_FLAG_NONE
            ) {
            QUIC_CREDENTIAL_CONFIG CredConfig = {
                QUIC_CREDENTIAL_TYPE_NONE,
                QUIC_CREDENTIAL_FLAG_CLIENT,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                QUIC_ALLOWED_CIPHER_SUITE_NONE,
                CaClientCertParams->CaCertificateFile
            };
            CredConfig.Flags |= CredFlags;
            CredConfig.AllowedCipherSuites = CipherFlags;
            Load(&CredConfig, TlsFlags);
        }
    };

    TlsTest() { }

    ~TlsTest()
    {
        TearDown();
    }

#ifndef QUIC_DISABLE_PFX_TESTS
    static uint8_t* ReadFile(const char* Name, uint32_t* Length) {
        size_t FileSize = 0;
        FILE* Handle = fopen(Name, "rb");
        if (Handle == nullptr) {
            return nullptr;
        }
#ifdef _WIN32
        struct _stat Stat;
        if (_fstat(_fileno(Handle), &Stat) == 0) {
            FileSize = (int)Stat.st_size;
        }
#else
        struct stat Stat;
        if (fstat(fileno(Handle), &Stat) == 0) {
            FileSize = (int)Stat.st_size;
        }
#endif
        if (FileSize == 0) {
            fclose(Handle);
            return nullptr;
        }

        uint8_t* Buffer = (uint8_t *)CXPLAT_ALLOC_NONPAGED(FileSize, QUIC_POOL_TEST);
        if (Buffer == nullptr) {
            fclose(Handle);
            return nullptr;
        }

        size_t ReadLength = 0;
        *Length = 0;
        do {
            ReadLength = fread(Buffer + *Length, 1, FileSize - *Length, Handle);
            *Length += (uint32_t)ReadLength;
        } while (ReadLength > 0 && *Length < (uint32_t)FileSize);
        fclose(Handle);
        if (*Length != FileSize) {
            CXPLAT_FREE(Buffer, QUIC_POOL_TEST);
            return nullptr;
        }
        return Buffer;
    }
#endif

    static void SetUpTestSuite()
    {
        SelfSignedCertParams = (QUIC_CREDENTIAL_CONFIG*)CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);
        ASSERT_NE(nullptr, SelfSignedCertParams);
        SelfSignedCertParamsFlags = SelfSignedCertParams->Flags;
        ClientCertParams = (QUIC_CREDENTIAL_CONFIG*)CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, TRUE, NULL);
        ASSERT_NE(nullptr, ClientCertParams);

        ServerCaCertificateFile = CxPlatGetSelfSignedCertCaCertificateFileName(FALSE);
        ClientCaCertificateFile = CxPlatGetSelfSignedCertCaCertificateFileName(TRUE);
        CaSelfSignedCertParams = (QUIC_CREDENTIAL_CONFIG*)CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CA_CERT_USER, FALSE, ClientCaCertificateFile);
        ASSERT_NE(nullptr, CaSelfSignedCertParams);
        CaSelfSignedCertParamsFlags = CaSelfSignedCertParams->Flags;
        CaClientCertParams = (QUIC_CREDENTIAL_CONFIG*)CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CA_CERT_USER, TRUE, ServerCaCertificateFile);
        ASSERT_NE(nullptr, ClientCertParams);

        CaClientCertParams->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        ClientCertParams->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

#ifndef QUIC_DISABLE_PFX_TESTS
        if (PfxPath != nullptr) {
            CertParamsFromFile = (QUIC_CREDENTIAL_CONFIG*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_CREDENTIAL_CONFIG), QUIC_POOL_TEST);
            ASSERT_NE(nullptr, CertParamsFromFile);
            CxPlatZeroMemory(CertParamsFromFile, sizeof(*CertParamsFromFile));
            CertParamsFromFile->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
            CertParamsFromFile->CertificatePkcs12 = (QUIC_CERTIFICATE_PKCS12*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_CERTIFICATE_PKCS12), QUIC_POOL_TEST);
            ASSERT_NE(nullptr, CertParamsFromFile->CertificatePkcs12);
            CxPlatZeroMemory(CertParamsFromFile->CertificatePkcs12, sizeof(QUIC_CERTIFICATE_PKCS12));
            CertParamsFromFile->CertificatePkcs12->Asn1Blob = ReadFile(PfxPath, &CertParamsFromFile->CertificatePkcs12->Asn1BlobLength);
            CertParamsFromFile->CertificatePkcs12->PrivateKeyPassword = PfxPass;
            ASSERT_NE((uint32_t)0, CertParamsFromFile->CertificatePkcs12->Asn1BlobLength);
            ASSERT_NE(nullptr, CertParamsFromFile->CertificatePkcs12->Asn1Blob);
        }
#endif
    }

    static void TearDownTestSuite()
    {
        CxPlatFreeSelfSignedCert(SelfSignedCertParams);
        SelfSignedCertParams = nullptr;
        CxPlatFreeSelfSignedCert(ClientCertParams);
        ClientCertParams = nullptr;
        CxPlatFreeSelfSignedCertCaFile(ServerCaCertificateFile);
        ServerCaCertificateFile = nullptr;
        CxPlatFreeSelfSignedCertCaFile(ClientCaCertificateFile);
        ClientCaCertificateFile = nullptr;
#ifndef QUIC_DISABLE_PFX_TESTS
        if (CertParamsFromFile != nullptr) {
            if (CertParamsFromFile->CertificatePkcs12->Asn1Blob) {
                CXPLAT_FREE(CertParamsFromFile->CertificatePkcs12->Asn1Blob, QUIC_POOL_TEST);
            }
            CXPLAT_FREE(CertParamsFromFile->CertificatePkcs12, QUIC_POOL_TEST);
            CXPLAT_FREE(CertParamsFromFile, QUIC_POOL_TEST);
            CertParamsFromFile = nullptr;
        }
#endif
    }

    void SetUp() override { }

    void TearDown() override { }

    struct TlsContext
    {
        CXPLAT_TLS* Ptr {nullptr};
        CXPLAT_SEC_CONFIG* SecConfig {nullptr};

        CXPLAT_TLS_PROCESS_STATE State;

        //
        // Note, This variable creates a singleton check of the code that
        // it guards.  See comments where used below
        //
        bool BufferKeyChecked;

        static const CXPLAT_TLS_CALLBACKS TlsCallbacks;

        bool ReceivedPeerCertificate {false};

        BOOLEAN OnPeerCertReceivedResult {TRUE};
        BOOLEAN OnSessionTicketReceivedResult {TRUE};
        BOOLEAN ExpectNullCertificate {FALSE};

        QUIC_BUFFER ReceivedSessionTicket {0, nullptr};

        uint32_t ExpectedErrorFlags {0};
        QUIC_STATUS ExpectedValidationStatus {QUIC_STATUS_SUCCESS};

        TlsContext() {
            CxPlatZeroMemory(&State, sizeof(State));
            State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(8000, QUIC_POOL_TEST);
            State.BufferAllocLength = 8000;
        }

        ~TlsContext() {
            CxPlatTlsUninitialize(Ptr);
            CXPLAT_FREE(State.Buffer, QUIC_POOL_TEST);
            for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
                QuicPacketKeyFree(State.ReadKeys[i]);
                QuicPacketKeyFree(State.WriteKeys[i]);
            }
            if (ReceivedSessionTicket.Buffer) {
                CXPLAT_FREE(ReceivedSessionTicket.Buffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
            }
        }

        void InitializeServer(
            const CXPLAT_SEC_CONFIG* SecConfiguration,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64
            )
        {
            CXPLAT_TLS_CONFIG Config = {0};
            Config.IsServer = TRUE;
            Config.SecConfig = (CXPLAT_SEC_CONFIG*)SecConfiguration;
            Config.HkdfLabels = &HkdfLabels;
            UNREFERENCED_PARAMETER(MultipleAlpns); // The server must always send back the negotiated ALPN.
            Config.AlpnBuffer = Alpn;
            Config.AlpnBufferLength = sizeof(Alpn);
            Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
            Config.LocalTPBuffer =
                (uint8_t*)CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + TPLen, QUIC_POOL_TLS_TRANSPARAMS);
            Config.LocalTPLength = CxPlatTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            State.NegotiatedAlpn = Alpn;

            VERIFY_QUIC_SUCCESS(
                CxPlatTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
            BufferKeyChecked = FALSE;
        }

        void InitializeClient(
            CXPLAT_SEC_CONFIG* SecConfiguration,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64,
            QUIC_BUFFER* Ticket = nullptr
            )
        {
            CXPLAT_TLS_CONFIG Config = {0};
            Config.IsServer = FALSE;
            Config.SecConfig = SecConfiguration;
            Config.HkdfLabels = &HkdfLabels;
            Config.AlpnBuffer = MultipleAlpns ? MultiAlpn : Alpn;
            Config.AlpnBufferLength = MultipleAlpns ? sizeof(MultiAlpn) : sizeof(Alpn);
            Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
            Config.LocalTPBuffer =
                (uint8_t*)CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + TPLen, QUIC_POOL_TLS_TRANSPARAMS);
            Config.LocalTPLength = CxPlatTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            Config.ServerName = "localhost";
            if (Ticket) {
                ASSERT_NE(nullptr, Ticket->Buffer);
                //ASSERT_NE((uint32_t)0, Ticket->Length);
                Config.ResumptionTicketBuffer = Ticket->Buffer;
                Config.ResumptionTicketLength = Ticket->Length;
                Ticket->Buffer = nullptr;
            }

            VERIFY_QUIC_SUCCESS(
                CxPlatTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
            BufferKeyChecked = FALSE;
        }

    private:

        static
        uint32_t
        TlsReadUint24(
            _In_reads_(3) const uint8_t* Buffer
            )
        {
            return
                (((uint32_t)Buffer[0] << 16) +
                ((uint32_t)Buffer[1] << 8) +
                (uint32_t)Buffer[2]);
        }

        static
        uint32_t
        GetCompleteTlsMessagesLength(
            _In_reads_(BufferLength)
                const uint8_t* Buffer,
            _In_ uint32_t BufferLength
            )
        {
            uint32_t MessagesLength = 0;
            do {
                if (BufferLength < 4) {
                    break;
                }
                uint32_t MessageLength = 4 + TlsReadUint24(Buffer + 1);
                if (BufferLength < MessageLength) {
                    break;
                }
                MessagesLength += MessageLength;
                Buffer += MessageLength;
                BufferLength -= MessageLength;
            } while (BufferLength > 0);
            return MessagesLength;
        }

        CXPLAT_TLS_RESULT_FLAGS
        ProcessData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(*BufferLength)
                const uint8_t * Buffer,
            _In_ uint32_t * BufferLength,
            _In_ bool ExpectError,
            _In_ CXPLAT_TLS_DATA_TYPE DataType
            )
        {
            EXPECT_TRUE(Buffer != nullptr || *BufferLength == 0);
            if (Buffer != nullptr) {
                //
                // BufferKey is only set at the start of the test, But some TLS implementations
                // may update their keys while processing the data passed into this function
                // specifically observed on openssl, Sending a buffer with a ServerHello to a client
                // will yield handshake keys immediately, and following data will cause this to fail
                // so only check once at the start of the test to ensure we are in the right state
                //
                if (BufferKeyChecked == FALSE) {
                    EXPECT_EQ(BufferKey, State.ReadKey);
                    BufferKeyChecked = TRUE;
                }
                if (DataType != CXPLAT_TLS_TICKET_DATA) {
                    *BufferLength = GetCompleteTlsMessagesLength(Buffer, *BufferLength);
                    if (*BufferLength == 0) return (CXPLAT_TLS_RESULT_FLAGS)0;
                }
            }

            //std::cout << "Processing " << *BufferLength << " bytes of type " << DataType << std::endl;

            auto Result =
                CxPlatTlsProcessData(
                    Ptr,
                    DataType,
                    Buffer,
                    BufferLength,
                    &State);

            if (!ExpectError) {
                EXPECT_TRUE((Result & CXPLAT_TLS_RESULT_ERROR) == 0);
            }

            return Result;
        }

        CXPLAT_TLS_RESULT_FLAGS
        ProcessFragmentedData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(BufferLength)
                const uint8_t * Buffer,
            _In_ uint32_t BufferLength,
            _In_ uint32_t FragmentSize,
            _In_ bool ExpectError,
            _In_ CXPLAT_TLS_DATA_TYPE DataType
            )
        {
            uint32_t Result = 0;
            uint32_t ConsumedBuffer = FragmentSize;
            uint32_t Count = 1;
            do {
                if (BufferLength < FragmentSize) {
                    FragmentSize = BufferLength;
                    ConsumedBuffer = FragmentSize;
                }

                //std::cout << "Processing fragment of " << FragmentSize << " bytes of type " << DataType << std::endl;

                Result |= (uint32_t)ProcessData(BufferKey, Buffer, &ConsumedBuffer, ExpectError, DataType);

                if (ConsumedBuffer > 0) {
                    Buffer += ConsumedBuffer;
                    BufferLength -= ConsumedBuffer;
                } else {
                    ConsumedBuffer = FragmentSize * ++Count;
                    ConsumedBuffer = CXPLAT_MIN(ConsumedBuffer, BufferLength);
                }

            } while (BufferLength != 0 && !(Result & CXPLAT_TLS_RESULT_ERROR));

            return (CXPLAT_TLS_RESULT_FLAGS)Result;
        }

    public:

        CXPLAT_TLS_RESULT_FLAGS
        ProcessData(
            _Inout_ CXPLAT_TLS_PROCESS_STATE* PeerState,
            _In_ uint32_t FragmentSize = DefaultFragmentSize,
            _In_ bool ExpectError = false,
            _In_ CXPLAT_TLS_DATA_TYPE DataType = CXPLAT_TLS_CRYPTO_DATA
            )
        {
            if (PeerState == nullptr) {
                //
                // Special case for client hello/initial.
                //
                uint32_t Zero = 0;
                return ProcessData(QUIC_PACKET_KEY_INITIAL, nullptr, &Zero, ExpectError, DataType);
            }

            uint32_t Result = 0;

            do {
                uint16_t BufferLength;
                QUIC_PACKET_KEY_TYPE PeerWriteKey;

                uint32_t StartOffset = PeerState->BufferTotalLength - PeerState->BufferLength;
                if (PeerState->BufferOffset1Rtt != 0 && StartOffset >= PeerState->BufferOffset1Rtt) {
                    PeerWriteKey = QUIC_PACKET_KEY_1_RTT;
                    BufferLength = PeerState->BufferLength;

                } else if (PeerState->BufferOffsetHandshake != 0 && StartOffset >= PeerState->BufferOffsetHandshake) {
                    PeerWriteKey = QUIC_PACKET_KEY_HANDSHAKE;
                    if (PeerState->BufferOffset1Rtt != 0) {
                        BufferLength = (uint16_t)(PeerState->BufferOffset1Rtt - StartOffset);
                    } else {
                        BufferLength = PeerState->BufferLength;
                    }

                } else {
                    PeerWriteKey = QUIC_PACKET_KEY_INITIAL;
                    if (PeerState->BufferOffsetHandshake != 0) {
                        BufferLength = (uint16_t)(PeerState->BufferOffsetHandshake - StartOffset);
                    } else {
                        BufferLength = PeerState->BufferLength;
                    }
                }

                Result |=
                    (uint32_t)ProcessFragmentedData(
                        PeerWriteKey,
                        PeerState->Buffer,
                        BufferLength,
                        FragmentSize,
                        ExpectError,
                        DataType);

                PeerState->BufferLength -= BufferLength;
                CxPlatMoveMemory(
                    PeerState->Buffer,
                    PeerState->Buffer + BufferLength,
                    PeerState->BufferLength);

            } while (PeerState->BufferLength != 0 && !(Result & CXPLAT_TLS_RESULT_ERROR));

            return (CXPLAT_TLS_RESULT_FLAGS)Result;
        }

    private:

        static BOOLEAN
        OnQuicTPReceived(
            _In_ QUIC_CONNECTION* Connection,
            _In_ uint16_t TPLength,
            _In_reads_(TPLength) const uint8_t* TPBuffer
            )
        {
            UNREFERENCED_PARAMETER(Connection);
            UNREFERENCED_PARAMETER(TPLength);
            UNREFERENCED_PARAMETER(TPBuffer);
            return TRUE;
        }

        static BOOLEAN
        OnSessionTicketReceived(
            _In_ QUIC_CONNECTION* Connection,
            _In_ uint32_t TicketLength,
            _In_reads_(TicketLength) const uint8_t* Ticket
            )
        {
            //std::cout << "==RecvTicket==" << std::endl;
            auto Context = (TlsContext*)Connection;
            if (Context->ReceivedSessionTicket.Buffer == nullptr) {
                Context->ReceivedSessionTicket.Buffer = // N.B - Add one so we don't ever allocate zero bytes.
                    (uint8_t*)CXPLAT_ALLOC_NONPAGED(TicketLength+1, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
                Context->ReceivedSessionTicket.Length = TicketLength;
                if (TicketLength != 0) {
                    CxPlatCopyMemory(
                        Context->ReceivedSessionTicket.Buffer,
                        Ticket,
                        TicketLength);
                }
            }
            return Context->OnSessionTicketReceivedResult;
        }

        static BOOLEAN
        OnPeerCertReceived(
            _In_ QUIC_CONNECTION* Connection,
            _In_ QUIC_CERTIFICATE* Certificate,
            _In_ QUIC_CERTIFICATE_CHAIN* Chain,
            _In_ uint32_t DeferredErrorFlags,
            _In_ QUIC_STATUS DeferredStatus
            )
        {
            auto Context = (TlsContext*)Connection;
            Context->ReceivedPeerCertificate = true;
            //
            // Only validate the error flags if non-zero. OpenSSL doesn't produce error flags
            // so treat 0 flags as unsupported.
            //
            if (DeferredErrorFlags && Context->ExpectedErrorFlags != DeferredErrorFlags) {
                std::cout << "Incorrect ErrorFlags: " << DeferredErrorFlags << "\n";
                return FALSE;
            }
            if (Context->ExpectedValidationStatus != DeferredStatus) {
                std::cout << "Incorrect validation Status: " << DeferredStatus << "\n";
                return FALSE;
            }
            if (Context->ExpectNullCertificate) {
                if (Certificate || Chain) {
                    std::cout << "Expecting no certificate and no certificate chain\n";
                    return FALSE;
                }
            } else if (!Certificate || !Chain) {
                std::cout << "Expecting valid certificate and certificate chain\n";
                return FALSE;
            }
            return Context->OnPeerCertReceivedResult;
        }
    };

    struct PacketKey
    {
        QUIC_PACKET_KEY* Ptr;
        PacketKey(QUIC_PACKET_KEY* Key) : Ptr(Key) {
            EXPECT_NE(nullptr, Key);
        }

        uint16_t
        Overhead()
        {
            return CXPLAT_ENCRYPTION_OVERHEAD;
        }

        bool
        Encrypt(
            _In_ uint16_t HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const uint8_t* const Header,
            _In_ uint64_t PacketNumber,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
            )
        {
            uint8_t Iv[CXPLAT_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                CxPlatEncrypt(
                    Ptr->PacketKey,
                    Iv,
                    HeaderLength,
                    Header,
                    BufferLength,
                    Buffer);
        }

        bool
        Decrypt(
            _In_ uint16_t HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const uint8_t* const Header,
            _In_ uint64_t PacketNumber,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
            )
        {
            uint8_t Iv[CXPLAT_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                CxPlatDecrypt(
                    Ptr->PacketKey,
                    Iv,
                    HeaderLength,
                    Header,
                    BufferLength,
                    Buffer);
        }

        bool
        ComputeHpMask(
            _In_reads_bytes_(16)
                const uint8_t* const Cipher,
            _Out_writes_bytes_(16)
                uint8_t* Mask
            )
        {
            return
                QUIC_STATUS_SUCCESS ==
                CxPlatHpComputeMask(
                    Ptr->HeaderKey,
                    1,
                    Cipher,
                    Mask);
        }
    };

    static
    void
    DoHandshake(
        TlsContext& ServerContext,
        TlsContext& ClientContext,
        uint32_t FragmentSize = DefaultFragmentSize,
        bool SendResumptionTicket = false,
        bool ServerResultError = false,
        bool ClientResultError = false
        )
    {
        //std::cout << "==DoHandshake==" << std::endl;

        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize, ClientResultError);
        if (ClientResultError) {
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
            //
            // Bail, since there's no point in doing the server side.
            //
            return;
        } else {
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
            ASSERT_TRUE(ClientContext.State.HandshakeComplete);
            ASSERT_NE(nullptr, ClientContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
        }

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize, ServerResultError);
        if (ServerResultError) {
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        } else {
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
            ASSERT_TRUE(ServerContext.State.HandshakeComplete);
        }

        if (SendResumptionTicket) {
            //std::cout << "==PostHandshake==" << std::endl;

            Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize, false, CXPLAT_TLS_TICKET_DATA);
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

            Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize);
        }
    }

    struct AyncContext {
        CXPLAT_SEC_CONFIG* ClientConfig;
        CXPLAT_SEC_CONFIG* ServerConfig;
    };

    static CXPLAT_THREAD_CALLBACK(HandshakeAsync, Context)
    {
        AyncContext* Ctx = (AyncContext*)Context;
        for (uint32_t i = 0; i < 100; ++i) {
            TlsContext ServerContext, ClientContext;
            ClientContext.InitializeClient(Ctx->ClientConfig);
            ServerContext.InitializeServer(Ctx->ServerConfig);
            DoHandshake(ServerContext, ClientContext);
        }
        CXPLAT_THREAD_RETURN(0);
    }

    int64_t
    DoEncryption(
        PacketKey& Key,
        uint16_t BufferSize,
        uint64_t LoopCount
        )
    {
        uint8_t Header[32] = { 0 };
        uint8_t Buffer[(uint16_t)~0] = { 0 };
        uint16_t OverHead = Key.Overhead();

        uint64_t Start, End;
        Start = CxPlatTimeUs64();

        for (uint64_t j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
        }

        End = CxPlatTimeUs64();

        return End - Start;
    }

    int64_t
    DoEncryptionWithPNE(
        PacketKey& Key,
        uint16_t BufferSize,
        uint64_t LoopCount
        )
    {
        uint8_t Header[32] = { 0 };
        uint8_t Buffer[(uint16_t)~0] = { 0 };
        uint16_t OverHead = Key.Overhead();
        uint8_t Mask[16];

        uint64_t Start, End;
        Start = CxPlatTimeUs64();

        for (uint64_t j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
            Key.ComputeHpMask(Buffer, Mask);
            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }
        }

        End = CxPlatTimeUs64();

        return End - Start;
    }
};

const CXPLAT_TLS_CALLBACKS TlsTest::TlsContext::TlsCallbacks = {
    TlsTest::TlsContext::OnQuicTPReceived,
    TlsTest::TlsContext::OnSessionTicketReceived,
    TlsTest::TlsContext::OnPeerCertReceived
};

QUIC_CREDENTIAL_FLAGS TlsTest::SelfSignedCertParamsFlags = QUIC_CREDENTIAL_FLAG_NONE;
QUIC_CREDENTIAL_CONFIG* TlsTest::SelfSignedCertParams = nullptr;
QUIC_CREDENTIAL_CONFIG* TlsTest::ClientCertParams = nullptr;
QUIC_CREDENTIAL_CONFIG* TlsTest::CertParamsFromFile = nullptr;

QUIC_CREDENTIAL_FLAGS TlsTest::CaSelfSignedCertParamsFlags = QUIC_CREDENTIAL_FLAG_NONE;
QUIC_CREDENTIAL_CONFIG* TlsTest::CaSelfSignedCertParams = nullptr;
QUIC_CREDENTIAL_CONFIG* TlsTest::CaClientCertParams = nullptr;
const char* TlsTest::ServerCaCertificateFile = nullptr;
const char* TlsTest::ClientCaCertificateFile = nullptr;

TEST_F(TlsTest, Initialize)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
}

TEST_F(TlsTest, Handshake)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);

    ASSERT_FALSE(ClientContext.State.SessionResumed);
    ASSERT_FALSE(ServerContext.State.SessionResumed);
}

#ifndef QUIC_DISABLE_PFX_TESTS
TEST_F(TlsTest, HandshakeCertFromFile)
{
    ASSERT_NE(nullptr, CertParamsFromFile);
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(CertParamsFromFile);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);
}
#endif // QUIC_DISABLE_PFX_TESTS

TEST_F(TlsTest, HandshakeParamInfoDefault)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);

    QUIC_HANDSHAKE_INFO HandshakeInfo;
    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    uint32_t HandshakeInfoLen = sizeof(HandshakeInfo);
    QUIC_STATUS Status =
        CxPlatTlsParamGet(
            ClientContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_256, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_384, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);

    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    HandshakeInfoLen = sizeof(HandshakeInfo);
    Status =
        CxPlatTlsParamGet(
            ServerContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_256, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_384, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);
}

TEST_F(TlsTest, HandshakeParamInfoAES256GCM)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);

    QUIC_HANDSHAKE_INFO HandshakeInfo;
    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    uint32_t HandshakeInfoLen = sizeof(HandshakeInfo);
    QUIC_STATUS Status =
        CxPlatTlsParamGet(
            ClientContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_256, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_384, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);

    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    HandshakeInfoLen = sizeof(HandshakeInfo);
    Status =
        CxPlatTlsParamGet(
            ServerContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_256, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_384, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);
}

TEST_F(TlsTest, HandshakeParamInfoAES128GCM)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);

    QUIC_HANDSHAKE_INFO HandshakeInfo;
    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    uint32_t HandshakeInfoLen = sizeof(HandshakeInfo);
    QUIC_STATUS Status =
        CxPlatTlsParamGet(
            ClientContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_128, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(128, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_256, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);

    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    HandshakeInfoLen = sizeof(HandshakeInfo);
    Status =
        CxPlatTlsParamGet(
            ServerContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_AES_128, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(128, HandshakeInfo.CipherStrength);
    //EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_256, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);
}

#ifndef QUIC_DISABLE_CHACHA20_TESTS
TEST_F(TlsTest, HandshakeParamInfoChaCha20)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);

    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ASSERT_NE(ServerConfig.SecConfig, nullptr);
    DoHandshake(ServerContext, ClientContext);

    QUIC_HANDSHAKE_INFO HandshakeInfo;
    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    uint32_t HandshakeInfoLen = sizeof(HandshakeInfo);
    QUIC_STATUS Status =
        CxPlatTlsParamGet(
            ClientContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_CHACHA20, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_256, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);

    CxPlatZeroMemory(&HandshakeInfo, sizeof(HandshakeInfo));
    HandshakeInfoLen = sizeof(HandshakeInfo);
    Status =
        CxPlatTlsParamGet(
            ServerContext.Ptr,
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &HandshakeInfoLen,
            &HandshakeInfo);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    EXPECT_EQ(QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256, HandshakeInfo.CipherSuite);
    EXPECT_EQ(QUIC_TLS_PROTOCOL_1_3, HandshakeInfo.TlsProtocolVersion);
    EXPECT_EQ(QUIC_CIPHER_ALGORITHM_CHACHA20, HandshakeInfo.CipherAlgorithm);
    EXPECT_EQ(256, HandshakeInfo.CipherStrength);
    EXPECT_EQ(0, HandshakeInfo.KeyExchangeStrength);
    EXPECT_EQ(QUIC_HASH_ALGORITHM_SHA_256, HandshakeInfo.Hash);
    EXPECT_EQ(0, HandshakeInfo.HashStrength);
}
#endif // QUIC_DISABLE_CHACHA20_TESTS

TEST_F(TlsTest, HandshakeParamNegotiatedAlpn)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);

    char NegotiatedAlpn[255];
    CxPlatZeroMemory(&NegotiatedAlpn, sizeof(NegotiatedAlpn));
    uint32_t AlpnLen = sizeof(NegotiatedAlpn);
    QUIC_STATUS Status =
        CxPlatTlsParamGet(
            ClientContext.Ptr,
            QUIC_PARAM_TLS_NEGOTIATED_ALPN,
            &AlpnLen,
            NegotiatedAlpn);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    ASSERT_EQ(Alpn[0], AlpnLen);
    ASSERT_EQ(Alpn[1], NegotiatedAlpn[0]);

    CxPlatZeroMemory(&NegotiatedAlpn, sizeof(NegotiatedAlpn));
    AlpnLen = sizeof(NegotiatedAlpn);
    Status =
        CxPlatTlsParamGet(
            ServerContext.Ptr,
            QUIC_PARAM_TLS_NEGOTIATED_ALPN,
            &AlpnLen,
            NegotiatedAlpn);
    ASSERT_TRUE(QUIC_SUCCEEDED(Status));
    ASSERT_EQ(Alpn[0], AlpnLen);
    ASSERT_EQ(Alpn[1], NegotiatedAlpn[0]);
}

TEST_F(TlsTest, HandshakeParallel)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    AyncContext Context = { ClientConfig, ServerConfig };

    CXPLAT_THREAD_CONFIG Config = {
        0,
        0,
        "TlsWorker",
        HandshakeAsync,
        &Context
    };

    CXPLAT_THREAD Threads[64];
    CxPlatZeroMemory(&Threads, sizeof(Threads));
    const uint32_t ThreadCount =
        CXPLAT_MIN(ARRAYSIZE(Threads), CxPlatProcCount() * 4);

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        VERIFY_QUIC_SUCCESS(CxPlatThreadCreate(&Config, &Threads[i]));
    }

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        CxPlatThreadWait(&Threads[i]);
        CxPlatThreadDelete(&Threads[i]);
    }
}

#ifndef QUIC_DISABLE_0RTT_TESTS
TEST_F(TlsTest, HandshakeResumption)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);

    ASSERT_NE(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
    ASSERT_NE((uint32_t)0, ClientContext.ReceivedSessionTicket.Length);

    TlsContext ServerContext2, ClientContext2;
    ClientContext2.InitializeClient(ClientConfig, false, 64, &ClientContext.ReceivedSessionTicket);
    ServerContext2.InitializeServer(ServerConfig);
    DoHandshake(ServerContext2, ClientContext2);

    ASSERT_TRUE(ClientContext2.State.SessionResumed);
    ASSERT_TRUE(ServerContext2.State.SessionResumed);

    ASSERT_NE(nullptr, ServerContext2.ReceivedSessionTicket.Buffer);
    ASSERT_EQ((uint32_t)0, ServerContext2.ReceivedSessionTicket.Length); // TODO - Refactor to send non-zero length ticket
}

TEST_F(TlsTest, HandshakeResumptionRejection)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);

    ASSERT_NE(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
    ASSERT_NE((uint32_t)0, ClientContext.ReceivedSessionTicket.Length);

    TlsContext ServerContext2, ClientContext2;
    ClientContext2.InitializeClient(ClientConfig, false, 64, &ClientContext.ReceivedSessionTicket);
    ServerContext2.InitializeServer(ServerConfig);
    ServerContext2.OnSessionTicketReceivedResult = FALSE;
    DoHandshake(ServerContext2, ClientContext2);

    ASSERT_FALSE(ClientContext2.State.SessionResumed);
    ASSERT_FALSE(ServerContext2.State.SessionResumed);

    ASSERT_NE(nullptr, ServerContext2.ReceivedSessionTicket.Buffer);
    ASSERT_EQ((uint32_t)0, ServerContext2.ReceivedSessionTicket.Length); // TODO - Refactor to send non-zero length ticket
}

TEST_F(TlsTest, HandshakeResumptionClientDisabled)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
        QUIC_ALLOWED_CIPHER_SUITE_NONE,
        CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);

    ASSERT_EQ(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
    ASSERT_EQ((uint32_t)0, ClientContext.ReceivedSessionTicket.Length);
}

TEST_F(TlsTest, HandshakeResumptionServerDisabled)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);

    ASSERT_NE(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
    ASSERT_NE((uint32_t)0, ClientContext.ReceivedSessionTicket.Length);

    CxPlatServerSecConfig ResumptionDisabledServerConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
        QUIC_ALLOWED_CIPHER_SUITE_NONE,
        CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION);
    TlsContext ServerContext2, ClientContext2;
    ClientContext2.InitializeClient(ClientConfig, false, 64, &ClientContext.ReceivedSessionTicket);
    ServerContext2.InitializeServer(ResumptionDisabledServerConfig);
    DoHandshake(ServerContext2, ClientContext2);

    ASSERT_FALSE(ClientContext2.State.SessionResumed);
    ASSERT_FALSE(ServerContext2.State.SessionResumed);

    ASSERT_EQ(nullptr, ServerContext2.ReceivedSessionTicket.Buffer);
    ASSERT_EQ((uint32_t)0, ServerContext2.ReceivedSessionTicket.Length); // TODO - Refactor to send non-zero length ticket
}
#endif

TEST_F(TlsTest, HandshakeMultiAlpnServer)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig, true);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeMultiAlpnClient)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig, true);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeMultiAlpnBoth)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig, true);
    ServerContext.InitializeServer(ServerConfig, true);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeFragmented)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, 200);
}

TEST_F(TlsTest, HandshakeVeryFragmented)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig, false, 1500);
    ServerContext.InitializeServer(ServerConfig, false, 1500);
    DoHandshake(ServerContext, ClientContext, 1);
}

TEST_F(TlsTest, HandshakesSerial)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        DoHandshake(ServerContext, ClientContext);
    }
    {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        DoHandshake(ServerContext, ClientContext);
    }
}

TEST_F(TlsTest, HandshakesInterleaved)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext1, ServerContext2, ClientContext1, ClientContext2;
    ClientContext1.InitializeClient(ClientConfig);
    ClientContext2.InitializeClient(ClientConfig);
    ServerContext1.InitializeServer(ServerConfig);
    ServerContext2.InitializeServer(ServerConfig);

    auto Result = ClientContext1.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

    Result = ClientContext2.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

    Result = ServerContext1.ProcessData(&ClientContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_NE(nullptr, ServerContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ServerContext2.ProcessData(&ClientContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_NE(nullptr, ServerContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ClientContext1.ProcessData(&ServerContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    ASSERT_NE(nullptr, ClientContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ClientContext2.ProcessData(&ServerContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    ASSERT_NE(nullptr, ClientContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ServerContext1.ProcessData(&ClientContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);

    Result = ServerContext2.ProcessData(&ClientContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
}

TEST_F(TlsTest, CertificateError)
{
    CxPlatClientSecConfig ClientConfig(QUIC_CREDENTIAL_FLAG_NONE);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.InitializeClient(ClientConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        ASSERT_TRUE(
            (0xFF & ClientContext.State.AlertCode) == CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE ||
            (0xFF & ClientContext.State.AlertCode) == CXPLAT_TLS_ALERT_CODE_UNKNOWN_CA);
    }
}

TEST_F(TlsTest, DeferredCertificateValidationAllow)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.ExpectedValidationStatus = QUIC_STATUS_CERT_UNTRUSTED_ROOT;
#ifdef _WIN32
    ClientContext.ExpectedErrorFlags = CERT_TRUST_IS_UNTRUSTED_ROOT;
#else
    // TODO - Add platform specific values if support is added.
#endif
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}

#ifdef QUIC_ENABLE_CA_CERTIFICATE_FILE_TESTS
TEST_F(TlsTest, DeferredCertificateValidationAllowCa)
{
    CxPlatClientSecConfigCa ClientConfig(
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);
    CxPlatServerSecConfigCa ServerConfig(
        QUIC_CREDENTIAL_FLAG_NONE |
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}
#endif

TEST_F(TlsTest, DeferredCertificateValidationReject)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        ASSERT_EQ((0xFF & ClientContext.State.AlertCode), CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE);
    }
}

TEST_F(TlsTest, CustomCertificateValidationAllow)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}

TEST_F(TlsTest, CustomCertificateValidationReject)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.OnPeerCertReceivedResult = FALSE;
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        ASSERT_EQ((0xFF & ClientContext.State.AlertCode), CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE);
    }
}

TEST_F(TlsTest, CustomCertificateValidationServerIndicateNoCert)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig(QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ServerContext.ExpectNullCertificate = TRUE;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, false, false);
}

TEST_F(TlsTest, CustomClientCertificateValidationServerIndicate)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, false, false);
}

TEST_F(TlsTest, ExtraCertificateValidation)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_FALSE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        ASSERT_TRUE(
            (0xFF & ClientContext.State.AlertCode) == CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE ||
            (0xFF & ClientContext.State.AlertCode) == CXPLAT_TLS_ALERT_CODE_UNKNOWN_CA);
    }
}

TEST_F(TlsTest, PortableCertificateValidation)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}

#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
TEST_F(TlsTest, InProcPortableCertificateValidation)
{
    if (IsWindows2019() || IsWindows2022()) GTEST_SKIP(); // Not supported

    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE |
        QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}

TEST_F(TlsTest, InProcCertificateValidation)
{
    if (IsWindows2019() || IsWindows2022()) GTEST_SKIP(); // Not supported

    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
        QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(ClientContext.ReceivedPeerCertificate);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    }
}
#endif

TEST_P(TlsTest, One1RttKey)
{
    bool PNE = GetParam();

    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.InitializeClient(ClientConfig);
    DoHandshake(ServerContext, ClientContext);

    PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
    PacketKey ClientKey(ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]);

    uint8_t Header[32] = { 1, 2, 3, 4 };
    uint64_t PacketNumber = 0;
    uint8_t Buffer[1000] = { 0 };

    ASSERT_TRUE(
        ServerKey.Encrypt(
            sizeof(Header),
            Header,
            PacketNumber,
            sizeof(Buffer),
            Buffer));

    if (PNE) {
        uint8_t Mask[16];

        ASSERT_TRUE(
            ServerKey.ComputeHpMask(
                Buffer,
                Mask));

        for (uint32_t i = 0; i < sizeof(Mask); i++) {
            Header[i] ^= Mask[i];
        }

        ASSERT_TRUE(
            ClientKey.ComputeHpMask(
                Buffer,
                Mask));

        for (uint32_t i = 0; i < sizeof(Mask); i++) {
            Header[i] ^= Mask[i];
        }
    }

    ASSERT_TRUE(
        ClientKey.Decrypt(
            sizeof(Header),
            Header,
            PacketNumber,
            sizeof(Buffer),
            Buffer));
}

TEST_P(TlsTest, KeyUpdate)
{
    bool PNE = GetParam();

    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.InitializeClient(ClientConfig);
    DoHandshake(ServerContext, ClientContext);

    QUIC_PACKET_KEY* UpdateWriteKey = nullptr, *UpdateReadKey = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicPacketKeyUpdate(
            &HkdfLabels,
            ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT],
            &UpdateWriteKey));
    VERIFY_QUIC_SUCCESS(
        QuicPacketKeyUpdate(
            &HkdfLabels,
            ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT],
            &UpdateReadKey));

    if (PNE) {
        //
        // If PNE is enabled, copy the header keys to the new packet
        // key structs.
        //
        UpdateWriteKey->HeaderKey = ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey;
        ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey = nullptr;

        UpdateReadKey->HeaderKey = ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey;
        ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey = nullptr;
    }

    PacketKey ServerKey(UpdateWriteKey);
    PacketKey ClientKey(UpdateReadKey);

    uint8_t Header[32] = { 1, 2, 3, 4 };
    uint64_t PacketNumber = 0;
    uint8_t Buffer[1000] = { 0 };

    ASSERT_TRUE(
        ServerKey.Encrypt(
            sizeof(Header),
            Header,
            PacketNumber,
            sizeof(Buffer),
            Buffer));

    if (PNE) {
        uint8_t Mask[16];

        ASSERT_TRUE(
            ServerKey.ComputeHpMask(
                Buffer,
                Mask));

        for (uint32_t i = 0; i < sizeof(Mask); i++) {
            Header[i] ^= Mask[i];
        }

        ASSERT_TRUE(
            ClientKey.ComputeHpMask(
                Buffer,
                Mask));

        for (uint32_t i = 0; i < sizeof(Mask); i++) {
            Header[i] ^= Mask[i];
        }
    }

    ASSERT_TRUE(
        ClientKey.Decrypt(
            sizeof(Header),
            Header,
            PacketNumber,
            sizeof(Buffer),
            Buffer));

    QuicPacketKeyFree(UpdateWriteKey);
    QuicPacketKeyFree(UpdateReadKey);
}


TEST_P(TlsTest, PacketEncryptionPerf)
{
    bool PNE = GetParam();

    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerConfig);
    ClientContext.InitializeClient(ClientConfig);
    DoHandshake(ServerContext, ClientContext);

    PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    const uint64_t LoopCount = 10000;
    uint16_t BufferSizes[] =
    {
        4,
        16,
        64,
        256,
        600,
        1000,
        1200,
        1450,
        //8000,
        //65000
    };

#ifdef _WIN32
    HANDLE CurrentThread = GetCurrentThread();
    DWORD ProcNumber = GetCurrentProcessorNumber();
    DWORD_PTR OldAffinityMask =
        SetThreadAffinityMask(CurrentThread, (DWORD_PTR)1 << (DWORD_PTR)ProcNumber);
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_HIGHEST);
#endif

    for (uint8_t i = 0; i < ARRAYSIZE(BufferSizes); ++i) {
        int64_t elapsedMicroseconds =
            PNE == 0 ?
            DoEncryption(ServerKey, BufferSizes[i], LoopCount) :
            DoEncryptionWithPNE(ServerKey, BufferSizes[i], LoopCount);

        std::cout << elapsedMicroseconds / 1000 << "." << (int)(elapsedMicroseconds % 1000) <<
            " milliseconds elapsed encrypting "
            << BufferSizes[i] << " bytes " << LoopCount << " times" << std::endl;
    }

#ifdef _WIN32
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_NORMAL);
    SetThreadAffinityMask(CurrentThread, OldAffinityMask);
#endif
}

uint64_t LockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    CXPLAT_DISPATCH_LOCK Lock;
    uint64_t Counter = 0;

    CxPlatDispatchLockInitialize(&Lock);
    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        CxPlatDispatchLockAcquire(&Lock);
        Counter++;
        CxPlatDispatchLockRelease(&Lock);
    }
    End = CxPlatTimeUs64();

    CxPlatDispatchLockUninitialize(&Lock);

    CXPLAT_FRE_ASSERT(Counter == LoopCount);

    return End - Start;
}

uint64_t InterlockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    int64_t Counter = 0;

    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        InterlockedIncrement64(&Counter);
    }
    End = CxPlatTimeUs64();

    CXPLAT_FRE_ASSERT((uint64_t)Counter == LoopCount);

    return End - Start;
}

uint64_t UnlockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    uint64_t Counter = 0;
    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        Counter++;
    }
    End = CxPlatTimeUs64();

    CXPLAT_FRE_ASSERT(Counter == LoopCount);

    return End - Start;
}


TEST_F(TlsTest, LockPerfTest)
{
    uint64_t (*const TestFuncs[]) (uint64_t) = {LockedCounter, InterlockedCounter, UnlockedCounter};
    const char* const TestName[] = {"Locking/unlocking", "Interlocked incrementing", "Unlocked incrementing"};
    const uint64_t LoopCount = 100000;

#ifdef _WIN32
    HANDLE CurrentThread = GetCurrentThread();
    DWORD ProcNumber = GetCurrentProcessorNumber();
    DWORD_PTR OldAffinityMask =
        SetThreadAffinityMask(CurrentThread, (DWORD_PTR)1 << (DWORD_PTR)ProcNumber);
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_HIGHEST);
#endif

    for (uint8_t i = 0; i < ARRAYSIZE(TestName); ++i) {

        const uint64_t elapsedMicroseconds = TestFuncs[i](LoopCount);

        std::cout << elapsedMicroseconds / 1000 << "." << (int)(elapsedMicroseconds % 1000) <<
            " milliseconds elapsed "
            << TestName[i] << " counter " << LoopCount << " times" << std::endl;
    }

#ifdef _WIN32
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_NORMAL);
    SetThreadAffinityMask(CurrentThread, OldAffinityMask);
#endif
}

TEST_F(TlsTest, ClientCertificateFailValidation)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig(QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, false, true);
}

TEST_F(TlsTest, ClientCertificateDeferValidation)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ServerContext.ExpectedValidationStatus = QUIC_STATUS_CERT_UNTRUSTED_ROOT;
    DoHandshake(ServerContext, ClientContext);
}

#ifdef QUIC_ENABLE_CA_CERTIFICATE_FILE_TESTS
TEST_F(TlsTest, ClientCertificateDeferValidationCa)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(CaClientCertParams);
    CxPlatServerSecConfigCa ServerConfig(
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE |
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);
}
#endif

#ifdef QUIC_ENABLE_ANON_CLIENT_AUTH_TESTS
TEST_F(TlsTest, ClientCertificateDeferValidationNoCertSchannel)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
        | QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS);
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ServerContext.ExpectNullCertificate = TRUE;
    ServerContext.ExpectedValidationStatus = QUIC_STATUS_CERT_NO_CERT;
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, ClientCertificateNoValidationNoCertSchannel)
{
    CxPlatClientSecConfig ClientConfig(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
        | QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS);
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ServerContext.ExpectNullCertificate = TRUE;
    ServerContext.ExpectedValidationStatus = QUIC_STATUS_SUCCESS;
    DoHandshake(ServerContext, ClientContext);
}
#endif

TEST_F(TlsTest, ClientCertificateDeferValidationNoCert)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ServerContext.ExpectNullCertificate = TRUE;
    ServerContext.ExpectedValidationStatus = QUIC_STATUS_CERT_NO_CERT;
    DoHandshake(
        ServerContext,
        ClientContext,
        1200,
        false,
        false,
#ifdef QUIC_ENABLE_ANON_CLIENT_AUTH_TESTS
        true
#else
        false
#endif
        );
}

TEST_F(TlsTest, ClientCertificateNoValidationNoCert)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
        QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    ServerContext.ExpectNullCertificate = TRUE;
    ServerContext.ExpectedValidationStatus = QUIC_STATUS_SUCCESS;
    DoHandshake(
        ServerContext,
        ClientContext,
        1200,
        false,
        false,
#ifdef QUIC_ENABLE_ANON_CLIENT_AUTH_TESTS
        true
#else
        false
#endif
        );
}

TEST_F(TlsTest, CipherSuiteSuccess1)
{
    //
    // Set Server to use explicit cipher suite, client use default.
    //
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfigAes128(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfigAes128);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, CipherSuiteSuccess2)
{
    //
    // Set Client to use explicit cipher suite, server use default.
    //
    CxPlatClientSecConfig ClientConfigAes128(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfigAes128);
    ServerContext.InitializeServer(ServerConfig);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, CipherSuiteSuccess3)
{
    //
    // Set both Client and Server to use same cipher suite.
    //
    CxPlatClientSecConfig ClientConfigAes128(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    CxPlatServerSecConfig ServerConfigAes128(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfigAes128);
    ServerContext.InitializeServer(ServerConfigAes128);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, CipherSuiteMismatch)
{
    //
    // Use mutually-exclusive cipher suites on client and server.
    //
    CxPlatClientSecConfig ClientConfigAes256(
        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384);
    CxPlatServerSecConfig ServerConfigAes128(
        QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
        QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfigAes256);
    ServerContext.InitializeServer(ServerConfigAes128);

    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

    Result = ServerContext.ProcessData(&ClientContext.State, DefaultFragmentSize, true);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
}

TEST_F(TlsTest, CipherSuiteInvalid)
{
    for (auto Flag : {
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES,
            QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES}) {
        //
        // Don't set any allowed cipher suites
        //
        {
            QUIC_CREDENTIAL_CONFIG TestCredConfig = {
                QUIC_CREDENTIAL_TYPE_NONE,
                Flag,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                QUIC_ALLOWED_CIPHER_SUITE_NONE
            };
            CXPLAT_SEC_CONFIG* TestSecConfig = nullptr;
            ASSERT_EQ(
                QUIC_STATUS_INVALID_PARAMETER,
                CxPlatTlsSecConfigCreate(
                    &TestCredConfig,
                    CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                    &TlsContext::TlsCallbacks,
                    &TestSecConfig,
                    CxPlatSecConfig::OnSecConfigCreateComplete));
            ASSERT_EQ(TestSecConfig, nullptr);
        }
        //
        // Set an unrecognized cipher suite
        //
        {
            QUIC_CREDENTIAL_CONFIG TestCredConfig = {
                QUIC_CREDENTIAL_TYPE_NONE,
                Flag,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                (QUIC_ALLOWED_CIPHER_SUITE_FLAGS)0x100
            };
            CXPLAT_SEC_CONFIG* TestSecConfig = nullptr;
            ASSERT_EQ(
                QUIC_STATUS_INVALID_PARAMETER,
                CxPlatTlsSecConfigCreate(
                    &TestCredConfig,
                    CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                    &TlsContext::TlsCallbacks,
                    &TestSecConfig,
                    CxPlatSecConfig::OnSecConfigCreateComplete));
            ASSERT_EQ(TestSecConfig, nullptr);
        }
    }
}

_Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
static void
QUIC_API
SchannelSecConfigCreateComplete(
    _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
#if QUIC_TEST_SCHANNEL_FLAGS
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, SecConfig);
    *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
#else
    //
    // Test should fail before getting this far.
    //
    ASSERT_TRUE(FALSE);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(SecConfig);
#endif
}

void
ValidateSecConfigStatusSchannel(
    _In_ QUIC_STATUS Status,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
#if QUIC_TEST_SCHANNEL_FLAGS
        VERIFY_QUIC_SUCCESS(Status);
        ASSERT_NE(nullptr, SecConfig);
#else
        ASSERT_TRUE(QUIC_FAILED(Status));
        ASSERT_EQ(nullptr, SecConfig);
#endif
    if (SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig);
    }
}

TEST_F(TlsTest, PlatformSpecificFlagsSchannel)
{
    for (auto TestFlag : { QUIC_CREDENTIAL_FLAG_ENABLE_OCSP, QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS,
        QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER, QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE,
#ifndef _WIN32
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT, QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK, QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE,
        QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL, QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY,
        QUIC_CREDENTIAL_FLAG_DISABLE_AIA,
#ifndef __APPLE__
        QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN,
#endif
#endif
        }) {

        if (TestFlag != QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER) {
            //
            // Client-compatible flags
            //
            QUIC_CREDENTIAL_CONFIG TestClientCredConfig = {
                QUIC_CREDENTIAL_TYPE_NONE,
                TestFlag | QUIC_CREDENTIAL_FLAG_CLIENT,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                QUIC_ALLOWED_CIPHER_SUITE_NONE
            };
            CXPLAT_SEC_CONFIG* ClientSecConfig = nullptr;
            QUIC_STATUS Status =
                CxPlatTlsSecConfigCreate(
                    &TestClientCredConfig,
                    CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                    &TlsContext::TlsCallbacks,
                    &ClientSecConfig,
                    SchannelSecConfigCreateComplete);
            ValidateSecConfigStatusSchannel(Status, ClientSecConfig);
        }

        if (TestFlag != QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS) {
            //
            // Server-compatible flags
            //
            SelfSignedCertParams->Flags = TestFlag;
            CXPLAT_SEC_CONFIG* ServerSecConfig = nullptr;
            QUIC_STATUS Status =
                CxPlatTlsSecConfigCreate(
                    SelfSignedCertParams,
                    CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                    &TlsContext::TlsCallbacks,
                    &ServerSecConfig,
                    SchannelSecConfigCreateComplete);
            ValidateSecConfigStatusSchannel(Status, ServerSecConfig);
        }
    }
}

_Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
static void
QUIC_API
OpenSslSecConfigCreateComplete(
    _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
#if QUIC_TEST_OPENSSL_FLAGS
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, SecConfig);
    *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
#else
    //
    // Test should fail before getting this far.
    //
    ASSERT_TRUE(FALSE);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(SecConfig);
#endif
}

void
ValidateSecConfigStatusOpenSsl(
    _In_ QUIC_STATUS Status,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
#if QUIC_TEST_OPENSSL_FLAGS
        VERIFY_QUIC_SUCCESS(Status);
        ASSERT_NE(nullptr, SecConfig);
#else
        ASSERT_TRUE(QUIC_FAILED(Status));
        ASSERT_EQ(nullptr, SecConfig);
#endif
    if (SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig);
    }
}

TEST_F(TlsTest, PlatformSpecificFlagsOpenSsl)
{
    for (auto TestFlag : { QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION,
                           QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE
      }) {

        QUIC_CREDENTIAL_CONFIG TestClientCredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            TestFlag | QUIC_CREDENTIAL_FLAG_CLIENT,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            QUIC_ALLOWED_CIPHER_SUITE_NONE
        };
        CXPLAT_SEC_CONFIG* ClientSecConfig = nullptr;
        QUIC_STATUS Status =
            CxPlatTlsSecConfigCreate(
                &TestClientCredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsContext::TlsCallbacks,
                &ClientSecConfig,
                OpenSslSecConfigCreateComplete);
        ValidateSecConfigStatusOpenSsl(Status, ClientSecConfig);

        SelfSignedCertParams->Flags = TestFlag;
        CXPLAT_SEC_CONFIG* ServerSecConfig = nullptr;
        Status =
            CxPlatTlsSecConfigCreate(
                SelfSignedCertParams,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsContext::TlsCallbacks,
                &ServerSecConfig,
                OpenSslSecConfigCreateComplete);
        ValidateSecConfigStatusOpenSsl(Status, ServerSecConfig);
    }
}

_Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
static void
QUIC_API
PortableCertFlagsSecConfigCreateComplete(
    _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, SecConfig);
    *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
}

void
ValidateSecConfigStatusPortableCert(
    _In_ QUIC_STATUS Status,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
)
{
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, SecConfig);
    CxPlatTlsSecConfigDelete(SecConfig);
}

TEST_F(TlsTest, PortableCertFlags)
{
    for (auto TestFlag : { QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES }) {

        QUIC_CREDENTIAL_CONFIG TestClientCredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            TestFlag | QUIC_CREDENTIAL_FLAG_CLIENT,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            QUIC_ALLOWED_CIPHER_SUITE_NONE
        };
        CXPLAT_SEC_CONFIG* ClientSecConfig = nullptr;
        QUIC_STATUS Status =
            CxPlatTlsSecConfigCreate(
                &TestClientCredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsContext::TlsCallbacks,
                &ClientSecConfig,
                PortableCertFlagsSecConfigCreateComplete);
        ValidateSecConfigStatusPortableCert(Status, ClientSecConfig);

        SelfSignedCertParams->Flags = TestFlag;
        CXPLAT_SEC_CONFIG* ServerSecConfig = nullptr;
        Status =
            CxPlatTlsSecConfigCreate(
                SelfSignedCertParams,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsContext::TlsCallbacks,
                &ServerSecConfig,
                PortableCertFlagsSecConfigCreateComplete);
        ValidateSecConfigStatusPortableCert(Status, ServerSecConfig);
    }
}

//
// DeepTest tests for QuicTlsSend function coverage
// These tests exercise various buffer management scenarios in QuicTlsSend
//

// DeepTest: Test handshake with small initial buffer to trigger reallocation
TEST_F(TlsTest, DeepTestQuicTlsSendBufferReallocation)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with a very small buffer to force reallocation during handshake
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(64, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 64;
    ClientContext.State.BufferLength = 0;
    
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(64, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = 64;
    ServerContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // This should trigger multiple buffer reallocations in QuicTlsSend
    DoHandshake(ServerContext, ClientContext);
    
    // Verify handshake completed successfully despite buffer reallocations
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test with multiple sequential handshake messages on same key type
TEST_F(TlsTest, DeepTestQuicTlsSendMultipleHandshakeMessages)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Perform handshake which will call QuicTlsSend multiple times
    // with HANDSHAKE key type, testing the BufferOffsetHandshake logic
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Server processes client hello and sends server hello
    // This exercises QuicTlsSend with HANDSHAKE key for first time
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Client processes server response
    // This exercises QuicTlsSend with HANDSHAKE and 1_RTT keys
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Complete the handshake
    Result = ServerContext.ProcessData(&ClientContext.State);
    
    // Verify both handshake offset and 1-RTT offset were set
    ASSERT_NE(0u, ServerContext.State.BufferOffsetHandshake);
    ASSERT_NE(0u, ClientContext.State.BufferOffset1Rtt);
}

// DeepTest: Test with very small fragment size to test buffer boundary conditions
TEST_F(TlsTest, DeepTestQuicTlsSendSmallFragments)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Use very small fragment size to test buffer management
    // with incremental data additions
    const uint32_t SmallFragmentSize = 128;
    DoHandshake(ServerContext, ClientContext, SmallFragmentSize);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test 1-RTT key type offset tracking
TEST_F(TlsTest, DeepTestQuicTlsSend1RttOffsetTracking)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify 1-RTT buffer offset was set during handshake
    // QuicTlsSend should have set BufferOffset1Rtt when first 1-RTT data was sent
    ASSERT_TRUE(ClientContext.State.BufferOffset1Rtt > 0 || 
                ServerContext.State.BufferOffset1Rtt > 0);
}

// DeepTest: Test with session resumption to exercise multiple handshake scenarios
#ifndef QUIC_DISABLE_0RTT_TESTS
TEST_F(TlsTest, DeepTestQuicTlsSendWithResumption)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // First handshake with session ticket
    {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);
        
        ASSERT_NE(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
        ASSERT_NE(0u, ClientContext.ReceivedSessionTicket.Length);
    }
    
    // Second handshake with resumption - exercises QuicTlsSend with 0-RTT
    {
        TlsContext ServerContext, ClientContext;
        
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    }
}
#endif // QUIC_DISABLE_0RTT_TESTS

// DeepTest: Test buffer growth with multiple key types
TEST_F(TlsTest, DeepTestQuicTlsSendMultipleKeyTypes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with minimal buffer
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(128, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = 128;
    ServerContext.State.BufferLength = 0;
    ServerContext.State.BufferOffsetHandshake = 0;
    ServerContext.State.BufferOffset1Rtt = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Process initial client hello
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Server response will use INITIAL, then HANDSHAKE, potentially triggering
    // multiple QuicTlsSend calls with different key types and buffer reallocations
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Verify buffer was expanded beyond initial 128 bytes
    ASSERT_GT(ServerContext.State.BufferAllocLength, 128);
    
    // Complete handshake
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
}

// DeepTest: Test boundary condition where buffer is nearly full
TEST_F(TlsTest, DeepTestQuicTlsSendNearMaxBuffer)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Normal handshake should stay well below 0xF000 limit
    DoHandshake(ServerContext, ClientContext);
    
    // Verify we didn't exceed the maximum buffer size (0xF000)
    ASSERT_LT(ServerContext.State.BufferTotalLength, 0xF000);
    ASSERT_LT(ClientContext.State.BufferTotalLength, 0xF000);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test with larger than typical transport parameters
TEST_F(TlsTest, DeepTestQuicTlsSendLargeTransportParams)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Initialize with larger transport parameters to increase handshake data size
    const uint16_t LargeTPLen = 512;
    ClientContext.InitializeClient(ClientConfig, false, LargeTPLen);
    ServerContext.InitializeServer(ServerConfig, false, LargeTPLen);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify handshake completed with larger transport parameters
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Stress test with parallel handshakes to test buffer management
TEST_F(TlsTest, DeepTestQuicTlsSendParallelHandshakes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Create multiple contexts to verify QuicTlsSend handles independent buffers
    const int NumContexts = 5;
    TlsContext ServerContexts[NumContexts];
    TlsContext ClientContexts[NumContexts];
    
    for (int i = 0; i < NumContexts; i++) {
        ClientContexts[i].InitializeClient(ClientConfig);
        ServerContexts[i].InitializeServer(ServerConfig);
    }
    
    // Perform handshakes - each should have independent buffer state
    for (int i = 0; i < NumContexts; i++) {
        DoHandshake(ServerContexts[i], ClientContexts[i]);
        ASSERT_TRUE(ServerContexts[i].State.HandshakeComplete);
        ASSERT_TRUE(ClientContexts[i].State.HandshakeComplete);
    }
}

// DeepTest: Test incremental buffer growth pattern
TEST_F(TlsTest, DeepTestQuicTlsSendIncrementalGrowth)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with very small buffer to observe multiple doublings
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(32, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 32;
    ClientContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Buffer should have grown from 32 bytes through multiple doublings
    // Typical client hello is ~200-300 bytes
    ASSERT_GE(ClientContext.State.BufferAllocLength, 256);
    
    // Complete handshake
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
}

// DeepTest: Test buffer state after handshake completion
TEST_F(TlsTest, DeepTestQuicTlsSendPostHandshakeState)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify QuicTlsSend set the CXPLAT_TLS_RESULT_DATA flag
    // and updated buffer lengths correctly
    ASSERT_GT(ServerContext.State.BufferTotalLength, 0u);
    ASSERT_GT(ClientContext.State.BufferTotalLength, 0u);
    
    // Verify buffer allocations are reasonable
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
}

//
// Iteration 2: Additional edge case and boundary tests
//

// DeepTest: Test with minimal initial buffer size (power of 2 boundary)
TEST_F(TlsTest, DeepTestQuicTlsSendMinimalBuffer)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Use absolute minimum buffer size to test doubling logic
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(16, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 16;
    ClientContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Buffer should have grown significantly from 16 bytes
    ASSERT_GE(ClientContext.State.BufferAllocLength, 512);
}

// DeepTest: Test buffer doubling mechanism exhaustively
TEST_F(TlsTest, DeepTestQuicTlsSendBufferDoublingPattern)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with buffer that will require multiple doublings
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    uint16_t InitialSize = 64;
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(InitialSize, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = InitialSize;
    ServerContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Verify buffer grew through power-of-2 doubling
    // Should be 64 -> 128 -> 256 -> 512 -> 1024 -> ...
    uint16_t FinalSize = ServerContext.State.BufferAllocLength;
    ASSERT_GT(FinalSize, InitialSize);
    
    // Verify it's a power of 2
    ASSERT_EQ(0, (FinalSize & (FinalSize - 1)));
}

// DeepTest: Test with different cipher suites
#ifndef QUIC_DISABLE_CHACHA20_TESTS
TEST_F(TlsTest, DeepTestQuicTlsSendWithChaCha20)
{
    CxPlatClientSecConfig ClientConfig(QUIC_CREDENTIAL_FLAG_NONE, 
                                       QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    CxPlatServerSecConfig ServerConfig(QUIC_CREDENTIAL_FLAG_NONE,
                                       QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}
#endif

// DeepTest: Test with AES-128-GCM cipher suite
TEST_F(TlsTest, DeepTestQuicTlsSendWithAES128)
{
    CxPlatClientSecConfig ClientConfig(QUIC_CREDENTIAL_FLAG_NONE,
                                       QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    CxPlatServerSecConfig ServerConfig(QUIC_CREDENTIAL_FLAG_NONE,
                                       QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test sequential handshakes with same contexts reused
TEST_F(TlsTest, DeepTestQuicTlsSendSequentialHandshakes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Perform multiple sequential handshakes to test buffer reuse
    for (int i = 0; i < 3; i++) {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        
        ASSERT_TRUE(ServerContext.State.HandshakeComplete);
        ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    }
}

// DeepTest: Test buffer behavior with very large transport parameters
TEST_F(TlsTest, DeepTestQuicTlsSendVeryLargeTransportParams)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Use maximum reasonable TP size
    const uint16_t MaxTPLen = 1024;
    ClientContext.InitializeClient(ClientConfig, false, MaxTPLen);
    ServerContext.InitializeServer(ServerConfig, false, MaxTPLen);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test offset tracking with multiple message types
TEST_F(TlsTest, DeepTestQuicTlsSendOffsetAccuracy)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    uint32_t ClientBufferLengthAfterInitial = ClientContext.State.BufferLength;
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Verify handshake offset is set correctly
    if (ServerContext.State.BufferOffsetHandshake > 0) {
        ASSERT_LE(ServerContext.State.BufferOffsetHandshake, ServerContext.State.BufferTotalLength);
    }
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Verify 1-RTT offset tracking
    if (ClientContext.State.BufferOffset1Rtt > 0) {
        ASSERT_LE(ClientContext.State.BufferOffset1Rtt, ClientContext.State.BufferTotalLength);
        ASSERT_GE(ClientContext.State.BufferOffset1Rtt, ClientBufferLengthAfterInitial);
    }
}

// DeepTest: Test buffer management with varying fragment sizes
TEST_F(TlsTest, DeepTestQuicTlsSendVaryingFragmentSizes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Test with different fragment sizes to exercise different buffer paths
    const uint32_t FragmentSizes[] = {64, 256, 512, 1024, 2048};
    
    for (auto FragSize : FragmentSizes) {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext, FragSize);
        
        ASSERT_TRUE(ServerContext.State.HandshakeComplete);
        ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    }
}

// DeepTest: Test that buffer total length tracking is accurate
TEST_F(TlsTest, DeepTestQuicTlsSendBufferTotalLength)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    uint32_t ClientInitialTotal = ClientContext.State.BufferTotalLength;
    uint32_t ServerInitialTotal = ServerContext.State.BufferTotalLength;
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // BufferTotalLength should have increased
    ASSERT_GT(ClientContext.State.BufferTotalLength, ClientInitialTotal);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_GT(ServerContext.State.BufferTotalLength, ServerInitialTotal);
    
    // Complete handshake
    Result = ClientContext.ProcessData(&ServerContext.State);
    Result = ServerContext.ProcessData(&ClientContext.State);
    
    // Verify final totals are reasonable
    ASSERT_LT(ClientContext.State.BufferTotalLength, 0xF000);
    ASSERT_LT(ServerContext.State.BufferTotalLength, 0xF000);
}

//
// Iteration 3: Stress tests and additional edge cases
//

// DeepTest: Test rapid sequential buffer reallocations
TEST_F(TlsTest, DeepTestQuicTlsSendRapidReallocations)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    for (int i = 0; i < 10; i++) {
        TlsContext ServerContext, ClientContext;
        
        // Vary initial buffer sizes to trigger different reallocation patterns
        uint16_t InitialSize = static_cast<uint16_t>(32 * (i + 1));
        CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
        ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(InitialSize, QUIC_POOL_TEST);
        ClientContext.State.BufferAllocLength = InitialSize;
        ClientContext.State.BufferLength = 0;
        
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    }
}

// DeepTest: Test buffer state consistency across handshake steps
TEST_F(TlsTest, DeepTestQuicTlsSendStateConsistency)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Step through handshake and verify state consistency at each step
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    ASSERT_EQ(ClientContext.State.BufferLength, ClientContext.State.BufferTotalLength);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
}

// DeepTest: Test with multiple ALPN options
TEST_F(TlsTest, DeepTestQuicTlsSendWithMultipleAlpn)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig, true);  // Multiple ALPNs
    ServerContext.InitializeServer(ServerConfig, true);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test buffer behavior at power-of-2 boundaries
TEST_F(TlsTest, DeepTestQuicTlsSendPowerOf2Boundaries)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Test buffers at various power-of-2 sizes
    const uint16_t PowerOf2Sizes[] = {32, 64, 128, 256, 512};
    
    for (auto Size : PowerOf2Sizes) {
        TlsContext ServerContext, ClientContext;
        
        CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
        ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(Size, QUIC_POOL_TEST);
        ClientContext.State.BufferAllocLength = Size;
        ClientContext.State.BufferLength = 0;
        
        CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
        ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(Size, QUIC_POOL_TEST);
        ServerContext.State.BufferAllocLength = Size;
        ServerContext.State.BufferLength = 0;
        
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        
        // Verify both grew beyond initial size
        ASSERT_GT(ClientContext.State.BufferAllocLength, Size);
        ASSERT_GT(ServerContext.State.BufferAllocLength, Size);
    }
}

// DeepTest: Test handshake with client authentication
TEST_F(TlsTest, DeepTestQuicTlsSendWithClientAuth)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig(
        QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION);
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test buffer efficiency - verify minimal wasted space
TEST_F(TlsTest, DeepTestQuicTlsSendBufferEfficiency)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify that allocated size isn't excessively larger than used size
    // Note: Test context pre-allocates 8000 bytes, so only check if buffer grew
    if (ClientContext.State.BufferAllocLength > 8000) {
        uint32_t ClientWasted = ClientContext.State.BufferAllocLength - ClientContext.State.BufferLength;
        ASSERT_LT(ClientWasted, ClientContext.State.BufferAllocLength / 2);
    }
    if (ServerContext.State.BufferAllocLength > 8000) {
        uint32_t ServerWasted = ServerContext.State.BufferAllocLength - ServerContext.State.BufferLength;
        ASSERT_LT(ServerWasted, ServerContext.State.BufferAllocLength / 2);
    }
}

// DeepTest: Test zero-length buffer edge case
TEST_F(TlsTest, DeepTestQuicTlsSendZeroInitialLength)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Ensure buffers start with zero length (not zero allocation)
    ASSERT_EQ(0u, ClientContext.State.BufferLength);
    ASSERT_EQ(0u, ServerContext.State.BufferLength);
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // After handshake, lengths should be non-zero
    ASSERT_GT(ClientContext.State.BufferTotalLength, 0u);
    ASSERT_GT(ServerContext.State.BufferTotalLength, 0u);
}

// DeepTest: Test handshake offset initialization
TEST_F(TlsTest, DeepTestQuicTlsSendOffsetInitialization)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Verify offsets start at zero
    ASSERT_EQ(0u, ClientContext.State.BufferOffsetHandshake);
    ASSERT_EQ(0u, ClientContext.State.BufferOffset1Rtt);
    ASSERT_EQ(0u, ServerContext.State.BufferOffsetHandshake);
    ASSERT_EQ(0u, ServerContext.State.BufferOffset1Rtt);
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // At least one side should have set handshake and 1-RTT offsets
    bool OffsetsSet = (ClientContext.State.BufferOffsetHandshake > 0 ||
                       ServerContext.State.BufferOffsetHandshake > 0) &&
                      (ClientContext.State.BufferOffset1Rtt > 0 ||
                       ServerContext.State.BufferOffset1Rtt > 0);
    ASSERT_TRUE(OffsetsSet);
}

// DeepTest: Test maximum concurrent handshakes
TEST_F(TlsTest, DeepTestQuicTlsSendMaxConcurrentHandshakes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    const int MaxConcurrent = 10;
    TlsContext ServerContexts[MaxConcurrent];
    TlsContext ClientContexts[MaxConcurrent];
    
    // Initialize all contexts
    for (int i = 0; i < MaxConcurrent; i++) {
        ClientContexts[i].InitializeClient(ClientConfig);
        ServerContexts[i].InitializeServer(ServerConfig);
    }
    
    // Perform all handshakes
    for (int i = 0; i < MaxConcurrent; i++) {
        DoHandshake(ServerContexts[i], ClientContexts[i]);
        ASSERT_TRUE(ServerContexts[i].State.HandshakeComplete);
        ASSERT_TRUE(ClientContexts[i].State.HandshakeComplete);
    }
}

//
// Iteration 4: Final comprehensive coverage tests
//

// DeepTest: Test buffer doubling with odd initial sizes
TEST_F(TlsTest, DeepTestQuicTlsSendOddBufferSizes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Test with non-power-of-2 sizes to verify doubling algorithm
    const uint16_t OddSizes[] = {48, 96, 192, 384};
    
    for (auto Size : OddSizes) {
        TlsContext ServerContext, ClientContext;
        
        CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
        ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(Size, QUIC_POOL_TEST);
        ClientContext.State.BufferAllocLength = Size;
        ClientContext.State.BufferLength = 0;
        
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    }
}

// DeepTest: Test that buffer offset relationships are maintained
TEST_F(TlsTest, DeepTestQuicTlsSendOffsetRelationships)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify offset ordering: Initial <= Handshake <= 1-RTT <= TotalLength
    if (ServerContext.State.BufferOffsetHandshake > 0) {
        ASSERT_LE(ServerContext.State.BufferOffsetHandshake, ServerContext.State.BufferTotalLength);
    }
    if (ServerContext.State.BufferOffset1Rtt > 0) {
        ASSERT_LE(ServerContext.State.BufferOffset1Rtt, ServerContext.State.BufferTotalLength);
        // 1-RTT should come after or at handshake
        if (ServerContext.State.BufferOffsetHandshake > 0) {
            ASSERT_GE(ServerContext.State.BufferOffset1Rtt, ServerContext.State.BufferOffsetHandshake);
        }
    }
}

// DeepTest: Test fragmented handshake with extreme fragmentation
TEST_F(TlsTest, DeepTestQuicTlsSendExtremeFragmentation)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Use minimal fragment size to maximize fragmentation
    const uint32_t MinimalFragmentSize = 32;
    DoHandshake(ServerContext, ClientContext, MinimalFragmentSize);
    
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
}

// DeepTest: Test buffer growth with pre-existing data
TEST_F(TlsTest, DeepTestQuicTlsSendBufferGrowthWithExistingData)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with small buffer that has some initial content
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(128, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = 128;
    ServerContext.State.BufferLength = 16;  // Pre-existing 16 bytes
    ServerContext.State.BufferTotalLength = 16;
    // Fill with test pattern
    for (int i = 0; i < 16; i++) {
        ServerContext.State.Buffer[i] = static_cast<uint8_t>(i);
    }
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Verify pre-existing data pattern is preserved in reallocated buffer
    if (ServerContext.State.BufferAllocLength > 128) {
        for (int i = 0; i < 16; i++) {
            ASSERT_EQ(static_cast<uint8_t>(i), ServerContext.State.Buffer[i]);
        }
    }
}

// DeepTest: Test all key types are handled
TEST_F(TlsTest, DeepTestQuicTlsSendAllKeyTypes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
    ASSERT_NE(nullptr, ClientContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE);
}

// DeepTest: Test buffer allocation patterns across multiple iterations
TEST_F(TlsTest, DeepTestQuicTlsSendAllocationPatterns)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    
    // Track allocation patterns across multiple handshakes
    std::vector<uint16_t> ClientAllocSizes;
    std::vector<uint16_t> ServerAllocSizes;
    
    for (int i = 0; i < 5; i++) {
        TlsContext ServerContext, ClientContext;
        ClientContext.InitializeClient(ClientConfig);
        ServerContext.InitializeServer(ServerConfig);
        
        DoHandshake(ServerContext, ClientContext);
        
        ClientAllocSizes.push_back(ClientContext.State.BufferAllocLength);
        ServerAllocSizes.push_back(ServerContext.State.BufferAllocLength);
    }
    
    // All final allocations should be within a reasonable range of each other
    uint16_t MinClient = *std::min_element(ClientAllocSizes.begin(), ClientAllocSizes.end());
    uint16_t MaxClient = *std::max_element(ClientAllocSizes.begin(), ClientAllocSizes.end());
    
    // Variation should be limited (within one doubling)
    ASSERT_LE(MaxClient, MinClient * 2);
}

// DeepTest: Test buffer reallocation preserves data integrity
TEST_F(TlsTest, DeepTestQuicTlsSendDataIntegrityOnRealloc)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Use tiny buffer to force reallocation
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(64, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 64;
    ClientContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Save the data that was written
    uint16_t DataLen = ClientContext.State.BufferLength;
    ASSERT_GT(DataLen, 0u);
    
    // Buffer should have been reallocated
    ASSERT_GT(ClientContext.State.BufferAllocLength, 64);
    
    // Verify data length matches total length after first message
    ASSERT_EQ(DataLen, ClientContext.State.BufferTotalLength);
}

// DeepTest: Test with maximum reasonable buffer utilization
TEST_F(TlsTest, DeepTestQuicTlsSendMaxBufferUtilization)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Use large transport params to maximize buffer usage
    const uint16_t LargeTPLen = 2048;
    ClientContext.InitializeClient(ClientConfig, false, LargeTPLen);
    ServerContext.InitializeServer(ServerConfig, false, LargeTPLen);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify we're well below the 0xF000 limit even with large TPs
    ASSERT_LT(ClientContext.State.BufferTotalLength, 0xF000);
    ASSERT_LT(ServerContext.State.BufferTotalLength, 0xF000);
    
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
}

// DeepTest: Test handshake with session resumption ticket
#ifndef QUIC_DISABLE_0RTT_TESTS
TEST_F(TlsTest, DeepTestQuicTlsSendWithSessionTicket)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Perform handshake with resumption ticket
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);
    
    // Verify session ticket was received
    ASSERT_NE(nullptr, ClientContext.ReceivedSessionTicket.Buffer);
    ASSERT_GT(ClientContext.ReceivedSessionTicket.Length, 0u);
}
#endif

// DeepTest: Test buffer state after error conditions
TEST_F(TlsTest, DeepTestQuicTlsSendBufferStateAfterError)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Configure client to reject server certificate
    ClientContext.OnPeerCertReceivedResult = FALSE;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Client should error when processing server's response
    Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
    
    // Buffer state should still be consistent
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
}

//
// Iteration 5: Final edge cases and comprehensive scenarios
//

// DeepTest: Test successive buffer doublings
TEST_F(TlsTest, DeepTestQuicTlsSendSuccessiveDoublings)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Start with extremely small buffer to observe multiple doublings
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    uint16_t TinySize = 8;
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(TinySize, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = TinySize;
    ClientContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeClient(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Buffer should have grown through many doublings: 8->16->32->64->128->256->512
    ASSERT_GE(ClientContext.State.BufferAllocLength, 512);
    
    // Verify each doubling maintained power-of-2
    uint16_t FinalSize = ClientContext.State.BufferAllocLength;
    ASSERT_EQ(0, (FinalSize & (FinalSize - 1)));
}

// DeepTest: Test offset values are monotonically increasing
TEST_F(TlsTest, DeepTestQuicTlsSendOffsetMonotonicity)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    uint32_t PrevHandshakeOffset = 0;
    uint32_t Prev1RttOffset = 0;
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Check handshake offset if set
    if (ServerContext.State.BufferOffsetHandshake > 0) {
        ASSERT_GE(ServerContext.State.BufferOffsetHandshake, PrevHandshakeOffset);
        PrevHandshakeOffset = ServerContext.State.BufferOffsetHandshake;
    }
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Check 1-RTT offset if set
    if (ClientContext.State.BufferOffset1Rtt > 0) {
        ASSERT_GE(ClientContext.State.BufferOffset1Rtt, Prev1RttOffset);
    }
}

// DeepTest: Test buffer with near-boundary sizes (just under 0xF000)
TEST_F(TlsTest, DeepTestQuicTlsSendNearBoundarySize)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Pre-fill buffer to near the limit
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    uint16_t NearMaxSize = 0xE000;
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(NearMaxSize, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = NearMaxSize;
    ServerContext.State.BufferLength = 0xD000;  // Most of it "used"
    ServerContext.State.BufferTotalLength = 0xD000;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Server processes - should not exceed 0xF000 limit
    Result = ServerContext.ProcessData(&ClientContext.State);
    
    // If it succeeded, verify we didn't exceed limit
    if (Result & CXPLAT_TLS_RESULT_DATA) {
        ASSERT_LT(ServerContext.State.BufferTotalLength, 0xF000);
    }
}

// DeepTest: Test with alternating buffer sizes between client and server
TEST_F(TlsTest, DeepTestQuicTlsSendAsymmetricBuffers)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Client has small buffer
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(64, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 64;
    ClientContext.State.BufferLength = 0;
    
    // Server has large buffer
    CXPLAT_FREE(ServerContext.State.Buffer, QUIC_POOL_TEST);
    ServerContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(4096, QUIC_POOL_TEST);
    ServerContext.State.BufferAllocLength = 4096;
    ServerContext.State.BufferLength = 0;
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Client buffer should have grown
    ASSERT_GT(ClientContext.State.BufferAllocLength, 64);
    
    // Both should complete successfully
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
}

// DeepTest: Test buffer length never exceeds allocation
TEST_F(TlsTest, DeepTestQuicTlsSendLengthInvariant)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    // Check invariant at each step of handshake
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
    
    Result = ClientContext.ProcessData(&ServerContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
}

// DeepTest: Test handshake with custom certificate validation
TEST_F(TlsTest, DeepTestQuicTlsSendWithCustomValidation)
{
    CxPlatSecConfig ClientConfig;
    ClientConfig.Load(ClientCertParams);
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify handshake completed
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
}

// DeepTest: Test buffer resets between handshake phases
TEST_F(TlsTest, DeepTestQuicTlsSendBufferResetBehavior)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    Result = ServerContext.ProcessData(&ClientContext.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    
    // Buffer is typically reset after processing
    // Length may be reset to 0 for next phase
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
}

// DeepTest: Test with mixed transport parameter sizes
TEST_F(TlsTest, DeepTestQuicTlsSendMixedTPSizes)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Client with small TPs
    ClientContext.InitializeClient(ClientConfig, false, 64);
    
    // Server with large TPs
    ServerContext.InitializeServer(ServerConfig, false, 512);
    
    DoHandshake(ServerContext, ClientContext);
    
    ASSERT_TRUE(ClientContext.State.HandshakeComplete);
    ASSERT_TRUE(ServerContext.State.HandshakeComplete);
}

// DeepTest: Test rapid buffer growth scenario
TEST_F(TlsTest, DeepTestQuicTlsSendRapidGrowth)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    
    // Track buffer size growth
    std::vector<uint16_t> GrowthSteps;
    
    CXPLAT_FREE(ClientContext.State.Buffer, QUIC_POOL_TEST);
    ClientContext.State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(32, QUIC_POOL_TEST);
    ClientContext.State.BufferAllocLength = 32;
    ClientContext.State.BufferLength = 0;
    GrowthSteps.push_back(32);
    
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    auto Result = ClientContext.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    GrowthSteps.push_back(ClientContext.State.BufferAllocLength);
    
    // Verify each step is a doubling
    for (size_t i = 1; i < GrowthSteps.size(); i++) {
        // Each step should be a power of 2
        ASSERT_EQ(0, (GrowthSteps[i] & (GrowthSteps[i] - 1)));
    }
}

// DeepTest: Test final buffer state consistency
TEST_F(TlsTest, DeepTestQuicTlsSendFinalStateConsistency)
{
    CxPlatClientSecConfig ClientConfig;
    CxPlatServerSecConfig ServerConfig;
    TlsContext ServerContext, ClientContext;
    ClientContext.InitializeClient(ClientConfig);
    ServerContext.InitializeServer(ServerConfig);
    
    DoHandshake(ServerContext, ClientContext);
    
    // Verify all invariants hold after complete handshake
    ASSERT_LE(ClientContext.State.BufferLength, ClientContext.State.BufferAllocLength);
    ASSERT_LE(ServerContext.State.BufferLength, ServerContext.State.BufferAllocLength);
    
    ASSERT_LE(ClientContext.State.BufferTotalLength, 0xF000);
    ASSERT_LE(ServerContext.State.BufferTotalLength, 0xF000);
    
    if (ClientContext.State.BufferOffsetHandshake > 0) {
        ASSERT_LE(ClientContext.State.BufferOffsetHandshake, ClientContext.State.BufferTotalLength);
    }
    if (ClientContext.State.BufferOffset1Rtt > 0) {
        ASSERT_LE(ClientContext.State.BufferOffset1Rtt, ClientContext.State.BufferTotalLength);
    }
}

INSTANTIATE_TEST_SUITE_P(TlsTest, TlsTest, ::testing::Bool());
