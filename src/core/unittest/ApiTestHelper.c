/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    C helper for ApiTest.cpp to avoid C/C++ linkage conflicts.
    Populates a QUIC_API_TABLE with function pointers from the
    statically-linked core library.

--*/

#include "precomp.h"

//
// These functions are defined in library.c but not declared in any header.
//
void QUIC_API MsQuicSetContext(HQUIC Handle, void* Context);
void* QUIC_API MsQuicGetContext(HQUIC Handle);
void QUIC_API MsQuicSetCallbackHandler(HQUIC Handle, void* Handler, void* Context);

//
// Populates a QUIC_API_TABLE with pointers to the api.c implementations.
// The caller must have already initialized the MsQuic library
// (MsQuicLibraryLoad + MsQuicAddRef).
//
void
QuicTestPopulateApiTable(
    QUIC_API_TABLE* Api
    )
{
    Api->SetContext = MsQuicSetContext;
    Api->GetContext = MsQuicGetContext;
    Api->SetCallbackHandler = MsQuicSetCallbackHandler;

    Api->SetParam = MsQuicSetParam;
    Api->GetParam = MsQuicGetParam;

    Api->RegistrationOpen = MsQuicRegistrationOpen;
    Api->RegistrationClose = MsQuicRegistrationClose;
    Api->RegistrationShutdown = MsQuicRegistrationShutdown;

    Api->ConfigurationOpen = MsQuicConfigurationOpen;
    Api->ConfigurationClose = MsQuicConfigurationClose;
    Api->ConfigurationLoadCredential = MsQuicConfigurationLoadCredential;

    Api->ListenerOpen = MsQuicListenerOpen;
    Api->ListenerClose = MsQuicListenerClose;
    Api->ListenerStart = MsQuicListenerStart;
    Api->ListenerStop = MsQuicListenerStop;

    Api->ConnectionOpen = MsQuicConnectionOpen;
    Api->ConnectionOpenInPartition = MsQuicConnectionOpenInPartition;
    Api->ConnectionClose = MsQuicConnectionClose;
    Api->ConnectionShutdown = MsQuicConnectionShutdown;
    Api->ConnectionStart = MsQuicConnectionStart;
    Api->ConnectionSetConfiguration = MsQuicConnectionSetConfiguration;
    Api->ConnectionSendResumptionTicket = MsQuicConnectionSendResumptionTicket;
    Api->ConnectionResumptionTicketValidationComplete = MsQuicConnectionResumptionTicketValidationComplete;
    Api->ConnectionCertificateValidationComplete = MsQuicConnectionCertificateValidationComplete;

    Api->StreamOpen = MsQuicStreamOpen;
    Api->StreamClose = MsQuicStreamClose;
    Api->StreamShutdown = MsQuicStreamShutdown;
    Api->StreamStart = MsQuicStreamStart;
    Api->StreamSend = MsQuicStreamSend;
    Api->StreamReceiveComplete = MsQuicStreamReceiveComplete;
    Api->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;
    Api->StreamProvideReceiveBuffers = MsQuicStreamProvideReceiveBuffers;

    Api->DatagramSend = MsQuicDatagramSend;
}
