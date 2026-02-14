/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for CUBIC congestion control.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CubicTest.cpp.clog.h"
#endif

//
// Helper to create a minimal valid connection for testing CUBIC initialization.
// Uses a real QUIC_CONNECTION structure to ensure proper memory layout when
// QuicCongestionControlGetConnection() does CXPLAT_CONTAINING_RECORD pointer arithmetic.
//
static void InitializeMockConnection(
    QUIC_CONNECTION& Connection,
    uint16_t Mtu)
{
    // Zero-initialize the entire connection structure
    CxPlatZeroMemory(&Connection, sizeof(Connection));

    // Initialize only the fields needed by CUBIC functions
    Connection.Paths[0].Mtu = Mtu;
    Connection.Paths[0].IsActive = TRUE;
    Connection.Send.NextPacketNumber = 0;

    // Initialize Settings with defaults
    Connection.Settings.PacingEnabled = FALSE;  // Disable pacing by default for simpler tests
    Connection.Settings.HyStartEnabled = FALSE; // Disable HyStart by default

    // Initialize Path fields needed for some functions
    Connection.Paths[0].GotFirstRttSample = FALSE;
    Connection.Paths[0].SmoothedRtt = 0;
}

//
// Test 1: Comprehensive initialization verification
// Scenario: Verifies CubicCongestionControlInitialize correctly sets up all CUBIC state
// including settings, function pointers, state flags, HyStart fields, and zero-initialized fields.
// This consolidates basic initialization, function pointer, state flags, HyStart, and zero-field checks.
//
TEST(CubicTest, InitializeComprehensive)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Pre-set some fields to verify they get zeroed
    Connection.CongestionControl.Cubic.BytesInFlight = 12345;
    Connection.CongestionControl.Cubic.Exemptions = 5;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Verify settings stored correctly
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 1000u);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);

    // Verify congestion window initialized
    ASSERT_GT(Cubic->CongestionWindow, 0u);
    ASSERT_EQ(Cubic->BytesInFlightMax, Cubic->CongestionWindow / 2);

    // Verify all 17 function pointers are set
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlCanSend, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlSetExemption, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlReset, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetSendAllowance, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataSent, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataInvalidated, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataLost, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnEcn, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlLogOutFlowStatus, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetExemptions, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetBytesInFlightMax, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlIsAppLimited, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlSetAppLimited, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetCongestionWindow, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetNetworkStatistics, nullptr);

    // Verify boolean state flags
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_FALSE(Cubic->TimeOfLastAckValid);

    // Verify HyStart fields
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 0u);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 2: Initialization with boundary parameter values
// Scenario: Tests initialization with extreme boundary values for MTU, InitialWindowPackets,
// and SendIdleTimeoutMs to ensure robustness across all valid configurations.
//
TEST(CubicTest, InitializeBoundaries)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    // Test minimum MTU with minimum window
    Settings.InitialWindowPackets = 1;
    Settings.SendIdleTimeoutMs = 0;
    InitializeMockConnection(Connection, QUIC_DPLPMTUD_MIN_MTU);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, 0u);

    // Test maximum MTU with maximum window and timeout
    Settings.InitialWindowPackets = 1000;
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    InitializeMockConnection(Connection, 65535);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1000u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, UINT32_MAX);

    // Test very small MTU (below minimum)
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    InitializeMockConnection(Connection, 500);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
}

//
// Test 3: Re-initialization behavior
// Scenario: Tests that CUBIC can be re-initialized with different settings and correctly
// updates its state. Verifies that calling CubicCongestionControlInitialize() multiple times
// properly resets state and applies new settings (e.g., doubling InitialWindowPackets should
// double the CongestionWindow). Important for connection migration or settings updates.
//
TEST(CubicTest, MultipleSequentialInitializations)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Initialize first time
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    uint32_t FirstCongestionWindow = Connection.CongestionControl.Cubic.CongestionWindow;

    // Re-initialize with different settings
    Settings.InitialWindowPackets = 20;
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Should reflect new settings with doubled window
    ASSERT_EQ(Cubic->InitialWindowPackets, 20u);
    ASSERT_EQ(Cubic->CongestionWindow, FirstCongestionWindow * 2);
}

//
// Test 4: CanSend scenarios (via function pointer)
// Scenario: Comprehensive test of CanSend logic covering: available window (can send),
// congestion blocked (cannot send), and exemptions (bypass blocking). Tests the core
// congestion control decision logic.
//
TEST(CubicTest, CanSendScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Available window - can send
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 2: Congestion blocked - cannot send
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 3: Exceeding window - still blocked
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 4: With exemptions - can send even when blocked
    Cubic->Exemptions = 2;
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
}

//
// Test 5: SetExemption (via function pointer)
// Scenario: Tests SetExemption to verify it correctly sets the number of packets that
// can bypass congestion control. Used for probe packets and other special cases.
//
TEST(CubicTest, SetExemption)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Initially should be 0
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set exemptions via function pointer
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 5);
    ASSERT_EQ(Cubic->Exemptions, 5u);

    // Set to zero
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 0);
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set to max
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 255);
    ASSERT_EQ(Cubic->Exemptions, 255u);
}

//
// Test 6: GetSendAllowance scenarios (via function pointer)
// Scenario: Tests GetSendAllowance under different conditions: congestion blocked (returns 0),
// available window without pacing (returns full window), and invalid time (skips pacing).
// Covers the main decision paths in send allowance calculation.
//
TEST(CubicTest, GetSendAllowanceScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Congestion blocked - should return 0
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);

    // Scenario 2: Available window without pacing - should return full window
    Connection.Settings.PacingEnabled = FALSE;
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    uint32_t ExpectedAllowance = Cubic->CongestionWindow - Cubic->BytesInFlight;
    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Scenario 3: Invalid time - should skip pacing and return full window
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, FALSE); // FALSE = invalid time
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 7: GetSendAllowance with active pacing (via function pointer)
// Scenario: Tests the pacing logic that limits send rate based on RTT and congestion window.
// When pacing is enabled with valid RTT samples, the function calculates a pacing rate to
// smooth out packet transmission. This prevents burst sending and improves performance over
// certain network paths. The pacing calculation is: (CongestionWindow * TimeSinceLastSend) / RTT.
// This test verifies that with pacing enabled, the allowance is rate-limited based on elapsed
// time, resulting in a smaller allowance than the full available congestion window.
//
TEST(CubicTest, GetSendAllowanceWithActivePacing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Enable pacing and provide valid RTT sample
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms (well above QUIC_MIN_PACING_RTT)

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set BytesInFlight to half the window to have available capacity
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;

    // Simulate 10ms elapsed since last send
    // Expected pacing calculation: (CongestionWindow * 10ms) / 50ms = CongestionWindow / 5
    uint32_t TimeSinceLastSend = 10000; // 10ms in microseconds

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Pacing should limit the allowance to less than the full available window
    ASSERT_GT(Allowance, 0u); // Should allow some sending
    ASSERT_LT(Allowance, AvailableWindow); // But less than full window due to pacing

    // Exact value is calculated considering the current implementation is right and this test is meant to
    // prevent future regressions
    uint32_t ExpectedPacedAllowance = 4928; // Pre-calculated expected value
    ASSERT_EQ(Allowance, ExpectedPacedAllowance);
}

//
// Test 8: Getter functions (via function pointers)
// Scenario: Tests all simple getter functions that return internal state values.
// Verifies GetExemptions, GetBytesInFlightMax, and GetCongestionWindow all return
// correct values matching the internal CUBIC state.
//
TEST(CubicTest, GetterFunctions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Test GetExemptions
    uint8_t Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(&Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 0u);
    Cubic->Exemptions = 3;
    Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(&Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 3u);

    // Test GetBytesInFlightMax
    uint32_t MaxBytes = Connection.CongestionControl.QuicCongestionControlGetBytesInFlightMax(&Connection.CongestionControl);
    ASSERT_EQ(MaxBytes, Cubic->BytesInFlightMax);
    ASSERT_EQ(MaxBytes, Cubic->CongestionWindow / 2);

    // Test GetCongestionWindow
    uint32_t CongestionWindow = Connection.CongestionControl.QuicCongestionControlGetCongestionWindow(&Connection.CongestionControl);
    ASSERT_EQ(CongestionWindow, Cubic->CongestionWindow);
    ASSERT_GT(CongestionWindow, 0u);
}

//
// Test 9: Reset scenarios (via function pointer)
// Scenario: Tests Reset function with both FullReset=FALSE (preserves BytesInFlight) and
// FullReset=TRUE (zeros BytesInFlight). Verifies that reset properly reinitializes CUBIC
// state while respecting the FullReset parameter for connection recovery scenarios.
//
TEST(CubicTest, ResetScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;
    uint32_t BytesInFlightBefore = Cubic->BytesInFlight;

    Connection.CongestionControl.QuicCongestionControlReset(&Connection.CongestionControl, FALSE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightBefore); // Preserved

    // Scenario 2: Full reset (FullReset=TRUE) - zeros BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;

    Connection.CongestionControl.QuicCongestionControlReset(&Connection.CongestionControl, TRUE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->BytesInFlight, 0u); // Zeroed with full reset
}

//
// Test 10: CubicCongestionControlOnDataSent - BytesInFlight increases and exemptions decrement
// Scenario: Tests that OnDataSent correctly increments BytesInFlight when data is sent
// and decrements exemptions when probe packets are sent. This tracks outstanding data
// in the network and consumes exemptions. Verifies BytesInFlightMax is updated when
// BytesInFlight reaches a new maximum.
//
TEST(CubicTest, OnDataSent_IncrementsBytesInFlight)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    uint32_t InitialBytesInFlight = Cubic->BytesInFlight;
    uint32_t InitialBytesInFlightMax = Cubic->BytesInFlightMax;
    uint32_t BytesToSend = 1500;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, BytesToSend);

    ASSERT_EQ(Cubic->BytesInFlight, InitialBytesInFlight + BytesToSend);
    // BytesInFlightMax should update if new BytesInFlight exceeds previous max
    if (InitialBytesInFlight + BytesToSend > InitialBytesInFlightMax) {
        ASSERT_EQ(Cubic->BytesInFlightMax, InitialBytesInFlight + BytesToSend);
    } else {
        ASSERT_EQ(Cubic->BytesInFlightMax, InitialBytesInFlightMax);
    }

    // Test exemption decrement
    Cubic->Exemptions = 5;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1500);
    ASSERT_EQ(Cubic->Exemptions, 4u);
}

//
// Test 11: CubicCongestionControlOnDataInvalidated - BytesInFlight decreases
// Scenario: Tests OnDataInvalidated when sent packets are discarded (e.g., due to key
// phase change). BytesInFlight should decrease by the invalidated bytes since they're
// no longer considered in-flight. Critical for accurate congestion window management.
//
TEST(CubicTest, OnDataInvalidated_DecrementsBytesInFlight)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Send some data first
    Cubic->BytesInFlight = 5000;
    uint32_t BytesToInvalidate = 2000;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataInvalidated(
        &Connection.CongestionControl, BytesToInvalidate);

    ASSERT_EQ(Cubic->BytesInFlight, 3000u);
}

//
// Test 12: OnDataAcknowledged - Basic ACK Processing and CUBIC Growth
// Scenario: Tests the core CUBIC congestion control algorithm by acknowledging sent data.
// Exercises CubicCongestionControlOnDataAcknowledged and internally calls CubeRoot for CUBIC calculations.
// Verifies congestion window grows appropriately after successful ACK.
//
TEST(CubicTest, OnDataAcknowledged_BasicAck)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms in microseconds

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data sent
    Cubic->BytesInFlight = 5000;

    // Create ACK event with correct structure
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = CxPlatTimeUs64();
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 5000;
    AckEvent.NumTotalAckedRetransmittableBytes = 5000;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL; // NULL pointer is valid

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);
    // Verify window may have grown (depends on slow start vs congestion avoidance)
    ASSERT_GE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 13: OnDataLost - Packet Loss Handling and Window Reduction
// Scenario: Tests CUBIC's response to packet loss. When packets are declared lost,
// the congestion window should be reduced according to CUBIC algorithm (multiplicative decrease).
// Verifies proper loss recovery state transitions.
//
TEST(CubicTest, OnDataLost_WindowReduction)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    // Create loss event with correct structure
    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 3600; // 3 packets * 1200 bytes
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 10;
    LossEvent.LargestSentPacketNumber = 15;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Verify window was reduced (CUBIC multiplicative decrease)
    ASSERT_LT(Cubic->CongestionWindow, InitialWindow);
    ASSERT_GT(Cubic->SlowStartThreshold, 0u);
    ASSERT_LT(Cubic->SlowStartThreshold, UINT32_MAX);
}

//
// Test 14: OnEcn - ECN Marking Handling
// Scenario: Tests Explicit Congestion Notification (ECN) handling. When ECN-marked packets
// are received, CUBIC should treat it as a congestion signal and reduce the window appropriately.
//
TEST(CubicTest, OnEcn_CongestionSignal)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.EcnEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    // Create ECN event with correct structure
    QUIC_ECN_EVENT EcnEvent;
    CxPlatZeroMemory(&EcnEvent, sizeof(EcnEvent));
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl,
        &EcnEvent);

    // Verify window was reduced due to ECN congestion signal
    ASSERT_LE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 15: GetNetworkStatistics - Statistics Retrieval
// Scenario: Tests retrieval of network statistics including congestion window, RTT estimates,
// and throughput metrics. Used for monitoring and diagnostics.
//
TEST(CubicTest, GetNetworkStatistics_RetrieveStats)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    Connection.Paths[0].MinRtt = 40000; // 40ms
    Connection.Paths[0].RttVariance = 5000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    Cubic->BytesInFlight = 8000;

    // Prepare network statistics structure (not QUIC_STATISTICS_V2)
    QUIC_NETWORK_STATISTICS NetworkStats;
    CxPlatZeroMemory(&NetworkStats, sizeof(NetworkStats));

    // Call through function pointer - note it takes Connection as first param
    Connection.CongestionControl.QuicCongestionControlGetNetworkStatistics(
        &Connection,
        &Connection.CongestionControl,
        &NetworkStats);

    // Verify statistics were populated
    ASSERT_EQ(NetworkStats.CongestionWindow, Cubic->CongestionWindow);
    ASSERT_EQ(NetworkStats.BytesInFlight, Cubic->BytesInFlight);
    ASSERT_GT(NetworkStats.SmoothedRTT, 0u);
}

//
// Test 16: Miscellaneous Small Functions - Complete API Coverage
// Scenario: Tests remaining small functions to achieve comprehensive API coverage:
// SetExemption, GetExemptions, OnDataInvalidated, GetCongestionWindow, LogOutFlowStatus, OnSpuriousCongestionEvent.
//
TEST(CubicTest, MiscFunctions_APICompleteness)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Test SetExemption
    Connection.CongestionControl.QuicCongestionControlSetExemption(
        &Connection.CongestionControl,
        1); // Set exemption count

    // Test GetExemptions
    uint8_t Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(
        &Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 1u);

    // Test OnDataInvalidated
    Cubic->BytesInFlight = 5000;
    Connection.CongestionControl.QuicCongestionControlOnDataInvalidated(
        &Connection.CongestionControl,
        2000); // Invalidate 2000 bytes
    ASSERT_EQ(Cubic->BytesInFlight, 3000u);

    // Test GetCongestionWindow
    uint32_t CongestionWindow = Connection.CongestionControl.QuicCongestionControlGetCongestionWindow(
        &Connection.CongestionControl);
    ASSERT_EQ(CongestionWindow, Cubic->CongestionWindow);

    // Test LogOutFlowStatus
    Connection.CongestionControl.QuicCongestionControlLogOutFlowStatus(
        &Connection.CongestionControl);
    // No assertion needed - just ensure it doesn't crash

    // Test OnSpuriousCongestionEvent
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(
        &Connection.CongestionControl);
    // No assertion needed - just ensure it doesn't crash
}

//
// Test 17: HyStart State Transitions - Complete Coverage
// Scenario: Tests HyStart state transitions and behavior in different states.
// HyStart is an algorithm to safely exit slow start by detecting delay increases.
// Tests HYSTART_NOT_STARTED -> HYSTART_ACTIVE -> HYSTART_DONE transitions.
//
TEST(CubicTest, HyStart_StateTransitions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Initial state should be HYSTART_NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Transition to HYSTART_ACTIVE by acknowledging data (triggers slow start)
    Cubic->BytesInFlight = 5000;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 5000;
    AckEvent.NumTotalAckedRetransmittableBytes = 5000;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // HyStart may transition states based on RTT measurements
    // Just verify state is valid and divisor is set appropriately
    ASSERT_TRUE(Cubic->HyStartState >= HYSTART_NOT_STARTED &&
                Cubic->HyStartState <= HYSTART_DONE);
    ASSERT_GE(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// DeepTest 1: Slow Start Threshold Crossing with Overflow Bytes
// Scenario: Tests the transition from slow start to congestion avoidance when window
// crosses the SlowStartThreshold, with proper handling of "overflow" bytes.
// How: Set window just below threshold, ACK enough to cross it, verify spare bytes
// are treated as congestion avoidance bytes.
// Assertions: Verifies window stops at threshold and TimeOfCongAvoidStart is set.
//
TEST(CubicTest, DeepTest_SlowStartThresholdCrossing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set window just below slow start threshold
    Cubic->SlowStartThreshold = 15000;
    Cubic->CongestionWindow = 14000;
    Cubic->AimdWindow = 14000;
    Cubic->BytesInFlight = 7000;
    Cubic->BytesInFlightMax = 7000;

    ASSERT_LT(Cubic->CongestionWindow, Cubic->SlowStartThreshold);

    // ACK enough to cross threshold
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 50;
    AckEvent.LargestSentPacketNumber = 55;
    AckEvent.NumRetransmittableBytes = 3000; // Crosses threshold
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Should now be at threshold (or slightly above due to AIMD of overflow)
    ASSERT_GE(Cubic->CongestionWindow, Cubic->SlowStartThreshold);
    ASSERT_GT(Cubic->TimeOfCongAvoidStart, 0u);
}

//
// DeepTest 2: Persistent Congestion Window Reduction
// Scenario: Tests the persistent congestion event which causes a drastic window reduction
// and sets multiple CUBIC parameters accordingly.
// How: Trigger a congestion event with IsPersistentCongestion=TRUE and verify state changes.
// Assertions: Checks IsInPersistentCongestion=TRUE, window reduced significantly, HyStartState=HYSTART_DONE.
//
TEST(CubicTest, DeepTest_PersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up a scenario where we have a good window size
    Cubic->CongestionWindow = 20000;
    Cubic->BytesInFlight = 10000;
    uint32_t OldWindow = Cubic->CongestionWindow;

    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);

    // Trigger persistent congestion via loss event
    QUIC_LOSS_EVENT LossEvent{};
    LossEvent.LargestPacketNumberLost = 100;
    LossEvent.LargestSentPacketNumber = 105;
    LossEvent.NumRetransmittableBytes = 5000;
    LossEvent.PersistentCongestion = TRUE; // Key: persistent congestion

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    // Verify persistent congestion state
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
    
    // Window should be drastically reduced
    ASSERT_LT(Cubic->CongestionWindow, OldWindow / 5); // At least 5x reduction
    
    // HyStart should be in DONE state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    
    // Verify bytes in flight was updated
    ASSERT_EQ(Cubic->BytesInFlight, 5000u); // 10000 - 5000
}

//
// DeepTest 3: Congestion Avoidance with AIMD Window and Reno-Friendly Region
// Scenario: Tests congestion avoidance when AIMD window exceeds CUBIC window, entering
// the "Reno-friendly" region where traditional AIMD behavior dominates.
// How: Set up state in congestion avoidance (CongestionWindow >= SlowStartThreshold),
// artificially boost AimdWindow above expected CubicWindow, then ACK data to verify
// CongestionWindow follows AimdWindow growth.
// Assertions: Verifies CongestionWindow == AimdWindow when AIMD dominates, and proper
// accumulator-based growth per RFC 3465 (Appropriate Byte Counting).
//
TEST(CubicTest, DeepTest_CongestionAvoidanceAIMDRegion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Force into congestion avoidance mode
    Cubic->SlowStartThreshold = 15000;
    Cubic->CongestionWindow = 15000;
    Cubic->AimdWindow = 15000;
    Cubic->WindowMax = 12000; // Lower than current, so CUBIC window will be lower
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 10000;
    Cubic->BytesInFlightMax = 10000;

    uint32_t InitialWindow = Cubic->CongestionWindow;

    // ACK some data in congestion avoidance
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1100000; // 100ms later
    AckEvent.LargestAck = 50;
    AckEvent.LargestSentPacketNumber = 55;
    AckEvent.NumRetransmittableBytes = 2560; // 2 MTUs
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 48000;
    AckEvent.MinRttValid = TRUE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // In Reno-friendly region, window should grow following AIMD
    // Window should have grown (though maybe not by much due to ABC)
    ASSERT_GE(Cubic->CongestionWindow, InitialWindow);
    
    // AimdAccumulator should have increased
    ASSERT_GT(Cubic->AimdAccumulator, 0u);
    
    // Bytes in flight should be decremented
    ASSERT_EQ(Cubic->BytesInFlight, 7440u); // 10000 - 2560
}

//
// DeepTest 4: Pacing Calculation in Slow Start with Estimated Window
// Scenario: Tests the pacing send allowance calculation during slow start where the
// estimated window is doubled (exponential growth prediction).
// How: Enable pacing, set state in slow start, provide a valid RTT sample, then call
// GetSendAllowance with a time delta and verify the paced allowance is calculated
// correctly using the doubled estimated window.
// Assertions: Checks that send allowance is non-zero but limited (not full window),
// and that it's based on the pacing formula: (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt.
//
TEST(CubicTest, DeepTest_PacingInSlowStart)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.PacingEnabled = TRUE; // Enable pacing

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE; // Must set on Connection too
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Ensure we're in slow start
    ASSERT_LT(Cubic->CongestionWindow, Cubic->SlowStartThreshold);
    
    uint32_t InitialWindow = Cubic->CongestionWindow;
    Cubic->BytesInFlight = InitialWindow / 2; // Half full

    // Request send allowance with pacing
    uint64_t TimeSinceLastSend = 10000; // 10ms
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl,
        TimeSinceLastSend,
        TRUE);

    // In slow start with pacing, allowance should be paced (not full window)
    ASSERT_GT(Allowance, 0u);
    ASSERT_LE(Allowance, InitialWindow - Cubic->BytesInFlight);
    
    // Verify LastSendAllowance was updated
    ASSERT_EQ(Cubic->LastSendAllowance, Allowance);
}

//
// DeepTest 5: Recovery Exit on ACK After Recovery Sent Packet Number
// Scenario: Tests the exit from recovery state when an ACK is received for a packet
// sent after the congestion event (LargestAck > RecoverySentPacketNumber).
// How: Enter recovery via loss, then send a new packet and ACK it with LargestAck
// exceeding RecoverySentPacketNumber to trigger recovery exit.
// Assertions: Verifies IsInRecovery transitions from TRUE to FALSE, and
// IsInPersistentCongestion also clears.
//
TEST(CubicTest, DeepTest_RecoveryExit)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    Cubic->CongestionWindow = 20000;
    Cubic->BytesInFlight = 10000;

    // Enter recovery via loss
    QUIC_LOSS_EVENT LossEvent{};
    LossEvent.LargestPacketNumberLost = 100;
    LossEvent.LargestSentPacketNumber = 105;
    LossEvent.NumRetransmittableBytes = 2000;
    LossEvent.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    ASSERT_TRUE(Cubic->IsInRecovery);
    uint64_t RecoverySentPN = Cubic->RecoverySentPacketNumber;
    ASSERT_EQ(RecoverySentPN, 105u);

    // ACK a packet sent before recovery - should stay in recovery
    Cubic->BytesInFlight = 8000;
    QUIC_ACK_EVENT AckEvent1{};
    AckEvent1.TimeNow = 2000000;
    AckEvent1.LargestAck = RecoverySentPN - 1; // Before recovery
    AckEvent1.LargestSentPacketNumber = RecoverySentPN + 10;
    AckEvent1.NumRetransmittableBytes = 0; // No new bytes ACKed
    AckEvent1.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent1);
    
    ASSERT_TRUE(Cubic->IsInRecovery); // Still in recovery

    // ACK a packet sent after recovery starts - should exit recovery
    QUIC_ACK_EVENT AckEvent2{};
    AckEvent2.TimeNow = 2100000;
    AckEvent2.LargestAck = RecoverySentPN + 5; // After recovery
    AckEvent2.LargestSentPacketNumber = RecoverySentPN + 15;
    AckEvent2.NumRetransmittableBytes = 1280;
    AckEvent2.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent2);
    
    ASSERT_FALSE(Cubic->IsInRecovery); // Exited recovery
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
}

//
// DeepTest 6: Spurious Congestion Event Reversion
// Scenario: Tests the spurious congestion event detection which restores previous CUBIC state.
// How: Trigger a congestion event, then call OnSpuriousCongestionEvent to revert state.
// Assertions: Verifies window, threshold, and CUBIC parameters are restored to pre-congestion values.
//
TEST(CubicTest, DeepTest_SpuriousCongestionRevert)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up initial good state
    Cubic->CongestionWindow = 30000;
    Cubic->SlowStartThreshold = 25000;
    Cubic->WindowMax = 28000;
    Cubic->BytesInFlight = 15000;

    uint32_t OldWindow = Cubic->CongestionWindow;
    uint32_t OldThreshold = Cubic->SlowStartThreshold;

    // Trigger congestion event (non-ECN so prev state is saved)
    QUIC_LOSS_EVENT LossEvent{};
    LossEvent.LargestPacketNumberLost = 50;
    LossEvent.LargestSentPacketNumber = 55;
    LossEvent.NumRetransmittableBytes = 3000;
    LossEvent.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    // Verify in recovery with reduced window
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_LT(Cubic->CongestionWindow, OldWindow);

    // Now detect spurious congestion and revert
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(
        &Connection.CongestionControl);

    // Verify state reverted
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->CongestionWindow, OldWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, OldThreshold);
}

//
// DeepTest 7: Fast Convergence When WindowMax Decreases
// Scenario: Tests fast convergence logic when a new congestion event occurs before
// recovering to previous WindowMax, indicating persistent congestion.
// How: Trigger loss, let window grow a bit, then trigger another loss before reaching
// old WindowMax to exercise the fast convergence path.
// Assertions: Verifies WindowLastMax is reduced and WindowMax adjusted per fast convergence formula.
//
TEST(CubicTest, DeepTest_FastConvergence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // First congestion event at high window
    Cubic->CongestionWindow = 50000;
    Cubic->BytesInFlight = 25000;
    
    QUIC_LOSS_EVENT Loss1{};
    Loss1.LargestPacketNumberLost = 100;
    Loss1.LargestSentPacketNumber = 105;
    Loss1.NumRetransmittableBytes = 5000;
    Loss1.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &Loss1);

    uint32_t FirstWindowMax = Cubic->WindowMax; // Should be 50000
    ASSERT_EQ(FirstWindowMax, 50000u);

    // Exit recovery
    Cubic->BytesInFlight = 10000;
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 2000000;
    AckEvent.LargestAck = 150; // After recovery packet
    AckEvent.LargestSentPacketNumber = 155;
    AckEvent.NumRetransmittableBytes = 2000;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);
    
    ASSERT_FALSE(Cubic->IsInRecovery);

    // Second congestion event at LOWER window (triggers fast convergence)
    Cubic->CongestionWindow = 40000; // Lower than FirstWindowMax
    Cubic->WindowLastMax = FirstWindowMax + 1000; // > current WindowMax
    Cubic->BytesInFlight = 20000;

    QUIC_LOSS_EVENT Loss2{};
    Loss2.LargestPacketNumberLost = 200;
    Loss2.LargestSentPacketNumber = 205;
    Loss2.NumRetransmittableBytes = 5000;
    Loss2.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &Loss2);

    // Fast convergence should have adjusted WindowMax
    // WindowMax should be reduced: WindowMax * (10 + 7) / 20 = WindowMax * 0.85
    ASSERT_LT(Cubic->WindowMax, 40000u); // Should be 40000 * 0.85 = 34000
    ASSERT_EQ(Cubic->WindowLastMax, 40000u);
}

//
// DeepTest 8: Congestion Avoidance with Window Growth Limit
// Scenario: Tests the window growth limiter that caps growth at 2 * BytesInFlightMax
// to prevent window inflation when app/flow control limits actual sending.
// How: Set BytesInFlightMax low, then ACK data in congestion avoidance and verify
// window doesn't grow beyond 2 * BytesInFlightMax.
// Assertions: Verifies CongestionWindow capped at 2 * BytesInFlightMax.
//
TEST(CubicTest, DeepTest_WindowGrowthLimit)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Force into congestion avoidance
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 10000;
    Cubic->AimdWindow = 10000;
    Cubic->WindowMax = 8000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    
    // Set BytesInFlightMax to a low value
    Cubic->BytesInFlightMax = 5000;
    Cubic->BytesInFlight = 4000;

    // ACK a lot of data
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 100;
    AckEvent.LargestSentPacketNumber = 105;
    AckEvent.NumRetransmittableBytes = 3000;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Window should be capped at 2 * BytesInFlightMax = 10000
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// DeepTest 9: Time Gap Handling in Congestion Avoidance
// Scenario: Tests the time gap adjustment in congestion avoidance that freezes window
// growth when ACKs are delayed (idle periods).
// How: Set up congestion avoidance, then send ACK with large time gap to trigger
// the TimeOfCongAvoidStart adjustment.
// Assertions: Verifies TimeOfCongAvoidStart is adjusted forward, effectively freezing growth.
//
TEST(CubicTest, DeepTest_TimeGapHandling)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 100; // Short idle timeout

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Force into congestion avoidance
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 10000;
    Cubic->TimeOfCongAvoidStart = 1000000; // 1 second
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 5000;
    Cubic->BytesInFlightMax = 5000;

    uint64_t OriginalCongAvoidStart = Cubic->TimeOfCongAvoidStart;

    // ACK with large time gap (200ms > SendIdleTimeoutMs and > RTT + 4*variance)
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1250000; // 250ms later
    AckEvent.LargestAck = 50;
    AckEvent.LargestSentPacketNumber = 55;
    AckEvent.NumRetransmittableBytes = 1000;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // TimeOfCongAvoidStart should be adjusted forward
    ASSERT_GT(Cubic->TimeOfCongAvoidStart, OriginalCongAvoidStart);
}

//
// DeepTest 10: CUBIC Window Overflow Protection
// Scenario: Tests the overflow protection in CUBIC window calculation where very large
// time deltas could cause integer overflow.
// How: Set TimeInCongAvoid to a very large value and verify DeltaT is clamped.
// Assertions: Verifies window calculation doesn't overflow and is reasonable.
//
TEST(CubicTest, DeepTest_CubicOverflowProtection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up congestion avoidance with very old start time (huge delta)
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 10000;
    Cubic->AimdWindow = 10000;
    Cubic->WindowMax = 10000;
    Cubic->TimeOfCongAvoidStart = 1000000; // 1 second
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 5000;
    Cubic->BytesInFlightMax = 5000;
    Cubic->KCubic = 100;

    // ACK with HUGE time delta (3 seconds = 3,000,000 microseconds)
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 4000000; // 3 seconds later!
    AckEvent.LargestAck = 100;
    AckEvent.LargestSentPacketNumber = 105;
    AckEvent.NumRetransmittableBytes = 1000;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Window should be capped and not overflow (max is 2 * BytesInFlightMax)
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
    ASSERT_GT(Cubic->CongestionWindow, 0u); // Sanity check
}

//
// DeepTest 11: Pacing with Estimated Window in Congestion Avoidance
// Scenario: Tests pacing calculation in congestion avoidance where estimated window
// is calculated as current window * 1.25.
// How: Set up in congestion avoidance with pacing enabled and verify send allowance.
// Assertions: Verifies paced send allowance is calculated and reasonable.
//
TEST(CubicTest, DeepTest_PacingInCongestionAvoidance)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.PacingEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up in congestion avoidance
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 15000;
    Cubic->BytesInFlight = 7500; // Half full

    // Request send allowance with pacing
    uint64_t TimeSinceLastSend = 10000; // 10ms
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl,
        TimeSinceLastSend,
        TRUE);

    // Should get some paced allowance
    ASSERT_GT(Allowance, 0u);
    ASSERT_LE(Allowance, Cubic->CongestionWindow - Cubic->BytesInFlight);
}

//
// DeepTest 12: Second Congestion Event Without Recovery Exit
// Scenario: Tests that a second loss event while already in recovery doesn't
// trigger another congestion event (packet number comparison).
// How: Enter recovery, then trigger another loss for earlier packet numbers.
// Assertions: Verifies no additional window reduction occurs.
//
TEST(CubicTest, DeepTest_SecondLossInRecovery)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    Cubic->CongestionWindow = 20000;
    Cubic->BytesInFlight = 15000;

    // First loss event
    QUIC_LOSS_EVENT Loss1{};
    Loss1.LargestPacketNumberLost = 100;
    Loss1.LargestSentPacketNumber = 105;
    Loss1.NumRetransmittableBytes = 3000;
    Loss1.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &Loss1);

    ASSERT_TRUE(Cubic->IsInRecovery);
    uint32_t WindowAfterFirst = Cubic->CongestionWindow;
    uint64_t RecoveryPN = Cubic->RecoverySentPacketNumber;

    // Second loss for EARLIER packet (should not trigger new congestion event)
    QUIC_LOSS_EVENT Loss2{};
    Loss2.LargestPacketNumberLost = 95; // Earlier than first
    Loss2.LargestSentPacketNumber = RecoveryPN - 1; // Before recovery
    Loss2.NumRetransmittableBytes = 2000;
    Loss2.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &Loss2);

    // Window should not reduce further
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterFirst);
    ASSERT_TRUE(Cubic->IsInRecovery); // Still in same recovery
}

//
// DeepTest 13: Network Statistics Event Emission
// Scenario: Tests the emission of network statistics events when NetStatsEventEnabled.
// How: Enable NetStatsEventEnabled, then ACK data to trigger event emission.
// Assertions: Verifies ACK processing completes successfully with events enabled.
//
TEST(CubicTest, DeepTest_NetworkStatisticsEvent)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.NetStatsEventEnabled = TRUE; // Enable events

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.NetStatsEventEnabled = TRUE; // Must also set on Connection
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    Cubic->BytesInFlight = 5000;

    // ACK some data (should trigger event emission)
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 50;
    AckEvent.LargestSentPacketNumber = 55;
    AckEvent.NumRetransmittableBytes = 1280;
    AckEvent.SmoothedRtt = 50000;

    // This should emit network statistics event internally
    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Just verify it didn't crash
    ASSERT_GT(Cubic->CongestionWindow, 0u);
}

//
// DeepTest 14: AIMD Window Below WindowPrior
// Scenario: Tests AIMD accumulator behavior when AimdWindow < WindowPrior, which uses
// a slower growth rate (half the normal rate).
// How: Set AimdWindow below WindowPrior, ACK data, verify slower accumulation.
// Assertions: Verifies accumulator increments at half rate.
//
TEST(CubicTest, DeepTest_AIMDBelowWindowPrior)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 5000;
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up congestion avoidance with AimdWindow < WindowPrior
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 12000;
    Cubic->AimdWindow = 11000; // Below WindowPrior
    Cubic->WindowPrior = 15000; // Higher than AimdWindow
    Cubic->WindowMax = 10000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 6000;
    Cubic->BytesInFlightMax = 6000;
    Cubic->AimdAccumulator = 0;

    // ACK 2000 bytes
    QUIC_ACK_EVENT AckEvent{};
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 50;
    AckEvent.LargestSentPacketNumber = 55;
    AckEvent.NumRetransmittableBytes = 2000;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Accumulator should have increased by BytesAcked / 2 = 1000
    ASSERT_EQ(Cubic->AimdAccumulator, 1000u);
}

//
// DeepTest 15: Pacing With Estimated Window Overflow
// Scenario: Tests pacing calculation when estimated window calculation would overflow.
// How: Set up large window and time values that could cause overflow in pacing math.
// Assertions: Verifies send allowance is capped at available window space.
//
TEST(CubicTest, DeepTest_PacingOverflowProtection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.PacingEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set large window values (slow start)
    Cubic->CongestionWindow = UINT32_MAX / 4;
    Cubic->SlowStartThreshold = UINT32_MAX / 2;
    Cubic->BytesInFlight = UINT32_MAX / 8;

    // Request with large time delta
    uint64_t TimeSinceLastSend = 100000; // 100ms
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl,
        TimeSinceLastSend,
        TRUE);

    // Should cap at available space, not overflow
    uint32_t AvailableSpace = Cubic->CongestionWindow - Cubic->BytesInFlight;
    ASSERT_LE(Allowance, AvailableSpace);
    ASSERT_GT(Allowance, 0u);
}

//
// DeepTest 16: ECN Event After Recovery Sent Packet
// Scenario: Tests ECN congestion signal received for packets sent after current recovery.
// How: Enter recovery, then trigger ECN event for later packet number.
// Assertions: Verifies new congestion event is triggered with ECN flag.
//
TEST(CubicTest, DeepTest_ECNAfterRecovery)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    Cubic->CongestionWindow = 20000;
    Cubic->BytesInFlight = 15000;

    // First loss event
    QUIC_LOSS_EVENT LossEvent{};
    LossEvent.LargestPacketNumberLost = 100;
    LossEvent.LargestSentPacketNumber = 105;
    LossEvent.NumRetransmittableBytes = 3000;
    LossEvent.PersistentCongestion = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    ASSERT_TRUE(Cubic->IsInRecovery);
    uint64_t RecoveryPN = Cubic->RecoverySentPacketNumber;
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;

    // ECN event for LATER packet (should trigger new congestion event)
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = RecoveryPN + 10; // After recovery
    EcnEvent.LargestSentPacketNumber = RecoveryPN + 15;

    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl, &EcnEvent);

    // Should trigger new congestion event, reducing window again
    ASSERT_LT(Cubic->CongestionWindow, WindowAfterLoss);
    ASSERT_TRUE(Cubic->IsInRecovery);
}
