/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC Version Negotiation functions (version_neg.c)
    that are not covered by VersionNegExtTest.cpp.

    Tests cover:
      - QuicVersionNegotiationExtIsVersionServerSupported
      - QuicVersionNegotiationExtIsVersionClientSupported
      - QuicVersionNegotiationExtAreVersionsCompatible (comprehensive)
      - QuicVersionNegotiationExtIsVersionCompatible

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "VersionNegTest.cpp.clog.h"
#endif

// =====================================================================
// QuicVersionNegotiationExtIsVersionServerSupported
// =====================================================================

//
// With default settings (no custom VersionSettings), all standard versions
// should be supported.
//
TEST(VersionNegTest, IsVersionServerSupported_DefaultSettings)
{
    //
    // Save and clear any custom version settings.
    //
    QUIC_VERSION_SETTINGS* SavedSettings = MsQuicLib.Settings.VersionSettings;
    BOOLEAN SavedIsSet = MsQuicLib.Settings.IsSet.VersionSettings;
    MsQuicLib.Settings.VersionSettings = NULL;
    MsQuicLib.Settings.IsSet.VersionSettings = FALSE;

    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_1));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_2));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_MS_1));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_DRAFT_29));

    //
    // Unknown version should not be supported.
    //
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(0x12345678));

    //
    // Version negotiation version (0) should not be supported.
    //
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_VER_NEG));

    MsQuicLib.Settings.VersionSettings = SavedSettings;
    MsQuicLib.Settings.IsSet.VersionSettings = SavedIsSet;
}

//
// With custom VersionSettings, only the listed acceptable versions should
// be supported.
//
TEST(VersionNegTest, IsVersionServerSupported_CustomSettings)
{
    uint32_t AcceptableVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.AcceptableVersions = AcceptableVersions;
    VerSettings.AcceptableVersionsLength = ARRAYSIZE(AcceptableVersions);

    QUIC_VERSION_SETTINGS* SavedSettings = MsQuicLib.Settings.VersionSettings;
    BOOLEAN SavedIsSet = MsQuicLib.Settings.IsSet.VersionSettings;
    MsQuicLib.Settings.VersionSettings = &VerSettings;
    MsQuicLib.Settings.IsSet.VersionSettings = TRUE;

    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_1));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_2));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_MS_1));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(QUIC_VERSION_DRAFT_29));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(0x12345678));

    MsQuicLib.Settings.VersionSettings = SavedSettings;
    MsQuicLib.Settings.IsSet.VersionSettings = SavedIsSet;
}

//
// Reserved versions must be rejected even with custom settings.
//
TEST(VersionNegTest, IsVersionServerSupported_ReservedVersion)
{
    //
    // A reserved version has (Version & 0x0f0f0f0f) == 0x0a0a0a0a.
    //
    uint32_t ReservedVersion = 0x1a2a3a4a;
    uint32_t AcceptableVersions[] = {ReservedVersion};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.AcceptableVersions = AcceptableVersions;
    VerSettings.AcceptableVersionsLength = ARRAYSIZE(AcceptableVersions);

    QUIC_VERSION_SETTINGS* SavedSettings = MsQuicLib.Settings.VersionSettings;
    BOOLEAN SavedIsSet = MsQuicLib.Settings.IsSet.VersionSettings;
    MsQuicLib.Settings.VersionSettings = &VerSettings;
    MsQuicLib.Settings.IsSet.VersionSettings = TRUE;

    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionServerSupported(ReservedVersion));

    MsQuicLib.Settings.VersionSettings = SavedSettings;
    MsQuicLib.Settings.IsSet.VersionSettings = SavedIsSet;
}

// =====================================================================
// QuicVersionNegotiationExtIsVersionClientSupported
// =====================================================================

//
// With default settings (no custom VersionSettings on Connection), all
// standard versions should be supported.
//
TEST(VersionNegTest, IsVersionClientSupported_DefaultSettings)
{
    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = NULL;
    Connection.Settings.IsSet.VersionSettings = FALSE;

    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_1));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_2));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_MS_1));
    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_DRAFT_29));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, 0x12345678));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_VER_NEG));
}

//
// With custom VersionSettings on Connection, only FullyDeployedVersions
// should be supported.
//
TEST(VersionNegTest, IsVersionClientSupported_CustomSettings)
{
    uint32_t DeployedVersions[] = {QUIC_VERSION_2};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.FullyDeployedVersions = DeployedVersions;
    VerSettings.FullyDeployedVersionsLength = ARRAYSIZE(DeployedVersions);

    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = &VerSettings;
    Connection.Settings.IsSet.VersionSettings = TRUE;

    ASSERT_TRUE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_2));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_1));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, QUIC_VERSION_MS_1));
    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, 0x12345678));
}

//
// Reserved versions should be rejected even with custom settings.
//
TEST(VersionNegTest, IsVersionClientSupported_ReservedVersion)
{
    uint32_t ReservedVersion = 0x1a2a3a4a;
    uint32_t DeployedVersions[] = {ReservedVersion};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.FullyDeployedVersions = DeployedVersions;
    VerSettings.FullyDeployedVersionsLength = ARRAYSIZE(DeployedVersions);

    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = &VerSettings;
    Connection.Settings.IsSet.VersionSettings = TRUE;

    ASSERT_FALSE(QuicVersionNegotiationExtIsVersionClientSupported(&Connection, ReservedVersion));
}

// =====================================================================
// QuicVersionNegotiationExtAreVersionsCompatible (comprehensive)
// =====================================================================

//
// Same version is always compatible with itself.
//
TEST(VersionNegTest, AreVersionsCompatible_SameVersion)
{
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_1, QUIC_VERSION_1));
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_2, QUIC_VERSION_2));
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_MS_1, QUIC_VERSION_MS_1));
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_DRAFT_29, QUIC_VERSION_DRAFT_29));
}

//
// Known compatible version pairs from CompatibleVersionsMap:
//   {QUIC_VERSION_MS_1 -> QUIC_VERSION_1}
//   {QUIC_VERSION_1 -> QUIC_VERSION_MS_1}
//   {QUIC_VERSION_1 -> QUIC_VERSION_2}
//
TEST(VersionNegTest, AreVersionsCompatible_KnownPairs)
{
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_MS_1, QUIC_VERSION_1));
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_1, QUIC_VERSION_MS_1));
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_1, QUIC_VERSION_2));
}

//
// Version pairs NOT in the compatibility map.
//
TEST(VersionNegTest, AreVersionsCompatible_IncompatiblePairs)
{
    //
    // QUIC_VERSION_2 is NOT listed as original version in CompatibleVersionsMap,
    // so it's only compatible with itself.
    //
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_2, QUIC_VERSION_1));
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_2, QUIC_VERSION_MS_1));

    //
    // QUIC_VERSION_MS_1 -> QUIC_VERSION_2 not in map.
    //
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_MS_1, QUIC_VERSION_2));

    //
    // QUIC_VERSION_DRAFT_29 not in the compatibility map at all.
    //
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_DRAFT_29, QUIC_VERSION_1));
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_DRAFT_29, QUIC_VERSION_2));
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_1, QUIC_VERSION_DRAFT_29));
}

//
// Unknown versions are incompatible with everything except themselves.
//
TEST(VersionNegTest, AreVersionsCompatible_UnknownVersion)
{
    ASSERT_TRUE(QuicVersionNegotiationExtAreVersionsCompatible(0xDEADBEEF, 0xDEADBEEF));
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(0xDEADBEEF, QUIC_VERSION_1));
    ASSERT_FALSE(QuicVersionNegotiationExtAreVersionsCompatible(QUIC_VERSION_1, 0xDEADBEEF));
}

// =====================================================================
// QuicVersionNegotiationExtIsVersionCompatible
// =====================================================================

//
// With default settings (MsQuicLib.DefaultCompatibilityList), test that
// the default compatible versions are accepted.
//
TEST(VersionNegTest, IsVersionCompatible_DefaultSettings)
{
    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = NULL;
    Connection.Settings.IsSet.VersionSettings = FALSE;

    //
    // The default compatibility list should contain the standard versions.
    // Test a few expected compatible versions.
    //
    if (MsQuicLib.DefaultCompatibilityListLength > 0) {
        for (uint32_t i = 0; i < MsQuicLib.DefaultCompatibilityListLength; ++i) {
            ASSERT_TRUE(
                QuicVersionNegotiationExtIsVersionCompatible(
                    &Connection,
                    MsQuicLib.DefaultCompatibilityList[i]));
        }
    }

    //
    // Unknown version should not be compatible.
    //
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, 0x12345678));
}

//
// With custom VersionSettings, compatibility is determined by
// AreVersionsCompatible applied over the FullyDeployedVersions.
//
TEST(VersionNegTest, IsVersionCompatible_CustomSettings)
{
    //
    // Set FullyDeployedVersions = {V1, V2}.
    // V1 is compatible with MS_1 and V2 (from map).
    // V2 is only compatible with itself.
    //
    uint32_t DeployedVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.FullyDeployedVersions = DeployedVersions;
    VerSettings.FullyDeployedVersionsLength = ARRAYSIZE(DeployedVersions);

    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = &VerSettings;
    Connection.Settings.IsSet.VersionSettings = TRUE;

    //
    // V1 is in deployed list -> compatible with V1 (identity).
    //
    ASSERT_TRUE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_1));

    //
    // V2 is in deployed list -> compatible with V2 (identity).
    //
    ASSERT_TRUE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_2));

    //
    // MS_1 is compatible with V1 (V1->MS_1 in map), so negotiating MS_1
    // should be compatible.
    //
    ASSERT_TRUE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_MS_1));

    //
    // DRAFT_29 is NOT compatible with either V1 or V2 (no map entry).
    //
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_DRAFT_29));

    //
    // Unknown version.
    //
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, 0xDEADBEEF));
}

//
// With custom VersionSettings containing only DRAFT_29, compatibility
// is very limited.
//
TEST(VersionNegTest, IsVersionCompatible_Draft29Only)
{
    uint32_t DeployedVersions[] = {QUIC_VERSION_DRAFT_29};
    QUIC_VERSION_SETTINGS VerSettings;
    CxPlatZeroMemory(&VerSettings, sizeof(VerSettings));
    VerSettings.FullyDeployedVersions = DeployedVersions;
    VerSettings.FullyDeployedVersionsLength = ARRAYSIZE(DeployedVersions);

    QUIC_CONNECTION Connection {};
    Connection.Settings.VersionSettings = &VerSettings;
    Connection.Settings.IsSet.VersionSettings = TRUE;

    //
    // DRAFT_29 is compatible with itself (identity).
    //
    ASSERT_TRUE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_DRAFT_29));

    //
    // No compatibility map entries for DRAFT_29, so everything else fails.
    //
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_1));
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_2));
    ASSERT_FALSE(
        QuicVersionNegotiationExtIsVersionCompatible(&Connection, QUIC_VERSION_MS_1));
}
