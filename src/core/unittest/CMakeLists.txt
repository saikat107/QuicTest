# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    AckTrackerTest.cpp
    ApiTest.cpp
    ApiTestHelper.c
    BbrTest.cpp
    BindingTest.cpp
    ConfigurationTest.cpp
    CongestionControlTest.cpp
    ConnectionPoolTest.cpp
    ConnectionTest.cpp
    CryptoTest.cpp
    CryptoTlsTest.cpp
    CubicTest.cpp
    DatagramTest.cpp
    FrameTest.cpp
    InjectionTest.cpp
    LibraryTest.cpp
    ListenerTest.cpp
    LookupTest.cpp
    LossDetectionTest.cpp
    MtuDiscoveryTest.cpp
    OperationTest.cpp
    PacketBuilderTest.cpp
    PacketNumberTest.cpp
    PacketSpaceTest.cpp
    PartitionTest.cpp
    PathTest.cpp
    RangeTest.cpp
    RecvBufferTest.cpp
    RegistrationTest.cpp
    SendBufferTest.cpp
    SendTest.cpp
    SentPacketMetadataTest.cpp
    SettingsTest.cpp
    SlidingWindowExtremumTest.cpp
    SpinFrame.cpp
    StreamRecvTest.cpp
    StreamSendTest.cpp
    StreamSetTest.cpp
    StreamTest.cpp
    TicketTest.cpp
    TimerWheelTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
    VersionNegExtTest.cpp
    WorkerTest.cpp
)

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
set_property(TARGET msquiccoretest APPEND PROPERTY BUILD_RPATH "$ORIGIN")

target_link_libraries(msquiccoretest msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquiccoretest core msquic_platform)
endif()

target_link_libraries(msquiccoretest inc gtest warnings logging base_link)

if (WIN32)
    target_link_libraries(msquiccoretest oldnames)
endif()

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
