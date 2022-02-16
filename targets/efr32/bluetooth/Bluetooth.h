/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/Bluetooth.h
 */

#pragma once

#include <kernel/kernel.h>

#include <native_gecko.h>
#include <gatt_db.h>
#include <kernel/platform.h>

#include <base/Span.h>
#include <base/UuidLE.h>

#if Cstorage
#include <storage/ByteStorage.h>
#endif

#ifndef BLUETOOTH_MAX_CONNECTIONS
#define BLUETOOTH_MAX_CONNECTIONS	4
#endif

#ifndef BLUETOOTH_MAX_ADVERTISERS
#define BLUETOOTH_MAX_ADVERTISERS   1
#endif

#ifndef BLUETOOTH_ADDITIONAL_HEAP
#if SRAM_SIZE > 32768
#define BLUETOOTH_ADDITIONAL_HEAP	4096
#else
#define BLUETOOTH_ADDITIONAL_HEAP	1024
#endif
#endif

// this command was briefly exposed in API v2.4 but is implemented in other versions as well
// we need to keep it as it is very useful to check current buffer status and to prevent
// overflows when streaming
#ifndef gecko_cmd_test_debug_counter_id
#define gecko_cmd_test_debug_counter_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0c0e0000)
#define gecko_rsp_test_debug_counter_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0c0e0000)

PACKSTRUCT( struct gecko_msg_test_debug_counter_cmd_t
{
    uint32              id;
});
PACKSTRUCT( struct gecko_msg_test_debug_counter_rsp_t
{
    uint16              result;
    uint32              value;
});

extern "C" void sli_bt_cmd_test_debug_counter(const void*);

/**
*
* gecko_cmd_test_debug_counter
*
* debug_counter
*
* @param id   Counter id
*     17: Free bgbufs
*     19: The bgbuf data size
*     20: Maximum number of in/out bgbufs
*     21: The bgbuf internal counters (in/out/noFlow)
*     22: Force SMP to legacy pairing mode
*     23: Disable SMP pairing request flood protection
*
**/

static inline struct gecko_msg_test_debug_counter_rsp_t* gecko_cmd_test_debug_counter(uint32 id)
{
    struct gecko_cmd_packet *gecko_cmd_msg = (struct gecko_cmd_packet *)gecko_cmd_msg_buf;
    struct gecko_cmd_packet *gecko_rsp_msg = (struct gecko_cmd_packet *)gecko_rsp_msg_buf;

    ((gecko_msg_test_debug_counter_cmd_t*)(&gecko_cmd_msg->data))->id = id;
    gecko_cmd_msg->header=((gecko_cmd_test_debug_counter_id+((4)<<8)));

    sli_bt_cmd_handler_delegate(gecko_cmd_msg->header, sli_bt_cmd_test_debug_counter, &gecko_cmd_msg->data.payload);

    return (gecko_msg_test_debug_counter_rsp_t*)(&gecko_rsp_msg->data);
}
#endif

class Bluetooth
{
public:
    enum struct Security
    {
        None,
        Paired,
        Authenticated,
        Secure,
    };

    enum struct AddressType
    {
        Public,
        Random,
        PublicIdentity,
        RandomIdentity,
    };

    enum PHY
    {
        PHYUnknown = 0,
        PHY1M = le_gap_phy_1m,
        PHY2M = le_gap_phy_2m,
        PHYCoded = le_gap_phy_coded,
    };

    DECLARE_FLAG_ENUM(PHY);

    enum struct AttError : uint8_t
    {
        OK = 0,
        InvalidHandle = 1,
        ReadNotPermitted = 2,
        WriteNotPermitted = 3,
        InvalidPDU = 4,
        InsufficientAuthentication = 5,
        RequestNotSupported = 6,
        InvalidOffset = 7,
        InsufficientAuthorization = 8,
        PrepareQueueFull = 9,
        AttributeNotFound = 10,
        AttributeNotLong = 11,
        InsufficientEncryptionKeySize = 12,
        InvalidAttributeValueLength = 13,
        UnlikelyError = 14,
        InsufficientEncryption = 15,
        UnsupportedGroupType = 16,
        InsufficientResources = 17,
        ApplicationError0 = 0x80,
    };

    class Service
    {
        uint32_t handle;

    public:
        constexpr Service(uint32_t handle = 0)
            : handle(handle) {}

        constexpr operator uint32_t() const { return handle; }

        friend class Bluetooth;
    };

    class Attribute
    {
        uint16_t handle;

    public:
        constexpr Attribute(uint16_t handle = 0)
            : handle(handle) {}

        constexpr operator uint16_t() const { return handle; }

        friend class Bluetooth;
    };

    class Characteristic : public Attribute
    {
    public:
        constexpr Characteristic(uint16_t handle = 0)
            : Attribute(handle) {}
    };

    class Descriptor : public Attribute
    {
    public:
        constexpr Descriptor(uint16_t handle)
            : Attribute(handle) {}
    };

    class CharacteristicWithProperties
    {
        union
        {
            struct
            {
                uint16_t handle;
                uint16_t properties;
            };
            uint32_t raw;
        };

        constexpr CharacteristicWithProperties(uint16_t handle, uint16_t properties)
            : handle(handle), properties(properties) {}

    public:
        constexpr CharacteristicWithProperties(uint32_t raw = 0)
            : raw(raw) {}

        constexpr operator Characteristic() const { return handle; }
        constexpr operator uint32_t() const { return raw; }

        friend class Bluetooth;
    };

    class Connection
    {
        union
        {
            struct
            {
                uint16_t error : 15;
                uint16_t isError : 1;
            };
            struct
            {
                uint8_t id;
                uint8_t seq : 7;
            };
            uint16_t raw;
        };

        constexpr Connection(uint8_t id, uint8_t seq)
            : raw(id | ((seq & 0x7F) << 8)) {}

        constexpr static Connection Error(uint16_t error) { return Connection(error ? error | BIT(15) : 0); }

        constexpr bool CheckSequence(uint8_t seq) const { return !((this->seq ^ seq) & 0x7F); }

    public:
        constexpr Connection(uint16_t rawValue = 0)
            : raw(rawValue) {}

        constexpr operator uint16_t() const { return isError ? 0 : id; }

        constexpr bool operator ==(const Connection& other) const { return raw == other.raw; }
        constexpr bool operator !=(const Connection& other) const { return raw != other.raw; }

        async(Close);

        //! Gets the current security level
        Bluetooth::Security Security() const;
        //! Gets the current MTU
        size_t MTU() const;
        //! Gets maximum allowed notification size
        size_t MaxNotification() const;
        //! Gets the maximum allowed read payload size
        size_t MaxReadResponse() const;
        //! Gets the maximum allowed write payload size
        size_t MaxWrite() const;
        //! Gets the maximum allowed write without response payload size
        size_t MaxWriteNoResponse() const;

        friend class Bluetooth;
    };

    class IncomingConnection : public Connection
    {
        constexpr IncomingConnection(uint8_t id, uint8_t seq)
            : Connection(id, seq) {}

        constexpr IncomingConnection(Connection conn)
            : Connection(conn) {}

    public:
        constexpr IncomingConnection(uint16_t rawValue = 0)
            : Connection(rawValue) {}

        async(SendNotification, Characteristic characteristic, Span value);

        friend class Bluetooth;
    };

    class OutgoingConnection : public Connection
    {
        constexpr OutgoingConnection(uint8_t id, uint8_t seq)
            : Connection(id, seq) {}

        constexpr OutgoingConnection(Connection conn)
            : Connection(conn) {}

    public:
        constexpr OutgoingConnection(uint16_t rawValue = 0)
            : Connection(rawValue) {}

        //! Registers a handler for handling an attribute (characteristic or descriptor) event
        template<typename T> void RegisterHandler(Attribute attribute, T&& handler);
        //! Registers a handler for handling an attribute (characteristic or descriptor) event
        template<typename TTarget, typename THandler> void RegisterHandler(Attribute attribute, TTarget&& target, THandler&& handler)
            { RegisterHandler(attribute, GetDelegate(std::forward<TTarget>(target), std::forward<THandler>(handler))); }

        async(DiscoverService, const UuidLE& uuid);
        async(DiscoverCharacteristic, Service service, const UuidLE& uuid);

        async(EnableNotifications, Characteristic characteristic);
        async(DisableNotifications, Characteristic characteristic);

        async(Read, Characteristic characteristic, Buffer value);
        async(Write, Characteristic characteristic, Span value);
        async(WriteWithoutResponse, Characteristic characteristic, Span value);

        errorcode_t GetLastError() const;
        const char* GetLastErrorMessage() const { return GetErrorMessage(GetLastError()); }

        friend class Bluetooth;
    };

    struct AttributeValueChanged
    {
        IncomingConnection connection;
        Attribute attribute;
        uint8_t opcode;
        uint32_t offset;
        Span value;
    };

    struct CharacteristicReadRequest
    {
        IncomingConnection connection;
        Characteristic characteristic;
        uint8_t opcode;
        uint32_t offset;

        void Success(Span data) { Respond(data, AttError::OK); }
        void Error(AttError error) { Respond(Span(), error); }
        void Respond(Span data, AttError error);
    };

    struct CharacteristicWriteRequest
    {
        IncomingConnection connection;
        Characteristic characteristic;
        uint8_t opcode;
        uint32_t offset;
        Span data;

        void Success() { Respond(AttError::OK); }
        void Error(AttError error) { Respond(error); }
        void Respond(AttError error);
    };

    enum struct EventLevel : uint8_t { Disabled, Notification, Indication };
    struct CharacteristicEventRequest
    {
        IncomingConnection connection;
        EventLevel level;
        Characteristic characteristic;
    };

    struct CharacteristicNotification
    {
        OutgoingConnection connection;
        Characteristic characteristic;
        Span data;
        uint16_t offset;
    };

    template<typename TConnection> struct ConnectionOpenedEvent
    {
        TConnection connection;
        errorcode_t reason;
    };

    using IncomingConnectionOpened = ConnectionOpenedEvent<IncomingConnection>;
    using OutgoingConnectionOpened = ConnectionOpenedEvent<OutgoingConnection>;

    template<typename TConnection> struct ConnectionClosedEvent
    {
        TConnection connection;
        errorcode_t reason;
    };

    using IncomingConnectionClosed = ConnectionClosedEvent<IncomingConnection>;
    using OutgoingConnectionClosed = ConnectionClosedEvent<OutgoingConnection>;

    struct Advertisement
    {
        uint8_t packetType;
        bd_addr address;
        AddressType addressType;
        uint8_t bonding;
        PHY phy, phy2;
        uint8_t sid;
        int8_t rssi, txPower;
        uint8_t channel;
        uint16_t periodicInterval;
        Span data;

        Span HostAddress() const { return address; }
        Span GetField(uint8_t field) const { return GetFieldImpl(data, field); }

    private:
        static RES_PAIR_DECL(GetFieldImpl, Span s, uint8_t field);
    };

    //! Initializes the Bluetooth stack and waits until the startup is complete
    async(Init);
    //! Returns true if the Bluetooth stack initialization is complete
    bool Initialized() const { return !!(flags & Flags::Initialized); }

    //! Gets a bit mask determining active connections
    const uint32_t& Connections() const { return connections; }
    //! Gets the current security level of the specified connection
    Security ConnectionSecurity(Connection connection) const { return GetConnectionInfo(connection)->security; }
    //! Gets the current MTU of the specified connection
    size_t ConnectionMTU(Connection connection) const { return GetConnectionInfo(connection)->mtu; }
    //! Gets maximum allowed notification size for the specified connection
    size_t ConnectionMaxNotification(Connection connection) const { return ConnectionMTU(connection) - 3; }
    //! Gets the maximum allowed read payload size for the specified connection
    size_t ConnectionMaxReadResponse(Connection connection) const { return ConnectionMTU(connection) - 1; }
    //! Gets the maximum allowed write payload size for the specified connection
    size_t ConnectionMaxWrite(Connection connection) const { return ConnectionMTU(connection) - 5; }
    //! Gets the maximum allowed write without response payload size for the specified connection
    size_t ConnectionMaxWriteNoResponse(Connection connection) const { return ConnectionMTU(connection) - 3; }
    //! Gets the IncomingConnection from an index, if it is incoming
    IncomingConnection GetIncomingConnection(Connection connection) const
    {
        auto con = GetConnectionInfo(connection);
        return con->IsIncoming() ? IncomingConnection(connection, con->seq) : IncomingConnection();
    }
    //! Gets the OutgoingConnection from an index, if it is outgoing
    OutgoingConnection GetOutgoingConnection(Connection connection) const
    {
        auto con = GetConnectionInfo(connection);
        return con->IsOutgoing() ? OutgoingConnection(connection, con->seq) : OutgoingConnection();
    }

    //! Gets the total number of I/O buffers used by the Bluetooth stack
    int BuffersTotal() const { return ioBuffers; }
    //! Gets the size of an individual I/O buffer used by the Bluetooth stack
    int BufferSize() const { return bufferSize; }
    //! Gets the number of free I/O buffers
    int BuffersAvailable() const { return gecko_cmd_test_debug_counter(17)->value; }
    //! Gets the number of I/O buffers currently used for receiving
    int RxBuffersUsed() const { return BufferCounts().in; }
    //! Gets the number of I/O buffers currently used for transmitting
    int TxBuffersUsed() const { return BufferCounts().out; }
    //! Gets the total number of I/O buffers currently used
    int IoBuffersUsed() const { auto counts = BufferCounts(); return counts.in + counts.out; }
    //! Gets the number of free I/O buffers available for receiving
    int RxBuffersAvailable() const { return std::min(BuffersAvailable(), ioBuffers - IoBuffersUsed()); }
    //! Gets the number of free I/O buffers available for transmitting
    int TxBuffersAvailable() const { return std::min(BuffersAvailable(), ioBuffers - IoBuffersUsed() - 10); }	// empirically found out that TX fails with OOM somewhere aroung 10 free buffers
    //! Checks if the transmitter queue is almost empty
    bool TxAlmostIdle() const { return TxBuffersUsed() < 10; }	// empirical value for good latency
    //! Waits until the transmitter queue is almost empty
    async(TxAlmostIdle);

    /********** le_gap **********/

    enum struct ScanMode
    {
        Limited = le_gap_discover_limited,
        Generic = le_gap_discover_generic,
        Observation = le_gap_discover_observation,
    };

    enum struct Discoverable
    {
        No = le_gap_non_discoverable,
        Limited = le_gap_limited_discoverable,
        General = le_gap_general_discoverable,
        Broadcast = le_gap_broadcast,
        UserData = le_gap_user_data,
    };

    enum struct Connectable
    {
        No = le_gap_non_connectable,
        Directed = le_gap_directed_connectable,
        Undirected = le_gap_undirected_connectable,
        Scannable = le_gap_connectable_scannable,
        ScannableOnly = le_gap_scannable_non_connectable,
        NonScannable = le_gap_connectable_non_scannable,
    };

    class AdvertisementSet
    {
    public:
#if BLUETOOTH_MAX_ADVERTISERS > 1
        //! Gets the index of this advertisement set
        uint8_t Index() const;
#else
        //! Gets the index of this advertisement set
        constexpr uint8_t Index() const { return 0; }
#endif

        //! Sets advertisement PHY
        errorcode_t SetAdvertisementPHY(PHY primary, PHY secondary = PHY1M)
        {
            return ProcessResult(gecko_cmd_le_gap_set_advertise_phy(Index(), primary, secondary)->result);
        }

        //! Sets custom advertisement data
        errorcode_t SetAdvertisementData(Span data)
        {
            ASSERT(data.Length() <= 30);
            return ProcessResult(gecko_cmd_le_gap_bt5_set_adv_data(Index(), 0, data.Length(), data)->result);
        }

        //! Sets custom scan response data
        errorcode_t SetScanResponseData(Span data)
        {
            ASSERT(data.Length() <= 30);
            return ProcessResult(gecko_cmd_le_gap_bt5_set_adv_data(Index(), 1, data.Length(), data)->result);
        }

        //! Configures advertisement interval duration in milliseconds
        void SetAdvertisementInterval(float tMin, float tMax = 0)
        {
            uint32_t min = tMin / 0.625f, max = tMax < tMin ? min : (tMax / 0.625f);
            ASSERT(min >= 0x20 && min <= 0x4000);
            ASSERT(max >= 0x20 && max <= 0x4000);
            this->min = min;
            this->max = max;
            flags |= Flags::Update;
        }

        //! Configures the channels used for advertising
        void SetAdvertisementChannels(uint8_t channelMask = 7)
        {
            ASSERT(!(channelMask & 7));
            channels = channelMask;
            flags |= Flags::Update;
        }

        //! Configures advertisement timeout (time after which advertising stops)
        void SetAdvertisementTimeout(float t)
        {
            ASSERT(t >= 0 && t <= 655.35f);
            timeout = t * 100;
            flags |= Flags::Update;
        }

        //! Configures number of advertisements sent before stopping
        void SetAdvertisementCount(uint8_t count)
        {
            this->count = count;
            flags |= Flags::Update;
        }

        //! Starts advertising
        void StartAdvertising(Discoverable discover, Connectable connect, bool keep = false);
        //! Stops advertising
        void StopAdvertising();

    private:
        AdvertisementSet() {}

        enum struct Flags : uint8_t
        {
            None = 0,

            KeepDiscoverable = BIT(0),      //< Whether to keep advertising even while a connection is open
            Update = BIT(1),                //< Advertisement parameters have changed
            Requested = BIT(2),             //< Advertising is requested
            Active = BIT(3),                //< Advertising is currently active
        };

        DECLARE_FLAG_ENUM(Flags);

        uint32_t min = 160, max = 160;      //< Advertising interval in native BLE units (625 us), default 100 ms
        uint16_t timeout = 0;               //< Advertisement timeout
        uint8_t count = 0;                  //< Advertisement count limit
        uint8_t channels = 7;               //< Advertising channel mask
        uint8_t discover = 0;               //< Advertised discoverability mode
        uint8_t connect = 0;                //< Advertised connectability mode
        Flags flags = Flags::None;          //< Various state flags, see above

        friend class Bluetooth;

        void StopImpl();
        void StartImpl();
    };

    //! Gets the specified advertiser configuration
    ALWAYS_INLINE AdvertisementSet& Advertiser(unsigned index = 0)
        { ASSERT(index < BLUETOOTH_MAX_ADVERTISERS); return adv[index]; }

    //! Sets advertisement PHY
    ALWAYS_INLINE errorcode_t SetAdvertisementPHY(PHY primary, PHY secondary = PHY1M)
        { return adv[0].SetAdvertisementPHY(primary, secondary); }

    //! Sets custom advertisement data
    ALWAYS_INLINE errorcode_t SetAdvertisementData(Span data)
        { return adv[0].SetAdvertisementData(data); }

    //! Sets custom scan response data
    ALWAYS_INLINE errorcode_t SetScanResponseData(Span data)
        { return adv[0].SetScanResponseData(data); }

    //! Configures advertisement interval duration in milliseconds
    ALWAYS_INLINE void SetAdvertisementInterval(float tMin, float tMax = 0)
        { return adv[0].SetAdvertisementInterval(tMin, tMax); }

    //! Configures the channels used for advertising
    ALWAYS_INLINE void SetAdvertisementChannels(uint8_t channelMask = 7)
        { return adv[0].SetAdvertisementChannels(channelMask); }

    //! Configures advertisement timeout (time after which advertising stops)
    ALWAYS_INLINE void SetAdvertisementTimeout(float t)
        { return adv[0].SetAdvertisementTimeout(t); }

    //! Configures number of advertisements sent before stopping
    ALWAYS_INLINE void SetAdvertisementCount(uint8_t count)
        { return adv[0].SetAdvertisementCount(count); }

    //! Starts advertising
    ALWAYS_INLINE void StartAdvertising(Discoverable discover, Connectable connect, bool keep = false)
        { return adv[0].StartAdvertising(discover, connect, keep); }

    //! Stops advertising
    ALWAYS_INLINE void StopAdvertising()
        { return adv[0].StopAdvertising(); }

    //! Configures the preferred and accepted PHYs to be used for connections
    errorcode_t SetConnectionPHY(PHY preferred, PHY accepted)
    {
        return ProcessResult(gecko_cmd_le_gap_set_conn_phy(preferred, accepted)->result);
    }

    //! Configures the parameters of new connections
    errorcode_t SetConnectionParameters(float tConMin, float tConMax, uint32_t slaveLatency, uint32_t timeout)
    {
        uint32_t min = tConMin / 1.25f, max = tConMax / 1.25f;
        ASSERT(min >= 6 && min <= 3200);
        ASSERT(max >= 6 && max <= 3200);
        ASSERT(slaveLatency <= 500);
        ASSERT(timeout >= 100 && timeout <= 32000);
        ASSERT(max >= min);
        ASSERT(timeout > tConMax * (slaveLatency + 1));
        return ProcessResult(gecko_cmd_le_gap_set_conn_timing_parameters(min, max, slaveLatency, timeout / 10, 0, 0xFFFF)->result);
    }

    //! Configures the parameters of the specified connection
    errorcode_t SetConnectionParameters(uint32_t connection, float tConMin, float tConMax, uint32_t slaveLatency, uint32_t timeout)
    {
        uint32_t min = tConMin / 1.25f, max = tConMax / 1.25f;
        ASSERT(min >= 6 && min <= 3200);
        ASSERT(max >= 6 && max <= 3200);
        ASSERT(slaveLatency <= 500);
        ASSERT(timeout >= 100 && timeout <= 32000);
        ASSERT(max >= min);
        ASSERT(timeout > tConMax * (slaveLatency + 1));
        return ProcessResult(gecko_cmd_le_connection_set_timing_parameters(connection, min, max, slaveLatency, timeout / 10, 0, 0xFFFF)->result);
    }

    //! Configures scanning parameters
    errorcode_t SetScanningParameters(float tWindow, float tInterval = 0, bool active = false, PHY phys = PHY1M | PHYCoded)
    {
        uint32_t window = tWindow / 0.625f, interval = tInterval < tWindow ? window : (tInterval / 0.625f);
        ASSERT(interval >= 4 && interval <= 0x4000);
        ASSERT(window >= 4 && window <= 0x4000);
        auto err = ProcessResult(gecko_cmd_le_gap_set_discovery_timing(phys, interval, window)->result);
        if (!err) err = ProcessResult(gecko_cmd_le_gap_set_discovery_type(phys, active)->result);
        return err;
    }

    //! Tries to connect to the peripheral with the specified address
    //! @returns A valid @ref OutgoingConnection object if connection succeeded
    async(Connect, bd_addr address, Timeout timeout, PHY phy = PHY1M);

    //! Closes an active connection
    async(CloseConnection, Connection connection);

    typedef AsyncDelegate<Advertisement&> ScannerDelegate;

    //! Adds a scanner (handler for advertisements)
    void AddScanner(ScannerDelegate scanner, ScanMode mode = ScanMode::Observation, PHY phy = PHY1M);
    template<typename TTarget, typename THandler> void AddScanner(TTarget&& target, THandler&& handler, ScanMode mode = ScanMode::Observation, PHY phy = PHY1M)
        { AddScanner(GetDelegate(std::forward<TTarget>(target), std::forward<THandler>(handler)), mode, phy); }

    //! Removes a scanner
    void RemoveScanner(ScannerDelegate scanner);
    template<typename TTarget, typename THandler> void RemoveScanner(TTarget&& target, THandler&& handler)
        { RemoveScanner(GetDelegate(std::forward<TTarget>(target), std::forward<THandler>(handler))); }

    /********** gatt **********/

    //! Initiates the write of a new value to the specified characteristic or descriptor
    ALWAYS_INLINE errorcode_t WriteAttribute(uint32_t characteristicOrDescriptor, Span data)
    {
        return ProcessResult(gecko_cmd_gatt_server_write_attribute_value(characteristicOrDescriptor, 0, data.Length(), data)->result);
    }

    //! Sends a value change notfication for the specified characteristic to the specified connection
    ALWAYS_INLINE errorcode_t SendNotification(uint32_t connection, uint32_t characteristic, Span data)
    {
        return (errorcode_t)RES_PAIR_FIRST(SendNotificationImpl(connection, characteristic, data));
    }

    //! Sends a value change notfication for the specified characteristic to the specified connection, retrieving the number of bytes actually sent
    ALWAYS_INLINE errorcode_t SendNotification(uint32_t connection, uint32_t characteristic, Span data, uint32_t& sent)
    {
        res_pair_t packed = SendNotificationImpl(connection, characteristic, data);
        sent = RES_PAIR_SECOND(packed);
        return (errorcode_t)RES_PAIR_FIRST(packed);
    }

    async(DiscoverService, OutgoingConnection connection, const UuidLE& uuid);
    async(DiscoverCharacteristic, OutgoingConnection connection, Service service, const UuidLE& uuid);
    async(SetCharacteristicNotification, OutgoingConnection connection, Characteristic characteristic, gatt_client_config_flag flags);
    async(EnableNotifications, OutgoingConnection connection, Characteristic characteristic)
        { return async_forward(SetCharacteristicNotification, connection, characteristic, gatt_notification); }
    async(DisableNotifications, OutgoingConnection connection, Characteristic characteristic)
        { return async_forward(SetCharacteristicNotification, connection, characteristic, gatt_disable); }
    async(ReadCharacteristic, OutgoingConnection connection, Characteristic characteristic, Buffer buffer);
    async(WriteCharacteristic, OutgoingConnection connection, Characteristic characteristic, Span data);
    async(WriteCharacteristicWithoutResponse, OutgoingConnection connection, Characteristic characteristic, Span data);
    async(SendCharacteristicNotification, IncomingConnection connection, Characteristic characteristic, Span data);
    async(BroadcastCharacteristicNotification, Characteristic characteristic, Span data);
    size_t TryBroadcastCharacteristicNotification(Characteristic characteristic, Span data);

    //! Registers a handler for handling an attribute (characteristic or descriptor)
    template<typename T> void RegisterHandler(Attribute attribute, T&& handler)
        { RegisterHandler(handlers, AttributeHandler(attribute, std::forward<T>(handler))); }
    //! Registers a handler for handling an attribute (characteristic or descriptor)
    template<typename TTarget, typename THandler> void RegisterHandler(Attribute attribute, TTarget&& target, THandler&& handler)
        { RegisterHandler(attribute, GetDelegate(std::forward<TTarget>(target), std::forward<THandler>(handler))); }

    //! Registers a general handler (e.g. connection)
    template<typename T> void RegisterHandler(T&& handler)
        { RegisterHandler(handlers, AttributeHandler(std::forward<T>(handler))); }
    //! Registers a general handler (e.g. connection)
    template<typename TTarget, typename THandler> void RegisterHandler(TTarget&& target, THandler&& handler)
        { RegisterHandler(GetDelegate(std::forward<TTarget>(target), std::forward<THandler>(handler))); }

    //! Registers standard handler for the Gecko OTA Control characteristic
    void RegisterGeckoOTAControlHandler(Characteristic characteristic)
        { RegisterHandler(characteristic, this, &Bluetooth::GeckoOTAControlWriteHandler); }
#if Cstorage
    //! Registers standard handler for the Gecko OTA Control characteristic, with direct write support
    void RegisterGeckoOTAStorageHandler(Characteristic charCtl, Characteristic charData, storage::ByteStorage& storage);
#endif
    //! Registers standard handler for the Gecko OTA Version characteristic
    void RegisterGeckoOTAVersionHandler(Characteristic characteristic)
        { RegisterHandler(characteristic, this, &Bluetooth::GeckoOTAVersionReadHandler); }
    //! Registers a handler called just before a reset to DFU
    void RegisterGeckoOTAResetHandler(Delegate<void> handler)
        { beforeReset.Push(handler); }
    //! Registers standard handler for retrieving System ID
    void RegisterSystemIDHandler(Characteristic characteristic)
        { RegisterHandler(characteristic, this, &Bluetooth::SystemIDReadHandler); }
    //! Registers standard handler for retrieving Application Product ID
    void RegisterApplicationProductHandler(Characteristic characteristic)
        { RegisterHandler(characteristic, this, &Bluetooth::ApplicationProductReadHandler); }

    /********** sm (Security Manager) **********/

    enum struct IOCapabilities
    {
        DisplayOnly, DisplayYesNo, KeyboardOnly, None, Full,
    };

    //! Configures required security level
    errorcode_t SetSecurity(bool mitmProtection, IOCapabilities caps)
    {
        return ProcessResult(gecko_cmd_sm_configure(mitmProtection | 2, (uint8_t)caps)->result);
    }

    //! Configures a fixed passkey
    errorcode_t SetPasskey(uint32_t key)
    {
        return ProcessResult(gecko_cmd_sm_set_passkey(key)->result);
    }

    //! Sets passkey autoconfirmation
    errorcode_t SetPasskeyAutoconfirm(bool state = true)
    {
        if (state) { flags |= Flags::PassAutoConfirm; }
        else { flags &= ~Flags::PassAutoConfirm; }
        return bg_err_success;
    }

    //! Configures the bonding database
    errorcode_t SetBondingConfiguration(uint32_t maxBondings, bool newReplaceOld)
    {
        return ProcessResult(gecko_cmd_sm_store_bonding_configuration(maxBondings, newReplaceOld)->result);
    }

    //! Enables or disables device bondability
    errorcode_t SetBondable(bool bondable = true)
    {
        return ProcessResult(gecko_cmd_sm_set_bondable_mode(bondable)->result);
    }

    /********** system **********/

    //! Configures transmission power
    float SetTxPower(float power)
    {
        return gecko_cmd_system_set_tx_power(power * 10)->set_power / 10.0f;
    }

    //! Gets the message corresponding to the provided error code
    static const char* GetErrorMessage(uint32_t err);

private:

    union BufferCounts
    {
        uint32_t raw;
        struct {
            uint8_t in, out, noFlow;
        };
    };
    union BufferCounts BufferCounts() const { return (union BufferCounts){ gecko_cmd_test_debug_counter(21)->value }; }

    enum struct Flags : uint32_t
    {
        None = 0,
        Initialized = BIT(0),               //< Set to true once the stack initialization is complete
        ScanUpdate = BIT(1),                //< Scanning parameters have changed
        Connecting = BIT(2),                //< An outgoing connection is currently pending
        ScanningRequested = BIT(3),         //< Scanning for advertisements is requested
        ScanningActive = BIT(4),            //< Scanning for advertisements is currently active
        PassAutoConfirm = BIT(5),           //< Automatic confirmation when using DisplayYesNo security

        ScanningRequestedAndActive = ScanningRequested | ScanningActive,
    };

    DECLARE_FLAG_ENUM(Flags);

    enum struct AttributeHandlerType : uint16_t
    {
        ValueChange,
        ReadRequest,
        WriteRequest,
        EventRequest,
        Notification,
        IncomingConnectionOpened,
        OutgoingConnectionOpened,
        IncomingConnectionClosed,
        OutgoingConnectionClosed,

        _Sync = 0x10,
        SyncValueChange = _Sync | ValueChange,
        SyncReadRequest = _Sync | ReadRequest,
        SyncWriteRequest = _Sync | WriteRequest,
        SyncEventRequest = _Sync | EventRequest,
        SyncNotification = _Sync | Notification,
        SyncIncomingConnectionOpened = _Sync | IncomingConnectionOpened,
        SyncOutgoingConnectionOpened = _Sync | OutgoingConnectionOpened,
        SyncIncomingConnectionClosed = _Sync | IncomingConnectionClosed,
        SyncOutgoingConnectionClosed = _Sync | OutgoingConnectionClosed,

        _TypeMask = 0xF,
    };

    struct AttributeHandler
    {
        constexpr AttributeHandler(Attribute attribute, AsyncDelegate<AttributeValueChanged&> delegate)
            : attribute(attribute), type(AttributeHandlerType::ValueChange), valueChange(delegate) {}
        constexpr AttributeHandler(Attribute attribute, AsyncDelegate<CharacteristicReadRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::ReadRequest), read(delegate) {}
        constexpr AttributeHandler(Attribute attribute, AsyncDelegate<CharacteristicWriteRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::WriteRequest), write(delegate) {}
        constexpr AttributeHandler(Attribute attribute, AsyncDelegate<CharacteristicEventRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::EventRequest), eventRequest(delegate) {}
        constexpr AttributeHandler(Attribute attribute, AsyncDelegate<CharacteristicNotification&> delegate)
            : attribute(attribute), type(AttributeHandlerType::Notification), notification(delegate) {}

        constexpr AttributeHandler(Attribute attribute, Delegate<void, AttributeValueChanged&> delegate)
            : attribute(attribute), type(AttributeHandlerType::SyncValueChange), syncValueChange(delegate) {}
        constexpr AttributeHandler(Attribute attribute, Delegate<void, CharacteristicReadRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::SyncReadRequest), syncRead(delegate) {}
        constexpr AttributeHandler(Attribute attribute, Delegate<void, CharacteristicWriteRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::SyncWriteRequest), syncWrite(delegate) {}
        constexpr AttributeHandler(Attribute attribute, Delegate<void, CharacteristicEventRequest&> delegate)
            : attribute(attribute), type(AttributeHandlerType::SyncEventRequest), syncEventRequest(delegate) {}
        constexpr AttributeHandler(Attribute attribute, Delegate<void, CharacteristicNotification&> delegate)
            : attribute(attribute), type(AttributeHandlerType::SyncNotification), syncNotification(delegate) {}

        constexpr AttributeHandler(Delegate<void, IncomingConnectionOpened&> delegate)
            : attribute(), type(AttributeHandlerType::SyncIncomingConnectionOpened), syncIncomingConnectionOpened(delegate) {}
        constexpr AttributeHandler(Delegate<void, OutgoingConnectionOpened&> delegate)
            : attribute(), type(AttributeHandlerType::SyncOutgoingConnectionOpened), syncOutgoingConnectionOpened(delegate) {}
        constexpr AttributeHandler(Delegate<void, IncomingConnectionClosed&> delegate)
            : attribute(), type(AttributeHandlerType::SyncIncomingConnectionClosed), syncIncomingConnectionClosed(delegate) {}
        constexpr AttributeHandler(Delegate<void, OutgoingConnectionClosed&> delegate)
            : attribute(), type(AttributeHandlerType::SyncOutgoingConnectionClosed), syncOutgoingConnectionClosed(delegate) {}

        Attribute attribute;
        AttributeHandlerType type;

        constexpr bool IsSynchronous() const { return int(type) & int(AttributeHandlerType::_Sync); }

        union
        {
            AsyncDelegate<AttributeValueChanged&> valueChange;
            AsyncDelegate<CharacteristicReadRequest&> read;
            AsyncDelegate<CharacteristicWriteRequest&> write;
            AsyncDelegate<CharacteristicEventRequest&> eventRequest;
            AsyncDelegate<CharacteristicNotification&> notification;

            Delegate<void, AttributeValueChanged&> syncValueChange;
            Delegate<void, CharacteristicReadRequest&> syncRead;
            Delegate<void, CharacteristicWriteRequest&> syncWrite;
            Delegate<void, CharacteristicEventRequest&> syncEventRequest;
            Delegate<void, CharacteristicNotification&> syncNotification;
            Delegate<void, IncomingConnectionOpened&> syncIncomingConnectionOpened;
            Delegate<void, OutgoingConnectionOpened&> syncOutgoingConnectionOpened;
            Delegate<void, ConnectionOpenedEvent<Connection>&> syncConnectionOpened;
            Delegate<void, IncomingConnectionClosed&> syncIncomingConnectionClosed;
            Delegate<void, OutgoingConnectionClosed&> syncOutgoingConnectionClosed;
            Delegate<void, ConnectionClosedEvent<Connection>&> syncConnectionClosed;
        };
    };

    struct Scanner
    {
        constexpr Scanner(ScannerDelegate delegate, ScanMode mode, PHY phy)
            : delegate(delegate), mode(mode), phy(phy) {}

        ScannerDelegate delegate;
        ScanMode mode;
        PHY phy;
    };

    Flags flags = Flags::None;              //< Various state flags, see above
    bool event = false;                     //< Event handler trigger from stack
    bool llEvent = false;                   //< Event handler trigger from interrupt
    uint32_t connections = 0;               //< Active connections mask
    int ioBuffers;                          //< Total count of I/O buffers
    int bufferSize;                         //< I/O buffer size
    AdvertisementSet adv[BLUETOOTH_MAX_ADVERTISERS];
    LinkedList<AttributeHandler> handlers;
    LinkedList<Scanner> scanners;
    LinkedList<Delegate<void>> beforeReset;

    async(CallScanners, Advertisement& advert);

    enum struct ConnectionFlags : uint8_t
    {
        Connecting = BIT(0),
        Connected = BIT(1),
        Master = BIT(2),
        Procedure = BIT(3),
        ProcedureRunning = BIT(4),
#ifdef gattdb_ota_control
        UpgradeResetRequested = BIT(6),
        DfuResetRequested = BIT(7),
#endif
    };

    DECLARE_FLAG_ENUM(ConnectionFlags);

    enum struct GattProcedure
    {
        Idle,

        // master / OutgoingConnection procedures
        Connection,
        DiscoverService,
        DiscoverCharacteristic,
        SetCharacteristicNotification,
        ReadCharacteristic,
        WriteCharacteristic,
        WriteCharacteristicWithoutResponse,

        // slave / IncomingConnection procedures
        SendCharacteristicNotification,
    };

    struct ReadOperation
    {
        Buffer buffer;
        uint32_t read;
    };

    struct WriteOperation
    {
        Span value;
        uint32_t written;
    };

    struct ConnectionInfo
    {
        struct
        {
            union
            {
                OutgoingConnection* connect;
                Service* service;
                CharacteristicWithProperties* characteristic;
                ReadOperation* read;
                WriteOperation* write;
                void* ptr;
            };
            GattProcedure type;
        } procedure;

        LinkedList<AttributeHandler> handlers;

        uint16_t error;
        uint16_t seq;
        uint32_t start;
        uint16_t mtu;
        uint16_t interval, latency, timeout, txsize;
        ConnectionFlags flags;
        Security security;
        int8_t bonding;
        int8_t rssi;
        PHY phy;
        bd_addr address;
        AddressType addressType;

        void EndProcedure();

        bool IsIncoming() const { return !(flags & ConnectionFlags::Master); }
        bool IsOutgoing() const { return !!(flags & ConnectionFlags::Master); }
    } connectionInfo[BLUETOOTH_MAX_CONNECTIONS] = {};	// connection numbers are one-based

    ALWAYS_INLINE uint8_t GetConnectionIndex(const ConnectionInfo* con) const
    {
        ASSERT(con >= connectionInfo && con < endof(connectionInfo));
        return con - connectionInfo + 1;
    }

    static constexpr uint8_t GetConnectionIndex(uint8_t index) { return index; }

    ALWAYS_INLINE const ConnectionInfo* GetConnectionInfo(uint8_t id) const
    {
        ASSERT(id > 0 && id <= BLUETOOTH_MAX_CONNECTIONS);
        return &connectionInfo[id - 1];
    }

    ALWAYS_INLINE ConnectionInfo* GetConnectionInfo(uint8_t id)
    {
        ASSERT(id > 0 && id <= BLUETOOTH_MAX_CONNECTIONS);
        return &connectionInfo[id - 1];
    }

    ALWAYS_INLINE const ConnectionInfo* GetConnectionInfo(Connection con) const
    {
        ASSERT(con.id > 0 && con.id <= BLUETOOTH_MAX_CONNECTIONS);
        return &connectionInfo[con.id - 1];
    }

    ALWAYS_INLINE ConnectionInfo* GetConnectionInfo(Connection con)
    {
        ASSERT(con.id > 0 && con.id <= BLUETOOTH_MAX_CONNECTIONS);
        return &connectionInfo[con.id - 1];
    }

    static void RegisterHandler(LinkedList<AttributeHandler>& handlers, AttributeHandler handler);

    struct HandlerEnumerator
    {
        constexpr HandlerEnumerator(LinkedList<AttributeHandler> handlers, LinkedList<AttributeHandler> globalHandlers, Attribute attribute, AttributeHandlerType type)
            : iter(handlers.begin()), global(globalHandlers.begin()), attributeAndType(uint32_t(attribute) | (uint32_t(type) << 16))
        {
        }

        AttributeHandler* Next();

    private:
        LinkedList<AttributeHandler>::Iterator iter, global;
        uint32_t attributeAndType;

        constexpr class Attribute Attribute() const { return (uint16_t)attributeAndType; }
        constexpr AttributeHandlerType Type() const { return AttributeHandlerType(attributeAndType >> 16); }
    };

    constexpr HandlerEnumerator FindHandlers(ConnectionInfo& ci, Attribute attr, AttributeHandlerType type)
        { return HandlerEnumerator(ci.handlers, handlers, attr, type); }

    async(Task);
    async(LLTask);

    static void ScheduleLL();
    static void ScheduleMain();

    DEBUG_NO_INLINE static errorcode_t ProcessResult(uint16_t res)
    {
        // arguments are validated, there should never be an error result
        if (res)
            DBGC("bluetooth", "Unexpected result: %s\n", GetErrorMessage(res));
        ASSERT(res == 0);
        return (errorcode_t)res;
    }

    ALWAYS_INLINE RES_PAIR_DECL(SendNotificationImpl, uint32_t connection, uint32_t characteristic, Span data)
        { return SendNotificationImpl((connection << 16) | (characteristic & 0xFFFF), data); }
    RES_PAIR_DECL(SendNotificationImpl, uint32_t connectionAndCharacteristic, Span data);

    async(BeginProcedure, OutgoingConnection connection, GattProcedure procedure);
    async(CloseConnectionImpl, ConnectionInfo* connection);

    async(GeckoOTAControlWriteHandler, CharacteristicWriteRequest& e);
#if Cstorage && Cboot
    static async(GeckoOTAControlStorageWriteHandler, storage::ByteStorage& storage, CharacteristicWriteRequest& e);
    static async(GeckoOTADataStorageHandler, storage::ByteStorage& storage, CharacteristicWriteRequest& e);
#endif
    async(GeckoOTAVersionReadHandler, CharacteristicReadRequest& e);
    async(SystemIDReadHandler, CharacteristicReadRequest& e);
    async(ApplicationProductReadHandler, CharacteristicReadRequest& e);

#if Cnvram
    async(NVConfigEventHandler, CharacteristicEventRequest& e);
    async(NVConfigWriteHandler, CharacteristicWriteRequest& e);
#endif

    void UpdateBackgroundProcess();

    friend class BluetoothConfig;
};

DEFINE_FLAG_ENUM(Bluetooth::PHY);
DEFINE_FLAG_ENUM(Bluetooth::Flags);
DEFINE_FLAG_ENUM(Bluetooth::ConnectionFlags);
DEFINE_FLAG_ENUM(Bluetooth::AdvertisementSet::Flags);

extern Bluetooth bluetooth;

template<typename T> ALWAYS_INLINE void Bluetooth::OutgoingConnection::RegisterHandler(Attribute attribute, T&& handler)
    { return Bluetooth::RegisterHandler(bluetooth.GetConnectionInfo(id)->handlers, AttributeHandler(attribute, std::forward<T>(handler))); }

ALWAYS_INLINE async(Bluetooth::OutgoingConnection::DiscoverService, const UuidLE& uuid)
    { return async_forward(bluetooth.DiscoverService, *this, uuid); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::DiscoverCharacteristic, Service service, const UuidLE& uuid)
    { return async_forward(bluetooth.DiscoverCharacteristic, *this, service, uuid); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::EnableNotifications, Characteristic characteristic)
    { return async_forward(bluetooth.EnableNotifications, *this, characteristic); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::DisableNotifications, Characteristic characteristic)
    { return async_forward(bluetooth.DisableNotifications, *this, characteristic); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::Read, Characteristic characteristic, Buffer buffer)
    { return async_forward(bluetooth.ReadCharacteristic, *this, characteristic, buffer); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::Write, Characteristic characteristic, Span value)
    { return async_forward(bluetooth.WriteCharacteristic, *this, characteristic, value); }
ALWAYS_INLINE async(Bluetooth::OutgoingConnection::WriteWithoutResponse, Characteristic characteristic, Span value)
    { return async_forward(bluetooth.WriteCharacteristicWithoutResponse, *this, characteristic, value); }
ALWAYS_INLINE async(Bluetooth::IncomingConnection::SendNotification, Characteristic characteristic, Span value)
    { return async_forward(bluetooth.SendCharacteristicNotification, *this, characteristic, value); }
ALWAYS_INLINE async(Bluetooth::Connection::Close)
    { return async_forward(bluetooth.CloseConnection, *this); }
ALWAYS_INLINE Bluetooth::Security Bluetooth::Connection::Security() const
    { return bluetooth.ConnectionSecurity(*this); }
ALWAYS_INLINE size_t Bluetooth::Connection::MTU() const
    { return bluetooth.ConnectionMTU(*this); }
ALWAYS_INLINE size_t Bluetooth::Connection::MaxNotification() const
    { return bluetooth.ConnectionMaxNotification(*this); }
ALWAYS_INLINE size_t Bluetooth::Connection::MaxReadResponse() const
    { return bluetooth.ConnectionMaxReadResponse(*this); }
ALWAYS_INLINE size_t Bluetooth::Connection::MaxWrite() const
    { return bluetooth.ConnectionMaxWrite(*this); }
ALWAYS_INLINE size_t Bluetooth::Connection::MaxWriteNoResponse() const
    { return bluetooth.ConnectionMaxWriteNoResponse(*this); }

#if BLUETOOTH_MAX_ADVERTISERS > 1
ALWAYS_INLINE uint8_t Bluetooth::AdvertisementSet::Index() const { return this - bluetooth.adv; }
#endif

inline void Bluetooth::AdvertisementSet::StartAdvertising(Discoverable discover, Connectable connect, bool keep)
{
    this->discover = (uint8_t)discover;
    this->connect = (uint8_t)connect;
    flags |= Flags::Requested | (keep * Flags::KeepDiscoverable);
    if (!keep)
    {
        flags &= ~Flags::KeepDiscoverable;
    }
    bluetooth.UpdateBackgroundProcess();
}

inline void Bluetooth::AdvertisementSet::StopAdvertising()
{
    flags &= ~Flags::Requested;
    bluetooth.UpdateBackgroundProcess();
}
