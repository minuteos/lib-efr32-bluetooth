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

#ifndef BLUETOOTH_MAX_CONNECTIONS
#define BLUETOOTH_MAX_CONNECTIONS	4
#endif

#ifndef BLUETOOTH_ADDITIONAL_HEAP
#define BLUETOOTH_ADDITIONAL_HEAP	4096
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
    /********** EXTERNAL EVENTS **********/

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
        PHY1M = le_gap_phy_1m,
        PHY2M = le_gap_phy_2m,
        PHYCoded = le_gap_phy_coded,
    };

    DECLARE_FLAG_ENUM(PHY);

    struct AttributeValueChanged
    {
        uint8_t connection;
        uint8_t opcode;
        uint16_t attribute;
        uint32_t offset;
        Span value;
    };

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

    struct CharacteristicReadRequest
    {
        uint8_t connection;
        uint8_t opcode;
        uint16_t characteristic;
        uint32_t offset;

        void Success(Span data) { Respond(data, AttError::OK); }
        void Error(AttError error) { Respond(Span(), error); }
        void Respond(Span data, AttError error);
    };

    struct CharacteristicWriteRequest
    {
        uint8_t connection;
        uint8_t opcode;
        uint16_t characteristic;
        uint32_t offset;
        Span data;

        void Success() { Respond(AttError::OK); }
        void Error(AttError error) { Respond(error); }
        void Respond(AttError error);
    };

    enum struct EventLevel : uint8_t { Disabled, Notification, Indication };
    struct CharacteristicEventRequest
    {
        uint8_t connection;
        EventLevel level;
        uint16_t characteristic;
    };

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

    struct Callbacks
    {
        virtual async(OnBluetoothAttributeValueChanged, AttributeValueChanged e) async_def_return(0);
        virtual async(OnBluetoothCharacteristicReadRequest, CharacteristicReadRequest e) async_def_return(0);
        virtual async(OnBluetoothCharacteristicWriteRequest, CharacteristicWriteRequest e) async_def_return(0);
        virtual async(OnBluetoothCharacteristicEventRequest, CharacteristicEventRequest e) async_def_return(0);
        virtual async(OnBluetoothAdvertisementReceived, Advertisement e) async_def_return(0);
    };

    /**** BUFFER STATUS ****/
private:
    union BufferCounts
    {
        uint32_t raw;
        struct {
            uint8_t in, out, noFlow;
        };
    };
    union BufferCounts BufferCounts() const { return (union BufferCounts){ gecko_cmd_test_debug_counter(21)->value }; }

public:
    //! Sets the callbacks implementation for various events
    void SetCallbacks(Callbacks* callbacks) { this->callbacks = callbacks; }
    //! Initializes the Bluetooth stack and waits until the startup is complete
    async(Init);
    //! Returns true if the Bluetooth stack initialization is complete
    bool Initialized() const { return initialized; }

    //! Gets a bit mask determining active connections
    uint32_t Connections() const { return connections; }
    //! Gets the current security level of the specified connection
    Security ConnectionSecurity(uint32_t connection) const { return GETBIT(connections, connection) ? connInfo[connection].security : Security::None; }
    //! Gets the current MTU of the specified connection
    int ConnectionMTU(uint32_t connection) const { return GETBIT(connections, connection) ? connInfo[connection].mtu : 0; }
    //! Gets maximum allowed notification size for the specified connection
    int ConnectionMaxNotification(uint32_t connection) const { return ConnectionMTU(connection) - 3; }
    //! Gets the maximum allowed read payload size for the specified connection
    int ConnectionMaxReadResponse(uint32_t connection) const { return ConnectionMTU(connection) - 1; }
    //! Gets the maximum allowed write payload size for the specified connection
    int ConnectionMaxWrite(uint32_t connection) const { return ConnectionMTU(connection) - 5; }
    //! Gets the maximum allowed write without response payload size for the specified connection
    int ConnectionMaxWriteNoResponse(uint32_t connection) const { return ConnectionMTU(connection) - 3; }

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

    //! Sets advertisement PHY
    errorcode_t SetAdvertisementPHY(PHY primary, PHY secondary = PHY1M)
    {
        return ProcessResult(gecko_cmd_le_gap_set_advertise_phy(0, primary, secondary)->result);
    }

    //! Sets custom advertisement data
    errorcode_t SetAdvertisementData(Span data)
    {
        ASSERT(data.Length() <= 30);
        return ProcessResult(gecko_cmd_le_gap_bt5_set_adv_data(0, 0, data.Length(), data)->result);
    }

    //! Sets custom scan response data
    errorcode_t SetScanResponseData(Span data)
    {
        ASSERT(data.Length() <= 30);
        return ProcessResult(gecko_cmd_le_gap_bt5_set_adv_data(0, 1, data.Length(), data)->result);
    }

    //! Configures advertisement interval duration in milliseconds
    void SetAdvertisementInterval(float tMin, float tMax = 0)
    {
        uint32_t min = tMin / 0.625f, max = tMax < tMin ? min : (tMax / 0.625f);
        ASSERT(min >= 0x20 && min <= 0x4000);
        ASSERT(max >= 0x20 && max <= 0x4000);
        advMin = min;
        advMax = max;
        advUpdate = true;
    }

    //! Configures the channels used for advertising
    void SetAdvertisementChannels(uint8_t channelMask = 7)
    {
        ASSERT(!(channelMask & 7));
        advChannels = channelMask;
        advUpdate = true;
    }

    //! Configures advertisement timeout (time after which advertising stops)
    void SetAdvertisementTimeout(float t)
    {
        ASSERT(t >= 0 && t <= 655.35f);
        advTimeout = t * 100;
        advUpdate = true;
    }

    //! Configures number of advertisements sent before stopping
    void SetAdvertisementCount(uint8_t count)
    {
        advCount = count;
        advUpdate = true;
    }

    //! Starts advertising
    errorcode_t StartAdvertising(Discoverable discover, Connectable connect, bool keep = false);

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

    //! Starts the scanning process
    errorcode_t StartScanning(ScanMode mode, PHY phy = PHY1M)
    {
        return ProcessResult(gecko_cmd_le_gap_start_discovery((uint8_t)phy, (uint8_t)mode)->result);
    }

    //! Stops the scanning process
    errorcode_t StopScanning()
    {
        return ProcessResult(gecko_cmd_le_gap_end_procedure()->result);
    }

    //! Closes the specified connection
    errorcode_t CloseConnection(uint8_t connection)
    {
        return ProcessResult(gecko_cmd_le_connection_close(connection)->result);
    }

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

    //! Configures the bonding database
    errorcode_t SetBondingConfuguration(uint32_t maxBondings, bool newReplaceOld)
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
    bool initialized = false;               //< Set to true once the stack initialization is complete
    bool keepDiscoverable = false;          //< Whether to keep advertising even while a connection is open
    bool event = false, llEvent = false;    //< Signals for event handling tasks
    uint8_t discover = 0;                   //< Current discoverability mode
    uint8_t connect = 0;                    //< Current connectability mode
    bool advUpdate = true;                  //< If the advertisement parameters have changed
    uint8_t advChannels = 7;                //< Advertising channel mask
    uint32_t advMin = 160, advMax = 160;    //< Advertising interval
#ifdef gecko_cmd_le_gap_set_advertise_timing_id
    uint16_t advTimeout = 0;                //< Advertisement timeout
    uint8_t advCount = 0;                   //< Advertisement count limit
#endif
    uint32_t connections = 0;               //< Active connections mask
#ifdef gattdb_ota_control
    uint32_t dfuConnection = 0;             //< Connection requesting DFU reset
#endif
    int ioBuffers;                          //< Total count of I/O buffers
    int bufferSize;                         //< I/O buffer size
    Callbacks *callbacks = NULL;            //< Callbacks

    struct ConnectionInfo
    {
        uint32_t start;
        uint16_t interval, latency, timeout, mtu, txsize;
        Security security;
        int8_t bonding;
        bool master;
        bd_addr address;
        AddressType addressType;

        void UpdateConnectionParams();
    } connInfo[BLUETOOTH_MAX_CONNECTIONS + 1] = {0};	// connection numbers are one-based

    async(Task);
    async(LLTask);

    static void ScheduleLL();
    static void ScheduleMain();

    DEBUG_NO_INLINE errorcode_t ProcessResult(uint16_t res)
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

    friend class BluetoothConfig;
};

DEFINE_FLAG_ENUM(Bluetooth::PHY);

extern Bluetooth bluetooth;
