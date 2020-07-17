/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/Bluetooth.cpp
 */

#include "Bluetooth.h"

#include <application_properties.h>
#include <rail.h>
#include <btl_interface.h>

//#define BLUETOOTH_TRACE   1

#define MYDBG(...)  DBGCL("bluetooth", __VA_ARGS__)

#if BLUETOOTH_TRACE
#define MYTRACE(...) MYDBG(__VA_ARGS__)
#else
#define MYTRACE(...)
#endif

#define CONDBG(con, fmt, ...)    DBGCL("bluetooth", "[%d] " fmt, GetConnectionIndex(con), ## __VA_ARGS__)

Bluetooth bluetooth;

//! IRQ priority setup from libbluetooth
extern "C" void irq_init();

static uint8_t heap[DEFAULT_BLUETOOTH_HEAP(BLUETOOTH_MAX_CONNECTIONS) + BLUETOOTH_ADDITIONAL_HEAP];

struct BluetoothConfig : gecko_configuration_t
{
    constexpr BluetoothConfig()
        : gecko_configuration_t({0})
    {
        config_flags = GECKO_CONFIG_FLAG_RTOS;
        sleep.flags = SLEEP_FLAGS_DEEP_SLEEP_ENABLE;
        bluetooth.heap = heap;
        bluetooth.heap_size = sizeof(heap);
        bluetooth.max_connections = BLUETOOTH_MAX_CONNECTIONS;
        bluetooth.max_advertisers = BLUETOOTH_MAX_ADVERTISERS;
        scheduler_callback = Bluetooth::ScheduleLL;
        stack_schedule_callback = Bluetooth::ScheduleMain;
        gattdb = bg_gattdb;
#ifdef BLUETOOTH_OTA_NAME
        ota.device_name_len = sizeof(BLUETOOTH_OTA_NAME) - 1;
        ota.device_name_ptr = (char*)BLUETOOTH_OTA_NAME;
#endif
    }
};

void Bluetooth::UpdateBackgroundProcess()
{
    // we don't want to modify the actual flags
    auto flags = this->flags;

    if (!(flags & Flags::Initialized))
    {
        return;
    }

    if (scanners)
    {
        flags |= Flags::ScanningRequested;
    }

    // scanning and advertising must be disabled while connecting, otherwise the stack gets completely confused
    bool connecting = !!(flags & Flags::Connecting);
    auto requiredAdvFlags = AdvertisementSet::Flags::Requested | (!!connections * AdvertisementSet::Flags::KeepDiscoverable);

    for (auto& a: adv)
    {
        bool requested = !connecting && (a.flags & requiredAdvFlags) == requiredAdvFlags;
        bool active = !!(a.flags & AdvertisementSet::Flags::Active);

        if (active != requested)
        {
            active ? a.StopImpl() : a.StartImpl();
        }
    }

    switch (flags & (Flags::ScanningActive | Flags::ScanningRequested))
    {
        case Flags::ScanningActive:
            MYDBG("le_gap_end_procedure()");
            ProcessResult(gecko_cmd_le_gap_end_procedure()->result);
            this->flags &= ~Flags::ScanningActive;
            break;

        case Flags::ScanningActive | Flags::ScanningRequested:
            if (!(flags & Flags::ScanUpdate))
            {
                break;
            }
            // parameters updated, restart scanning
            MYDBG("le_gap_end_procedure()");
            ProcessResult(gecko_cmd_le_gap_end_procedure()->result);
            // fallthrough...

        case Flags::ScanningRequested:
        {
            auto scanner = *scanners.begin();
            MYDBG("le_gap_start_discovery(%d, %d)", scanner.phy, scanner.mode);
            ProcessResult(gecko_cmd_le_gap_start_discovery(scanner.phy, uint8(scanner.mode))->result);
            this->flags = (this->flags & ~Flags::ScanUpdate) | Flags::ScanningActive;
            break;
        }

        default:
            break;
    }
}

void Bluetooth::AdvertisementSet::StopImpl()
{
    MYDBG("le_gap_stop_advertising(%d)", Index());
    ProcessResult(gecko_cmd_le_gap_stop_advertising(Index())->result);
    flags &= ~Flags::Active;
}

void Bluetooth::AdvertisementSet::StartImpl()
{
    if (!!(flags & Flags::Update))
    {
        // reconfigure advertising
        DBGCL("bluetooth", "le_gap_set_advertise_timing(%d, %d, %d, %d, %d)", Index(), min, max, timeout, count);
        ProcessResult(gecko_cmd_le_gap_set_advertise_timing(Index(), min, max, timeout, count)->result);
        ProcessResult(gecko_cmd_le_gap_set_advertise_channel_map(Index(), channels)->result);
    }
    MYTRACE("le_gap_start_advertising(%d, %d, %d)", Index(), discover, connect);
    ProcessResult(gecko_cmd_le_gap_start_advertising(Index(), discover, connect)->result);
    flags = (flags & ~Flags::Update) | Flags::Active;
}

async(Bluetooth::Init)
async_def()
{
    static const BluetoothConfig cfg;

    irq_init(); // configure IRQ priorities

    MSC->LOCK = MSC_LOCK_LOCKKEY_UNLOCK;
    MSC->CTRL &= ~MSC_CTRL_CLKDISFAULTEN;
    MSC->LOCK = MSC_LOCK_LOCKKEY_LOCK;

    gecko_stack_init(&cfg);

    MSC->LOCK = MSC_LOCK_LOCKKEY_UNLOCK;
    MSC->CTRL |= MSC_CTRL_CLKDISFAULTEN;
    MSC->LOCK = MSC_LOCK_LOCKKEY_LOCK;

    gecko_bgapi_class_system_init();
    gecko_bgapi_class_le_gap_init();
    gecko_bgapi_class_le_connection_init();
    gecko_bgapi_class_gatt_init();
    gecko_bgapi_class_gatt_server_init();
    gecko_bgapi_class_test_init();
    gecko_bgapi_class_sm_init();

    kernel::Task::Run(this, &Bluetooth::Task);
    kernel::Task::Run(this, &Bluetooth::LLTask);

    await_mask_not(flags, Flags::Initialized, 0);
}
async_end

#define EVENT_CLASS(evt) (((uint32_t)(evt) >> 16) & MASK(8))
#define EVENT_ID(evt) (((uint32_t)(evt) >> 24))

void Bluetooth::ScheduleLL()
{
    bluetooth.llEvent = true;
}

void Bluetooth::ScheduleMain()
{
    bluetooth.event = true;
}

async(Bluetooth::LLTask)
async_def()
{
    for (;;)
    {
        await_acquire_zero(llEvent, 1);
        gecko_priority_handle();
    }
}
async_end

struct CreateCallbackDataRequest
{
    uint8_t dataLength;
    uint8_t eventLength;
    uint16_t dataSpanOffset;
};

static void* CreateCallbackData(CreateCallbackDataRequest req, const void* event, const void* data, Delegate<void, intptr_t>* pOnComplete)
{
    auto len = req.eventLength + req.dataLength;
    void* copy;
    void (*pFree)(void*,intptr_t);
    if (len <= 32)
    {
        copy = MemPoolAlloc<32>();
        pFree = (decltype(pFree))MemPoolFree<32>;
    }
    else if (len <= 64)
    {
        copy = MemPoolAlloc<64>();
        pFree = (decltype(pFree))MemPoolFree<64>;
    }
    else
    {
        copy = malloc(len);
        pFree = (decltype(pFree))free;
    }
    memcpy(copy, event, req.eventLength);
    memcpy((uint8_t*)copy + req.eventLength, data, req.dataLength);
    *(Span*)((uint8_t*)copy + req.dataSpanOffset) = Span((uint8_t*)copy + req.eventLength, req.dataLength);
    *pOnComplete = GetDelegate(pFree, copy);
    return copy;
}

template<typename TCallback> static void RunCallback(AsyncDelegate<TCallback&> delegate, const TCallback& cbk)
{
    TCallback* copy = MemPoolAlloc<TCallback>();
    memcpy(copy, &cbk, sizeof(TCallback));
    kernel::Task::Run(delegate, *copy).OnComplete(GetDelegate((void(*)(void*,intptr_t))MemPoolFree<TCallback>, (void*)copy));
}

template<typename TCallback> static void RunCallback(AsyncDelegate<TCallback&> delegate, const TCallback& cbk, Span& callbackData, const uint8array& data)
{
    Delegate<void, intptr_t> onComplete;
    auto copy = CreateCallbackData({ data.len, sizeof(TCallback), (uint16_t)((intptr_t)&callbackData - (intptr_t)&cbk) }, &cbk, data.data, &onComplete);
    kernel::Task::Run(delegate, *(TCallback*)copy).OnComplete(onComplete);
}

async(Bluetooth::Task)
async_def()
{
    for (;;)
    {
        while (auto evt = ((event = false), gecko_peek_event()))
        {
            uint32_t len = BGLIB_MSG_LEN(evt->header);
            uint32_t cls = EVENT_CLASS(evt->header);
            uint32_t id = EVENT_ID(evt->header);
            Span data(&evt->data, len);

            switch (cls)
            {
            case EVENT_CLASS(gecko_evt_system_boot_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_system_boot_id):
                {
                    UNUSED auto &e = evt->data.evt_system_boot;
                    MYDBG("evt_system_boot: ver %d.%d.%d.%d, bl %d, hw %d",
                        e.major, e.minor, e.patch, e.build, e.bootloader, e.hw);
                    ioBuffers = gecko_cmd_test_debug_counter(20)->value;
                    bufferSize = gecko_cmd_test_debug_counter(19)->value;
                    MYDBG("bgbuf: total = %d, size = %d, free = %d, in = %d, out = %d",
                        BuffersTotal(), BufferSize(), BuffersAvailable(),
                        RxBuffersUsed(), TxBuffersUsed());

                    gecko_cmd_le_gap_set_discovery_extended_scan_response(true);

                    flags |= Flags::Initialized;
                    UpdateBackgroundProcess();
                    break;
                }

                default:
                    MYDBG("unknown system event: %d %H", id, data);
                    break;
                }
                break;

            case EVENT_CLASS(gecko_evt_le_connection_opened_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_le_connection_opened_id):
                {
                    auto &e = evt->data.evt_le_connection_opened;
                    CONDBG(e.connection, "evt_le_connection_opened: %s %-H (%d), bonding %d",
                        e.master ? "to" : "from", Span(e.address), e.address_type, (int8_t)e.bonding);

                    SETBIT(connections, e.connection);

                    // advertising automatically stops when a connection is open, restore what needs to be restored
                    for (auto& a: adv)
                    {
                        a.flags &= ~AdvertisementSet::Flags::Active;
                    }
                    UpdateBackgroundProcess();

                    auto &ci = *GetConnectionInfo(e.connection);
                    if (!!(ci.flags & ConnectionFlags::Connecting) && ci.procedure.type == GattProcedure::Connection && ci.procedure.connect && e.master)
                    {
                        *ci.procedure.connect = OutgoingConnection(e.connection, ++ci.seq);
                    }
                    else if (e.master)
                    {
                        CONDBG(e.connection, "ERROR: connection opened unexpectedly");
                    }
                    ci.flags = ConnectionFlags::Connected | (ConnectionFlags::Master * e.master);
                    ci.error = 0;
                    ci.procedure.type = GattProcedure::Idle;
                    ci.procedure.ptr = NULL;
                    ci.start = MONO_CLOCKS;
                    ci.mtu = 23;
                    ci.security = Security::None;
                    ci.bonding = e.bonding;
                    ci.address = e.address;
                    ci.addressType = (AddressType)e.address_type;
                    ci.phy = PHYUnknown;
                    ci.rssi = -128;
                    ci.handlers.Clear();

                    // these arrive later
                    ci.interval = ci.latency = ci.timeout = ci.txsize = 0;
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_closed_id):
                {
                    auto &e = evt->data.evt_le_connection_closed;
                    CONDBG(e.connection, "evt_le_connection_closed: %s",
                        GetErrorMessage(e.reason));

                    RESBIT(connections, e.connection);
                    // restore advertising if requested
                    UpdateBackgroundProcess();

                    auto& ci = *GetConnectionInfo(e.connection);
#ifdef gattdb_ota_control
                    if (!!(ci.flags & (ConnectionFlags::DfuResetRequested | ConnectionFlags::UpgradeResetRequested)))
                    {
                        CONDBG(&ci, "...%s reset", !!(ci.flags & ConnectionFlags::UpgradeResetRequested) ? "UPGRADE" : "DFU");
                        for (auto& handler: beforeReset)
                        {
                            handler();
                        }
#if Cstorage
                        if (!!(ci.flags & ConnectionFlags::UpgradeResetRequested))
                        {
                            BootloaderResetCause_t* resetCause = (BootloaderResetCause_t*) (RAM_MEM_BASE);
                            resetCause->reason = BOOTLOADER_RESET_REASON_BOOTLOAD;
                            resetCause->signature = BOOTLOADER_RESET_SIGNATURE_VALID;
                            ASSERT(RMU->RSTCAUSE == 0);
                            NVIC_SystemReset();
                        }
#endif
                        gecko_cmd_system_reset(2);
                    }
#endif
                    // this can happen twice during connection procedure,
                    // if the close event with an error arrives within the same batch
                    // as the connection event
                    if (ci.procedure.type == GattProcedure::Connection && ci.procedure.connect)
                    {
                        *ci.procedure.connect = Connection::Error(e.reason);
                    }

                    if (!!(ci.flags & ConnectionFlags::Connecting))
                    {
                        CONDBG(&ci, "Connection aborted: %s", GetErrorMessage(e.reason));
                        ci.error = e.reason;
                        flags &= ~Flags::Connecting;
                    }
                    else if (!!(ci.flags & ConnectionFlags::ProcedureRunning))
                    {
                        CONDBG(&ci, "Connection interrupted: %s", GetErrorMessage(e.reason));
                        ci.error = e.reason;
                        ci.flags &= ~ConnectionFlags::ProcedureRunning;
                    }
                    else
                    {
                        CONDBG(&ci, "Connection closed: %s", GetErrorMessage(e.reason));
                    }
                    ci.flags &= ~(ConnectionFlags::Connecting | ConnectionFlags::Connected);
                    ci.handlers.Clear();
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_parameters_id):
                {
                    auto &e = evt->data.evt_le_connection_parameters;
                    CONDBG(e.connection, "evt_le_connection_parameters: txsize %d, interval %.2q ms, latency %d, timeout %d ms, security %d",
                        e.txsize, e.interval * 125, e.latency, e.timeout * 10, e.security_mode);

                    auto &ci = *GetConnectionInfo(e.connection);
                    ci.interval = e.interval;
                    ci.timeout = e.timeout * 10;
                    ci.latency = e.latency;
                    ci.security = (Security)e.security_mode;
                    ci.txsize = e.txsize;
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_rssi_id):
                {
                    auto &e = evt->data.evt_le_connection_rssi;
                    CONDBG(e.connection, "evt_le_connection_rssi: %d, status %d",
                        e.rssi, e.status);

                    auto &ci = *GetConnectionInfo(e.connection);
                    ci.rssi = e.rssi;
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_phy_status_id):
                {
                    auto &e = evt->data.evt_le_connection_phy_status;
                    CONDBG(e.connection, "evt_le_connection_phy_status: %d",
                        e.phy);

                    auto &ci = *GetConnectionInfo(e.connection);
                    ci.phy = PHY(e.phy);
                    break;
                }

                default:
                    MYDBG("unknown connection event: %d %H", id, data);
                    break;
                }
                break;

            case EVENT_CLASS(gecko_evt_le_gap_scan_response_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_le_gap_extended_scan_response_id):
                {
                    auto &e = evt->data.evt_le_gap_extended_scan_response;

                    if (scanners)
                    {
                        Advertisement evt;
                        evt.packetType = e.packet_type;
                        evt.address = e.address;
                        evt.addressType = (AddressType)e.address_type;
                        evt.bonding = e.bonding;
                        evt.phy = PHY(e.primary_phy);
                        evt.phy2 = PHY(e.secondary_phy);
                        evt.sid = e.adv_sid;
                        evt.txPower = e.tx_power;
                        evt.rssi = e.rssi;
                        evt.channel = e.channel;
                        evt.periodicInterval = e.periodic_interval;

                        auto scannerIterator = scanners.begin();
                        auto scanner = *scannerIterator;
                        ScannerDelegate delegate;
                        if (++scannerIterator != scanners.end())
                        {
                            // invoke multiple scanners
                            delegate = GetDelegate(this, &Bluetooth::CallScanners);
                        }
                        else
                        {
                            // there is only one scanner
                            delegate = scanner.delegate;
                        }

                        RunCallback(delegate, evt, evt.data, e.data);
                    }
                    else
                    {
                        MYDBG("evt_le_gap_extended_scan_response: %d, host %-H (%d), bonding %d, phy %d/%d, SID %d, TX %d, RSSI %d, CH %d, ival %d, data %H",
                            e.packet_type, Span(e.address), e.address_type, e.bonding, e.primary_phy, e.secondary_phy, e.adv_sid, e.tx_power, e.rssi, e.channel, e.periodic_interval, Span(e.data.data, e.data.len));
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_le_gap_adv_timeout_id):
                {
                    auto &e = evt->data.evt_le_gap_adv_timeout;
                    adv[e.handle].flags &= ~(AdvertisementSet::Flags::Active | AdvertisementSet::Flags::Requested);
                    break;
                }

                case EVENT_ID(gecko_evt_le_gap_scan_request_id):
                {
                    UNUSED auto &e = evt->data.evt_le_gap_scan_request;
                    MYDBG("evt_le_gap_scan_request: %d, host %-H (%d), bonding %d",
                        e.handle, Span(e.address), e.address_type, e.bonding);
                    break;
                }

                default:
                    MYDBG("unknown le_gap event: %d %H", id, data);
                    break;
                }
                break;

            case EVENT_CLASS(gecko_evt_gatt_mtu_exchanged_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_gatt_mtu_exchanged_id):
                {
                    auto &e = evt->data.evt_gatt_mtu_exchanged;
                    CONDBG(e.connection, "evt_gatt_mtu_exchanged: %d",
                        e.mtu);

                    GetConnectionInfo(e.connection)->mtu = e.mtu;
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_service_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_service;
                    CONDBG(e.connection, "evt_gatt_service: %H == %08X",
                        Span(e.uuid.data, e.uuid.len), e.service);

                    auto& ci = *GetConnectionInfo(e.connection);
                    if (ci.procedure.type == GattProcedure::DiscoverService && ci.procedure.service)
                    {
                        *ci.procedure.service = e.service;
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_characteristic_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_characteristic;
                    CONDBG(e.connection, "evt_gatt_characteristic: %H = %04X, props %X",
                        Span(e.uuid.data, e.uuid.len), e.characteristic, e.properties);

                    auto& ci = *GetConnectionInfo(e.connection);
                    if (ci.procedure.type == GattProcedure::DiscoverCharacteristic && ci.procedure.characteristic)
                    {
                        *ci.procedure.characteristic = CharacteristicWithProperties(e.characteristic, e.properties);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_characteristic_value_id):
                {
                    auto& e = evt->data.evt_gatt_characteristic_value;
                    auto& ci = *GetConnectionInfo(e.connection);
                    if (e.att_opcode == gatt_handle_value_notification)
                    {
                        if (auto handler = FindHandler(ci.handlers, e.characteristic, AttributeHandlerType::Notification))
                        {
                            CharacteristicNotification evt;
                            evt.connection = OutgoingConnection(e.connection, ci.seq);
                            evt.characteristic = e.characteristic;
                            evt.offset = e.offset;
                            if (handler->IsSynchronous())
                            {
                                evt.data = Span(e.value.data, e.value.len);
                                handler->syncNotification(evt);
                            }
                            else
                            {
                                RunCallback(handler->notification, evt, evt.data, e.value);
                            }
                        }
                        else
                        {
                            CONDBG(&ci, "Unhandled notification %04X + %d: %H", e.characteristic, e.att_opcode, e.offset, Span(e.value.data, e.value.len));
                        }
                    }
                    else if (ci.procedure.type == GattProcedure::ReadCharacteristic && ci.procedure.read)
                    {
                        CONDBG(&ci, "Read characteristic %04X + %d via op %d: %H", e.characteristic, e.offset, e.att_opcode, Span(e.value.data, e.value.len));
                        Span(e.value.data, e.value.len).CopyTo(ci.procedure.read->buffer.RemoveLeft(e.offset));
                        ci.procedure.read->read = std::max(uint32_t(e.offset + e.value.len), ci.procedure.read->read);
                    }
                    else
                    {
                        CONDBG(&ci, "Received characteristic %04X + %d via op %d: %H", e.characteristic, e.offset, e.att_opcode, Span(e.value.data, e.value.len));
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_procedure_completed_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_procedure_completed;
                    CONDBG(e.connection, "evt_gatt_procedure_completed: %s",
                        GetErrorMessage(e.result));

                    auto& ci = *GetConnectionInfo(e.connection);
                    if (!!(ci.flags & ConnectionFlags::ProcedureRunning))
                    {
                        ci.error = e.result;
                        ci.flags &= ~ConnectionFlags::ProcedureRunning;
                    }
                    break;
                }

                default:
                    MYDBG("unknown gatt event: %d %H", id, data);
                    break;
                }
                break;

            case EVENT_CLASS(gecko_evt_gatt_server_attribute_value_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_gatt_server_attribute_value_id):
                {
                    auto &e = evt->data.evt_gatt_server_attribute_value;
                    CONDBG(e.connection, "evt_gatt_server_attribute_value: %04X, op %d, offset %d, data %H",
                        e.attribute, e.att_opcode, e.offset, Span(e.value.data, e.value.len));

                    if (auto handler = FindHandler(handlers, e.attribute, AttributeHandlerType::ValueChange))
                    {
                        AttributeValueChanged evt;
                        evt.connection = IncomingConnection(e.connection, GetConnectionInfo(e.connection)->seq);
                        evt.attribute = e.attribute;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        if (handler->IsSynchronous())
                        {
                            evt.value = Span(e.value.data, e.value.len);
                            handler->syncValueChange(evt);
                        }
                        else
                        {
                            RunCallback(handler->valueChange, evt, evt.value, e.value);
                        }
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_user_read_request_id):
                {
                    auto &e = evt->data.evt_gatt_server_user_read_request;
                    CONDBG(e.connection, "evt_gatt_server_user_read_request: %04X, op %d, offset %d",
                        e.characteristic, e.att_opcode, e.offset);

                    if (auto handler = FindHandler(handlers, e.characteristic, AttributeHandlerType::ReadRequest))
                    {
                        CharacteristicReadRequest evt;
                        evt.connection = IncomingConnection(e.connection, GetConnectionInfo(e.connection)->seq);
                        evt.characteristic = e.characteristic;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        if (handler->IsSynchronous())
                        {
                            handler->syncRead(evt);
                        }
                        else
                        {
                            RunCallback(handler->read, evt);
                        }
                    }
                    else
                    {
                        MYDBG("...no read handler found");
                        gecko_cmd_gatt_server_send_user_read_response(e.connection, e.characteristic, (uint8_t)bg_err_att_att_not_found, 0, NULL);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_user_write_request_id):
                {
                    auto &e = evt->data.evt_gatt_server_user_write_request;
                    CONDBG(e.connection, "evt_gatt_server_user_write_request: %04X, op %d, offset %d, data %H",
                        e.characteristic, e.att_opcode, e.offset, Span(e.value.data, e.value.len));

                    if (auto handler = FindHandler(handlers, e.characteristic, AttributeHandlerType::WriteRequest))
                    {
                        CharacteristicWriteRequest evt;
                        evt.connection = IncomingConnection(e.connection, GetConnectionInfo(e.connection)->seq);
                        evt.characteristic = e.characteristic;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        if (handler->IsSynchronous())
                        {
                            evt.data = Span(e.value.data, e.value.len);
                            handler->syncWrite(evt);
                        }
                        else
                        {
                            RunCallback(handler->write, evt, evt.data, e.value);
                        }
                    }
                    else
                    {
                        MYDBG("...no write handler found");
                        gecko_cmd_gatt_server_send_user_write_response(e.connection, e.characteristic, (uint8_t)bg_err_att_att_not_found);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_characteristic_status_id):
                {
                    auto &e = evt->data.evt_gatt_server_characteristic_status;
                    CONDBG(e.connection, "evt_gatt_server_characteristic_status: %04X, status %x, client %x",
                        e.characteristic, e.status_flags, e.client_config_flags);

                    if (e.status_flags & gatt_server_client_config)
                    {
                        if (auto handler = FindHandler(handlers, e.characteristic, AttributeHandlerType::EventRequest))
                        {
                            CharacteristicEventRequest evt;
                            evt.connection = IncomingConnection(e.connection, GetConnectionInfo(e.connection)->seq);
                            evt.characteristic = e.characteristic;
                            evt.level = (EventLevel)e.client_config_flags;
                            if (handler->IsSynchronous())
                            {
                                handler->syncEventRequest(evt);
                            }
                            else
                            {
                                RunCallback(handler->eventRequest, evt);
                            }
                        }
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_execute_write_completed_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_server_execute_write_completed;
                    CONDBG(e.connection, "evt_gatt_server_execute_write_completed: %s",
                        GetErrorMessage(e.result));
                    break;
                }

                default:
                    MYDBG("unknown gatt_server event: %d %H", id, data);
                    break;
                }
                break;

            case EVENT_CLASS(gecko_evt_sm_passkey_display_id):
                switch (id)
                {
                case EVENT_ID(gecko_evt_sm_passkey_display_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_passkey_display;
                    CONDBG(e.connection, "evt_sm_passkey_display: %06d",
                        e.passkey);
                    break;
                }

                case EVENT_ID(gecko_evt_sm_passkey_request_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_passkey_request;
                    CONDBG(e.connection, "evt_sm_passkey_request");
                    break;
                }

                case EVENT_ID(gecko_evt_sm_confirm_passkey_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_confirm_passkey;
                    CONDBG(e.connection, "evt_sm_confirm_passkey: %06d",
                        e.passkey);
                    break;
                }

                case EVENT_ID(gecko_evt_sm_bonded_id):
                {
                    auto &e = evt->data.evt_sm_bonded;
                    CONDBG(e.connection, "evt_sm_bonded: %d",
                        e.bonding);

                    GetConnectionInfo(e.connection)->bonding = e.bonding;
                    break;
                }
                case EVENT_ID(gecko_evt_sm_bonding_failed_id):
                {
                    auto &e = evt->data.evt_sm_bonding_failed;
                    CONDBG(e.connection, "evt_sm_bonding_failed: reason %s",
                        GetErrorMessage(e.reason));

                    auto &con = *GetConnectionInfo(e.connection);
                    if (e.reason == bg_err_smp_pairing_not_supported && con.bonding != -1)
                    {
                        // this error is reported when there is a mismatch between the device key and the current one
                        // delete the entire bonding and try again
                        MYDBG("deleting corrupted bonding %d", con.bonding);
                        gecko_cmd_sm_delete_bonding(con.bonding);
                        con.bonding = -1;
                        gecko_cmd_sm_increase_security(e.connection);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_sm_confirm_bonding_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_confirm_bonding;
                    CONDBG(e.connection, "evt_sm_confirm_bonding: %d",
                        e.bonding_handle);
                    break;
                }

                default:
                    MYDBG("unknown sm event: %d %H", id, data);
                    break;
                }
                break;

            default:
                MYDBG("unknown event: %08X %H", evt->header, data);
                break;
            }

            // yield after every event
            async_yield();
        }

        if (Initialized())
        {
            await_signal_ticks(event, std::min((mono_t)MONO_SIGNED_MAX, gecko_can_sleep_ticks()));
        }
        else
        {
            async_yield();
        }
    }
}
async_end

void Bluetooth::CharacteristicReadRequest::Respond(Span data, AttError error)
{
    UNUSED auto resp = gecko_cmd_gatt_server_send_user_read_response(connection, characteristic, (uint8_t)error, data.Length(), data);
    CONDBG(connection, "evt_gatt_server_user_read_response: %04X, sent %d, status %s, data %H = %s",
        characteristic, resp->sent_len, GetErrorMessage(error == AttError::OK ? 0 : (uint32_t)bg_errspc_att + (uint32_t)error), data.Left(resp->sent_len), GetErrorMessage(resp->result));
}

void Bluetooth::CharacteristicWriteRequest::Respond(AttError error)
{
    UNUSED auto resp = gecko_cmd_gatt_server_send_user_write_response(connection, characteristic, (uint8_t)error);
    CONDBG(connection, "evt_gatt_server_user_write_response: %04X, status %s = %s",
        characteristic, GetErrorMessage(error == AttError::OK ? 0 : (uint32_t)bg_errspc_att + (uint32_t)error), GetErrorMessage(resp->result));
}

async(Bluetooth::TxAlmostIdle)
async_def()
{
    for (;;)
    {
        if (TxAlmostIdle())
            async_return(true);

        async_sleep_ms(10);
    }
}
async_end

res_pair_t Bluetooth::SendNotificationImpl(uint32_t connectionAndCharacteristic, Span data)
{
    uint8_t connection = connectionAndCharacteristic >> 16;
    uint16_t characteristic = connectionAndCharacteristic;

    auto res = gecko_cmd_gatt_server_send_characteristic_notification(connection, characteristic, data.Length(), data);
    if (res->result != bg_err_success)
    {
        CONDBG(connection, "gecko_cmd_gatt_server_send_characteristic_notification: %04X %H = %s",
            characteristic, data, GetErrorMessage(res->result));
    }
    return RES_PAIR(res->result, res->sent_len);
}

res_pair_t Bluetooth::Advertisement::GetFieldImpl(Span data, uint8_t field)
{
    while (data.Length() > 2)
    {
        auto len = data.Element<uint8_t>(0);
        if (data.Element<uint8_t>(1) == field)
        {
            return data.Slice(2, 1 + len);
        }
        data = data.RemoveLeft(1 + len);
    }

    return Span();
}

void Bluetooth::AddScanner(ScannerDelegate delegate, ScanMode mode, PHY phy)
{
    scanners.Push(Scanner(delegate, mode, phy));
    flags |= Flags::ScanUpdate;
    UpdateBackgroundProcess();
}

void Bluetooth::RemoveScanner(ScannerDelegate delegate)
{
    for (auto m: scanners.Manipulate())
    {
        if (m.Element().delegate == delegate)
        {
            flags |= Flags::ScanUpdate;
            m.Remove();
        }
    }

    if (!!(flags & Flags::ScanUpdate))
    {
        UpdateBackgroundProcess();
    }
}

void Bluetooth::RegisterHandler(LinkedList<AttributeHandler>& handlers, AttributeHandler handler)
{
    auto manipulator = handlers.Manipulate();
    while (manipulator && manipulator.Element().attribute < handler.attribute)
        ++manipulator;
    manipulator.Insert(handler);
}

Bluetooth::AttributeHandler* Bluetooth::FindHandler(LinkedList<AttributeHandler> handlers, Attribute attribute, AttributeHandlerType type)
{
    for (auto& ah: handlers)
    {
        if (ah.attribute < attribute)
            continue;
        if (ah.attribute > attribute)
            break;
        if (AttributeHandlerType(int(ah.type) & int(AttributeHandlerType::_TypeMask)) == type)
            return &ah;
    }
    return NULL;
}

static void Decrement(uint32_t* ptr, intptr_t result)
{
    (*ptr)--;
}

async(Bluetooth::CallScanners, Advertisement& adv)
async_def(uint32_t running)
{
    for (auto scanner: scanners)
    {
        f.running++;
        kernel::Task::Run(scanner.delegate, adv).OnComplete(GetDelegate(Decrement, &f.running));
    }

    await_mask(f.running, ~0u, 0);
}
async_end

async(Bluetooth::Connect, bd_addr address, Timeout timeout, PHY phy)
async_def(
    Timeout timeout;
    ConnectionInfo* connection;
    OutgoingConnection res;
)
{
    f.timeout = timeout.MakeAbsolute();

    if (!await_acquire_timeout(flags, Flags::Connecting, f.timeout))
    {
        MYDBG("Cannot connect to %-H - timeout waiting for other connections to complete", Span(address));
        async_return(false);
    }

    UpdateBackgroundProcess();  // turn off scanning and advertising

    auto rsp = gecko_cmd_le_gap_connect(address, le_gap_address_type_public, phy);
    f.res = Connection::Error(rsp->result);

    if (rsp->result != bg_err_success)
    {
        MYDBG("Connection to %-H failed immediately: %s", Span(address), GetErrorMessage(rsp->result));
    }
    else
    {
        CONDBG(rsp->connection, "Connecting to %-H...", Span(address));
        f.connection = GetConnectionInfo(rsp->connection);
        f.connection->flags = ConnectionFlags::Connecting;
        f.connection->procedure.type = GattProcedure::Connection;
        f.connection->procedure.connect = &f.res;
        if (!await_mask_timeout(f.connection->flags, ConnectionFlags::Connecting, 0, f.timeout))
        {
            CONDBG(f.connection, "Timed out");
            auto rsp = gecko_cmd_le_connection_close(GetConnectionIndex(f.connection));
            if (rsp->result != bg_err_success)
            {
                CONDBG(f.connection, "Failed to abort connection: %s", GetErrorMessage(rsp->result));
            }
            if (!await_mask_sec(f.connection->flags, ConnectionFlags::Connecting, 0, 1))
            {
                CONDBG(f.connection, "FORCING end of connection attempt");
                f.connection->flags &= ~ConnectionFlags::Connecting;
                f.res = Connection::Error(bg_err_gatt_connection_timeout);
            }
            else if (f.res == Connection::Error(bg_err_bt_unknown_connection_identifier))  // this is how the stack reports the connection attempt has been canceled
            {
                f.res = Connection::Error(bg_err_gatt_connection_timeout);
            }
        }

        ASSERT(!(f.connection->flags & ConnectionFlags::Connecting));

        if (f.res)
        {
            CONDBG(f.connection, "CONNECTION SUCESS");
            ASSERT(f.connection->flags & ConnectionFlags::Connected);
        }
        else
        {
            CONDBG(f.connection, "CONNECTION FAILED: %s", GetErrorMessage(f.res.error));
            ASSERT(!(f.connection->flags & ConnectionFlags::Connected));
        }

        f.connection->EndProcedure();
    }

    flags &= ~Flags::Connecting;
    UpdateBackgroundProcess();  // resume scanning and advertising if configured

    async_return(f.res.raw);
}
async_end

async(Bluetooth::CloseConnection, Connection con)
async_def(ConnectionInfo* connection)
{
    // cannot use GetConnectionInfo, we want to survive cases when the connection is already reused
    f.connection = GetConnectionInfo(con);
    if (con.seq == f.connection->seq && GETBIT(connections, con.id))
    {
        await(CloseConnectionImpl, f.connection);
    }
}
async_end

async(Bluetooth::CloseConnectionImpl, ConnectionInfo* connection)
async_def(unsigned retry)
{
    await_acquire(connection->flags, ConnectionFlags::Procedure);
    ASSERT(!(connection->flags & ConnectionFlags::ProcedureRunning));
    CONDBG(connection, "Closing");

    // we have to try closing the connection a few times, there appears to be a bug in
    // some versions of libbluetooth that it occasionaly fails to disconnect
    f.retry = 5;
    do
    {
        auto rsp = gecko_cmd_le_connection_close(GetConnectionIndex(connection));
        if (rsp->result != bg_err_success)
        {
            CONDBG(connection, "Failed to close connection: %s", GetErrorMessage(rsp->result));
        }

        if (!await_mask_ms(connection->flags, ConnectionFlags::Connected, 0, 500))
        {
            CONDBG(connection, "Connection did not close");
        }
        else
        {
            break;
        }
    } while (f.retry--);

    if (!!(connection->flags & ConnectionFlags::Connected))
    {
        CONDBG(connection, "FORCING connection closed");
        connection->flags &= ~ConnectionFlags::Connected;
    }

    connection->EndProcedure();
    async_return(!connection->error);
}
async_end

errorcode_t Bluetooth::OutgoingConnection::GetLastError() const
{
    if (isError)
    {
        return (errorcode_t)error;
    }
    auto conn = bluetooth.GetConnectionInfo(*this);
    if (seq != conn->seq)
    {
        return bg_err_not_connected;
    }
    else
    {
        return (errorcode_t)conn->error;
    }
}

async(Bluetooth::BeginProcedure, OutgoingConnection connection, GattProcedure procedure)
async_def(
    ConnectionInfo* connection;
)
{
    f.connection = GetConnectionInfo(connection);
    if (f.connection->seq != connection.seq)
    {
        // connection was already replaced
        CONDBG(f.connection, "connection instance mismatch, %d != %d", f.connection->seq, connection.seq);
        async_return(0);
    }

    await_acquire(f.connection->flags, ConnectionFlags::Procedure);
    if (f.connection->seq != connection.seq)
    {
        // connection was already replaced, we must not hold it
        CONDBG(f.connection, "connection instance mismatch, %d != %d", f.connection->seq, connection.seq);
        f.connection->flags &= ~ConnectionFlags::Procedure;
        async_return(0);
    }

    ASSERT(!(f.connection->flags & ConnectionFlags::ProcedureRunning));
    ASSERT(!f.connection->procedure.ptr);
    ASSERT(f.connection->procedure.type == GattProcedure::Idle);
    f.connection->flags |= ConnectionFlags::ProcedureRunning;
    f.connection->procedure.type = procedure;
    async_return((intptr_t)f.connection);
}
async_end

void Bluetooth::ConnectionInfo::EndProcedure()
{
    CONDBG((this - bluetooth.connectionInfo) + 1, "procedure complete");
    procedure.type = GattProcedure::Idle;
    procedure.ptr = NULL;
    flags &= ~(ConnectionFlags::Procedure | ConnectionFlags::ProcedureRunning);
}

async(Bluetooth::DiscoverService, OutgoingConnection connection, const UuidLE& uuid)
async_def(
    ConnectionInfo* connection;
    Service res;
)
{
    if ((f.connection = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::DiscoverService)))
    {
        f.connection->procedure.service = &f.res;
        CONDBG(f.connection, "Discovering service %-H...", Span(uuid));

        auto rsp = gecko_cmd_gatt_discover_primary_services_by_uuid(connection.id, sizeof(UuidLE), (const uint8_t*)&uuid);
        f.connection->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(f.connection, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            await_mask(f.connection->flags, ConnectionFlags::ProcedureRunning, 0);
        }

        if (f.connection->seq == connection.seq)
        {
            f.connection->EndProcedure();
            async_return(f.connection->error ? 0 : f.res.handle);
        }
    }

    async_return(0);
}
async_end

async(Bluetooth::DiscoverCharacteristic, OutgoingConnection connection, Service service, const UuidLE& uuid)
async_def(
    ConnectionInfo* connection;
    CharacteristicWithProperties res;
)
{
    if ((f.connection = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::DiscoverCharacteristic)))
    {
        f.connection->procedure.characteristic = &f.res;
        CONDBG(f.connection, "Discovering characteristic %-H of service %08X...", Span(uuid), service);

        auto rsp = gecko_cmd_gatt_discover_characteristics_by_uuid(connection.id, service, sizeof(UuidLE), (const uint8_t*)&uuid);
        f.connection->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(f.connection, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            await_mask(f.connection->flags, ConnectionFlags::ProcedureRunning, 0);
        }

        if (f.connection->seq == connection.seq)
        {
            f.connection->EndProcedure();
            async_return(f.connection->error ? 0 : f.res.raw);
        }
    }

    async_return(0);
}
async_end

async(Bluetooth::SetCharacteristicNotification, OutgoingConnection connection, Characteristic characteristic, gatt_client_config_flag flags)
async_def(
    ConnectionInfo* connection
)
{
    if ((f.connection = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::SetCharacteristicNotification)))
    {
        CONDBG(f.connection, "Setting notifications for characteristic %04X to %02X..", characteristic, flags);

        auto rsp = gecko_cmd_gatt_set_characteristic_notification(connection.id, characteristic, flags);
        f.connection->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(f.connection, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            await_mask(f.connection->flags, ConnectionFlags::ProcedureRunning, 0);
        }

        if (f.connection->seq == connection.seq)
        {
            f.connection->EndProcedure();
            async_return(!f.connection->error);
        }
    }

    async_return(false);
}
async_end

async(Bluetooth::ReadCharacteristic, OutgoingConnection connection, Characteristic characteristic, Buffer buffer)
async_def(
    ConnectionInfo* connection;
    ReadOperation op;
)
{
    f.op.buffer = buffer;

    if ((f.connection = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::ReadCharacteristic)))
    {
        f.connection->procedure.read = &f.op;
        CONDBG(f.connection, "Reading characteristic %04X..", characteristic);

        auto rsp = gecko_cmd_gatt_read_characteristic_value(connection.id, characteristic);
        f.connection->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(f.connection, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            await_mask(f.connection->flags, ConnectionFlags::ProcedureRunning, 0);
        }

        if (f.connection->seq == connection.seq)
        {
            f.connection->EndProcedure();
            async_return(f.connection->error ? 0 : f.op.read);
        }
    }

    async_return(0);
}
async_end

async(Bluetooth::WriteCharacteristic, OutgoingConnection connection, Characteristic characteristic, Span value)
async_def(
    ConnectionInfo* connection;
    WriteOperation op;
)
{
    f.op.value = value;

    if ((f.connection = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::WriteCharacteristic)))
    {
        f.connection->procedure.write = &f.op;
        CONDBG(f.connection, "Writing characteristic %04X = %H", characteristic, value);

        auto rsp = gecko_cmd_gatt_write_characteristic_value(connection.id, characteristic, value.Length(), value.Pointer<uint8_t>());
        f.connection->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(f.connection, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            await_mask(f.connection->flags, ConnectionFlags::ProcedureRunning, 0);
        }

        if (f.connection->seq == connection.seq)
        {
            f.connection->EndProcedure();
            async_return(f.connection->error ? 0 : f.op.written);
        }
    }

    async_return(0);
}
async_end

async(Bluetooth::WriteCharacteristicWithoutResponse, OutgoingConnection connection, Characteristic characteristic, Span value)
async_def()
{
    await(TxAlmostIdle);

    if (auto conn = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::WriteCharacteristicWithoutResponse))
    {
        CONDBG(conn, "Writing characteristic w/o response %04X = %H", characteristic, value);

        auto rsp = gecko_cmd_gatt_write_characteristic_value_without_response(connection.id, characteristic, value.Length(), value.Pointer<uint8_t>());
        conn->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(conn, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            CONDBG(conn, "...sent %d", rsp->sent_len);
        }

        conn->EndProcedure();
        async_return(rsp->sent_len);
    }

    async_return(0);
}
async_end

async(Bluetooth::SendCharacteristicNotification, IncomingConnection connection, Characteristic characteristic, Span value)
async_def()
{
    await(TxAlmostIdle);

    if (auto conn = (ConnectionInfo*)await(BeginProcedure, connection, GattProcedure::SendCharacteristicNotification))
    {
        CONDBG(conn, "Notifying characteristic %04X = %H", characteristic, value);

        auto rsp = gecko_cmd_gatt_server_send_characteristic_notification(connection.id, characteristic, value.Length(), value.Pointer<uint8_t>());
        conn->error = rsp->result;

        if (rsp->result != bg_err_success)
        {
            CONDBG(conn, "...immediately failed: %s", GetErrorMessage(rsp->result));
        }
        else
        {
            CONDBG(conn, "...sent %d", rsp->sent_len);
        }

        conn->EndProcedure();
        async_return(rsp->sent_len);
    }

    async_return(0);
}
async_end

async(Bluetooth::BroadcastCharacteristicNotification, Characteristic characteristic, Span value)
async_def()
{
    await(TxAlmostIdle);

    async_return(TryBroadcastCharacteristicNotification(characteristic, value));
}
async_end

size_t Bluetooth::TryBroadcastCharacteristicNotification(Characteristic characteristic, Span value)
{
    if (!TxAlmostIdle())
    {
        return 0;
    }

    MYTRACE("Broadcast characteristic notification %04X = %H", characteristic, value);

    auto rsp = gecko_cmd_gatt_server_send_characteristic_notification(0xFF, characteristic, value.Length(), value.Pointer<uint8_t>());

    if (rsp->result != bg_err_success)
    {
        MYTRACE("...immediately failed: %s", GetErrorMessage(rsp->result));
        return 0;
    }
    else
    {
        MYTRACE("...sent %d", rsp->sent_len);
        return rsp->sent_len;
    }
}

async(Bluetooth::GeckoOTAControlWriteHandler, CharacteristicWriteRequest& e)
async_def(
    ConnectionInfo* connection;
)
{
    MYDBG("...DFU reset requested");
    f.connection = GetConnectionInfo(e.connection);
    f.connection->flags |= ConnectionFlags::DfuResetRequested;
    e.Success();
    await(CloseConnectionImpl, f.connection);
}
async_end

#if Cstorage

void Bluetooth::RegisterGeckoOTAStorageHandler(Characteristic charCtl, Characteristic charData, storage::ByteStorage& storage)
{
    struct Handlers
    {
        Handlers(storage::ByteStorage& storage)
            : storage(storage) {}

        async(Control, CharacteristicWriteRequest& e)
        async_def()
        {
            if (e.data.Length() > 0)
            {
                switch (e.data[0])
                {
                    case 0:
                        bluetooth.SetConnectionParameters(e.connection, 7.5, 7.5, 2, 3000);
                        // prepare slot (erase first block)
                        eraseUpTo = await(storage.EraseFirst, 0, 1);
                        offset = 0;
                        e.Success();
                        async_return(true);

                    case 3:
                        // OTA complete
                        MYDBG("OTA complete");
                        offset = ~0u;
                        bluetooth.GetConnectionInfo(e.connection)->flags |= ConnectionFlags::UpgradeResetRequested;
                        e.Success();
                        async_return(true);
                }
            }

            e.Respond(AttError::RequestNotSupported);
        }
        async_end

        async(Data, CharacteristicWriteRequest& e)
        async_def()
        {
            if (offset != ~0u)
            {
                MYDBG("OTA data recieved: %X+%d=%X", offset, e.data.Length(), offset + e.data.Length());
                await(storage.Write, offset, e.data);
                offset += e.data.Length();
                if (offset + 256 > eraseUpTo)
                {
                    // erase one more sector
                    eraseUpTo = await(storage.EraseFirst, eraseUpTo, 1);
                }
                e.Success();
            }
            else
            {
                e.Respond(AttError::UnlikelyError);
            }
        }
        async_end

    private:
        storage::ByteStorage& storage;
        uint32_t offset = ~0u;
        uint32_t eraseUpTo;
    };

    auto handlers = new(malloc_once(sizeof(Handlers))) Handlers(storage);
    RegisterHandler(charCtl, handlers, &Handlers::Control);
    RegisterHandler(charData, handlers, &Handlers::Data);
}

#endif

extern "C" const ApplicationProperties_t applicationProperties;

async(Bluetooth::GeckoOTAVersionReadHandler, CharacteristicReadRequest& e)
async_def_sync()
{
    e.Success(applicationProperties.app.version);
}
async_end

async(Bluetooth::SystemIDReadHandler, CharacteristicReadRequest& e)
async_def_sync()
{
    auto addr = gecko_cmd_system_get_bt_address()->address;
    e.Success(BYTES(
        addr.addr[0], addr.addr[1], addr.addr[2],
        0xFE, 0xFF,
        addr.addr[3], addr.addr[4], addr.addr[5]));
}
async_end
