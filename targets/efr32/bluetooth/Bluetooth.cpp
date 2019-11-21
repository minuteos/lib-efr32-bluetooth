/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/Bluetooth.cpp
 */

#include "Bluetooth.h"

#include <rail.h>

#define MYDBG(...)  DBGCL("bluetooth", __VA_ARGS__)

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
        scheduler_callback = Bluetooth::ScheduleLL;
        stack_schedule_callback = Bluetooth::ScheduleMain;
        gattdb = bg_gattdb;
    }
};

errorcode_t Bluetooth::StartAdvertising(Discoverable discover, Connectable connect, bool keep)
{
    this->discover = (uint8_t)discover;
    this->connect = (uint8_t)connect;
    keepDiscoverable = keep;

    errorcode_t err = bg_err_success;
    if (advUpdate)
    {
        // reconfigure advertising
        advUpdate = false;
#ifdef gecko_cmd_le_gap_set_advertise_timing_id
        err = ProcessResult(gecko_cmd_le_gap_set_advertise_timing(0, advMin, advMax, advTimeout, advCount)->result);
        if (!err) err = ProcessResult(gecko_cmd_le_gap_set_advertise_channel_map(0, advChannels)->result);
#else
        err = ProcessResult(gecko_cmd_le_gap_set_adv_parameters(advMin, advMax, adbChannels)->result);
#endif
    }

    if (!err)
    {
#ifdef gecko_cmd_le_gap_start_advertising_id
        err = ProcessResult(gecko_cmd_le_gap_start_advertising(0, this->discover, this->connect)->result);
#else
        err = ProcessResult(gecko_cmd_le_gap_set_mode(this->discover, this->connect)->result);
#endif
    }

    return err;
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

    await_signal(initialized);
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
        await_signal(llEvent);
        llEvent = false;
        gecko_priority_handle();
    }
}
async_end

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
                    initialized = true;
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
                    MYDBG("evt_le_connection_opened: %d, from %H (%d), %s, bonding %d",
                        e.connection, Span(e.address), e.address_type, e.master ? "master" : "slave", (int8_t)e.bonding);

                    if (keepDiscoverable)
                    {
                        MYDBG("restoring advertising after connection opened");
                        StartAdvertising((Discoverable)discover, (Connectable)connect, true);
                    }

                    auto &ci = connInfo[e.connection - 1];
                    ci = {0};
                    ci.start = MONO_CLOCKS;
                    ci.master = e.master;
                    ci.bonding = e.bonding;
                    ci.address = e.address;
                    ci.addressType = (AddressType)e.address_type;
                    ci.mtu = 23;

                    SETBIT(connections, e.connection);
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_closed_id):
                {
                    auto &e = evt->data.evt_le_connection_closed;
                    MYDBG("evt_le_connection_closed: %d, reason %s",
                        e.connection, GetErrorMessage(e.reason));

                    if (keepDiscoverable || (!connections && (discover || connect)))
                    {
                        // restore advertising
                        if (keepDiscoverable)
                            MYDBG("restoring advertising after connection closed");
                        else
                            MYDBG("restoring advertising after last connection closed");
                        StartAdvertising((Discoverable)discover, (Connectable)connect, keepDiscoverable);
                    }

                    RESBIT(connections, e.connection);

#ifdef gattdb_ota_control
                    if (GETBIT(dfuConnection, e.connection))
                    {
                        MYDBG("...DFU reset");
                        gecko_cmd_system_reset(2);
                    }
#endif
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_parameters_id):
                {
                    auto &e = evt->data.evt_le_connection_parameters;
                    MYDBG("evt_le_connection_parameters: %d, txsize %d, interval %.2q ms, latency %d, timeout %d ms, security %d",
                        e.connection, e.txsize, e.interval * 125, e.latency, e.timeout * 10, e.security_mode);

                    auto &ci = connInfo[e.connection];
                    ci.interval = e.interval;
                    ci.timeout = e.timeout * 10;
                    ci.latency = e.latency;
                    ci.security = (Security)e.security_mode;
                    ci.txsize = e.txsize;
                    break;
                }

                case EVENT_ID(gecko_evt_le_connection_rssi_id):
                {
                    UNUSED auto &e = evt->data.evt_le_connection_rssi;
                    MYDBG("evt_le_connection_rssi: %d, status %d, RSSI %d",
                        e.connection, e.status, e.rssi);
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
                case EVENT_ID(gecko_evt_le_gap_scan_response_id):
                {
                    UNUSED auto &e = evt->data.evt_le_gap_scan_response;
                    MYDBG("evt_le_gap_scan_response: %d, host %H (%d), bonding %d, RSSI %d, data %H",
                        e.packet_type, Span(e.address), e.address_type, e.bonding, e.rssi, Span(e.data.data, e.data.len));
                    break;
                }

                case EVENT_ID(gecko_evt_le_gap_adv_timeout_id):
                    break;

                case EVENT_ID(gecko_evt_le_gap_scan_request_id):
                {
                    UNUSED auto &e = evt->data.evt_le_gap_scan_request;
                    MYDBG("evt_le_gap_scan_request: %d, host %H (%d), bonding %d",
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
                    MYDBG("evt_gatt_mtu_exchanged: %d, MTU %d",
                        e.connection, e.mtu);

                    connInfo[e.connection].mtu = e.mtu;
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_service_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_service;
                    MYDBG("evt_gatt_service: %d.%d, %H",
                        e.connection, e.service, Span(e.uuid.data, e.uuid.len));
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_characteristic_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_characteristic;
                    MYDBG("evt_gatt_characteristic: %d.%d, props %d, %H",
                        e.connection, e.characteristic, e.properties, Span(e.uuid.data, e.uuid.len));
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
                    MYDBG("evt_gatt_server_attribute_value: %d, attr %04X, op %d, offset %d, data %H",
                        e.connection, e.attribute, e.att_opcode, e.offset, Span(e.value.data, e.value.len));

                    if (callbacks)
                    {
                        AttributeValueChanged evt;
                        evt.connection = e.connection;
                        evt.attribute = e.attribute;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        evt.value = Span(e.value.data, e.value.len);
                        kernel::Task::Run(callbacks, &Callbacks::OnBluetoothAttributeValueChanged, evt);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_user_read_request_id):
                {
                    auto &e = evt->data.evt_gatt_server_user_read_request;
                    MYDBG("evt_gatt_server_user_read_request: %d, char %04X, op %d, offset %d",
                        e.connection, e.characteristic, e.att_opcode, e.offset);

                    if (callbacks)
                    {
                        CharacteristicReadRequest evt;
                        evt.connection = e.connection;
                        evt.characteristic = e.characteristic;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        kernel::Task::Run(callbacks, &Callbacks::OnBluetoothCharacteristicReadRequest, evt);
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_user_write_request_id):
                {
                    auto &e = evt->data.evt_gatt_server_user_write_request;
                    MYDBG("evt_gatt_server_user_write_request: %d, char %04X, op %d, offset %d, data %H",
                        e.connection, e.characteristic, e.att_opcode, e.offset, Span(e.value.data, e.value.len));

#ifdef gattdb_ota_control
                    // built-in DFU handling
                    if (e.characteristic == gattdb_ota_control)
                    {
                        MYDBG("...DFU reset requested");
                        SETBIT(dfuConnection, e.connection);
                        gecko_cmd_gatt_server_send_user_write_response(e.connection, gattdb_ota_control, bg_err_success);
                        CloseConnection(e.connection);
                        break;
                    }
#endif

                    if (callbacks)
                    {
                        CharacteristicWriteRequest evt;
                        evt.connection = e.connection;
                        evt.characteristic = e.characteristic;
                        evt.opcode = e.att_opcode;
                        evt.offset = e.offset;
                        // store the value for the callback
                        auto pData = e.value.len <= 32 ? MemPoolAlloc<32>() : malloc(e.value.len);
                        memcpy(pData, e.value.data, e.value.len);
                        evt.data = Span(pData, e.value.len);

                        kernel::Task::Run(callbacks, &Callbacks::OnBluetoothCharacteristicWriteRequest, evt)
                            .OnComplete(GetDelegate((void(*)(void*,intptr_t))(e.value.len <= 32 ? MemPoolFree<32> : free), pData));
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_characteristic_status_id):
                {
                    auto &e = evt->data.evt_gatt_server_characteristic_status;
                    MYDBG("evt_gatt_server_characteristic_status: %d, char %04X, status %x, client %x", e.connection, e.characteristic, e.status_flags, e.client_config_flags);

                    if (e.status_flags & gatt_server_client_config)
                    {
                        if (callbacks)
                        {
                            CharacteristicEventRequest evt;
                            evt.connection = e.connection;
                            evt.characteristic = e.characteristic;
                            evt.level = (EventLevel)e.client_config_flags;
                            kernel::Task::Run(callbacks, &Callbacks::OnBluetoothCharacteristicEventRequest, evt);
                        }
                    }
                    break;
                }

                case EVENT_ID(gecko_evt_gatt_server_execute_write_completed_id):
                {
                    UNUSED auto &e = evt->data.evt_gatt_server_execute_write_completed;
                    MYDBG("evt_gatt_server_execute_write_completed: %d, result %s", e.connection, GetErrorMessage(e.result));
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
                    MYDBG("evt_sm_passkey_display: %d, %06d", e.connection, e.passkey);
                    break;
                }

                case EVENT_ID(gecko_evt_sm_passkey_request_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_passkey_request;
                    MYDBG("evt_sm_passkey_request: %d", e.connection);
                    break;
                }

                case EVENT_ID(gecko_evt_sm_confirm_passkey_id):
                {
                    UNUSED auto &e = evt->data.evt_sm_confirm_passkey;
                    MYDBG("evt_sm_confirm_passkey: %d, %06d", e.connection, e.passkey);
                    break;
                }

                case EVENT_ID(gecko_evt_sm_bonded_id):
                {
                    auto &e = evt->data.evt_sm_bonded;
                    MYDBG("evt_sm_bonded: %d, bonding %d", e.connection, e.bonding);

                    connInfo[e.connection].bonding = e.bonding;
                    break;
                }
                case EVENT_ID(gecko_evt_sm_bonding_failed_id):
                {
                    auto &e = evt->data.evt_sm_bonding_failed;
                    auto &con = connInfo[e.connection];
                    MYDBG("evt_sm_bonding_failed: %d, reason %s", e.connection, GetErrorMessage(e.reason));
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
                    MYDBG("evt_sm_confirm_bonding: %d, bonding %d", e.connection, e.bonding_handle);
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
        }

        await_signal_ticks(event, std::min((mono_t)MONO_SIGNED_MAX, gecko_can_sleep_ticks()));
    }
}
async_end

void Bluetooth::CharacteristicReadRequest::Respond(Span data, AttError error)
{
    UNUSED auto resp = gecko_cmd_gatt_server_send_user_read_response(connection, characteristic, (uint8_t)error, data.Length(), data);
    MYDBG("evt_gatt_server_user_read_response: %d, char %04X, sent %d, status %s, data %H",
        connection, characteristic, resp->sent_len, GetErrorMessage(resp->result), data.Left(resp->sent_len));
}

void Bluetooth::CharacteristicWriteRequest::Respond(AttError error)
{
    UNUSED auto resp = gecko_cmd_gatt_server_send_user_write_response(connection, characteristic, (uint8_t)error);
    MYDBG("evt_gatt_server_user_write_response: %d, char %04X, status %s",
        connection, characteristic, GetErrorMessage(resp->result));
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
        MYDBG("gecko_cmd_gatt_server_send_characteristic_notification: %d %04X %H = %s", connection, characteristic, data, GetErrorMessage(res->result));
    }
    return RES_PAIR(res->result, res->sent_len);
}
