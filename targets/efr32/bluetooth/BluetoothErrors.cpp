/*
 * Copyright (c) 2019 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32/bluetooth/BluetoothErrors.cpp
 *
 * Implementation of the Bluetooth::GetErrorMessage helper
 */

#include "Bluetooth.h"

#include <base/format.h>

static const char* s_errors1[] = { "invalid_conn_handle", "waiting_response", "gatt_connection_timeout" };
static const char* s_errors1x[] = { "invalid_param", "wrong_state", "out_of_memory", "not_implemented", "invalid_command", "timeout", "not_connected", "flow", "user_attribute", "invalid_license_key", "command_too_long", "out_of_bounds", "unspecified", "hardware", "buffers_full", "disconnected", "too_many_requests", "not_supported", "no_bonding", "crypto", "data_corrupted", "command_complete" };
static const char* s_errors2[] = {
    /* 01-0F */ NULL, "unknown_connection_identifier", NULL, "page_timeout", "authentication_failure", "pin_or_key_missing", "memory_capacity_exceeded", "connection_timeout", "connection_limit_exceeded", "synchronous_connection_limit_exceeded", "acl_connection_already_exists", "command_disallowed", "connection_rejected_due_to_limited_resources", "connection_rejected_due_to_security_reasons", "connection_rejected_due_to_unacceptable_bd_addr",
    /* 10-1F */ "connection_accept_timeout_exceeded", "unsupported_feature_or_parameter_value", "invalid_command_parameters", "remote_user_terminated", "remote_device_terminated_connection_due_to_low_resources", "remote_powering_off", "connection_terminated_by_local_host", "repeated_attempts", "pairing_not_allowed", "unknown_lmp_pdu", "unsupported_remote_feature", "sco_offset_rejected", "sco_interval_rejected", "sco_air_mode_rejected", "invalid_lmp_parameters", "unspecified_error",
    /* 20-2F */ "unsupported_lmp_parameter_value", "role_change_not_allowed", "ll_response_timeout", "lmp_error_transaction_collision", "lmp_pdu_not_allowed", "encryption_mode_not_acceptable", "link_key_cannot_be_changed", "requested_qos_not_supported", "instant_passed", "pairing_with_unit_key_not_supported", "different_transaction_collision", "qos_unacceptable_parameter", "qos_rejected", "channel_assesment_not_supported", "insufficient_security",
    /* 30-3F */ "parameter_out_of_mandatory_range", "role_switch_pending", "reserved_slot_violation", "role_switch_failed", "extended_inquiry_response_too_large", "simple_pairing_not_supported_by_host", "host_busy_pairing", "connection_rejected_due_to_no_suitable_channel_found", "controller_busy", "unacceptable_connection_interval", "directed_advertising_timeout", "connection_terminated_due_to_mic_failure", "connection_failed_to_be_established", "mac_connection_failed",
    /* 40 */    "coarse_clock_adjustment_rejected_but_will_try_to_adjust_using_clock_dragging" };
static const char* s_errors3[] = { "passkey_entry_failed", "oob_not_available", "authentication_requirements", "confirm_value_failed", "pairing_not_supported", "encryption_key_size", "command_not_supported", "unspecified_reason", "repeated_attempts", "invalid_parameters", "dhkey_check_failed", "numeric_comparison_failed", "bredr_pairing_in_progress", "cross_transport_key_derivation_generation_not_allowed" };
static const char* s_errors4[] = { "invalid_handle", "read_not_permitted", "write_not_permitted", "invalid_pdu", "insufficient_authentication", "request_not_supported", "invalid_offset", "insufficient_authorization", "prepare_queue_full", "att_not_found", "att_not_long", "insufficient_enc_key_size", "invalid_att_length", "unlikely_error", "insufficient_encryption", "unsupported_group_type", "insufficient_resources" };
static const char* s_errors5[] = { "ps_store_full", "ps_key_not_found", "i2c_ack_missing", "i2c_timeout" };
static const char* s_errors9[] = { "file_not_found" };
static const char* s_errors10[] = { "file_open_failed", "xml_parse_failed", "device_connection_failed", "device_comunication_failed", "authentication_failed", "incorrect_gatt_database", "disconnected_due_to_procedure_collision", "disconnected_due_to_secure_session_failed", "encryption_decryption_error", "maximum_retries", "data_parse_failed", "pairing_removed", "inactive_timeout" };
static const char* s_errors11[] = { "image_signature_verification_failed", "file_signature_verification_failed", "image_checksum_error" };
static const char* s_errors12[] = { "already_exists", "does_not_exist", "limit_reached", "invalid_address", "malformed_data" };

static const char** s_errors[] = {
    s_errors1,
    s_errors2,
    s_errors3,
    s_errors4,
    s_errors5,
    NULL,
    NULL,
    NULL,
    s_errors9,
    s_errors10,
    s_errors11,
    s_errors12,
};

const char* Bluetooth::GetErrorMessage(uint32_t err)
{
    static char buf[9];

    if (err == 0)
        return "OK";
    unsigned cat = (err >> 8) - 1;
    unsigned i;
    const char** table = NULL;
    if (cat == 0 && err & 0x80)
    {
        table = s_errors1x;	// special case, extended error codes in class 1
        i = err & 0x7F;
    }
    else if (cat < countof(s_errors))
    {
        table = s_errors[cat];
        i = (err & 0xFF) - 1;
    }

    if (table == NULL || i > 0x40)
    {
        format(format_output_unsafe, buf, "%x", err);
        return buf;
    }

    return table[i];
}
