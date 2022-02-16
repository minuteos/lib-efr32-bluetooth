/*
 * Copyright (c) 2022 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * test/bluetooth/Bluetooth.h
 */

#pragma once

#include <kernel/kernel.h>

#include <gatt_db.h>

class Bluetooth
{
public:
    class Characteristic
    {
    public:
        Characteristic(int n) {}
    };

    class Connection
    {
    };

    class IncomingConnection : public Connection
    {
    public:
        async(SendNotification, Characteristic characteristic, Span value) async_def_return(true);
    };

    class OutgoingConnection : public Connection
    {
    };

    //! Gets the current MTU of the specified connection
    size_t ConnectionMTU(Connection connection) const { return 200; }
    //! Gets maximum allowed notification size for the specified connection
    size_t ConnectionMaxNotification(Connection connection) const { return ConnectionMTU(connection) - 3; }
    //! Gets the maximum allowed read payload size for the specified connection
    size_t ConnectionMaxReadResponse(Connection connection) const { return ConnectionMTU(connection) - 1; }
    //! Gets the maximum allowed write payload size for the specified connection
    size_t ConnectionMaxWrite(Connection connection) const { return ConnectionMTU(connection) - 5; }
    //! Gets the maximum allowed write without response payload size for the specified connection
    size_t ConnectionMaxWriteNoResponse(Connection connection) const { return ConnectionMTU(connection) - 3; }

    async(BroadcastCharacteristicNotification, Characteristic characteristic, Span data) async_def_return(true);
};

inline Bluetooth bluetooth;
