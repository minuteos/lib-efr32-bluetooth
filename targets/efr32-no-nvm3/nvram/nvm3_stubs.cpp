/*
 * Copyright (c) 2020 triaxis s.r.o.
 * Licensed under the MIT license. See LICENSE.txt file in the repository root
 * for full license information.
 *
 * efr32-no-nvm3/nvram/nvm3_stubs.cpp
 */

#include <nvram/nvram.h>

#include <bg_errorcodes.h>

#define MYDBG(...)      DBGCL("no-nvm3", __VA_ARGS__)

// from emdrv/common/inc/ecode.h
#define ECODE_EMDRV_BASE  (0xF0000000U)   ///< Base value for all EMDRV errorcodes.
#define ECODE_OK          (0U)            ///< Generic success return value.
#define ECODE_EMDRV_NVM3_BASE        (ECODE_EMDRV_BASE | 0x0000E000U)   ///< Base value for NVM3 error codes.

// from emdrv/nvm3/inc/nvm3.h
#define ECODE_NVM3_OK                               (ECODE_OK)                                   ///< Success return value
#define ECODE_NVM3_ERR_STORAGE_FULL                 (ECODE_EMDRV_NVM3_BASE | 0x00000006U)        ///< No more NVM space available
#define ECODE_NVM3_ERR_KEY_INVALID                  (ECODE_EMDRV_NVM3_BASE | 0x0000000AU)        ///< Invalid key value
#define ECODE_NVM3_ERR_KEY_NOT_FOUND                (ECODE_EMDRV_NVM3_BASE | 0x0000000BU)        ///< Key not found
#define ECODE_NVM3_ERR_READ_DATA_SIZE               (ECODE_EMDRV_NVM3_BASE | 0x00000011U)        ///< Trying to read with a length different from actual object siz

nvram::VariableUniqueKeyStorage nvm3("NVM3");

BEGIN_EXTERN_C

void nvm3_open(intptr_t handle, intptr_t init)
{
    nvram::RegisterCollector(nvm3.pageId, 10, nvram::CollectorRelocate);
}

// antyhing to make linker happy - the arguments are passed to nvm3_open and ignored
char nvm3_defaultInit[0];
char nvm3_defaultHandle[0];

uint32_t nvm3_writeData(intptr_t handle, uint32_t key, const void* data, size_t length)
{
    if (nvm3.Set(key, Span(data, length)))
        return ECODE_NVM3_OK;
    else
        return ECODE_NVM3_ERR_STORAGE_FULL;
}

uint32_t nvm3_readData(intptr_t handle, uint32_t key, void* data, size_t length)
{
    if (auto span = nvm3.Get(key))
    {
        span.CopyTo(data, length);
        if (length == span.Length())
            return ECODE_NVM3_OK;
        else
            return ECODE_NVM3_ERR_READ_DATA_SIZE;
    }
    return ECODE_NVM3_ERR_KEY_NOT_FOUND;
}

uint32_t nvm3_deleteObject(intptr_t handle, uint32_t key)
{
    if (nvm3.Delete(key))
        return ECODE_NVM3_OK;
    else
        return ECODE_NVM3_ERR_KEY_NOT_FOUND;
}

uint32_t nvm3_deleteObjects(intptr_t handle, uint32_t from, uint32_t to)
{
    for (auto rec = nvram::Page::FindUnorderedFirst(nvm3.pageId); rec; rec = nvram::Page::FindUnorderedNext(rec.Pointer()))
    {
        if (rec.Length() < sizeof(uint32_t))
            continue;
        auto key = rec.Element<uint32_t>();
        if (key >= from && key < to)
        {
            nvram::Flash::ShredWord(rec.Pointer());
        }
    }

    return ECODE_NVM3_OK;
}

// called from libbluetooth directly, nvm3_deleteObjects is from the same module, so we have to replace these as well
bg_error ubt_pskey_write_callback(uint32_t key, size_t length, const void* data)
{
    MYDBG("W %X = %H", key, Span(data, length));
    if (nvm3.Set(key | 0x40000, Span(data, length)))
        return bg_err_success;
    else
        return bg_err_hardware_ps_store_full;
}

bg_error ubt_pskey_read_callback(uint32_t key, size_t length, void* data)
{
    if (auto span = nvm3.Get(key | 0x40000))
    {
        MYDBG("R %X = %H (%d)", key, span, length);
        span.CopyTo(data, length);
        return bg_err_success;
    }
    MYDBG("R %X = ?", key);
    return bg_err_hardware_ps_key_not_found;
}

bg_error ubt_pskey_delete(uint32_t key)
{
    MYDBG("- %X", key);
    if (nvm3.Delete(key | 0x40000))
        return bg_err_success;
    else
        return bg_err_hardware_ps_key_not_found;
}

bg_error ubt_pskey_delete_callback(uint32_t first, uint32_t count)
{
    nvm3_deleteObjects(0, first | 0x40000, ((first + count + 1) & 0xFFFF) | 0x40000);
    return bg_err_success;
}

// only called directly after nvm3_open
bg_error ecode2bg()
{
    return bg_err_success;
}

END_EXTERN_C
