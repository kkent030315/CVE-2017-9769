/*
 * MIT License
 *
 * Copyright (c) 2020 Kento Oki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#pragma once
#include <Windows.h>
#include <filesystem>

#include "raw_driver.hpp"
#include "logger.hpp"
#include "file_utils.hpp"
#include "service_utils.hpp"

#define RAZER_DRIVER_NAME "rzpnk.sys"
#define RAZER_DEVICE_NAME "\\\\.\\47CD78C9-64C3-47C2-B80F-677B887CF095"

#define RAZER_IOCTL_OPEN_PROCESS_HANDLE 0x22A050

namespace razer
{
    typedef struct _RAZER_OPEN_PROCESS_HANDLE_REQUEST
    {
        uint64_t process_id;
        uint64_t result;
    } RAZER_OPEN_PROCESS_HANDLE_REQUEST, * PRAZER_OPEN_PROCESS_HANDLE_REQUEST;

    namespace detail
    {
        inline SC_HANDLE service_handle;
        inline HANDLE device_handle;
    }

    bool razer_init();
    void razer_unload();
    bool send_ioctl(const DWORD ioctl_code,
        void* buffer, size_t buffer_size);

    namespace driver_impl
    {
        HANDLE open_process_handle(const uint32_t process_id);
    }
}