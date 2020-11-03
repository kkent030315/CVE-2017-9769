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

#include "utils.hpp"

DWORD utils::query_granted_access(const uint32_t process_id, HANDLE handle)
{
    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION buffer = NULL;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

    do
    {
        size *= 2;
        void* new_buffer = realloc(buffer, size);
        
        if (NULL == new_buffer)
            break;

        buffer = (PSYSTEM_HANDLE_INFORMATION)new_buffer;
        ULONG length = 0;

        status = NtQuerySystemInformation(SystemHandleInformation, buffer, size, &length);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status))
    {
        free(buffer);
        return NULL;
    }

    for (ULONG i = 0; i < buffer->NumberOfHandles; ++i)
    {
        if (buffer->Handles[i].UniqueProcessId == process_id &&
            buffer->Handles[i].HandleValue == (UINT_PTR)handle)
        {
            ULONG result = buffer->Handles[i].GrantedAccess;
            free(buffer);
            return result;
        }
    }

    free(buffer);

    return NULL;
}
