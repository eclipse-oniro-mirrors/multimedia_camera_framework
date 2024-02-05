/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <buffer_handle.h>
#include <cstdlib>
#include <securec.h>
#include <stdint.h>
#include <unistd.h>

#include "buffer_handle_utils.h"
#include "camera_log.h"
#include "dps_metadata_info.h"


namespace OHOS {
namespace CameraStandard {
#define BUFFER_HANDLE_RESERVE_MAX_SIZE 1024

BufferHandle *CameraAllocateBufferHandle(uint32_t reserveFds, uint32_t reserveInts)
{
    if (reserveFds > BUFFER_HANDLE_RESERVE_MAX_SIZE || reserveInts > BUFFER_HANDLE_RESERVE_MAX_SIZE) {
        MEDIA_ERR_LOG("CameraAllocateBufferHandle reserveFds or reserveInts too lager");
        return nullptr;
    }
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (reserveFds + reserveInts));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    if (handle != nullptr) {
        (void)memset_s(handle, handleSize, 0, handleSize);
        handle->fd = -1;
        for (uint32_t i = 0; i < reserveFds; i++) {
            handle->reserve[i] = -1;
        }
        handle->reserveFds = reserveFds;
        handle->reserveInts = reserveInts;
    } else {
        MEDIA_ERR_LOG("InitBufferHandle malloc %zu failed", handleSize);
    }
    return handle;
}

int32_t CameraFreeBufferHandle(BufferHandle *handle)
{
    if (handle == nullptr) {
        MEDIA_ERR_LOG("CameraFreeBufferHandle with nullptr handle");
        return 0;
    }
    if (handle->fd >= 0) {
        close(handle->fd);
        handle->fd = -1;
    }
    const uint32_t reserveFds = handle->reserveFds;
    for (uint32_t i = 0; i < reserveFds; i++) {
        if (handle->reserve[i] >= 0) {
            close(handle->reserve[i]);
            handle->reserve[i] = -1;
        }
    }
    free(handle);
    return 0;
}

BufferHandle *CameraCloneBufferHandle(const BufferHandle *handle)
{
    if (handle == nullptr) {
        MEDIA_ERR_LOG("%{public}s handle is nullptr", __func__);
        return nullptr;
    }
    BufferHandle *newHandle = CameraAllocateBufferHandle(handle->reserveFds, handle->reserveInts);
    if (newHandle == nullptr) {
        MEDIA_ERR_LOG("%{public}s CameraAllocateBufferHandle failed, newHandle is nullptr", __func__);
        return nullptr;
    }

    if (handle->fd == -1) {
        newHandle->fd = handle->fd;
    } else {
        newHandle->fd = dup(handle->fd);
        if (newHandle->fd == -1) {
            MEDIA_ERR_LOG("CameraCloneBufferHandle dup failed");
            CameraFreeBufferHandle(newHandle);
            return nullptr;
        }
    }
    newHandle->width = handle->width;
    newHandle->stride = handle->stride;
    newHandle->height = handle->height;
    newHandle->size = handle->size;
    newHandle->format = handle->format;
    newHandle->usage = handle->usage;
    newHandle->phyAddr = handle->phyAddr;

    // 此处当前缺乏reserveFds中各个fd的dup，原因在于surfacebuffer中reserveFds fd不合法。且相机流程中reserveFds暂时无用

    if (handle->reserveInts == 0) {
        MEDIA_INFO_LOG("There is no reserved integer value in old handle, no need to copy");
        return newHandle;
    }

    if (memcpy_s(&newHandle->reserve[newHandle->reserveFds], sizeof(int32_t) * newHandle->reserveInts,
        &handle->reserve[handle->reserveFds], sizeof(int32_t) * handle->reserveInts) != EOK) {
        MEDIA_ERR_LOG("CameraCloneBufferHandle memcpy_s failed");
        CameraFreeBufferHandle(newHandle);
        return nullptr;
    }
    return newHandle;
}

} // namespace CameraStandard
} // namespace OHOS
