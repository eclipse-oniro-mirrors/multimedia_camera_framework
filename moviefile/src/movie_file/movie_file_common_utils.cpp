/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "movie_file_common_utils.h"

#include <fstream>

#include "audio_stream_info.h"
#include "camera_log.h"
#include "native_audio_channel_layout.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
namespace MovieFile {
std::shared_ptr<uint8_t> CopyData(uint8_t* srcPtr, size_t size)
{
    std::unique_ptr<uint8_t[]> dstPtr = std::make_unique<uint8_t[]>(size);
    int32_t ret = memcpy_s(dstPtr.get(), size, srcPtr, size);
    CHECK_RETURN_RET(ret != 0, nullptr);
    return dstPtr;
}

void DumpBufferToFile(const char* buffer, size_t size, const char* fileName)
{
    char* canonicalPath = new (std::nothrow) char[PATH_MAX];
    if (canonicalPath == nullptr) {
        MEDIA_ERR_LOG("Memory allocation failed for path normalization");
        return;
    }
    if (realpath(fileName, canonicalPath) == nullptr) {
        MEDIA_ERR_LOG("Path normalization failed: %{public}s", fileName);
        delete[] canonicalPath;
        return;
    }

    std::ofstream ofs(canonicalPath, std::ios::binary);
    if (ofs.is_open()) {
        ofs.write(buffer, size);
        ofs.close();
    } else {
        MEDIA_ERR_LOG("Failed to open file:%{public}s", canonicalPath);
        delete[] canonicalPath;
        canonicalPath = nullptr;
        return;
    }
    delete[] canonicalPath;
    canonicalPath = nullptr;
}

uint64_t GetChannelLayoutByChannelCount(uint32_t channelCount)
{
    uint64_t channelLayout = 0;
    switch (channelCount) {
        case AudioStandard::MONO:
            channelLayout = CH_LAYOUT_MONO;
            break;
        case AudioStandard::STEREO:
            channelLayout = CH_LAYOUT_STEREO;
            break;
        case AudioStandard::CHANNEL_4:
            channelLayout = CH_LAYOUT_4POINT0;
            break;
        case AudioStandard::CHANNEL_8:
            channelLayout = CH_LAYOUT_7POINT1;
            break;
        default:
            channelLayout = CH_LAYOUT_STEREO;
            break;
    }
    return channelLayout;
}
} // namespace MovieFile
} // namespace CameraStandard
} // namespace OHOS
