/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "reader_fuzzer.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "securec.h"
#include <memory>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

std::shared_ptr<Reader> ReaderFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void ReaderFuzzer::ReaderFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<Reader>();
    }
    int32_t inputFd = GetData<int32_t>();
    fuzz_->Create(inputFd);
    fuzz_->GetSourceFormat();
    Format sourceFormat;
    fuzz_->sourceFormat_ = std::make_shared<Format>(sourceFormat);
    fuzz_->InitTracksAndDemuxer();
    auto mediaInfo = std::make_shared<MediaInfo>();
    fuzz_->GetMediaInfo(mediaInfo);
    fuzz_->GetSourceMediaInfo(mediaInfo);
    
    int32_t trackType = GetData<int32_t>();
    int32_t trackIndex = GetData<int32_t>();
    TrackFormat formatOfIndex;
    Format trackFormat;
    trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType);
    formatOfIndex.format = std::make_shared<Format>(trackFormat);
    formatOfIndex.trackId = trackIndex;
    fuzz_->GetTrackMediaInfo(formatOfIndex, mediaInfo);
}

void Test()
{
    auto reader = std::make_unique<ReaderFuzzer>();
    if (reader == nullptr) {
        MEDIA_INFO_LOG("mpegManager is null");
        return;
    }
    reader->ReaderFuzzTest();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}