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

#include "capture_output_fuzzer.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

CaptureOutput *CaptureOutputFuzzer::fuzz_ = nullptr;

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

void CaptureOutputFuzzer::CaptureOutputFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t randomInt = GetData<int32_t>();
    if (fuzz_ == nullptr) {
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        CHECK_ERROR_RETURN_LOG(photoSurface, "PhotoOutputFuzzer: create photoSurface Error");
        sptr<IBufferProducer> bufferProducer = photoSurface->GetProducer();
        CHECK_ERROR_RETURN_LOG(bufferProducer, "GetProducer Error");
        sptr<IStreamCommon> stream;
        CaptureOutputType randomOutputType = static_cast<CaptureOutputType>(
        (randomInt % static_cast<int32_t>(CAPTURE_OUTPUT_TYPE_MAX)));
        fuzz_ = new CaptureOutputTest(randomOutputType, StreamType::CAPTURE,
            bufferProducer, stream);
    }
    fuzz_->GetBufferProducer();
    int32_t pid = GetData<int32_t>();
    fuzz_->OnCameraServerDied(pid);
    fuzz_->IsStreamCreated();
    DepthProfile depthProfile;
    fuzz_->SetDepthProfile(depthProfile);
    fuzz_->GetDepthProfile();
    fuzz_->ClearProfiles();
    fuzz_->AddTag(CaptureOutput::Tag::DYNAMIC_PROFILE);
    fuzz_->RemoveTag(CaptureOutput::Tag::DYNAMIC_PROFILE);
}

void Test()
{
    auto captureOutput = std::make_unique<CaptureOutputFuzzer>();
    if (captureOutput == nullptr) {
        MEDIA_INFO_LOG("captureOutput is null");
        return;
    }
    captureOutput->CaptureOutputFuzzTest();
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