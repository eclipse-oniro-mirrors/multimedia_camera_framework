/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hstream_operator_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include "camera_log.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "buffer_extra_data_impl.h"
#include "picture.h"
#include "camera_server_photo_proxy.h"
#include "camera_photo_proxy.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 36;
static constexpr int32_t NUM_1 = 1;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

sptr<HStreamOperator> HStreamOperatorFuzzer::fuzz_{nullptr};

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

void HStreamOperatorFuzzer::HStreamOperatorFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    fuzz_ = HStreamOperator::NewInstance(0, 0);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "NewInstance Error");
    int32_t streamId = GetData<int32_t>();
    fuzz_->GetStreamByStreamID(streamId);
    int32_t rotation = GetData<int32_t>();
    int32_t format = GetData<int32_t>();
    int32_t captureId = GetData<int32_t>();
    int64_t timestamp = GetData<int64_t>();
    fuzz_->StartMovingPhotoEncode(rotation, timestamp, format, captureId);
    fuzz_->StartRecord(timestamp, rotation, captureId);
    fuzz_->GetHdiStreamByStreamID(streamId);
    fuzz_->EnableMovingPhotoMirror(GetData<bool>(), GetData<bool>());
    ColorSpace getColorSpace;
    fuzz_->GetActiveColorSpace(getColorSpace);
    constexpr int32_t executionModeCount = static_cast<int32_t>(ColorSpace::P3_PQ_LIMIT) + NUM_1;
    ColorSpace colorSpace = static_cast<ColorSpace>(GetData<uint8_t>() % executionModeCount);
    fuzz_->SetColorSpace(colorSpace, GetData<bool>());
    fuzz_->GetStreamOperator();
    std::vector<int32_t> results = {GetData<uint32_t>()};
    fuzz_->ReleaseStreams();
    std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos;
    fuzz_->CreateStreams(streamInfos);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    const int32_t NUM_10 = 10;
    const int32_t NUM_100 = 100;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    int32_t operationMode = GetData<int32_t>();
    fuzz_->CommitStreams(settings, operationMode);
    fuzz_->UpdateStreams(streamInfos);
    fuzz_->CreateAndCommitStreams(streamInfos, settings, operationMode);
    const std::vector<int32_t> streamIds;
    fuzz_->OnCaptureStarted(captureId, streamIds);
    const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo> infos;
    fuzz_->OnCaptureStarted_V1_2(captureId, infos);
    const std::vector<CaptureEndedInfo> infos_OnCaptureEnded;
    fuzz_->OnCaptureEnded(captureId, infos_OnCaptureEnded);
    const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt> infos_OnCaptureEndedExt;
    fuzz_->OnCaptureEndedExt(captureId, infos_OnCaptureEndedExt);
    const std::vector<CaptureErrorInfo> infos_OnCaptureError;
    fuzz_->OnCaptureError(captureId, infos_OnCaptureError);
    fuzz_->OnFrameShutter(captureId, results, timestamp);
    fuzz_->OnFrameShutterEnd(captureId, results, timestamp);
    fuzz_->OnCaptureReady(captureId, results, timestamp);
}

void Test()
{
    auto HStreamOperator = std::make_unique<HStreamOperatorFuzzer>();
    if (HStreamOperator == nullptr) {
        MEDIA_INFO_LOG("HStreamOperator is null");
        return;
    }
    HStreamOperator->HStreamOperatorFuzzTest();
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
