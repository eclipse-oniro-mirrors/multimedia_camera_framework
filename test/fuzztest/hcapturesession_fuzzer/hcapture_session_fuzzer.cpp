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

#include "hcapture_session_fuzzer.h"

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
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

HCaptureSession *HCaptureSessionFuzzer::fuzz_ = nullptr;
HCaptureSession *HCaptureSessionFuzzer::manager_ = nullptr;

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

void HCaptureSessionFuzzer::HCaptureSessionFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    if (fuzz_ == nullptr) {
        fuzz_ = new (std::nothrow) HCaptureSession();
    }
    fuzz_->BeginConfig();
    fuzz_->CommitConfig();
    int32_t streamId = GetData<int32_t>();
    fuzz_->GetStreamByStreamID(streamId);
    int32_t rotation = GetData<int32_t>();
    int32_t format = GetData<int32_t>();
    int32_t captureId = GetData<int32_t>();
    int64_t timestamp = GetData<int64_t>();
    fuzz_->StartMovingPhotoEncode(rotation, timestamp, format, captureId);
    fuzz_->StartRecord(timestamp, rotation, captureId);
    fuzz_->GetHdiStreamByStreamID(streamId);
    int32_t featureMode = GetData<int32_t>();
    fuzz_->SetFeatureMode(featureMode);
    float currentFps = GetData<float>();
    float currentZoomRatio = GetData<float>();
    fuzz_->QueryFpsAndZoomRatio(currentFps, currentZoomRatio);
    int outFd = GetData<int32_t>();
    CameraInfoDumper infoDumper(outFd);
    fuzz_->DumpSessionInfo(infoDumper);
    fuzz_->DumpSessions(infoDumper);
    fuzz_->DumpCameraSessionSummary(infoDumper);
    uint32_t interfaceCode = GetData<uint32_t>();
    fuzz_->OperatePermissionCheck(interfaceCode);
    fuzz_->EnableMovingPhotoMirror(GetData<bool>(), GetData<bool>());
    ColorSpace getColorSpace;
    fuzz_->GetActiveColorSpace(getColorSpace);
    ColorSpace colorSpace = static_cast<ColorSpace>(callerToken % 23);
    ColorSpace captureColorSpace = static_cast<ColorSpace>(callerToken % 23);
    fuzz_->SetColorSpace(colorSpace, captureColorSpace, GetData<bool>());
}

void Test()
{
    auto hcaptureSession = std::make_unique<HCaptureSessionFuzzer>();
    if (hcaptureSession == nullptr) {
        MEDIA_INFO_LOG("hcaptureSession is null");
        return;
    }
    hcaptureSession->HCaptureSessionFuzzTest();
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