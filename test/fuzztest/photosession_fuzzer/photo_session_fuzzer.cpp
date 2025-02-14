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

#include "photo_session_fuzzer.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "time_lapse_photo_session.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

sptr<PhotoSession> fuzz = nullptr;
sptr<CameraDevice> camera = nullptr;
sptr<CameraManager> cameraManager = nullptr;
sptr<CaptureOutput> photoOutput = nullptr;

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

void PhotoSessionFuzzer::PhotoSessionFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    cameraManager = CameraManager::GetInstance();
    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(SceneMode::CAPTURE);
    fuzz = static_cast<PhotoSession*>(captureSession.GetRefPtr());
    if (fuzz == nullptr) {
        return;
    }
    fuzz->CanAddOutput(photoOutput);
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<PreconfigType> preconfigTypeVec = {
        PRECONFIG_720P,
        PRECONFIG_1080P,
        PRECONFIG_4K,
        PRECONFIG_HIGH_QUALITY,
    };
    uint8_t underNum = randomNum % preconfigTypeVec.size();
    PreconfigType preconfigType = preconfigTypeVec[underNum];
    std::vector<ProfileSizeRatio> profileSizeRatioVec = {
        UNSPECIFIED,
        RATIO_1_1,
        RATIO_4_3,
        RATIO_16_9,
    };
    uint8_t underNumSec = randomNum % profileSizeRatioVec.size();
    ProfileSizeRatio profileSizeRatio = profileSizeRatioVec[underNumSec];
    fuzz->GeneratePreconfigProfiles(preconfigType, profileSizeRatio);
    auto configs = fuzz->GeneratePreconfigProfiles(PRECONFIG_720P, RATIO_1_1);
    fuzz->IsPreconfigProfilesLegal(configs);
    fuzz->CanPreconfig(preconfigType, profileSizeRatio);
    fuzz->Preconfig(preconfigType, profileSizeRatio);
    auto cameras = cameraManager->GetSupportedCameras();
    camera = cameras[0];
    CHECK_ERROR_RETURN_LOG(!camera, "PhotoSessionFuzzer: Camera is null");
    Profile photo(CameraFormat::CAMERA_FORMAT_JPEG, {640, 480});
    fuzz->IsPhotoProfileLegal(camera, photo);
    Profile preview(CameraFormat::CAMERA_FORMAT_YUV_420_SP, {640, 480});
    fuzz->IsPreviewProfileLegal(camera, preview);
}

void Test()
{
    auto photoSession = std::make_unique<PhotoSessionFuzzer>();
    if (photoSession == nullptr) {
        MEDIA_INFO_LOG("photoSession is null");
        return;
    }
    photoSession->PhotoSessionFuzzTest();
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