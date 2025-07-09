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

#include "sketch_wrapper_fuzzer.h"
#include "camera_device.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "capture_scene_const.h"
#include <cstdint>
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
const uint32_t METADATA_ITEM_SIZE = 20;
const uint32_t METADATA_DATA_SIZE = 200;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const uint32_t PREVIEW_WIDTH_1 = 1440;
const uint32_t PREVIEW_HEIGHT_1 = 1080;
const uint32_t PREVIEW_WIDTH_2 = 640;
const uint32_t PREVIEW_HEIGHT_2 = 480;

std::shared_ptr<SketchWrapper> SketchWrapperFuzzer::fuzz_{nullptr};

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

void SketchWrapperFuzzer::SketchWrapperFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto cameraManager = CameraManager::GetInstance();
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = PREVIEW_WIDTH_1;
    previewSize.height = PREVIEW_HEIGHT_1;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    Size sketchSize;
    sketchSize.width = PREVIEW_WIDTH_2;
    sketchSize.height = PREVIEW_HEIGHT_2;
    fuzz_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), sketchSize);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<CaptureSession> session = CameraManager::GetInstance()->CreateCaptureSession();
    auto modeName = session->GetFeaturesMode();
    fuzz_->Init(deviceMetadata, modeName);
    float floatNum = GetData<float>();
    fuzz_->UpdateSketchRatio(floatNum);
    fuzz_->AttachSketchSurface(nullptr);
    fuzz_->StartSketchStream();
    fuzz_->StopSketchStream();
    SketchStatus sketchStatus = SketchStatus::STARTING;
    std::shared_ptr<SceneFeaturesMode> sceneFeaturesMode = std::make_shared<SceneFeaturesMode>();
    fuzz_->OnSketchStatusChanged(sketchStatus, *sceneFeaturesMode);
    fuzz_->OnSketchStatusChanged(*sceneFeaturesMode);
    fuzz_->UpdateSketchStaticInfo(deviceMetadata);
    fuzz_->GetSceneFeaturesModeFromModeData(floatNum);
    fuzz_->UpdateSketchEnableRatio(deviceMetadata);
    SketchReferenceFovRange sketchReferenceFovRange = { .zoomMin = -1.0f, .zoomMax = -1.0f, .referenceValue = -1.0f };
    fuzz_->InsertSketchReferenceFovRatioMapValue(*sceneFeaturesMode, sketchReferenceFovRange);
    fuzz_->InsertSketchEnableRatioMapValue(*sceneFeaturesMode, floatNum);
    fuzz_->UpdateSketchReferenceFovRatio(deviceMetadata);
}

void SketchWrapperFuzzer::SketchWrapperFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto cameraManager = CameraManager::GetInstance();
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize;
    previewSize.width = PREVIEW_WIDTH_1;
    previewSize.height = PREVIEW_HEIGHT_1;
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    Size sketchSize;
    sketchSize.width = PREVIEW_WIDTH_2;
    sketchSize.height = PREVIEW_HEIGHT_2;
    fuzz_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), sketchSize);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<CaptureSession> session = CameraManager::GetInstance()->CreateCaptureSession();
    auto modeName = session->GetFeaturesMode();
    fuzz_->Init(deviceMetadata, modeName);
    float floatNum = GetData<float>();
    std::shared_ptr<SceneFeaturesMode> sceneFeaturesMode = std::make_shared<SceneFeaturesMode>();
    camera_metadata_item_t item;
    OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    fuzz_->UpdateSketchReferenceFovRatio(item);
    fuzz_->GetMoonCaptureBoostAbilityItem(deviceMetadata, item);
    fuzz_->UpdateSketchConfigFromMoonCaptureBoostConfig(deviceMetadata);
    fuzz_->GetSketchReferenceFovRatio(*sceneFeaturesMode, floatNum);
    fuzz_->GetSketchEnableRatio(*sceneFeaturesMode);
    fuzz_->UpdateZoomRatio(floatNum);
    fuzz_->AutoStream();
    camera_device_metadata_tag_t tag = OHOS_CONTROL_ZOOM_RATIO;
    
    fuzz_->OnMetadataChangedMacro(*sceneFeaturesMode, tag, item);
    fuzz_->Destroy();
    fuzz_->sketchStream_ = nullptr;
    fuzz_->StartSketchStream();
    fuzz_->StopSketchStream();
}

void Test()
{
    auto sketchWrapper = std::make_unique<SketchWrapperFuzzer>();
    if (sketchWrapper == nullptr) {
        MEDIA_INFO_LOG("sketchWrapper is null");
        return;
    }
    sketchWrapper->SketchWrapperFuzzTest1();
    sketchWrapper->SketchWrapperFuzzTest2();
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