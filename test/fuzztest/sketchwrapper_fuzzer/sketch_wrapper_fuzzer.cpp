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
#include "istream_repeat_callback.h"
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
static constexpr int32_t MIN_SIZE_NUM = 80;
static constexpr int32_t ZERO_NUM = 0;
const size_t THRESHOLD = 10;
const uint32_t PREVIEW_WIDTH_1 = 1440;
const uint32_t PREVIEW_HEIGHT_1 = 1080;
const uint32_t PREVIEW_WIDTH_2 = 640;
const uint32_t PREVIEW_HEIGHT_2 = 480;

std::vector<uint32_t> previewSizeData = {
    PREVIEW_WIDTH_1,
    PREVIEW_HEIGHT_1,
    PREVIEW_WIDTH_2,
    PREVIEW_HEIGHT_2
};

std::shared_ptr<SketchWrapper> SketchWrapperFuzzer::fuzz_{nullptr};

std::vector<CameraFormat> cameraFormat = {
    CAMERA_FORMAT_INVALID,
    CAMERA_FORMAT_YCBCR_420_888,
    CAMERA_FORMAT_RGBA_8888,
    CAMERA_FORMAT_DNG,
    CAMERA_FORMAT_DNG_XDRAW,
    CAMERA_FORMAT_YUV_420_SP,
    CAMERA_FORMAT_NV12,
    CAMERA_FORMAT_YUV_422_YUYV,
    CAMERA_FORMAT_JPEG,
    CAMERA_FORMAT_YCBCR_P010,
    CAMERA_FORMAT_YCRCB_P010,
    CAMERA_FORMAT_HEIC,
    CAMERA_FORMAT_DEPTH_16,
    CAMERA_FORMAT_DEPTH_32,
};


void SketchWrapperFuzzer::SketchWrapperFuzzTest1(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto cameraManager = CameraManager::GetInstance();
    uint32_t underFormat = fdp.ConsumeIntegral<uint32_t>();
    CameraFormat previewFormat = cameraFormat[underFormat % cameraFormat.size()];
    Size previewSize;
    previewSize.width = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    previewSize.height = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    Size sketchSize;
    sketchSize.width = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    sketchSize.height = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    fuzz_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), sketchSize);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<CaptureSession> session = CameraManager::GetInstance()->CreateCaptureSession();
    auto modeName = session->GetFeaturesMode();
    fuzz_->Init(deviceMetadata, modeName);
    float floatNum = fdp.ConsumeFloatingPoint<float>();
    fuzz_->UpdateSketchRatio(floatNum);
    fuzz_->AttachSketchSurface(nullptr);
    fuzz_->StartSketchStream();
    fuzz_->StopSketchStream();
    SketchStatus sketchStatus = static_cast<SketchStatus>(fdp.ConsumeIntegralInRange(ZERO_NUM, MIN_SIZE_NUM));
    std::shared_ptr<SceneFeaturesMode> sceneFeaturesMode = std::make_shared<SceneFeaturesMode>();
    fuzz_->OnSketchStatusChanged(sketchStatus, *sceneFeaturesMode);
    fuzz_->OnSketchStatusChanged(*sceneFeaturesMode);
    fuzz_->UpdateSketchStaticInfo(deviceMetadata);
    fuzz_->GetSceneFeaturesModeFromModeData(floatNum);
    fuzz_->UpdateSketchEnableRatio(deviceMetadata);
    SketchReferenceFovRange sketchReferenceFovRange = { .zoomMin = fdp.ConsumeFloatingPoint<float>(),
        .zoomMax = fdp.ConsumeFloatingPoint<float>(), .referenceValue = fdp.ConsumeFloatingPoint<float>() };
    fuzz_->InsertSketchReferenceFovRatioMapValue(*sceneFeaturesMode, sketchReferenceFovRange);
    fuzz_->InsertSketchEnableRatioMapValue(*sceneFeaturesMode, floatNum);
    fuzz_->UpdateSketchReferenceFovRatio(deviceMetadata);
}

void SketchWrapperFuzzer::SketchWrapperFuzzTest2(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto cameraManager = CameraManager::GetInstance();
    uint32_t underFormat = fdp.ConsumeIntegral<uint32_t>();
    CameraFormat previewFormat = cameraFormat[underFormat % cameraFormat.size()];
    Size previewSize;
    previewSize.width = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    previewSize.height = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(previewFormat, previewSize);
    sptr<CaptureOutput> previewOutput = cameraManager->CreatePreviewOutput(previewProfile, surface);
    Size sketchSize;
    sketchSize.width = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    sketchSize.height = previewSizeData[fdp.ConsumeIntegral<uint32_t>() % previewSizeData.size()];
    fuzz_ = std::make_shared<SketchWrapper>(previewOutput->GetStream(), sketchSize);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(METADATA_ITEM_SIZE, METADATA_DATA_SIZE);
    sptr<CaptureSession> session = CameraManager::GetInstance()->CreateCaptureSession();
    auto modeName = session->GetFeaturesMode();
    fuzz_->Init(deviceMetadata, modeName);
    float floatNum = fdp.ConsumeFloatingPoint<float>();
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

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto sketchWrapper = std::make_unique<SketchWrapperFuzzer>();
    if (sketchWrapper == nullptr) {
        MEDIA_INFO_LOG("sketchWrapper is null");
        return;
    }
    sketchWrapper->SketchWrapperFuzzTest1(fdp);
    sketchWrapper->SketchWrapperFuzzTest2(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}