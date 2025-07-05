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

#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "ipc_skeleton.h"
#include "input/camera_manager_for_sys.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "securec.h"
#include "slow_motion_session_fuzzer.h"
#include "test_token.h"
#include "time_lapse_photo_session.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 50;
const int32_t DEFAULT_ITEMS = 10;
const int32_t DEFAULT_DATA_LENGTH = 100;
sptr<CameraManager> manager;
std::vector<Profile> previewProfile_ = {};
std::vector<VideoProfile> videoProfile_;

sptr<CaptureOutput> CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = manager->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_RET(cameras.empty(), nullptr);
    auto outputCapability = manager->GetSupportedOutputCapability(cameras[0],
        static_cast<int32_t>(SceneMode::SLOW_MOTION));
    previewProfile_ = outputCapability->GetPreviewProfiles();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager->CreatePreviewOutput(previewProfile_[0], surface);
}

sptr<CaptureOutput> CreateVideoOutput()
{
    videoProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = manager->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_RET(cameras.empty(), nullptr);
    auto outputCapability = manager->GetSupportedOutputCapability(cameras[0],
        static_cast<int32_t>(SceneMode::SLOW_MOTION));
    videoProfile_ = outputCapability->GetVideoProfiles();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager->CreateVideoOutput(videoProfile_[0], surface);
}

void SlowMotionSessionFuzzer::SlowMotionSessionFuzzTest(FuzzedDataProvider& fdp)
{
    manager = CameraManager::GetInstance();
    sptr<CaptureSessionForSys> captureSessionForSys =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    std::vector<sptr<CameraDevice>> cameras;
    cameras = manager->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "SlowMotionSessionFuzzer: GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = manager->CreateCameraInput(cameras[0]);
    CHECK_ERROR_RETURN_LOG(!input, "CreateCameraInput Error");
    input->Open();
    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    captureSessionForSys->BeginConfig();
    captureSessionForSys->AddInput(input);
    sptr<CameraDevice> info = captureSessionForSys->innerInputDevice_->GetCameraDeviceInfo();
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), previewProfile_);
    info->modeVideoProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), videoProfile_);
    captureSessionForSys->AddOutput(previewOutput);
    captureSessionForSys->AddOutput(videoOutput);
    captureSessionForSys->CommitConfig();
    input->Release();
    sptr<SlowMotionSession> fuzz_ = static_cast<SlowMotionSession*>(captureSessionForSys.GetRefPtr());
    if (fuzz_ == nullptr) {
        return;
    }
    fuzz_->IsSlowMotionDetectionSupported();
    Rect rect = {fdp.ConsumeFloatingPointInRange<double>(0, 100), fdp.ConsumeFloatingPointInRange<double>(0, 100),
        fdp.ConsumeFloatingPointInRange<double>(0, 100), fdp.ConsumeFloatingPointInRange<double>(0, 100)};
    fuzz_->NormalizeRect(rect);
    fuzz_->SetSlowMotionDetectionArea(rect);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    SlowMotionSession::SlowMotionSessionMetadataResultProcessor processor(fuzz_);
    uint64_t timestamp = fdp.ConsumeIntegralInRange<uint64_t>(0, 10);
    auto metadata = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    processor.ProcessCallbacks(timestamp, metadata);
    std::shared_ptr<SlowMotionStateCallback> callback = std::make_shared<TestSlowMotionStateCallback>();
    fuzz_->SetCallback(callback);
    fuzz_->OnSlowMotionStateChange(metadata);
    fuzz_->GetApplicationCallback();
    bool isEnable = fdp.ConsumeBool();
    fuzz_->LockForControl();
    fuzz_->EnableMotionDetection(isEnable);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_ERROR_RETURN_LOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
    auto slowMotionSession = std::make_unique<SlowMotionSessionFuzzer>();
    if (slowMotionSession == nullptr) {
        MEDIA_INFO_LOG("slowMotionSession is null");
        return;
    }
    slowMotionSession->SlowMotionSessionFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}