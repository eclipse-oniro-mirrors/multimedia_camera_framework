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

#include "hcamera_host_manager_fuzzer.h"

#include "camera_log.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"

using namespace OHOS::CameraStandard::DeferredProcessing;
namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::ICameraDeviceCallback;
static constexpr int32_t MIN_SIZE_NUM = 128;
const size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<HCameraHostManager> HCameraHostManagerFuzzer::fuzz_{nullptr};
std::shared_ptr<HCameraHostManager::CameraHostInfo> HCameraHostManagerFuzzer::hostInfo{nullptr};

void HCameraHostManagerFuzzer::HCameraHostManagerFuzzTest1(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    std::shared_ptr<HCameraHostManager::StatusCallback> statusCallback = std::make_shared<StatusCallbackDemo>();
    fuzz_ = std::make_shared<HCameraHostManager>(statusCallback);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    std::string cameraId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    bool isEnable = fdp.ConsumeBool();
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    fuzz_->GetCameraAbility(cameraId, ability);
    fuzz_->SetFlashlight(cameraId, isEnable);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hCameraHostManagerFuzzer = std::make_unique<HCameraHostManagerFuzzer>();
    if (hCameraHostManagerFuzzer == nullptr) {
        MEDIA_INFO_LOG("hCameraHostManagerFuzzer is null");
        return;
    }
    hCameraHostManagerFuzzer->HCameraHostManagerFuzzTest1(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}