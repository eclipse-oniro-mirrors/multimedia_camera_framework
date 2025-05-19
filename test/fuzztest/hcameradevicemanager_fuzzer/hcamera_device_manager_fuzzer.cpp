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

#include "hcamera_device_manager_fuzzer.h"

#include "camera_log.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MIN_SIZE_NUM = 64;
const size_t THRESHOLD = 10;
sptr<HCameraDevice> g_HCameraDevice = nullptr;
std::string g_cameraID;

void InitCameraDevice()
{
    if (g_HCameraDevice != nullptr) {
        return;
    }
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::vector<std::string> cameraIds;
    cameraHostManager->GetCameras(cameraIds);
    CHECK_ERROR_RETURN_LOG(cameraIds.empty(), "Fuzz:PrepareHCameraDevice: GetCameras returns empty");
    g_cameraID = cameraIds[0];
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    std::string permissionName = OHOS_PERMISSION_CAMERA;
    int32_t ret = CheckPermission(permissionName, callingTokenId);
    CHECK_ERROR_RETURN_LOG(ret != CAMERA_OK, "Fuzz:PrepareHCameraDevice: CheckPermission Failed");
    g_HCameraDevice = new HCameraDevice(cameraHostManager, g_cameraID, callingTokenId);
}

void HCameraDeviceManagerFuzzer::HCameraDeviceManagerFuzzTest1(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto hCameraDeviceManager = HCameraDeviceManager::GetInstance();
    if (hCameraDeviceManager == nullptr) {
        MEDIA_INFO_LOG("hCameraDeviceManager is null");
        return;
    };
    InitCameraDevice();
    pid_t pid = fdp.ConsumeIntegral<int32_t>();
    hCameraDeviceManager->GetCameraHolderByPid(pid);
    hCameraDeviceManager->GetCamerasByPid(pid);
    hCameraDeviceManager->GetActiveClient();
    hCameraDeviceManager->GetActiveCameraHolders();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    hCameraDeviceManager->SetStateOfACamera(g_cameraID, state);
    hCameraDeviceManager->GetCameraStateOfASide();
    sptr<ICameraBroker> callback = nullptr;
    hCameraDeviceManager->SetPeerCallback(callback);
    hCameraDeviceManager->UnsetPeerCallback();
    std::vector<sptr<HCameraDevice>> cameraNeedEvict = {};
    int32_t type = 0;
    hCameraDeviceManager->GetConflictDevices(cameraNeedEvict, g_HCameraDevice, type);
    hCameraDeviceManager->RemoveDevice(g_cameraID);
    int32_t processState = fdp.ConsumeIntegral<int32_t>();
    hCameraDeviceManager->GenerateEachProcessCameraState(processState, fdp.ConsumeIntegral<uint32_t>());
    hCameraDeviceManager->IsMultiCameraActive(pid);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto hCameraDeviceManagerFuzzer = std::make_unique<HCameraDeviceManagerFuzzer>();
    if (hCameraDeviceManagerFuzzer == nullptr) {
        MEDIA_INFO_LOG("hCameraDeviceManagerFuzzer is null");
        return;
    }
    hCameraDeviceManagerFuzzer->HCameraDeviceManagerFuzzTest1(fdp);
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