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
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
sptr<HCameraDevice> g_HCameraDevice = nullptr;
std::string g_cameraID;

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

void HCameraDeviceManagerFuzzer::HCameraDeviceManagerFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto hCameraDeviceManager = HCameraDeviceManager::GetInstance();
    if (hCameraDeviceManager == nullptr) {
        MEDIA_INFO_LOG("hCameraDeviceManager is null");
        return;
    };
    InitCameraDevice();
    pid_t pid = GetData<int32_t>();
    hCameraDeviceManager->GetCameraHolderByPid(pid);
    hCameraDeviceManager->GetCameraByPid(pid);
    hCameraDeviceManager->GetActiveClient();
    hCameraDeviceManager->GetActiveCameraHolders();
    int32_t state = GetData<int32_t>();
    hCameraDeviceManager->SetStateOfACamera(g_cameraID, state);
    hCameraDeviceManager->GetCameraStateOfASide();
    sptr<ICameraBroker> callback = nullptr;
    hCameraDeviceManager->SetPeerCallback(callback);
    hCameraDeviceManager->UnsetPeerCallback();
    sptr<HCameraDevice> cameraNeedEvict = nullptr;
    hCameraDeviceManager->GetConflictDevices(cameraNeedEvict, g_HCameraDevice);
    hCameraDeviceManager->RemoveDevice(g_cameraID);
    int32_t processState = GetData<int32_t>();
    hCameraDeviceManager->UpdateEachProcessState(processState, GetData<uint32_t>());
    hCameraDeviceManager->IsMultiCameraActive(pid);
}

void Test()
{
    auto hCameraDeviceManagerFuzzer = std::make_unique<HCameraDeviceManagerFuzzer>();
    if (hCameraDeviceManagerFuzzer == nullptr) {
        MEDIA_INFO_LOG("hCameraDeviceManagerFuzzer is null");
        return;
    }
    hCameraDeviceManagerFuzzer->HCameraDeviceManagerFuzzTest1();
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