/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_input_fuzzer.h"
#include "camera_input.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraInputFuzzer {
const int32_t LIMITSIZE = 4;
const int32_t CAM_NUM = 2;
bool g_isCameraDevicePermission = false;

void GetPermission()
{
    if (!g_isCameraDevicePermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        g_isCameraDevicePermission = true;
    }
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    GetPermission();
    auto manager = CameraManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    auto cameras = manager->GetSupportedCameras();
    if (cameras.size() < CAM_NUM) {
        return;
    }
    MessageParcel data;
    data.WriteRawData(rawData, size);
    auto camera = cameras[data.ReadUint32() % CAM_NUM];
    if (camera == nullptr) {
        return;
    }
    auto input = manager->CreateCameraInput(camera);
    if (input == nullptr) {
        return;
    }
    TestInput(input, rawData, size);
}

void TestInput(sptr<CameraInput> input, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    input->Open();
    input->SetErrorCallback(make_shared<ErrorCallbackMock>());
    input->SetResultCallback(make_shared<ResultCallbackMock>());
    input->GetCameraId();
    input->GetCameraDevice();
    input->GetErrorCallback();
    input->GetResultCallback();
    shared_ptr<OHOS::Camera::CameraMetadata> result;
    data.RewindRead(0);
    input->ProcessCallbackUpdates(data.ReadUint64(), result);
    input->GetCameraSettings();
    data.RewindRead(0);
    input->SetCameraSettings(data.ReadString());
    data.RewindRead(0);
    input->GetMetaSetting(data.ReadUint32());
    std::vector<vendorTag_t> infos;
    input->GetCameraAllVendorTags(infos);
    input->Close();
    input->Release();
    uint64_t secureSeqId;
    data.RewindRead(0);
    input->Open(data.ReadBool(), &secureSeqId);
    input->Release();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraInputFuzzer::Test(data, size);
    return 0;
}