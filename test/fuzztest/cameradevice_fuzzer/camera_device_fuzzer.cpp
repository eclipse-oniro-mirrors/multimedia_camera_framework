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

#include "camera_device_fuzzer.h"
#include "metadata_utils.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ICameraDeviceService";
const size_t LIMITCOUNT = 4;
const int32_t LIMITSIZE = 2;
bool g_isCameraDevicePermission = false;
sptr<HCameraHostManager> fuzzCameraHostManager = nullptr;
HCameraDevice *fuzzCameraDevice = nullptr;

void CameraDeviceFuzzTestGetPermission()
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

void CameraDeviceFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CameraDeviceFuzzTestGetPermission();

    int32_t itemCount = 10;
    int32_t dataSize = 100;
    int32_t *streams = reinterpret_cast<int32_t *>(rawData);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams, size / LIMITCOUNT);
    int32_t compensationRange[2] = {rawData[0], rawData[1]};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = rawData[0];
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = rawData[0];
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = rawData[0];
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));

    MessageParcel data;
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(ability, data))) {
        return;
    }
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (fuzzCameraDevice == nullptr || fuzzCameraHostManager == nullptr) {
        fuzzCameraHostManager = new(std::nothrow) HCameraHostManager(nullptr);
        fuzzCameraDevice = new(std::nothrow) HCameraDevice(fuzzCameraHostManager, "", 0);
    }
    if (fuzzCameraDevice) {
        uint32_t code = 4;
        fuzzCameraDevice->OnRemoteRequest(code, data, reply, option);
    }
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraDeviceFuzzTest(data, size);
    return 0;
}

