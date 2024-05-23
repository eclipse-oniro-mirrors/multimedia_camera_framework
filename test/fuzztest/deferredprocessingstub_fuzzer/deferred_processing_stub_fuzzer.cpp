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

#include "deferred_processing_stub_fuzzer.h"
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
using namespace OHOS::CameraStandard::DeferredProcessing;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IDeferredPhotoProcessingSession";
const size_t LIMITCOUNT = 4;
const int32_t LIMITSIZE = 2;
const int USERID = 1;
bool g_isDeferredProcessingPermission = false;
DeferredPhotoProcessingSession *fuzz = nullptr;

int32_t IDeferredPhotoProcessingSessionCallbackFuzz::OnProcessImageDone(
    const std::string &imageId, sptr<IPCFileDescriptor> ipcFd, const long bytes)
{
    return 0;
}

int32_t IDeferredPhotoProcessingSessionCallbackFuzz::OnError(const std::string &imageId, const ErrorCode errorCode)
{
    return 0;
}

int32_t IDeferredPhotoProcessingSessionCallbackFuzz::OnStateChanged(const StatusCode status)
{
    return 0;
}

void DeferredProcessingFuzzTestGetPermission()
{
    if (!g_isDeferredProcessingPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        g_isDeferredProcessingPermission = true;
    }
}

void DeferredProcessingFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    DeferredProcessingFuzzTestGetPermission();

    int32_t itemCount = 0;
    int32_t dataSize = 0;
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

    sptr<IDeferredPhotoProcessingSessionCallbackFuzz> IDPSessionCallbackFuzz = nullptr;

    if (fuzz == nullptr) {
        fuzz = new DeferredPhotoProcessingSession(USERID, nullptr, nullptr, IDPSessionCallbackFuzz);
    }

    if (fuzz != nullptr) {
        const int maxNum = 7;
        for (uint32_t code = 0; code < maxNum; ++code) {
            fuzz->OnRemoteRequest(code, data, reply, option);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::DeferredProcessingFuzzTest(data, size);
    return 0;
}
