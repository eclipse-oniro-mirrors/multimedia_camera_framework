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

#include "camera_restore_param_fuzzer.h"
#include "hcamera_restore_param.h"
#include "hstream_capture.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"

namespace {

const int32_t LIMITSIZE = 20;

}

namespace OHOS {
namespace CameraStandard {

bool CameraRestoreParamFuzzer::hasPermission = false;
HCameraRestoreParam *CameraRestoreParamFuzzer::fuzz = nullptr;

void CameraRestoreParamFuzzer::CheckPermission()
{
    if (!hasPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        hasPermission = true;
    }
}

void CameraRestoreParamFuzzer::Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CheckPermission();

    if (fuzz == nullptr) {
        std::string clientName;
        std::string cameraId;
        fuzz = new HCameraRestoreParam(clientName, cameraId);
    }
    
    MessageParcel data;
    data.WriteRawData(rawData, size);

    data.RewindRead(0);
    int32_t opMode = data.ReadInt32();
    fuzz->SetCameraOpMode(opMode);

    data.RewindRead(0);
    int foldStaus = data.ReadInt32();
    fuzz->SetFoldStatus(foldStaus);

    data.RewindRead(0);
    timeval closeCameraTime = {
        data.ReadUint32(),
        data.ReadUint32(),
    };
    fuzz->SetCloseCameraTime(closeCameraTime);

    data.RewindRead(0);
    int activeTime = data.ReadInt32();
    fuzz->SetStartActiveTime(activeTime);

    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS;
    fuzz->SetRestoreParamType(restoreParamType);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    fuzz->SetSetting(settings);

    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz->SetStreamInfo(streamInfos);
    
    data.RewindRead(0);
    const void *objectId = data.ReadBuffer(1);
    fuzz->IncStrongRef(objectId);
    fuzz->IncWeakRef(objectId);
    fuzz->AttemptIncStrong(objectId);
    fuzz->AttemptIncStrongRef(objectId);
    fuzz->DecStrongRef(objectId);
    fuzz->DecWeakRef(objectId);
    fuzz->AttemptAcquire(objectId);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraRestoreParamFuzzer::Test(data, size);
    return 0;
}