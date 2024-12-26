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
HCameraRestoreParam *CameraRestoreParamFuzzer::fuzz_ = nullptr;

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

    if (fuzz_ == nullptr) {
        std::string clientName;
        std::string cameraId;
        fuzz_ = new HCameraRestoreParam(clientName, cameraId);
    }
    
    MessageParcel data;
    data.WriteRawData(rawData, size);

    data.RewindRead(0);
    int32_t opMode = data.ReadInt32();
    fuzz_->SetCameraOpMode(opMode);

    data.RewindRead(0);
    int foldStaus = data.ReadInt32();
    fuzz_->SetFoldStatus(foldStaus);

    data.RewindRead(0);
    timeval closeCameraTime = {
        data.ReadUint32(),
        data.ReadUint32(),
    };
    fuzz_->SetCloseCameraTime(closeCameraTime);

    data.RewindRead(0);
    int activeTime = data.ReadInt32();
    fuzz_->SetStartActiveTime(activeTime);

    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS;
    fuzz_->SetRestoreParamType(restoreParamType);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    fuzz_->SetSetting(settings);

    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->SetStreamInfo(streamInfos);
    
    data.RewindRead(0);
    auto obj = std::make_unique<int32_t>(data.ReadInt32());
    const void *objectId = obj.get();
    fuzz_->IncStrongRef(objectId);
    fuzz_->IncWeakRef(objectId);
    fuzz_->AttemptIncStrong(objectId);
    fuzz_->AttemptIncStrongRef(objectId);
    fuzz_->DecStrongRef(objectId);
    fuzz_->DecWeakRef(objectId);
    fuzz_->AttemptAcquire(objectId);
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