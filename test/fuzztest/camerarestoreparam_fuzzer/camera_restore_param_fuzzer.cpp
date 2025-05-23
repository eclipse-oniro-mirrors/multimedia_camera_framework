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

const int32_t LIMITSIZE = 24;

}

namespace OHOS {
namespace CameraStandard {

bool CameraRestoreParamFuzzer::hasPermission = false;
std::shared_ptr<HCameraRestoreParam> CameraRestoreParamFuzzer::fuzz_{nullptr};

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

void CameraRestoreParamFuzzer::Test(uint8_t* data, size_t size)
{
    if (fdp.remaining_bytes() < LIMITSIZE) {
        return;
    }
    CheckPermission();

    std::string clientName;
    std::string cameraId;
    fuzz_ = std::make_shared<HCameraRestoreParam>(clientName, cameraId);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");

    int32_t opMode = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetCameraOpMode(opMode);

    int foldStaus = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetFoldStatus(foldStaus);

    timeval closeCameraTime = {
        fdp.ConsumeIntegral<uint32_t>(),
        fdp.ConsumeIntegral<uint32_t>(),
    };
    fuzz_->SetCloseCameraTime(closeCameraTime);

    int activeTime = fdp.ConsumeIntegral<int32_t>();
    fuzz_->SetStartActiveTime(activeTime);

    RestoreParamTypeOhos restoreParamType = RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS;
    fuzz_->SetRestoreParamType(restoreParamType);

    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    fuzz_->SetSetting(settings);

    std::vector<StreamInfo_V1_1> streamInfos;
    fuzz_->SetStreamInfo(streamInfos);
    
    auto obj = std::make_unique<int32_t>(fdp.ConsumeIntegral<int32_t>());
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
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraRestoreParamFuzzer::Test(data, size);
    return 0;
}