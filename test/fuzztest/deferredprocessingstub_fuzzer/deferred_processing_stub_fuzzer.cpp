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
#include "buffer_info.h"
#include "deferred_processing_service.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
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
const int32_t LIMITSIZE = 2;
const int32_t USERID = 1;
bool g_isDeferredProcessingPermission = false;

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

void DeferredProcessingPhotoFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    DeferredProcessingFuzzTestGetPermission();

    MessageParcel data;
    data.WriteRawData(rawData, size);
    DeferredProcessingService::GetInstance().Initialize();
    sptr<IDeferredPhotoProcessingSessionCallbackFuzz> IDPSessionCallbackFuzz =
        sptr<IDeferredPhotoProcessingSessionCallbackFuzz>::MakeSptr();
    sptr<IDeferredPhotoProcessingSession> session =
        DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(USERID, IDPSessionCallbackFuzz);
    session->BeginSynchronize();
    session->EndSynchronize();
    auto imageId = data.ReadString();
    bool restorable = data.RewindRead(0);
    session->RemoveImage(imageId, restorable);
    session->RestoreImage(imageId);
    auto appName = data.ReadString();
    session->ProcessImage(appName, imageId);
    session->CancelProcessImage(imageId);
}

void DeferredProcessingVideoFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    DeferredProcessingFuzzTestGetPermission();

    MessageParcel data;
    data.WriteRawData(rawData, size);
    DeferredProcessingService::GetInstance().Initialize();
    sptr<IDeferredVideoProcessingSessionCallbackFuzz> IDPSessionCallbackFuzz =
        sptr<IDeferredVideoProcessingSessionCallbackFuzz>::MakeSptr();
    sptr<IDeferredVideoProcessingSession> session =
        DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(USERID, IDPSessionCallbackFuzz);
    session->BeginSynchronize();
    session->EndSynchronize();
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(data.ReadFileDescriptor());
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(data.ReadFileDescriptor());
    auto videoId = data.ReadString();
    session->AddVideo(videoId, srcFd, dstFd);
    bool restorable = data.RewindRead(0);
    session->RemoveVideo(videoId, restorable);
    session->RestoreVideo(videoId);
}

void TestBufferInfo(uint8_t *rawData, size_t size)
{
    CHECK_ERROR_RETURN(rawData == nullptr || size < LIMITSIZE);
    MessageParcel data;
    data.WriteRawData(rawData, size);
    const int32_t MAX_BUFF_SIZE = 1024 * 1024;
    int32_t dataSize = (data.ReadInt32() % MAX_BUFF_SIZE) + 1;
    auto sharedBuffer = make_shared<SharedBuffer>(dataSize);
    sharedBuffer->GetSize();
    sharedBuffer->GetFd();
    sharedBuffer->Initialize();
    sharedBuffer->GetSize();
    sharedBuffer->CopyFrom(rawData, size);
    sharedBuffer->GetFd();
    sharedBuffer->Reset();
    bool isHighQuality = data.ReadBool();
    bool isCloudImageEnhanceSupported = false;
    BufferInfo info(sharedBuffer, dataSize, isHighQuality, isCloudImageEnhanceSupported);
    info.GetDataSize();
    info.IsHighQuality();
    info.GetIPCFileDescriptor();
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::DeferredProcessingPhotoFuzzTest(data, size);
    OHOS::CameraStandard::TestBufferInfo(data, size);
    OHOS::CameraStandard::DeferredProcessingVideoFuzzTest(data, size);
    return 0;
}

