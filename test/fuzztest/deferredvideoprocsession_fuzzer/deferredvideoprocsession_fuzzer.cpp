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

#include "deferredvideoprocsession_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 4;
const size_t THRESHOLD = 10;
int g_userId = 0;
const size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<DeferredVideoProcessingSessionCallback> callback_ =
    std::make_shared<DeferredVideoProcessingSessionCallback>();
std::shared_ptr<IDeferredVideoProcSessionCallbackFuzz> sessionCallback_ =
    std::make_shared<IDeferredVideoProcSessionCallbackFuzz>();
std::shared_ptr<DeferredVideoProcSession> deferredVideoProcSession_ =
    std::make_shared<DeferredVideoProcSession>(g_userId, sessionCallback_);


void GetPermission()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

auto createSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback,
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_RET_LOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession object is null");
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    CHECK_ERROR_RETURN_RET_LOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession serviceProxy is null");

    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback =
        new(std::nothrow) DeferredVideoProcessingSessionCallback();
    CHECK_ERROR_RETURN_RET_LOG(remoteCallback == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession failed to new remoteCallback!");
    serviceProxy->CreateDeferredVideoProcessingSession(userId, remoteCallback, session);
    return CameraErrorCode::SUCCESS;
}

void DeferredVideoProcSessionFuzzer::DeferredVideoProcSessionFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    GetPermission();

    std::string videoId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    sptr<IPCFileDescriptor> ipcFileDescriptor = nullptr;
    callback_->OnProcessVideoDone(videoId, ipcFileDescriptor);
    callback_->OnError(videoId, DpsErrorCode::ERROR_SESSION_SYNC_NEEDED);
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    callback_->OnStateChanged(status);

    deferredVideoProcSession_->BeginSynchronize();
    deferredVideoProcSession_->EndSynchronize();
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(fdp.ConsumeIntegral<int>());
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(fdp.ConsumeIntegral<int>());
    deferredVideoProcSession_->AddVideo(videoId, srcFd, dstFd);
    bool restorable = fdp.ConsumeIntegral<bool>();
    deferredVideoProcSession_->RemoveVideo(videoId, restorable);
    deferredVideoProcSession_->RestoreVideo(videoId);
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    createSession(g_userId, sessionCallback_, session);
    CHECK_ERROR_RETURN_LOG(session == nullptr, "session is null!");
    deferredVideoProcSession_->SetDeferredVideoSession(session);
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    deferredVideoProcSession_->ReconnectDeferredProcessingSession();
    deferredVideoProcSession_->ConnectDeferredProcessingSession();
    deferredVideoProcSession_->GetCallback();
    deferredVideoProcSession_->remoteSession_ = nullptr;
    deferredVideoProcSession_->callback_ = nullptr;
    deferredVideoProcSession_->CameraServerDied(pid);
}

void Test(uint8_t* data, size_t size)
{
    auto deferredVideoProcSessionFuzz = std::make_unique<DeferredVideoProcSessionFuzzer>();
    if (deferredVideoProcSessionFuzz == nullptr) {
        MEDIA_INFO_LOG("deferredVideoProcSessionFuzz is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    deferredVideoProcSessionFuzz->DeferredVideoProcSessionFuzzTest(fdp);
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