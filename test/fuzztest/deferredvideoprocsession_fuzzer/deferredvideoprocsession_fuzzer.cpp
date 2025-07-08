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

#include <cstddef>
#include <cstdint>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "deferredvideoprocsession_fuzzer.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "test_token.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 128;
int g_userId = 0;
const size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<DeferredVideoProcessingSessionCallback> callback_ =
    std::make_shared<DeferredVideoProcessingSessionCallback>();
std::shared_ptr<IDeferredVideoProcSessionCallbackFuzz> sessionCallback_ =
    std::make_shared<IDeferredVideoProcSessionCallbackFuzz>();
std::shared_ptr<DeferredVideoProcSession> deferredVideoProcSession_ =
    std::make_shared<DeferredVideoProcSession>(g_userId, sessionCallback_);

auto createSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback,
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession object is null");
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    CHECK_RETURN_RET_ELOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession serviceProxy is null");

    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback =
        new(std::nothrow) DeferredVideoProcessingSessionCallback();
    CHECK_RETURN_RET_ELOG(remoteCallback == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession failed to new remoteCallback!");
    serviceProxy->CreateDeferredVideoProcessingSession(userId, remoteCallback, session);
    return CameraErrorCode::SUCCESS;
}

void DeferredVideoProcSessionFuzzer::DeferredVideoProcSessionFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
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
    bool restorable = fdp.ConsumeBool();
    deferredVideoProcSession_->RemoveVideo(videoId, restorable);
    deferredVideoProcSession_->RestoreVideo(videoId);
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    createSession(g_userId, sessionCallback_, session);
    CHECK_RETURN_ELOG(session == nullptr, "session is null!");
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
    OHOS::CameraStandard::Test(data, size);
    return 0;
}