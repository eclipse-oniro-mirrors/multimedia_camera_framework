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

#include "session_coordinator_fuzzer.h"
#include "camera_log.h"
#include "deferred_processing_service.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t NUM_TRI = 13;
static constexpr int32_t MIN_SIZE_NUM = 20;
const size_t THRESHOLD = 10;
constexpr int VIDEO_REQUEST_FD_ID = 1;

std::shared_ptr<DeferredProcessing::SessionCoordinator> SessionCoordinatorFuzzer::fuzz_{nullptr};

void SessionCoordinatorFuzzer::SessionCoordinatorFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<DeferredProcessing::SessionCoordinator>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->Initialize();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    uint8_t randomNum = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string imageId(testStrings[randomNum % testStrings.size()]);
    std::shared_ptr<DeferredProcessing::BufferInfo> bufferInfo =
        std::make_shared<DeferredProcessing::BufferInfo>(nullptr, 0, true, true);
    fuzz_->imageProcCallbacks_->OnProcessDone(userId, imageId, bufferInfo);
    std::shared_ptr<DeferredProcessing::BufferInfoExt> bufferInfoExt =
        std::make_shared<DeferredProcessing::BufferInfoExt>(nullptr, 0, true, true);
    fuzz_->imageProcCallbacks_->OnProcessDoneExt(userId, imageId, bufferInfoExt);
    DeferredProcessing::DpsError dpsError =
        static_cast<DeferredProcessing::DpsError>(fdp.ConsumeIntegral<int32_t>() % NUM_TRI);
    fuzz_->imageProcCallbacks_->OnError(userId, imageId, dpsError);
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID);
    fuzz_->videoProcCallbacks_->OnProcessDone(userId, imageId, ipcFd);
    fuzz_->videoProcCallbacks_->OnError(userId, imageId, dpsError);
    std::vector<DeferredProcessing::DpsStatus> dpsStatusVec = {
        DeferredProcessing::DPS_SESSION_STATE_IDLE,
        DeferredProcessing::DPS_SESSION_STATE_RUNNALBE,
        DeferredProcessing::DPS_SESSION_STATE_RUNNING,
        DeferredProcessing::DPS_SESSION_STATE_SUSPENDED,
    };
    uint8_t arrcodeNum = randomNum % dpsStatusVec.size();
    DeferredProcessing::DpsStatus dpsStatus = dpsStatusVec[arrcodeNum];
    fuzz_->imageProcCallbacks_->OnStateChanged(userId, dpsStatus);
    fuzz_->videoProcCallbacks_->OnStateChanged(userId, dpsStatus);
    fuzz_->Start();
    fuzz_->OnStateChanged(userId, dpsStatus);
    fuzz_->OnVideoStateChanged(userId, dpsStatus);
    fuzz_->GetImageProcCallbacks();
    fuzz_->GetVideoProcCallbacks();
    fuzz_->OnProcessDone(userId, imageId, ipcFd, userId, fdp.ConsumeBool());
    fuzz_->OnProcessDoneExt(userId, imageId, nullptr, fdp.ConsumeBool());
    fuzz_->OnError(userId, imageId, dpsError);
    fuzz_->OnVideoProcessDone(userId, imageId, ipcFd);
    fuzz_->OnVideoError(userId, imageId, dpsError);
    auto videoCallback = fuzz_->GetRemoteVideoCallback(userId);
    fuzz_->ProcessVideoResults(videoCallback);
    fuzz_->DeleteVideoSession(userId);
    fuzz_->DeletePhotoSession(userId);
    fuzz_->Stop();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    auto sessionCoordinatorFuzz = std::make_unique<SessionCoordinatorFuzzer>();
    if (sessionCoordinatorFuzz == nullptr) {
        MEDIA_INFO_LOG("sessionCoordinatorFuzz is null");
        return;
    }
    sessionCoordinatorFuzz->SessionCoordinatorFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}