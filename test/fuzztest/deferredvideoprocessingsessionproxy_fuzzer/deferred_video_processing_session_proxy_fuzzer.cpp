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

#include "deferred_video_processing_session_proxy_fuzzer.h"
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
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 64;
const size_t THRESHOLD = 10;
const size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<DeferredVideoProcessingSessionProxy>
    DeferredVideoProcessingSessionProxyFuzzer::fuzz_{nullptr};

void DeferredVideoProcessingSessionProxyFuzzer::DeferredVideoProcessingSessionProxyFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }

    sptr<IRemoteObject> object;
    fuzz_ = std::make_shared<DeferredVideoProcessingSessionProxy>(object);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->BeginSynchronize();
    fuzz_->EndSynchronize();
    std::string videoId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(fdp.ConsumeIntegral<int>());
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(fdp.ConsumeIntegral<int>());
    fuzz_->AddVideo(videoId, srcFd, dstFd);
    fuzz_->RemoveVideo(videoId, fdp.ConsumeBool());
    fuzz_->RestoreVideo(videoId);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto deferredVideoProcessingSessionProxy = std::make_unique<DeferredVideoProcessingSessionProxyFuzzer>();
    if (deferredVideoProcessingSessionProxy == nullptr) {
        MEDIA_INFO_LOG("deferredVideoProcessingSessionProxy is null");
        return;
    }
    deferredVideoProcessingSessionProxy->DeferredVideoProcessingSessionProxyFuzzTest(fdp);
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