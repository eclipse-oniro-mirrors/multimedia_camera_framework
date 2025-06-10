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

#include "deferred_processing_service.h"
#include "deferred_video_processing_session_stub_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static const size_t MAX_BUFFER_SIZE = 32;
static constexpr int32_t NUM_4 = 4;
static constexpr int32_t MIN_SIZE_NUM = 4;
const size_t THRESHOLD = (MAX_BUFFER_SIZE + 8) * 6;

std::shared_ptr<DeferredVideoProcessingSessionStubFuzz> DeferredVideoProcessingSessionStubFuzzer::fuzz_ { nullptr };

void DeferredVideoProcessingSessionStubFuzzer::OnRemoteRequest(FuzzedDataProvider& fdp, int32_t code)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }

    fuzz_ = std::make_shared<DeferredVideoProcessingSessionStubFuzz>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInterfaceToken(DeferredVideoProcessingSessionStubFuzz::GetDescriptor());

    size_t bufferSize = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bufferSize);
    dataMessageParcel.WriteBuffer(buffer.data(), buffer.size());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    fuzz_->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void Test(uint8_t* data, size_t size)
{
    auto deferredVideoProcessingSessionStub = std::make_unique<DeferredVideoProcessingSessionStubFuzzer>();
    if (deferredVideoProcessingSessionStub == nullptr) {
        MEDIA_INFO_LOG("deferredVideoProcessingSessionStub is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    for (uint32_t i = 0; i <= MIN_TRANSACTION_ID + NUM_4; i++) {
        deferredVideoProcessingSessionStub->OnRemoteRequest(fdp, i);
    }
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