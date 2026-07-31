/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "photo_post_processor_fuzzer.h"

#include "dp_log.h"
#include "securec.h"
#include <string>
#include <vector>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
const size_t THRESHOLD = 10;
static constexpr int32_t MAX_STR_LEN = 64;

void PhotoPostProcessorFuzzer::PhotoPostProcessorFuzzTest(FuzzedDataProvider& fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    auto processor = PhotoPostProcessor::Create(userId);
    if (processor == nullptr) {
        DP_INFO_LOG("PhotoPostProcessor create failed");
        return;
    }

    sptr<IImageProcessSession> nullSession;
    processor->RemoveNeedJbo(nullSession);

    constexpr int32_t executionModeCount = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode mode = static_cast<ExecutionMode>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    processor->GetConcurrency(mode);
    processor->SetExecutionMode(mode);
    processor->SetDefaultExecutionMode();

    std::vector<std::string> pendingImages;
    processor->GetPendingImages(pendingImages);

    std::string imageId = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    processor->ProcessImage(imageId);
    processor->RemoveImage(imageId);

    processor->Interrupt();
    processor->Reset();

    constexpr int32_t hdiStatusCount = static_cast<int32_t>(HdiStatus::HDI_NOT_READY_TEMPORARILY) + 1;
    HdiStatus hdiStatus = static_cast<HdiStatus>(fdp.ConsumeIntegral<uint8_t>() % hdiStatusCount);
    processor->NotifyHalStateChanged(hdiStatus);

    processor->OnSessionDied();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    PhotoPostProcessorFuzzer::PhotoPostProcessorFuzzTest(fdp);
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
