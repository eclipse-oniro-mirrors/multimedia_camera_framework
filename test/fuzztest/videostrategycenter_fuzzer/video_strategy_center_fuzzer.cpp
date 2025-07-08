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

#include "video_strategy_center_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
std::shared_ptr<VideoStrategyCenter> VideoStrategyCenterFuzzer::fuzz_ { nullptr };
const size_t MAX_LENGTH_STRING = 64;
const size_t THRESHOLD = MAX_LENGTH_STRING + 24;

void VideoStrategyCenterFuzzer::VideoStrategyCenterFuzzTest(FuzzedDataProvider& fdp)
{
    auto userId = fdp.ConsumeIntegral<int32_t>();
    auto repository = std::make_shared<VideoJobRepository>(userId);
    CHECK_RETURN_ELOG(!repository, "Create repository Error");
    std::string videoId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    repository->SetJobPending(videoId);
    repository->SetJobRunning(videoId);
    repository->SetJobCompleted(videoId);
    repository->SetJobFailed(videoId);
    repository->SetJobPause(videoId);
    repository->SetJobError(videoId);

    fuzz_ = std::make_shared<DeferredProcessing::VideoStrategyCenter>(repository);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetWork();
    fuzz_->GetJob();
    fuzz_->GetExecutionMode();
    {
        auto value = fdp.ConsumeIntegral<int32_t>();
        fuzz_->HandleCameraEvent(value);
    }
    {
        auto value = fdp.ConsumeIntegral<int32_t>();
        fuzz_->HandleMedialLibraryEvent(value);
    }
    {
        auto value = fdp.ConsumeIntegral<int32_t>();
        fuzz_->HandleScreenEvent(value);
    }
    {
        auto value = fdp.ConsumeIntegral<int32_t>();
        fuzz_->HandleChargingEvent(value);
    }
    {
        auto value = fdp.ConsumeIntegral<int32_t>();
        fuzz_->HandleBatteryEvent(value);
    }
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto VideoStrategyCenter = std::make_unique<VideoStrategyCenterFuzzer>();
    if (VideoStrategyCenter == nullptr) {
        MEDIA_INFO_LOG("VideoStrategyCenter is null");
        return;
    }
    VideoStrategyCenter->VideoStrategyCenterFuzzTest(fdp);
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