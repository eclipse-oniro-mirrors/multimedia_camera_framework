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

#include "deferred_video_processor_fuzzer.h"

#include <fcntl.h>

#include "camera_log.h"
#include "dp_log.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 128;
static constexpr int NUM_TWO = 2;
const size_t MAX_LENGTH_STRING = 64;
const char* TEST_FILE_PATH_1 = "/data/test/DeferredVideoProcessorFuzzTest_test_file1.mp4";
const char* TEST_FILE_PATH_2 = "/data/test/DeferredVideoProcessorFuzzTest_test_file2.mp4";
std::shared_ptr<DeferredVideoProcessor> DeferredVideoProcessorFuzzer::fuzz_{nullptr};
std::shared_ptr<VideoStrategyCenter> DeferredVideoProcessorFuzzer::center_{nullptr};

void DeferredVideoProcessorFuzzer::DeferredVideoProcessorFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    std::string videoId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    std::shared_ptr<VideoJobRepository> repository = std::make_shared<VideoJobRepository>(userId);
    DP_CHECK_ERROR_RETURN_LOG(!repository, "Create repository Error");
    repository->SetJobPending(videoId);
    repository->SetJobRunning(videoId);
    repository->SetJobCompleted(videoId);
    repository->SetJobFailed(videoId);
    repository->SetJobPause(videoId);
    repository->SetJobError(videoId);
    center_ = std::make_shared<DeferredProcessing::VideoStrategyCenter>(repository);
    DP_CHECK_ERROR_RETURN_LOG(!center_, "Create center_ Error");
    const std::shared_ptr<VideoPostProcessor> postProcessor = std::make_shared<VideoPostProcessor>(userId);
    const std::shared_ptr<IVideoProcessCallbacksFuzz> callback = std::make_shared<IVideoProcessCallbacksFuzz>();
    fuzz_ = std::make_shared<DeferredVideoProcessor>(repository, postProcessor, callback);
    int sfd = open(TEST_FILE_PATH_1, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    int dfd = open(TEST_FILE_PATH_2, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    fdsan_exchange_owner_tag(sfd, 0, LOG_DOMAIN);
    fdsan_exchange_owner_tag(dfd, 0, LOG_DOMAIN);
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(sfd);
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(dfd);
    std::shared_ptr<DeferredVideoJob> jobPtr = std::make_shared<DeferredVideoJob>(videoId, srcFd, dstFd);
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode =
        static_cast<ExecutionMode>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount1);
    std::shared_ptr<DeferredVideoWork> work =
        std::make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, fdp.ConsumeBool());
    fuzz_->Initialize();
    fuzz_->PostProcess(work);
    constexpr int32_t executionModeCount2 =
        static_cast<int32_t>(SchedulerType::NORMAL_TIME_STATE) + NUM_TWO;
    SchedulerType selectedScheduleType =
        static_cast<SchedulerType>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount2);
    constexpr int32_t executionModeCount3 =
        static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + NUM_TWO;
    DpsError selectedDpsError = static_cast<DpsError>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount3);
    constexpr int32_t executionModeCount4 =
        static_cast<int32_t>(DpsStatus::DPS_SESSION_STATE_SUSPENDED) + NUM_TWO;
    DpsStatus selectedDpsStatus = static_cast<DpsStatus>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount4);
    fuzz_->PauseRequest(selectedScheduleType);
    fuzz_->SetDefaultExecutionMode();
    fuzz_->IsFatalError(selectedDpsError);
    fuzz_->OnStateChanged(userId, selectedDpsStatus);
    fuzz_->OnError(userId, videoId, selectedDpsError);
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(fdp.ConsumeIntegral<int>());
    fuzz_->OnProcessDone(userId, videoId, ipcFd);

    remove(TEST_FILE_PATH_1);
    remove(TEST_FILE_PATH_2);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto deferredVideoProcessor = std::make_unique<DeferredVideoProcessorFuzzer>();
    if (deferredVideoProcessor == nullptr) {
        DP_INFO_LOG("deferredVideoProcessor is null");
        return;
    }
    deferredVideoProcessor->DeferredVideoProcessorFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}