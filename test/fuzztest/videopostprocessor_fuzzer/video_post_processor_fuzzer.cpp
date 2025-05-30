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

#include "video_post_processor_fuzzer.h"
#include <fcntl.h>
#include "dp_log.h"
#include "ipc_file_descriptor.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "v1_3/types.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;
std::shared_ptr<VideoPostProcessor> VideoPostProcessorFuzzer::processor_{nullptr};
static constexpr int32_t MIN_SIZE_NUM = 460;
constexpr int VIDEO_REQUEST_FD_ID = 1;
const char* TEST_FILE_PATH_1 = "/data/test/VideoPostProcessorFuzzTest_test_file1.mp4";
const char* TEST_FILE_PATH_2 = "/data/test/VideoPostProcessorFuzzTest_test_file2.mp4";

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest1(FuzzedDataProvider& fdp)
{
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount1);
    processor_->SetExecutionMode(selectedExecutionMode);
    processor_->SetDefaultExecutionMode();
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::string> testStrings = {fdp.ConsumeRandomLengthString(100), fdp.ConsumeRandomLengthString(100)};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = fdp.ConsumeIntegral<uint8_t>();
    auto dstFd = fdp.ConsumeIntegral<uint8_t>();
    processor_->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = fdp.ConsumeBool();
    std::string videoId1(testStrings[randomNum % testStrings.size()]);
    int sfd = open(TEST_FILE_PATH_1, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    int dfd = open(TEST_FILE_PATH_2, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    fdsan_exchange_owner_tag(sfd, 0, LOG_DOMAIN);
    fdsan_exchange_owner_tag(dfd, 0, LOG_DOMAIN);
    sptr<IPCFileDescriptor> srcFd1 = sptr<IPCFileDescriptor>::MakeSptr(sfd);
    sptr<IPCFileDescriptor> dstFd1 = sptr<IPCFileDescriptor>::MakeSptr(dfd);
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId1, srcFd1, dstFd1);
    std::shared_ptr<DeferredVideoWork> work =
        make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, isAutoSuspend);
    processor_->StartTimer(videoId, work);
    processor_->StopTimer(work);
    processor_->ProcessRequest(work);
    processor_->RemoveRequest(videoId);
    constexpr int32_t executionModeCount2 = static_cast<int32_t>(SchedulerType::NORMAL_TIME_STATE) + 2;
    SchedulerType selectedSchedulerType = static_cast<SchedulerType>(fdp.ConsumeIntegral<uint8_t>() %
        executionModeCount2);
    constexpr int32_t executionModeCount3 = static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + 2;
    DpsError selectedDpsError = static_cast<DpsError>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount3);
    constexpr int32_t executionModeCount4 = static_cast<int32_t>(MediaResult::PAUSE) + 2;
    MediaResult selectedMediaResult = static_cast<MediaResult>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount4);
    constexpr int32_t executionModeCount5 = static_cast<int32_t>(HdiStatus::HDI_NOT_READY_TEMPORARILY) + 1;
    HdiStatus selectedHdiStatus = static_cast<HdiStatus>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount5);
    processor_->PauseRequest(videoId, selectedSchedulerType);
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID);
    processor_->StartMpeg(videoId, inputFd);
    processor_->StopMpeg(selectedMediaResult, work);
    processor_->OnSessionDied();
    processor_->OnProcessDone(videoId, nullptr);
    processor_->OnError(videoId, selectedDpsError);
    processor_->OnStateChanged(selectedHdiStatus);
    processor_->OnTimerOut(videoId);

    remove(TEST_FILE_PATH_1);
    remove(TEST_FILE_PATH_2);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest2(FuzzedDataProvider& fdp)
{
    std::vector<std::string> pendingVideos;
    processor_->GetPendingVideos(pendingVideos);
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::string> testStrings = {fdp.ConsumeRandomLengthString(100), fdp.ConsumeRandomLengthString(100)};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = fdp.ConsumeIntegral<int>();
    processor_->PrepareStreams(videoId, inputFd);
    StreamDescription stream;
    stream.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO;
    sptr<BufferProducerSequenceable> producer;
    processor_->SetStreamInfo(stream, producer);
    processor_->GetRunningWork(videoId);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
         return;
    }
    auto videoPostProcessor = std::make_unique<VideoPostProcessorFuzzer>();
    if (videoPostProcessor == nullptr) {
        DP_INFO_LOG("videoPostProcessor is null");
        return;
    }
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    VideoPostProcessorFuzzer::processor_ = std::make_shared<VideoPostProcessor>(userId);
    if (VideoPostProcessorFuzzer::processor_ == nullptr) {
        return;
    }
    videoPostProcessor->VideoPostProcessorFuzzTest1(fdp);
    videoPostProcessor->VideoPostProcessorFuzzTest2(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}