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
#include "buffer_info.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "ipc_file_descriptor.h"
#include "securec.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;
std::shared_ptr<VideoPostProcessor> VideoPostProcessorFuzzer::processor_{nullptr};
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int NUM_1 = 1;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest1()
{
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(GetData<uint8_t>() % executionModeCount1);
    processor_->SetExecutionMode(selectedExecutionMode);
    processor_->SetDefaultExecutionMode();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = NUM_1;
    auto dstFd = NUM_1;
    processor_->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = GetData<bool>();
    std::string videoId1(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> srcFd1 = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    sptr<IPCFileDescriptor> dstFd1 = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId1, srcFd1, dstFd1);
    std::shared_ptr<DeferredVideoWork> work =
        make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, isAutoSuspend);
    processor_->StartTimer(videoId, work);
    processor_->StopTimer(work);
    processor_->ProcessRequest(work);
    processor_->RemoveRequest(videoId);
    constexpr int32_t executionModeCount2 = static_cast<int32_t>(ScheduleType::NORMAL_TIME_STATE) + 2;
    ScheduleType selectedScheduleType = static_cast<ScheduleType>(GetData<uint8_t>() % executionModeCount2);
    constexpr int32_t executionModeCount3 = static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + 2;
    DpsError selectedDpsError = static_cast<DpsError>(GetData<uint8_t>() % executionModeCount3);
    constexpr int32_t executionModeCount4 = static_cast<int32_t>(MediaResult::PAUSE) + 2;
    MediaResult selectedMediaResult = static_cast<MediaResult>(GetData<uint8_t>() % executionModeCount4);
    constexpr int32_t executionModeCount5 = static_cast<int32_t>(HdiStatus::HDI_NOT_READY_TEMPORARILY) + 1;
    HdiStatus selectedHdiStatus = static_cast<HdiStatus>(GetData<uint8_t>() % executionModeCount5);
    processor_->PauseRequest(videoId, selectedScheduleType);
    sptr<IPCFileDescriptor> inputFd = nullptr;
    processor_->StartMpeg(videoId, inputFd);
    processor_->StopMpeg(selectedMediaResult, work);
    processor_->OnSessionDied();
    processor_->OnProcessDone(videoId, nullptr);
    processor_->OnError(videoId, selectedDpsError);
    processor_->OnStateChanged(selectedHdiStatus);
    processor_->OnTimerOut(videoId);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest2()
{
    std::vector<std::string> pendingVideos;
    processor_->GetPendingVideos(pendingVideos);
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = GetData<int>();
    processor_->PrepareStreams(videoId, inputFd);
    StreamDescription stream;
    sptr<BufferProducerSequenceable> producer;
    processor_->SetStreamInfo(stream, producer);
    processor_->GetRunningWork(videoId);
}

void Test()
{
    auto videoPostProcessor = std::make_unique<VideoPostProcessorFuzzer>();
    if (videoPostProcessor == nullptr) {
        MEDIA_INFO_LOG("videoPostProcessor is null");
        return;
    }
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t userId = GetData<int32_t>();
    VideoPostProcessorFuzzer::processor_ = std::make_shared<VideoPostProcessor>(userId);
    if (VideoPostProcessorFuzzer::processor_ == nullptr) {
        return;
    }
    videoPostProcessor->VideoPostProcessorFuzzTest1();
    videoPostProcessor->VideoPostProcessorFuzzTest2();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}