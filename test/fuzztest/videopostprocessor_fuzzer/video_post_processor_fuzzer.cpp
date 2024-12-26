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
VideoPostProcessor *VideoPostProcessorFuzzer::processor = nullptr;
DeferredVideoWork *VideoPostProcessorFuzzer::work = nullptr;
VideoPostProcessor::VideoProcessListener *VideoPostProcessorFuzzer::listener = nullptr;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
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
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t userId = GetData<int32_t>();
    processor = new VideoPostProcessor(userId);
    if (processor == nullptr) {
        return;
    }
    constexpr int32_t EXECUTION_MODE_COUNT1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(GetData<uint8_t>() % EXECUTION_MODE_COUNT1);
    processor->SetExecutionMode(selectedExecutionMode);
    processor->SetDefaultExecutionMode();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = GetData<int>();
    auto dstFd = GetData<int>();
    processor->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = GetData<bool>();
    std::string videoId_(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    sptr<IPCFileDescriptor> dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId_, srcFd_, dstFd_);
    std::shared_ptr<DeferredVideoWork> work =
        make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, isAutoSuspend);
    processor->StartTimer(videoId, work);
    processor->StopTimer(work);
    processor->ProcessRequest(work);
    processor->RemoveRequest(videoId);
    constexpr int32_t EXECUTION_MODE_COUNT2 = static_cast<int32_t>(ScheduleType::NORMAL_TIME_STATE) + 2;
    ScheduleType selectedScheduleType = static_cast<ScheduleType>(GetData<uint8_t>() % EXECUTION_MODE_COUNT2);
    constexpr int32_t EXECUTION_MODE_COUNT3 = static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + 2;
    DpsError selectedDpsError = static_cast<DpsError>(GetData<uint8_t>() % EXECUTION_MODE_COUNT3);
    constexpr int32_t EXECUTION_MODE_COUNT4 = static_cast<int32_t>(MediaResult::PAUSE) + 2;
    MediaResult selectedMediaResult = static_cast<MediaResult>(GetData<uint8_t>() % EXECUTION_MODE_COUNT4);
    constexpr int32_t EXECUTION_MODE_COUNT5 = static_cast<int32_t>(HdiStatus::HDI_NOT_READY_TEMPORARILY) + 1;
    HdiStatus selectedHdiStatus = static_cast<HdiStatus>(GetData<uint8_t>() % EXECUTION_MODE_COUNT5);
    processor->PauseRequest(videoId, selectedScheduleType);
    sptr<IPCFileDescriptor> inputFd_ = nullptr;
    processor->StartMpeg(videoId, inputFd_);
    processor->StopMpeg(selectedMediaResult, work);
    processor->OnSessionDied();
    processor->OnProcessDone(videoId);
    processor->OnError(videoId, selectedDpsError);
    processor->OnStateChanged(selectedHdiStatus);
    processor->OnTimerOut(videoId);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t userId = GetData<int32_t>();
    processor = new VideoPostProcessor(userId);
    if (processor == nullptr) {
        return;
    }
    std::vector<std::string> pendingVideos;
    processor->GetPendingVideos(pendingVideos);
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = GetData<int>();
    processor->PrepareStreams(videoId, inputFd);
    StreamDescription stream;
    sptr<BufferProducerSequenceable> producer;
    processor->SetStreamInfo(stream, producer);
    processor->GetRunningWork(videoId);
}

void Test()
{
    auto videoPostProcessor = std::make_unique<VideoPostProcessorFuzzer>();
    if (videoPostProcessor == nullptr) {
        MEDIA_INFO_LOG("videoPostProcessor is null");
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