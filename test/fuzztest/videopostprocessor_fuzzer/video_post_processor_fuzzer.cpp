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
#include "mpeg_manager.h"
#include "securec.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;
std::shared_ptr<VideoPostProcessor> VideoPostProcessorFuzzer::processor_{nullptr};
static constexpr int32_t MAX_CODE_LEN  = 1000;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const char* TEST_FILE_SRC_PATH = "/data/test/VideoPostProcessorFuzzTest_test_file.mp4";
const char* TEST_FILE_PATH_1 = "/data/test/VideoPostProcessorFuzzTest_test_file1.mp4";
const char* TEST_FILE_PATH_2 = "/data/test/VideoPostProcessorFuzzTest_test_file2.mp4";

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
        DP_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest1()
{
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode =
        static_cast<ExecutionMode>(GetData<uint8_t>() % executionModeCount1);
    processor_->SetExecutionMode(selectedExecutionMode);
    processor_->SetDefaultExecutionMode();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto isAutoSuspend = GetData<bool>();
    int sfd = open(TEST_FILE_SRC_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(sfd);
    int temp1Fd = open(TEST_FILE_PATH_1, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    int temp2Fd = open(TEST_FILE_PATH_2, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    std::string srcPath(TEST_FILE_SRC_PATH);
    std::string temp1Path(TEST_FILE_PATH_1);
    std::string temp2Path(TEST_FILE_PATH_2);
    auto info = std::make_unique<VideoInfo>(srcPath, temp1Path, temp2Path, "");
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, std::move(info));
    jobPtr->SetExecutionMode(selectedExecutionMode);
    jobPtr->SetChargState(isAutoSuspend);
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    DeferredProcessing::TempVideoPath tempinfo;
    tempinfo.temp1Path = TEST_FILE_PATH_1;
    tempinfo.temp2Path = TEST_FILE_PATH_2;
    mediaManagerProxy->MpegAcquire(videoId, tempinfo, inputFd, 1920, 1080);
    processor_->ProcessRequest(videoId, {}, mediaManagerProxy);
    processor_->RemoveRequest(videoId);
    constexpr int32_t executionModeCount2 = static_cast<int32_t>(SchedulerType::NORMAL_TIME_STATE) + 2;
    SchedulerType selectedSchedulerType = static_cast<SchedulerType>(GetData<uint8_t>() % executionModeCount2);
    constexpr int32_t executionModeCount3 = static_cast<int32_t>(HdiStatus::HDI_NOT_READY_TEMPORARILY) + 1;
    HdiStatus selectedHdiStatus = static_cast<HdiStatus>(GetData<uint8_t>() % executionModeCount3);
    processor_->PauseRequest(videoId, selectedSchedulerType);
    processor_->OnSessionDied();
    processor_->OnStateChanged(selectedHdiStatus);

    if (temp1Fd >= 0) {
        close(temp1Fd);
    }
    if (temp2Fd >= 0) {
        close(temp2Fd);
    }
    remove(TEST_FILE_SRC_PATH);
    remove(TEST_FILE_PATH_1);
    remove(TEST_FILE_PATH_2);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest2()
{
    std::vector<std::string> pendingVideos;
    processor_->GetPendingVideos(pendingVideos);
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    std::string srcPath(TEST_FILE_SRC_PATH);
    std::string temp1Path(TEST_FILE_PATH_1);
    std::string temp2Path(TEST_FILE_PATH_2);
    auto info = std::make_unique<VideoInfo>(srcPath, temp1Path, temp2Path, "");
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, std::move(info));
    processor_->PrepareStreams(jobPtr);
    StreamDescription stream;
    sptr<BufferProducerSequenceable> producer;
    processor_->SetStreamInfo(stream, producer);
}

void VideoPostProcessorFuzzer::VideoPostProcessorFuzzTest3()
{
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);

    // 1. ProcessRequest with null mediaManagerIntf -> cover mediaManagerIntf==nullptr branch
    processor_->ProcessRequest(videoId, {}, nullptr);

    // 2. GetIntent with fuzzed MediaStreamType -> cover MAKER/VIDEO/default switch branches
    const HDI::Camera::V1_3::MediaStreamType streamTypes[] = {
        HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
        HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA,
    };
    constexpr size_t typeCount = sizeof(streamTypes) / sizeof(streamTypes[0]);
    uint8_t typeIdx1 = GetData<uint8_t>();
    auto streamIntent = processor_->GetIntent(streamTypes[typeIdx1 % typeCount]);
    (void)streamIntent;

    // 3. ProcessStream directly -> cover type switch + surface acquisition + null surface branch
    //    (a) null mediaManagerIntf -> cover mediaManagerIntf==nullptr return path
    StreamDescription stream{};
    stream.streamId = GetData<int32_t>();
    uint8_t typeIdx2 = GetData<uint8_t>();
    stream.type = streamTypes[typeIdx2 % typeCount];
    stream.width = GetData<uint32_t>();
    stream.height = GetData<uint32_t>();
    processor_->ProcessStream(stream, nullptr);
    //    (b) real mediaManagerIntf -> cover stream.type switch + MpegGetSurface/MpegGetMakerSurface
    auto mediaManagerProxy = MediaManagerProxy::CreateMediaManagerProxy();
    processor_->ProcessStream(stream, mediaManagerProxy);

    // 4. SetStreamInfo with streamInfo_ set -> cover body + GetIntent branches
    //    (streamInfo_ stays null after early-return paths, set it directly to reach the body)
    processor_->streamInfo_ = std::make_unique<VideoStreamInfo>(videoId);
    StreamDescription stream2{};
    stream2.streamId = GetData<int32_t>();
    uint8_t typeIdx3 = GetData<uint8_t>();
    stream2.type = streamTypes[typeIdx3 % typeCount];
    sptr<BufferProducerSequenceable> producer;
    processor_->SetStreamInfo(stream2, producer);

    // 5. ReleaseStreams with fuzzed videoId -> cover videoId match/mismatch + session null branch
    uint8_t releaseIdx = GetData<uint8_t>();
    std::string releaseId(testStrings[releaseIdx % testStrings.size()]);
    processor_->ReleaseStreams(releaseId);
}

void Test()
{
    auto videoPostProcessor = std::make_unique<VideoPostProcessorFuzzer>();
    if (videoPostProcessor == nullptr) {
        DP_INFO_LOG("videoPostProcessor is null");
        return;
    }
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t userId = GetData<int32_t>();
    VideoPostProcessorFuzzer::processor_ = VideoPostProcessor::Create(userId);
    if (VideoPostProcessorFuzzer::processor_ == nullptr) {
        return;
    }
    videoPostProcessor->VideoPostProcessorFuzzTest1();
    videoPostProcessor->VideoPostProcessorFuzzTest2();
    videoPostProcessor->VideoPostProcessorFuzzTest3();
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
        DP_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
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