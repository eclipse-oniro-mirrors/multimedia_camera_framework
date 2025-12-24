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

#include "deferred_video_controller_fuzzer.h"

#include <fcntl.h>

#include "dp_log.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const char* TEST_FILE_PATH_1 = "/data/test/DeferredVideoControllerFuzzTest_test_file1.mp4";
const char* TEST_FILE_PATH_2 = "/data/test/DeferredVideoControllerFuzzTest_test_file2.mp4";

std::shared_ptr<DeferredVideoController> DeferredVideoControllerFuzzer::fuzz_{nullptr};
std::shared_ptr<VideoStrategyCenter> DeferredVideoControllerFuzzer::center_{nullptr};

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

void DeferredVideoControllerFuzzer::DeferredVideoControllerFuzzTest()
{
    int32_t userId = GetData<int32_t>();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto repository = VideoJobRepository::Create(userId);
    DP_CHECK_ERROR_RETURN_LOG(!repository, "Create repository Error");
    repository->SetJobPending(videoId);
    repository->SetJobRunning(videoId);
    repository->SetJobCompleted(videoId);
    repository->SetJobFailed(videoId);
    repository->SetJobPause(videoId);
    repository->SetJobError(videoId);
    center_ = VideoStrategyCenter::Create(repository);
    DP_CHECK_ERROR_RETURN_LOG(!center_, "Create center_ Error");
    const std::shared_ptr<VideoPostProcessor> postProcessor =
        VideoPostProcessor::Create(userId);
    std::shared_ptr<DeferredVideoProcessor> processor =
        DeferredVideoProcessor::Create(userId, repository, postProcessor);
    fuzz_ = DeferredVideoController::Create(userId, processor);
    DP_CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    int sfd = open(TEST_FILE_PATH_1, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    int dfd = open(TEST_FILE_PATH_2, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(sfd);
    DpsFdPtr outFd = std::make_shared<DpsFd>(dfd);
    std::shared_ptr<DeferredVideoJob> jobPtr =
        std::make_shared<DeferredVideoJob>(videoId, inputFd, outFd, nullptr, nullptr);
    fuzz_->Initialize();
    fuzz_->OnVideoJobChanged();
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(GetData<uint8_t>() % executionModeCount1);
    constexpr int32_t executionModeCount2 = static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + 1;
    DpsError selectedDpsError = static_cast<DpsError>(GetData<uint8_t>() % executionModeCount2);
    jobPtr->SetExecutionMode(selectedExecutionMode);
    jobPtr->SetChargState(GetData<bool>());
    fuzz_->HandleSuccess(videoId, nullptr);
    fuzz_->HandleError(videoId, selectedDpsError);
    fuzz_->HandleServiceDied();
    fuzz_->TryDoSchedule();
    fuzz_->DoProcess(jobPtr);
    fuzz_->SetDefaultExecutionMode();
    fuzz_->StartSuspendLock();
    fuzz_->StopSuspendLock();
    fuzz_->HandleNormalSchedule(jobPtr);
    fuzz_->OnTimerOut();

    remove(TEST_FILE_PATH_1);
    remove(TEST_FILE_PATH_2);
}

void Test()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto deferredVideoController = std::make_unique<DeferredVideoControllerFuzzer>();
    if (deferredVideoController == nullptr) {
        DP_INFO_LOG("deferredVideoController is null");
        return;
    }
    deferredVideoController->DeferredVideoControllerFuzzTest();
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