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
#include "camera_log.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "securec.h"
#include <memory>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

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
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void DeferredVideoControllerFuzzer::DeferredVideoControllerFuzzTest()
{
    int32_t userId = GetData<int32_t>();
    std::shared_ptr<VideoJobRepository> repository;
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    if (repository == nullptr) {
        repository = std::make_shared<VideoJobRepository>(userId);
    }
    repository->SetJobPending(videoId);
    repository->SetJobRunning(videoId);
    repository->SetJobCompleted(videoId);
    repository->SetJobFailed(videoId);
    repository->SetJobPause(videoId);
    repository->SetJobError(videoId);
    if (center_ == nullptr) {
        center_ = std::make_shared<DeferredProcessing::VideoStrategyCenter>(userId, repository);
    }
    const std::shared_ptr<VideoPostProcessor> postProcessor =
        std::make_shared<VideoPostProcessor>(userId);
    const std::shared_ptr<IVideoProcessCallbacksFuzz> callback =
        std::make_shared<IVideoProcessCallbacksFuzz>();
    std::shared_ptr<DeferredVideoProcessor> processor =
        std::make_shared<DeferredVideoProcessor>(repository, postProcessor, callback);
    if (fuzz_ == nullptr) {
        fuzz_ = std::make_shared<DeferredVideoController>(userId, repository, processor);
    }
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    std::shared_ptr<DeferredVideoJob> jobPtr =
        std::make_shared<DeferredVideoJob>(videoId, srcFd, dstFd);
    fuzz_->Initialize();
    fuzz_->OnVideoJobChanged(jobPtr);
    constexpr int32_t executionModeCount1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(GetData<uint8_t>() % executionModeCount1);
    constexpr int32_t executionModeCount2 = static_cast<int32_t>(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) + 1;
    DpsError selectedDpsError = static_cast<DpsError>(GetData<uint8_t>() % executionModeCount2);
    std::shared_ptr<DeferredVideoWork> work =
        std::make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, dstFd);
    fuzz_->HandleSuccess(work);
    fuzz_->HandleError(work, selectedDpsError);
    fuzz_->HandleServiceDied();
    fuzz_->TryDoSchedule();
    fuzz_->PostProcess(work);
    fuzz_->SetDefaultExecutionMode();
    fuzz_->StartSuspendLock();
    fuzz_->StopSuspendLock();
    fuzz_->HandleNormalSchedule(work);
    fuzz_->OnTimerOut();
}

void Test()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto deferredVideoController = std::make_unique<DeferredVideoControllerFuzzer>();
    if (deferredVideoController == nullptr) {
        MEDIA_INFO_LOG("deferredVideoController is null");
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