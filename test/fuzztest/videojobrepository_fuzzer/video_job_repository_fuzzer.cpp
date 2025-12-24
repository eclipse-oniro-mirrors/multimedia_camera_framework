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

#include "video_job_repository_fuzzer.h"

#include <fcntl.h>

#include "dp_log.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;
std::shared_ptr<DeferredProcessing::VideoJobRepository> VideoJobRepositoryFuzzer::fuzz_{nullptr};
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const char* TEST_FILE_PATH_1 = "/data/test/VideoJobRepositoryFuzzTest_test_file1.mp4";
const char* TEST_FILE_PATH_2 = "/data/test/VideoJobRepositoryFuzzTest_test_file2.mp4";

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

void VideoJobRepositoryFuzzer::VideoJobRepositoryFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    int32_t userId = GetData<int32_t>();
    fuzz_ = VideoJobRepository::Create(userId);
    DP_CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    fuzz_->SetJobPending(videoId);
    fuzz_->SetJobRunning(videoId);
    fuzz_->SetJobCompleted(videoId);
    fuzz_->SetJobFailed(videoId);
    fuzz_->SetJobPause(videoId);
    fuzz_->SetJobError(videoId);
    fuzz_->GetJob();
    std::vector<std::string> list = {"fuzz1", "fuzz2"};
    fuzz_->GetRunningJobList(list);
    std::string videoId_(testStrings[randomNum % testStrings.size()]);
    int sfd = open(TEST_FILE_PATH_1, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    int dfd = open(TEST_FILE_PATH_2, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(sfd);
    DpsFdPtr outFd = std::make_shared<DpsFd>(dfd);
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId_, inputFd, outFd, nullptr, nullptr);
    fuzz_->NotifyJobChangedUnLocked(videoId);

    remove(TEST_FILE_PATH_1);
    remove(TEST_FILE_PATH_2);
}

void Test()
{
    auto videoJobRepository = std::make_unique<VideoJobRepositoryFuzzer>();
    if (videoJobRepository == nullptr) {
        DP_INFO_LOG("videoJobRepository is null");
        return;
    }
    videoJobRepository->VideoJobRepositoryFuzzTest();
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