/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
VideoStrategyCenter *VideoStrategyCenterFuzzer::fuzz = nullptr;
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

void VideoStrategyCenterFuzzer::VideoStrategyCenterFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    auto userId = GetData<int32_t>();
    std::shared_ptr<VideoJobRepository> repository;

    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    if(repository == nullptr){
        repository = std::make_shared<VideoJobRepository>(userId);
    }
    repository->SetJobPending(videoId);
    repository->SetJobRunning(videoId);
    repository->SetJobCompleted(videoId);
    repository->SetJobFailed(videoId);
    repository->SetJobPause(videoId);
    repository->SetJobError(videoId);

    if(fuzz == nullptr){
        fuzz = new DeferredProcessing::VideoStrategyCenter(userId, repository);
    }
    fuzz->GetWork();
    fuzz->GetJob();
    fuzz->GetExecutionMode();
    auto value = GetData<int32_t>();
    fuzz->HandleCameraEvent(value);
    fuzz->HandleMedialLibraryEvent(value);
    fuzz->HandleScreenEvent(value);
    fuzz->HandleChargingEvent(value);
    fuzz->HandleBatteryEvent(value);
    auto isNeedReset = GetData<bool>();
    auto useTime = GetData<int32_t>();
    fuzz->UpdateAvailableTime(isNeedReset, useTime);
}

void Test()
{
    auto VideoStrategyCenter = std::make_unique<VideoStrategyCenterFuzzer>();
    if (VideoStrategyCenter == nullptr) {
        MEDIA_INFO_LOG("VideoStrategyCenter is null");
        return;
    }
    VideoStrategyCenter->VideoStrategyCenterFuzzTest();
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