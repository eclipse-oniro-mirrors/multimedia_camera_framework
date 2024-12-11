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

#include "video_process_command_fuzzer.h"
#include "buffer_info.h"
#include "securec.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
using namespace std;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing{
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

void VideoProcessCommandFuzzer::VideoProcessCommandFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto userId = GetData<int32_t>();
    std::shared_ptr<VideoProcessCommandFuzz>command = std::make_shared<VideoProcessCommandFuzz>(userId);
    if (command == nullptr) {
        return;
    }
    command->Executing();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    std::shared_ptr<VideoProcessSuccessFuzz>success = std::make_shared<VideoProcessSuccessFuzz>(userId, videoId);
    if (success == nullptr) {
        return;
    }
    success->Executing();
    auto errorCode = GetData<int32_t>();
    std::shared_ptr<VideoProcessFailedFuzz>failed = std::make_shared<VideoProcessFailedFuzz>(userId,
        videoId, static_cast<DpsError>(errorCode));
    if (failed == nullptr) {
        return;
    }
    failed->Executing();
}

void Test()
{
    auto videoProcessCommand = std::make_unique<VideoProcessCommandFuzzer>();
    if (videoProcessCommand == nullptr) {
        MEDIA_INFO_LOG("videoProcessCommand is null");
        return;
    }
    videoProcessCommand->VideoProcessCommandFuzzTest();
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
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::DeferredProcessing::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::DeferredProcessing::FuzzTest(data, size);
    return 0;
}

