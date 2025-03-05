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

#include "session_coordinator_fuzzer.h"
#include "camera_log.h"
#include "deferred_processing_service.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t NUM_TRI = 13;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

std::shared_ptr<DeferredProcessing::SessionCoordinator> SessionCoordinatorFuzzer::fuzz_{nullptr};

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

void SessionCoordinatorFuzzer::SessionCoordinatorFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    fuzz_ = std::make_shared<DeferredProcessing::SessionCoordinator>();
    fuzz_->Initialize();
    int32_t userId = GetData<int32_t>();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string imageId(testStrings[randomNum % testStrings.size()]);
    std::shared_ptr<DeferredProcessing::BufferInfo> bufferInfo;
    fuzz_->imageProcCallbacks_->OnProcessDone(userId, imageId, bufferInfo);
    std::shared_ptr<DeferredProcessing::BufferInfoExt> bufferInfoExt;
    fuzz_->imageProcCallbacks_->OnProcessDoneExt(userId, imageId, bufferInfoExt);
    DeferredProcessing::DpsError dpsError = static_cast<DeferredProcessing::DpsError>(GetData<int32_t>() % NUM_TRI);
    fuzz_->imageProcCallbacks_->OnError(userId, imageId, dpsError);
    sptr<IPCFileDescriptor> ipcFd;
    fuzz_->videoProcCallbacks_->OnProcessDone(userId, imageId, ipcFd);
    fuzz_->videoProcCallbacks_->OnError(userId, imageId, dpsError);
    std::vector<DeferredProcessing::DpsStatus> dpsStatusVec = {
        DeferredProcessing::DPS_SESSION_STATE_IDLE,
        DeferredProcessing::DPS_SESSION_STATE_RUNNALBE,
        DeferredProcessing::DPS_SESSION_STATE_RUNNING,
        DeferredProcessing::DPS_SESSION_STATE_SUSPENDED,
    };
    uint8_t arrcodeNum = randomNum % dpsStatusVec.size();
    DeferredProcessing::DpsStatus dpsStatus = dpsStatusVec[arrcodeNum];
    fuzz_->imageProcCallbacks_->OnStateChanged(userId, dpsStatus);
    fuzz_->videoProcCallbacks_->OnStateChanged(userId, dpsStatus);
    fuzz_->Start();
    fuzz_->OnStateChanged(userId, dpsStatus);
    fuzz_->OnVideoStateChanged(userId, dpsStatus);
    fuzz_->GetImageProcCallbacks();
    fuzz_->GetVideoProcCallbacks();
    fuzz_->OnProcessDone(userId, imageId, ipcFd, userId, GetData<bool>());
    fuzz_->OnProcessDoneExt(userId, imageId, nullptr, GetData<bool>());
    fuzz_->OnError(userId, imageId, dpsError);
    fuzz_->OnVideoProcessDone(userId, imageId, ipcFd);
    fuzz_->OnVideoError(userId, imageId, dpsError);
    auto videoCallback = fuzz_->GetRemoteVideoCallback(userId);
    fuzz_->ProcessVideoResults(videoCallback);
    fuzz_->DeleteVideoSession(userId);
    fuzz_->DeletePhotoSession(userId);
    fuzz_->Stop();
}

void Test()
{
    auto sessionCoordinatorFuzz = std::make_unique<SessionCoordinatorFuzzer>();
    if (sessionCoordinatorFuzz == nullptr) {
        MEDIA_INFO_LOG("sessionCoordinatorFuzz is null");
        return;
    }
    sessionCoordinatorFuzz->SessionCoordinatorFuzzTest();
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