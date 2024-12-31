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

#include "deferredvideoprocsession_fuzzer.h"
#include "camera_log.h"
#include "deferred_processing_service.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
int g_userId = 0;
std::shared_ptr<DeferredVideoProcessingSessionCallback> callback =
    std::make_shared<DeferredVideoProcessingSessionCallback>();
std::shared_ptr<IDeferredVideoProcSessionCallbackFuzz> sessionCallback =
    std::make_shared<IDeferredVideoProcSessionCallbackFuzz>();
std::shared_ptr<DeferredVideoProcSession> deferredVideoProcSession =
    std::make_shared<DeferredVideoProcSession>(g_userId, sessionCallback);

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

void GetPermission()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

auto createSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback,
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_RET_LOG(object == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession object is null");
    sptr<ICameraService> serviceProxy = iface_cast<ICameraService>(object);
    CHECK_ERROR_RETURN_RET_LOG(serviceProxy == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession serviceProxy is null");

    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback =
        new(std::nothrow) DeferredVideoProcessingSessionCallback();
    CHECK_ERROR_RETURN_RET_LOG(remoteCallback == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateDeferredVideoProcessingSession failed to new remoteCallback!");
    serviceProxy->CreateDeferredVideoProcessingSession(userId, remoteCallback, session);
    return CameraErrorCode::SUCCESS;
}

void DeferredVideoProcSessionFuzzer::DeferredVideoProcSessionFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    GetPermission();

    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> ipcFileDescriptor = nullptr;
    callback->OnProcessVideoDone(videoId, ipcFileDescriptor);
    callback->OnError(videoId, DpsErrorCode::ERROR_SESSION_SYNC_NEEDED);
    int32_t status = GetData<int32_t>();
    callback->OnStateChanged(status);

    deferredVideoProcSession->BeginSynchronize();
    deferredVideoProcSession->EndSynchronize();
    sptr<IPCFileDescriptor> srcFd = nullptr;
    sptr<IPCFileDescriptor> dstFd = nullptr;
    deferredVideoProcSession->AddVideo(videoId, srcFd, dstFd);
    bool restorable = GetData<bool>();
    deferredVideoProcSession->RemoveVideo(videoId, restorable);
    deferredVideoProcSession->RestoreVideo(videoId);
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    createSession(g_userId, sessionCallback, session);
    deferredVideoProcSession->SetDeferredVideoSession(session);
    int32_t pid = GetData<int32_t>();
    deferredVideoProcSession->ReconnectDeferredProcessingSession();
    deferredVideoProcSession->ConnectDeferredProcessingSession();
    deferredVideoProcSession->GetCallback();
    deferredVideoProcSession->remoteSession_ = nullptr;
    deferredVideoProcSession->callback_ = nullptr;
    deferredVideoProcSession->CameraServerDied(pid);
}

void Test()
{
    auto deferredVideoProcSessionFuzz = std::make_unique<DeferredVideoProcSessionFuzzer>();
    if (deferredVideoProcSessionFuzz == nullptr) {
        MEDIA_INFO_LOG("deferredVideoProcSessionFuzz is null");
        return;
    }
    deferredVideoProcSessionFuzz->DeferredVideoProcSessionFuzzTest();
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