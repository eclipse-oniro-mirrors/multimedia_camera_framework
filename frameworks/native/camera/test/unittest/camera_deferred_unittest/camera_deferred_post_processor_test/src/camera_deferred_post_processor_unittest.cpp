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

#include "camera_deferred_post_processor_unittest.h"
#include "photo_post_processor.h"
#include "basic_definitions.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "dp_utils.h"
#include "iimage_process_callbacks.h"
#include "dps.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

static const uint8_t* RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

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

void DeferredPostPorcessorUnitTest::SetUpTestCase(void) {}

void DeferredPostPorcessorUnitTest::TearDownTestCase(void) {}

void DeferredPostPorcessorUnitTest::SetUp() {}

void DeferredPostPorcessorUnitTest::TearDown() {}

void DeferredPostPorcessorUnitTest::NativeAuthorization()
{
    const char *perms[2];
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
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test the exception branch of the Photo Post Processor when the session is nulptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the exception branch of the Photo Post Processor when the session is nulptr
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_001, TestSize.Level0)
{
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    postProcessor->session_ = nullptr;
    std::string imageId = "testImageId";
    postProcessor->RemoveImage(imageId);
    postProcessor->Reset();
    postProcessor->SetExecutionMode(ExecutionMode::HIGH_PERFORMANCE);
    postProcessor->DisconnectService();
    int32_t ret = postProcessor->GetConcurrency(ExecutionMode::HIGH_PERFORMANCE);
    EXPECT_EQ(ret, 1);
}

/*
 * Feature: Framework
 * Function: Test OnError with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnError with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_002, TestSize.Level0)
{
    constexpr int32_t EXECUTION_MODE_COUNT1 = static_cast<int32_t>(ExecutionMode::DUMMY) + 1;
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(GetData<uint8_t>() % EXECUTION_MODE_COUNT1);
    postProcessor->SetExecutionMode(selectedExecutionMode);
    postProcessor->SetDefaultExecutionMode();
    std::vector<std::string> testStrings = {"test1", "test2"};
    uint8_t randomNum = GetData<uint8_t>();
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = GetData<int>();
    auto dstFd = GetData<int>();
    postProcessor->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = GetData<bool>();
    std::string videoId_(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    sptr<IPCFileDescriptor> dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(GetData<int>());
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId_, srcFd_, dstFd_);
    std::shared_ptr<DeferredVideoWork> work =
        std::make_shared<DeferredVideoWork>(jobPtr, selectedExecutionMode, isAutoSuspend);
    postProcessor->StartTimer(videoId, work);
    DeferredProcessing::DPS_Initialize();
    EXPECT_NE(DeferredProcessing::DPS_GetSchedulerManager(), nullptr);
    postProcessor->OnError(videoId, DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    postProcessor->StartTimer(videoId, work);
    postProcessor->OnError(videoId, DpsError::DPS_ERROR_SESSION_SYNC_NEEDED);
}

/*
 * Feature: Framework
 * Function: Test GetIntent with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetIntent with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_003, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    HDI::Camera::V1_0::StreamIntent streamIntent = postProcessor->GetIntent(HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER);
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::CUSTOM);
    streamIntent = postProcessor->GetIntent(HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO);
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::VIDEO);
    streamIntent = postProcessor->GetIntent(static_cast<HDI::Camera::V1_3::MediaStreamType>(-1));
    EXPECT_EQ(streamIntent, HDI::Camera::V1_0::PREVIEW);
}

/*
 * Feature: Framework
 * Function: Test ProcessStream with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessStream with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_004, TestSize.Level0)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    StreamDescription steamInfo;
    postProcessor->mpegManager_ = std::make_shared<MpegManager>();
    ASSERT_NE(postProcessor->mpegManager_, nullptr);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO;
    bool result = postProcessor->ProcessStream(steamInfo);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER;
    result = postProcessor->ProcessStream(steamInfo);
    EXPECT_FALSE(result);
}
} // CameraStandard
} // OHOS