/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "photo_process_command.h"
#include "service_died_command.h"
#include "test_token.h"
#include "token_setproc.h"
#include "video_process_command.h"
#include "dp_utils.h"
#include "v1_3/iimage_process_callback.h"
#include "dps.h"
#include "media_manager_proxy.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

constexpr int VIDEO_SOURCE_FD = 1;
constexpr int VIDEO_DESTINATION_FD = 2;

void DeferredPostPorcessorUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void DeferredPostPorcessorUnitTest::TearDownTestCase(void) {}

void DeferredPostPorcessorUnitTest::SetUp() {}

void DeferredPostPorcessorUnitTest::TearDown() {}

/*
 * Feature: Framework
 * Function: Test the exception branch of the Photo Post Processor when the session is nulptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the exception branch of the Photo Post Processor when the session is nulptr
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_001, TestSize.Level1)
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
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_002, TestSize.Level1)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    postProcessor->Initialize();
    ExecutionMode selectedExecutionMode = static_cast<ExecutionMode>(1);
    postProcessor->SetExecutionMode(selectedExecutionMode);
    postProcessor->SetDefaultExecutionMode();
    std::vector<std::string> testStrings = {"test1", "test2"};
    uint8_t randomNum = 1;
    std::string videoId(testStrings[randomNum % testStrings.size()]);
    auto srcFd = 1;
    auto dstFd = 1;
    postProcessor->copyFileByFd(srcFd, dstFd);
    auto isAutoSuspend = true;
    std::string videoId_(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_SOURCE_FD));
    sptr<IPCFileDescriptor> dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_DESTINATION_FD));
    fdsan_exchange_owner_tag(srcFd_->GetFd(), 0, LOG_DOMAIN);
    fdsan_exchange_owner_tag(dstFd_->GetFd(), 0, LOG_DOMAIN);
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
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_003, TestSize.Level1)
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
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_004, TestSize.Level1)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    StreamDescription steamInfo;
    postProcessor->mediaManagerProxy_ = MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(postProcessor->mediaManagerProxy_, nullptr);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO;
    bool result = postProcessor->ProcessStream(steamInfo);
    steamInfo.type = HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER;
    result = postProcessor->ProcessStream(steamInfo);
    EXPECT_FALSE(result);
}

/*
 * Feature: Framework
 * Function: Test StopMpeg with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StopMpeg with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_009, TestSize.Level1)
{
    auto postProcessor = CreateShared<VideoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    std::string imageId = "testImageId";
    EXPECT_FALSE(postProcessor->StartMpeg(imageId, nullptr));
}

/*
 * Feature: Framework
 * Function: Test Executing with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Executing with abnormal branch
 */
HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_010, TestSize.Level1)
{
    std::string imageId = "testImageId";
    auto successCommand = CreateShared<PhotoProcessSuccessCommand>(userId_, imageId, nullptr);
    EXPECT_EQ(successCommand->Executing(), DP_NULL_POINTER);
    DpsError errorCode = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
    auto failedCommand = CreateShared<PhotoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(failedCommand->Executing(), DP_NULL_POINTER);
    auto photoDiedCommand = CreateShared<PhotoDiedCommand>(userId_);
    EXPECT_EQ(photoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoDiedCommand = CreateShared<VideoDiedCommand>(userId_);
    EXPECT_EQ(videoDiedCommand->Executing(), DP_NULL_POINTER);
    auto videoProcessSuccessCommand = CreateShared<VideoProcessSuccessCommand>(userId_, imageId);
    EXPECT_EQ(videoProcessSuccessCommand->Executing(), DP_NULL_POINTER);
    auto videoProcessFailedCommand = CreateShared<VideoProcessFailedCommand>(userId_, imageId, errorCode);
    EXPECT_EQ(videoProcessFailedCommand->Executing(), DP_NULL_POINTER);
}


HWTEST_F(DeferredPostPorcessorUnitTest, deferred_post_processor_unittest_012, TestSize.Level1)
{
    int32_t userId = 1;
    auto sharedResult = std::make_shared<VideoProcessResult>(userId);
    std::string videoId = "testId";
    auto metaData = sptr<HDI::Camera::V1_0::MapDataSequenceable>::MakeSptr();
    metaData->Set(VideoMetadataKeys::SCALING_FACTOR, 1.0);
    metaData->Set(VideoMetadataKeys::INTERPOLATION_FRAME_PTS, "0");
    metaData->Set(VideoMetadataKeys::STAGE_VID, "0");
    auto ret = sharedResult->ProcessVideoInfo(videoId, metaData);
    EXPECT_EQ(ret, DP_OK);
}
} // CameraStandard
} // OHOS