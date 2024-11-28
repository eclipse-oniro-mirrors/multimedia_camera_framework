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

#include "deferred_session_command_unittest.h"
#include "deferred_video_processing_session_callback_proxy.h"
#include "dps.h"
#include "iremote_object.h"
#include "session_command.h"
#include "sync_command.h"
#include "video_command.h"
#include "video_session_info.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

const int32_t USER_ID = 0;
void DeferredSessionCommandUnitTest::SetUpTestCase(void) {}

void DeferredSessionCommandUnitTest::TearDownTestCase(void) {}

void DeferredSessionCommandUnitTest::SetUp(void)
{
    DPS_Initialize();
}

void DeferredSessionCommandUnitTest::TearDown(void)
{
    DPS_Destroy();
    srcFd_ = nullptr;
    dstFd_ = nullptr;
    videoInfoMap_.clear();
    processor_ = nullptr;
    sessionInfo_ = nullptr;
}

void DeferredSessionCommandUnitTest::PrepareFd()
{
    srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(videoSourceFd_);
    ASSERT_NE(srcFd_, nullptr);
    dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(videoDestinationFd_);
    ASSERT_NE(dstFd_, nullptr);
}

void DeferredSessionCommandUnitTest::PrepareVideoInfo(const std::string& videoId)
{
    PrepareFd();
    std::shared_ptr<DeferredVideoProcessingSession::VideoInfo> videoInfo =
        std::make_shared<DeferredVideoProcessingSession::VideoInfo>(srcFd_, dstFd_);
    ASSERT_NE(videoInfo, nullptr);
    videoInfoMap_[videoId] = videoInfo;
}

void DeferredSessionCommandUnitTest::InitProcessor(int32_t userId)
{
    std::shared_ptr<VideoJobRepository> repository = std::make_shared<VideoJobRepository>(userId);
    ASSERT_NE(repository, nullptr);
    std::shared_ptr<VideoPostProcessor> postProcessor = std::make_shared<VideoPostProcessor>(userId);
    ASSERT_NE(postProcessor, nullptr);
    std::shared_ptr<TestIVideoProcCb> callback = std::make_shared<TestIVideoProcCb>();
    ASSERT_NE(callback, nullptr);
    processor_ =
        std::make_shared<DeferredVideoProcessor>(repository, postProcessor, callback);
    ASSERT_NE(processor_, nullptr);
}

void DeferredSessionCommandUnitTest::InitSessionInfo(int32_t userId)
{
    std::u16string descriptor = u"test";
    sptr<IRemoteObject> remoteObj = sptr<IRemoteObjectUnitTest>::MakeSptr(descriptor);
    ASSERT_NE(remoteObj, nullptr);
    sptr<DeferredVideoProcessingSessionCallbackProxy> cb =
        sptr<DeferredVideoProcessingSessionCallbackProxy>::MakeSptr(remoteObj);
    ASSERT_NE(cb, nullptr);
    sessionInfo_ = sptr<VideoSessionInfo>::MakeSptr(userId, cb);
    ASSERT_NE(sessionInfo_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions in class SessionCommand by using its derived class AddVideoSessionCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class SessionCommand by using its derived class AddVideoSessionCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_001, TestSize.Level0)
{
    InitSessionInfo(USER_ID);
    AddVideoSessionCommand sessionCommand(sessionInfo_);
    EXPECT_FALSE(sessionCommand.initialized_.load());
    EXPECT_EQ(sessionCommand.Initialize(), DP_OK);
    EXPECT_TRUE(sessionCommand.initialized_.load());
    EXPECT_EQ(sessionCommand.Initialize(), DP_OK);
}

/*
 * Feature: Framework
 * Function: Test functions in class AddVideoSessionCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class AddVideoSessionCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_002, TestSize.Level0)
{
    InitSessionInfo(USER_ID);
    AddVideoSessionCommand addVideoSC(sessionInfo_);
    EXPECT_EQ(addVideoSC.Initialize(), DP_OK);
    EXPECT_EQ(addVideoSC.Executing(), DP_OK);

    std::shared_ptr<SessionManager> sessionMgr = DPS_GetSessionManager();
    ASSERT_NE(sessionMgr, nullptr);
    DPS_Destroy();
    ASSERT_NE(sessionMgr, nullptr);

    sessionMgr->coordinator_ = nullptr;
    EXPECT_EQ(addVideoSC.Executing(), DP_NULL_POINTER);
}

/*
 * Feature: Framework
 * Function: Test functions in class DeleteVideoSessionCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeleteVideoSessionCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_003, TestSize.Level0)
{
    InitSessionInfo(USER_ID);
    DeleteVideoSessionCommand delVideoSC(sessionInfo_);
    EXPECT_EQ(delVideoSC.Initialize(), DP_OK);
    EXPECT_EQ(delVideoSC.Executing(), DP_OK);

    DPS_GetSessionManager()->coordinator_ = nullptr;
    EXPECT_EQ(delVideoSC.Executing(), DP_NULL_POINTER);
    delVideoSC.sessionManager_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test functions in class SyncCommand by using its derived class VideoSyncCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class SyncCommand by using its derived class VideoSyncCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_004, TestSize.Level0)
{
    std::string videoId = "testVideoId";
    PrepareVideoInfo(videoId);

    std::shared_ptr<VideoSyncCommand> syncCommand =
        std::make_shared<VideoSyncCommand>(USER_ID, videoInfoMap_);
    EXPECT_EQ(syncCommand->Initialize(), DP_NULL_POINTER);
    EXPECT_FALSE(syncCommand->initialized_.load());

    InitProcessor(USER_ID);
    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(syncCommand->Initialize(), DP_OK);

    syncCommand->initialized_.store(true);
    EXPECT_EQ(syncCommand->Initialize(), DP_OK);
}


/*
 * Feature: Framework
 * Function: Test functions in class VideoSyncCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class VideoSyncCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_005, TestSize.Level0)
{
    std::string videoId = "testVideoId";
    std::string invalidId = "invalidVideoId";
    PrepareVideoInfo(videoId);

    std::shared_ptr<VideoSyncCommand> videoSyncCommand =
        std::make_shared<VideoSyncCommand>(USER_ID, videoInfoMap_);
    ASSERT_NE(videoSyncCommand, nullptr);
    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    EXPECT_EQ(schedulerManager->videoProcessors_.count(USER_ID), 0);
    EXPECT_EQ(videoSyncCommand->Executing(), 1);

    videoSyncCommand->initialized_.store(false);
    InitProcessor(USER_ID);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(videoSyncCommand->Initialize(), DP_OK);

    EXPECT_EQ(videoSyncCommand->Executing(), DP_OK);
}

/*
 * Feature: Framework
 * Function: Test functions in class VideoCommand by using its derived class RestoreCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class VideoCommand by using its derived class RestoreCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_006, TestSize.Level0)
{
    std::string videoId = "testVideoId";

    std::shared_ptr<RestoreCommand> videoCommand = std::make_shared<RestoreCommand>(USER_ID, videoId);
    ASSERT_NE(videoCommand, nullptr);
    DPS_Destroy();
    EXPECT_EQ(videoCommand->Initialize(), DP_NULL_POINTER);

    videoCommand->initialized_.store(false);
    DPS_Initialize();
    EXPECT_EQ(videoCommand->Initialize(), DP_NULL_POINTER);

    videoCommand->initialized_.store(false);
    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    InitProcessor(USER_ID);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(videoCommand->Initialize(), DP_OK);
    EXPECT_TRUE(videoCommand->initialized_.load());
    EXPECT_EQ(videoCommand->Initialize(), DP_OK);
}

/*
 * Feature: Framework
 * Function: Test functions in class AddVideoCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class AddVideoCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_007, TestSize.Level0)
{
    std::string videoId = "testVideoId";
    PrepareFd();

    std::shared_ptr<AddVideoCommand> addVideoCmd = std::make_shared<AddVideoCommand>(USER_ID, videoId, srcFd_, dstFd_);
    EXPECT_EQ(addVideoCmd->Executing(), 1);
    EXPECT_FALSE(addVideoCmd->initialized_.load());

    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    InitProcessor(USER_ID);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(addVideoCmd->Executing(), DP_OK);
}

/*
 * Feature: Framework
 * Function: Test functions in class RemoveVideoCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class RemoveVideoCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_008, TestSize.Level0)
{
    std::string videoId = "testVideoId";

    std::shared_ptr<RemoveVideoCommand> removeVideoCmd = std::make_shared<RemoveVideoCommand>(USER_ID, videoId, true);
    EXPECT_EQ(removeVideoCmd->Executing(), 1);
    EXPECT_FALSE(removeVideoCmd->initialized_.load());

    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    InitProcessor(USER_ID);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(removeVideoCmd->Executing(), DP_OK);
}

/*
 * Feature: Framework
 * Function: Test functions in class RestoreCommand.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class RestoreCommand.
 */
HWTEST_F(DeferredSessionCommandUnitTest, deferred_session_command_unittest_009, TestSize.Level0)
{
    std::string videoId = "testVideoId";

    std::shared_ptr<RestoreCommand> restoreVideoCmd = std::make_shared<RestoreCommand>(USER_ID, videoId);
    EXPECT_EQ(restoreVideoCmd->Executing(), 1);
    EXPECT_FALSE(restoreVideoCmd->initialized_.load());

    std::shared_ptr<SchedulerManager> schedulerManager = DPS_GetSchedulerManager();
    ASSERT_NE(schedulerManager, nullptr);
    InitProcessor(USER_ID);
    schedulerManager->videoProcessors_[USER_ID] = processor_;
    EXPECT_EQ(restoreVideoCmd->Executing(), DP_OK);
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS