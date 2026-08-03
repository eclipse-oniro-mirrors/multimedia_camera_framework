/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "deferred_video_controller_unittest.h"

#include "deferred_processing_service.h"
#include "deferred_video_processing_session_callback_stub.h"
#include "dps.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t USER_ID = 0;
    const std::string VIDEO_ID_1 = "testVideo1";
    const std::string INVALID_VIDEO_ID = "nonexistent_video";
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH_1 = MEDIA_ROOT + "temp/" + "test_temp1.mp4";
    const std::string VIDEO_TEMP_PATH_2 = MEDIA_ROOT + "temp/" + "test_temp2.mp4";
}

class VideoProcessingSessionCallbackMock : public DeferredVideoProcessingSessionCallbackStub {
public:
    MOCK_METHOD(ErrCode, OnProcessVideoDone, (const std::string &videoId), (override));
    MOCK_METHOD(ErrCode, OnError, (const std::string& videoId, ErrorCode errorCode));
    MOCK_METHOD(ErrCode, OnStateChanged, (StatusCode status), (override));
    MOCK_METHOD(ErrCode, OnProcessingProgress, (const std::string& videoId, float progress), (override));

    VideoProcessingSessionCallbackMock()
    {
        ON_CALL(*this, OnProcessVideoDone).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnError).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnStateChanged).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnProcessingProgress).WillByDefault(Return(ERR_OK));
    }
};

void DeferredVideoControllerUnittest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void DeferredVideoControllerUnittest::TearDownTestCase(void)
{
    auto scheduler = DPS_GetSchedulerManager();
    if (scheduler != nullptr) {
        scheduler->videoController_.erase(USER_ID);
    }
}

void DeferredVideoControllerUnittest::SetUp()
{
    auto schedule = DPS_GetSchedulerManager();
    ASSERT_NE(schedule, nullptr);

    schedule->CreateVideoProcessor(USER_ID);
    sptr<IDeferredVideoProcessingSessionCallback> callback =
        new (std::nothrow) VideoProcessingSessionCallbackMock();
    DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(USER_ID, callback);

    sleep(1);
    controller_ = schedule->GetVideoController(USER_ID);
    ASSERT_NE(controller_, nullptr);

    processor_ = controller_->GetVideoProcessor();
    ASSERT_NE(processor_, nullptr);
}

void DeferredVideoControllerUnittest::TearDown()
{
    processor_ = nullptr;
    controller_ = nullptr;
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleSuccess with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleSuccess with valid job
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_001, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);
    processor_->AddVideo(VIDEO_ID_1, std::move(info));
    ASSERT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);

    controller_->HandleSuccess(VIDEO_ID_1, nullptr);
    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::ERROR);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleSuccess with null job branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleSuccess with non-existent videoId (job is nullptr)
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_002, TestSize.Level1)
{
    controller_->HandleSuccess(INVALID_VIDEO_ID, nullptr);
    EXPECT_NE(controller_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleError with DPS_ERROR_VIDEO_PROC_FAILED
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_003, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);

    processor_->AddVideo(VIDEO_ID_1, std::move(info));
    ASSERT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);

    controller_->HandleError(VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);

    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::ERROR);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleError with interrupted branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleError with DPS_ERROR_VIDEO_PROC_INTERRUPTED
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_004, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);

    processor_->AddVideo(VIDEO_ID_1, std::move(info));
    ASSERT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);

    controller_->HandleError(VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::PAUSE);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleError with timeout branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleError with DPS_ERROR_VIDEO_PROC_TIMEOUT
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_005, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);

    processor_->AddVideo(VIDEO_ID_1, std::move(info));
    ASSERT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);

    controller_->HandleError(VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT);
    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::FAILED);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleError with null job branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleError SetDefaultExecutionMode
 *   with non-existent videoId (job is nullptr)
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_006, TestSize.Level1)
{
    controller_->HandleError(INVALID_VIDEO_ID, DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    EXPECT_NE(controller_, nullptr);

    controller_->SetDefaultExecutionMode();
    EXPECT_NE(controller_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController SetDefaultExecutionMode with null processor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController SetDefaultExecutionMode when videoProcessor_ is nullptr
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_008, TestSize.Level1)
{
    auto tempProcessor = controller_->videoProcessor_;
    controller_->videoProcessor_ = nullptr;
    controller_->SetDefaultExecutionMode();
    controller_->videoProcessor_ = tempProcessor;
    EXPECT_NE(controller_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController StartSuspendLock with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController StartSuspendLock when normalTimeId_ is INVALID_TIMERID
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_009, TestSize.Level1)
{
    controller_->normalTimeId_ = INVALID_TIMERID;
    controller_->StartSuspendLock();

    EXPECT_EQ(controller_->normalTimeId_, INVALID_TIMERID);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController StartSuspendLock with already running branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController StartSuspendLock returns early when timer already running
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_010, TestSize.Level1)
{
    controller_->normalTimeId_ = 1;
    controller_->StartSuspendLock();

    EXPECT_EQ(controller_->normalTimeId_, 1);
    controller_->normalTimeId_ = INVALID_TIMERID;
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController StopSuspendLock with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController StopSuspendLock when normalTimeId_ is not INVALID_TIMERID
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_011, TestSize.Level1)
{
    controller_->normalTimeId_ = INVALID_TIMERID;
    controller_->StartSuspendLock();
    EXPECT_NE(controller_->normalTimeId_, INVALID_TIMERID);

    controller_->StopSuspendLock();
    EXPECT_EQ(controller_->normalTimeId_, INVALID_TIMERID);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleNormalSchedule with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleNormalSchedule when job is not suspend
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_012, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);
    processor_->AddVideo(VIDEO_ID_1, std::move(info));

    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);
    ASSERT_NE(jobPtr, nullptr);
    jobPtr->SetChargState(true);

    controller_->HandleNormalSchedule(jobPtr);
    EXPECT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController HandleNormalSchedule with suspend branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController HandleNormalSchedule when job is suspend (returns early)
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_013, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);
    processor_->AddVideo(VIDEO_ID_1, std::move(info));
    auto jobPtr = processor_->GetRepository()->GetJobUnLocked(VIDEO_ID_1);
    ASSERT_NE(jobPtr, nullptr);
    jobPtr->SetChargState(false);

    controller_->HandleNormalSchedule(jobPtr);
    EXPECT_EQ(processor_->GetRepository()->jobQueue_->GetSize(), 1);
    processor_->RemoveVideo(VIDEO_ID_1, false);

    controller_->OnTimerOut();
    EXPECT_EQ(controller_->normalTimeId_, INVALID_TIMERID);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController GetJob with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController GetJob when videoId exists
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_015, TestSize.Level1)
{
    std::vector<std::string> srcPaths = {VIDEO_PATH};
    auto info = std::make_unique<VideoInfo>(srcPaths, VIDEO_TEMP_PATH_1, VIDEO_TEMP_PATH_2);
    processor_->AddVideo(VIDEO_ID_1, std::move(info));

    auto jobPtr = controller_->GetJob(VIDEO_ID_1);
    EXPECT_NE(jobPtr, nullptr);
    EXPECT_EQ(jobPtr->GetVideoId(), VIDEO_ID_1);
    processor_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoController GetJob with null processor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoController GetJob when videoProcessor_ is nullptr
 */
HWTEST_F(DeferredVideoControllerUnittest, deferred_video_controller_unittest_016, TestSize.Level1)
{
    auto tempProcessor = controller_->videoProcessor_;
    controller_->videoProcessor_ = nullptr;

    auto jobPtr = controller_->GetJob(VIDEO_ID_1);
    EXPECT_EQ(jobPtr, nullptr);

    controller_->videoProcessor_ = tempProcessor;

    jobPtr = controller_->GetJob(INVALID_VIDEO_ID);
    EXPECT_EQ(jobPtr, nullptr);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS
