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

#include "deferred_video_processor_unittest.h"

#include "deferred_processing_service.h"
#include "deferred_video_processing_session_callback_stub.h"
#include "dps.h"
#include "gmock/gmock.h"
#include <fcntl.h>

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t USER_ID = 0;
    const std::string VIDEO_ID_1 = "testVideo1";
    const std::string VIDEO_ID_2 = "testVideo2";
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH = MEDIA_ROOT + "test_video_temp.mp4";
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

void DeferredVideoProcessorUnittest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void DeferredVideoProcessorUnittest::TearDownTestCase(void)
{
    auto scheduler = DPS_GetSchedulerManager();
    scheduler->videoController_.erase(USER_ID);
}

void DeferredVideoProcessorUnittest::SetUp()
{
    sptr<IDeferredVideoProcessingSessionCallback> callback = new (std::nothrow) VideoProcessingSessionCallbackMock();
    DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(USER_ID, callback);
    sleep(1);
    auto schedule = DPS_GetSchedulerManager();
    ASSERT_NE(schedule, nullptr);
    process_ = schedule->GetVideoProcessor(USER_ID);
    ASSERT_NE(process_, nullptr);
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    dtsFd_ = open(VIDEO_TEMP_PATH.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
}

void DeferredVideoProcessorUnittest::TearDown()
{
    if (srcFd_ > 0) {
        close(srcFd_);
    }
    if (dtsFd_ > 0) {
        close(dtsFd_);
    }
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor AddVideo with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor AddVideo with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_001, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 1);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor AddMovieVideo with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor AddMovieVideo with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_002, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DpsFdPtr movieFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr movieCopyFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd, movieFd, movieCopyFd);
    process_->AddVideo(VIDEO_ID_1, info);
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 1);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor AddVideo with ProcessCatch branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor AddVideo with ProcessCatch branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_003, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    process_->result_->cacheMap_.emplace(VIDEO_ID_1, DpsError::DPS_NO_ERROR);
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 0);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor RemoveVideo with restor branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor RemoveVideo with restor branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_004, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->RemoveVideo(VIDEO_ID_1, true);
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 1);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor RemoveVideo with no restor branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor RemoveVideo with no restor branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_005, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->RemoveVideo(VIDEO_ID_1, false);
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 0);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor RestoreVideoJob with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor RestoreVideoJob with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_006, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->RemoveVideo(VIDEO_ID_1, true);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::DELETED);
    process_->RestoreVideo(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::PENDING);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor ProcessVideo with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor ProcessVideo with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_007, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->ProcessVideo(VIDEO_ID_1);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurPriority(), JobPriority::HIGH);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor ProcessVideo with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor ProcessVideo with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_008, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    jobPtr->SetJobState(VideoJobState::FAILED);

    process_->ProcessVideo(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::PENDING);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor ProcessVideo with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor ProcessVideo with abnormal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_009, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->ProcessVideo(VIDEO_ID_1);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurPriority(), JobPriority::HIGH);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor CancelProcessVideo with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor CancelProcessVideo with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_010, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);

    process_->ProcessVideo(VIDEO_ID_1);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurPriority(), JobPriority::HIGH);
    process_->CancelProcessVideo(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurPriority(), JobPriority::NORMAL);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor DoProcess with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor DoProcess with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_011, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    process_->DoProcess(jobPtr);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::RUNNING);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor OnProcessSuccess with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor OnProcessSuccess with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_012, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    process_->OnProcessSuccess(USER_ID, VIDEO_ID_1, nullptr);

    process_->HandleSuccess(USER_ID, VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::COMPLETED);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor OnProcessError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor OnProcessError with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_013, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);

    process_->OnProcessError(USER_ID, VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::ERROR);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HandleError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HandleError with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_014, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);

    process_->HandleError(USER_ID, VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::ERROR);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HandleError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HandleError with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_015, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);

    process_->HandleError(USER_ID, VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::ERROR);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HandleError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HandleError with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_016, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);

    process_->HandleError(USER_ID, VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::FAILED);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HandleError with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HandleError with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_017, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);

    process_->HandleError(USER_ID, VIDEO_ID_1, DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::PAUSE);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor PauseRequest with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor PauseRequest with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_018, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    process_->repository_->SetJobRunning(VIDEO_ID_1);
    auto jobPtr = process_->repository_->jobQueue_->GetJobById(VIDEO_ID_1);
    EXPECT_EQ(jobPtr->GetCurStatus(), VideoJobState::RUNNING);
    process_->PauseRequest(SchedulerType::VIDEO_CAMERA_STATE);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor SetDefaultExecutionMode with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor SetDefaultExecutionMode with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_019, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    process_->SetDefaultExecutionMode();
    EXPECT_EQ(process_->repository_->jobQueue_->GetSize(), 1);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor SetDefaultExecutionMode with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor SetDefaultExecutionMode with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_020, TestSize.Level1)
{
    std::vector<std::string> pendingVideos;
    auto ret = process_->GetPendingVideos(pendingVideos);
    EXPECT_EQ(ret, true);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HasRunningJob with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HasRunningJob with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_021, TestSize.Level1)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    process_->AddVideo(VIDEO_ID_1, info);
    process_->repository_->SetJobRunning(VIDEO_ID_1);
    auto ret = process_->HasRunningJob();
    EXPECT_EQ(ret, true);
    process_->RemoveVideo(VIDEO_ID_1, false);
}

/*
 * Feature: Framework
 * Function: Test DeferredVideoProcessor HasRunningJob with normal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredVideoProcessor HasRunningJob with normal branch
 */
HWTEST_F(DeferredVideoProcessorUnittest, deferred_video_processor_unittest_022, TestSize.Level1)
{
    process_->repository_->ClearCatch();
    auto ret = process_->HasRunningJob();
    EXPECT_EQ(ret, false);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS