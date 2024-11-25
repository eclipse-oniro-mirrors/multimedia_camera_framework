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

#include "deferred_video_job.h"
#include "deferred_video_job_unittest.h"
#include "ipc_file_descriptor.h"
#include "video_job_queue.h"
#include "video_job_repository.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing{

constexpr int g_videoSourceFd = 111;
constexpr int g_videoDestinationFd = 222;
const int32_t g_userId = 0;

void DeferredVideoJobUnitTest::SetUpTestCase(void) {}

void DeferredVideoJobUnitTest::TearDownTestCase(void) {}

void DeferredVideoJobUnitTest::SetUp(void) {
    srcFd_ = sptr<IPCFileDescriptor>::MakeSptr(g_videoSourceFd);
    ASSERT_NE(srcFd_, nullptr);
    dstFd_ = sptr<IPCFileDescriptor>::MakeSptr(g_videoDestinationFd);
    ASSERT_NE(dstFd_, nullptr);
}

void DeferredVideoJobUnitTest::TearDown(void) {}

DeferredVideoJobPtr DeferredVideoJobUnitTest::CreateTestDeferredVideoJobPtr(const std::string& videoId, VideoJobStatus curStatus)
{
    if (!srcFd_ || !dstFd_) {
        return nullptr;
    }
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, srcFd_, dstFd_);
    if (!jobPtr) {
        return nullptr;
    }
    jobPtr->SetJobStatus(curStatus);
    return jobPtr;
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredVideoJob with test data to ensure the correctness.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_001, TestSize.Level0)
{
    std::string videoId1 = "videoTest1";
    std::string videoId2 = "videoTest2";

    std::shared_ptr<DeferredVideoJob> videoJobA = std::make_shared<DeferredVideoJob>(videoId1, srcFd_, dstFd_);
    std::shared_ptr<DeferredVideoJob> videoJobB = std::make_shared<DeferredVideoJob>(videoId2, srcFd_, dstFd_);

    bool createTimeResult = videoJobA->createTime_ < videoJobB->createTime_;
    EXPECT_EQ(videoJobA->curStatus_, videoJobB->curStatus_);
    EXPECT_TRUE(*videoJobA == *videoJobA);
    EXPECT_FALSE(*videoJobA == *videoJobB);
    EXPECT_EQ(*videoJobA > *videoJobB, createTimeResult);
    EXPECT_EQ(*videoJobB > *videoJobA, !createTimeResult);

    EXPECT_EQ(videoJobA->GetCurStatus(), VideoJobStatus::NONE);
    EXPECT_FALSE(videoJobA->SetJobStatus(VideoJobStatus::NONE));
    EXPECT_TRUE(videoJobA->SetJobStatus(VideoJobStatus::PENDING));
    EXPECT_EQ(videoJobA->GetCurStatus(), VideoJobStatus::PENDING);
    EXPECT_EQ(videoJobA->GetPreStatus(), VideoJobStatus::NONE);
    EXPECT_EQ(videoJobA->GetVideoId(), videoId1);
    EXPECT_EQ(videoJobA->GetInputFd()->GetFd(), g_videoSourceFd);
    EXPECT_EQ(videoJobA->GetOutputFd()->GetFd(), g_videoDestinationFd);

    bool statusResult = videoJobA->GetCurStatus() < videoJobB->GetCurStatus();
    EXPECT_EQ(videoJobA > videoJobB, statusResult);
    EXPECT_EQ(videoJobB > videoJobA, !statusResult);
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredVideoJob with test data to ensure the correctness.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_002, TestSize.Level0)
{
    std::string videoId = "video_test";
    uint32_t timeId = 1;
    ExecutionMode mode = ExecutionMode::LOAD_BALANCE;
    bool isAutoSuspend = false;
    
    std::shared_ptr<DeferredVideoJob> videoJob = std::make_shared<DeferredVideoJob>(videoId, srcFd_, dstFd_);
    EXPECT_TRUE(videoJob->SetJobStatus(VideoJobStatus::RUNNING));
    
    std::shared_ptr<DeferredVideoWork> dfVideoWork = std::make_shared<DeferredVideoWork>(videoJob, mode, isAutoSuspend);
    EXPECT_EQ(dfVideoWork->GetDeferredVideoJob()->GetCurStatus(), VideoJobStatus::RUNNING);
    EXPECT_EQ(dfVideoWork->GetExecutionMode(), ExecutionMode::LOAD_BALANCE);
    dfVideoWork->GetExecutionTime();
    EXPECT_TRUE(dfVideoWork->IsSuspend());
    EXPECT_LT(dfVideoWork->GetStartTime(), GetSteadyNow());
    dfVideoWork->SetTimeId(timeId);
    EXPECT_EQ(dfVideoWork->GetTimeId(), timeId);   
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in abnormal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in abnormal conditions, no DeferredVideoJobPtr added.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_003, TestSize.Level0)
{ 
    VideoJobQueue::Comparator comp = [](DeferredVideoJobPtr videoJbPtr1, DeferredVideoJobPtr videoJbPtr2) {
        return *videoJbPtr1 > *videoJbPtr2;
    };
    std::shared_ptr<VideoJobQueue> videoJbQuePtr = std::make_shared<VideoJobQueue>(comp);
    ASSERT_NE(videoJbQuePtr, nullptr);

    EXPECT_EQ(videoJbQuePtr->Peek(), nullptr);
    EXPECT_EQ(videoJbQuePtr->Pop(), nullptr);
    EXPECT_EQ(videoJbQuePtr->GetAllElements().size(), 0);
    videoJbQuePtr->Clear();
    EXPECT_TRUE(videoJbQuePtr->heap_.empty());
    EXPECT_TRUE(videoJbQuePtr->indexMap_.empty());
    EXPECT_TRUE(videoJbQuePtr->IsEmpty());
    EXPECT_EQ(videoJbQuePtr->GetSize(), 0);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal conditions.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal conditions,
 *                  four DeferredVideoJobPtr to be added.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_004, TestSize.Level0)
{
    std::string videoId1 = "videoTest1";
    std::string videoId2 = "videoTest2";
    std::string videoId3 = "videoTest3";
    std::string videoId4 = "videoTest4";

    DeferredVideoJobPtr videoJbPtr1 = CreateTestDeferredVideoJobPtr(videoId1, VideoJobStatus::NONE);
    DeferredVideoJobPtr videoJbPtr2 = CreateTestDeferredVideoJobPtr(videoId2, VideoJobStatus::PAUSE);
    DeferredVideoJobPtr videoJbPtr3 = CreateTestDeferredVideoJobPtr(videoId3, VideoJobStatus::PENDING);
    DeferredVideoJobPtr videoJbPtr4 = CreateTestDeferredVideoJobPtr(videoId4, VideoJobStatus::FAILED);

    VideoJobQueue::Comparator comp = [](DeferredVideoJobPtr videoJbPtr1, DeferredVideoJobPtr videoJbPtr2) {
        return *videoJbPtr1 > *videoJbPtr2;
    };
    std::shared_ptr<VideoJobQueue> videoJbQuePtr = std::make_shared<VideoJobQueue>(comp);
    ASSERT_NE(videoJbQuePtr, nullptr);

    videoJbQuePtr->Push(videoJbPtr4);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId4);
    videoJbQuePtr->Push(videoJbPtr3);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId3);
    videoJbQuePtr->Push(videoJbPtr2);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId2);
    videoJbQuePtr->Push(videoJbPtr1);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId1);
    videoJbPtr1->SetJobStatus(VideoJobStatus::PENDING);
    videoJbPtr2->SetJobStatus(VideoJobStatus::FAILED);
    videoJbPtr3->SetJobStatus(VideoJobStatus::PAUSE);
    videoJbPtr4->SetJobStatus(VideoJobStatus::NONE);

    videoJbQuePtr->Update(videoJbPtr1);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId3);
    videoJbQuePtr->Update(videoJbPtr2);
    EXPECT_EQ(videoJbQuePtr->heap_.back()->GetVideoId(), videoId2);
    videoJbQuePtr->Update(videoJbPtr3);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId4);
    videoJbQuePtr->Update(videoJbPtr4);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId4);
    videoJbQuePtr->Update(videoJbPtr2);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId4);

    videoJbQuePtr->Remove(videoJbPtr1);
    EXPECT_EQ(videoJbQuePtr->heap_.size(), 3);
    EXPECT_EQ(videoJbQuePtr->heap_.back()->GetVideoId(), videoId2);
    EXPECT_EQ(videoJbQuePtr->Pop()->GetVideoId(), videoId4);
    ASSERT_TRUE(videoJbQuePtr->indexMap_.find(videoJbPtr3) != videoJbQuePtr->indexMap_.end());
    videoJbQuePtr->indexMap_.erase(videoJbPtr3);
    videoJbQuePtr->Swap(0, 1);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId2);
    videoJbQuePtr->Swap(0, 1);
    EXPECT_EQ(videoJbQuePtr->Peek()->GetVideoId(), videoId3);
    videoJbQuePtr->Remove(videoJbPtr2);
    EXPECT_TRUE(videoJbQuePtr->indexMap_.empty());
    videoJbQuePtr->Clear();
    EXPECT_TRUE(videoJbQuePtr->heap_.empty());
}

/*
 * Feature: Framework
 * Function: Test functions in class VideoJobRepository when there is no job.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test functions in class VideoJobRepository in abnormal condition, no job added.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_005, TestSize.Level0)
{
    std::string videoId = "videoTest";
    std::shared_ptr<VideoJobRepository> videoJR = std::make_shared<VideoJobRepository>(g_userId);
    ASSERT_NE(videoJR, nullptr);

    EXPECT_EQ(videoJR->GetJobUnLocked(videoId), nullptr);
    EXPECT_EQ(videoJR->GetRunningJobCounts(), 0);
    std::vector<std::string> runningList;
    videoJR->GetRunningJobList(runningList);
    EXPECT_TRUE(runningList.empty());
    EXPECT_EQ(videoJR->GetJob(), nullptr);

    EXPECT_FALSE(videoJR->RemoveVideoJob(videoId, true));
    videoJR->RestoreVideoJob(videoId);
    videoJR->SetJobPending(videoId);
    videoJR->SetJobRunning(videoId);
    videoJR->SetJobCompleted(videoId);
    videoJR->RegisterJobListener(std::weak_ptr<IVideoJobRepositoryListener>());
    videoJR->SetJobFailed(videoId);
    videoJR->SetJobPause(videoId);
    videoJR->SetJobError(videoId);
    EXPECT_EQ(videoJR->GetJob(), nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions in class VideoJobRepository in normal condition.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test functions in class VideoJobRepository in abnormal condition, one test job added.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_006, TestSize.Level0)
{
    std::string videoId = "videoTest";
    std::shared_ptr<VideoJobRepository> videoJR = std::make_shared<VideoJobRepository>(g_userId);
    ASSERT_NE(videoJR, nullptr);

    videoJR->AddVideoJob(videoId, srcFd_, dstFd_);
    EXPECT_EQ(videoJR->GetJob()->GetVideoId(), videoId);
    videoJR->AddVideoJob(videoId, srcFd_, dstFd_);
    EXPECT_NE(videoJR->GetJobUnLocked(videoId), nullptr);
    EXPECT_EQ(videoJR->GetJob()->GetCurStatus(), VideoJobStatus::PENDING);

    EXPECT_FALSE(videoJR->RemoveVideoJob(videoId, true));
    EXPECT_EQ(videoJR->GetJob()->GetCurStatus(), VideoJobStatus::DELETED);
    videoJR->RestoreVideoJob(videoId);
    EXPECT_EQ(videoJR->GetJob()->GetCurStatus(), VideoJobStatus::PENDING);
    videoJR->SetJobPending(videoId);
    videoJR->RestoreVideoJob(videoId);
    EXPECT_EQ(videoJR->GetJob()->GetCurStatus(), VideoJobStatus::PENDING);
    videoJR->RegisterJobListener(std::weak_ptr<IVideoJobRepositoryListener>());
    videoJR->SetJobRunning(videoId);
    EXPECT_EQ(videoJR->GetJob(), nullptr);
    videoJR->SetJobRunning(videoId);
    EXPECT_EQ(videoJR->runningSet_.size(), 1);
    ASSERT_NE(videoJR->GetJobUnLocked(videoId), nullptr);
    EXPECT_EQ(videoJR->GetJobUnLocked(videoId)->GetCurStatus(), VideoJobStatus::RUNNING);
    videoJR->SetJobCompleted(videoId);
    EXPECT_EQ(videoJR->GetJobUnLocked(videoId)->GetPreStatus(), VideoJobStatus::RUNNING);
    EXPECT_EQ(videoJR->runningSet_.size(), 0);

    videoJR->SetJobCompleted(videoId);
    EXPECT_EQ(videoJR->GetJobUnLocked(videoId)->GetCurStatus(), VideoJobStatus::COMPLETED);
    videoJR->SetJobFailed(videoId);
    ASSERT_NE(videoJR->jobQueue_->Peek(), nullptr);
    EXPECT_EQ(videoJR->jobQueue_->Peek()->GetCurStatus(), VideoJobStatus::FAILED);
    EXPECT_EQ(videoJR->GetJob()->GetCurStatus(), VideoJobStatus::PENDING);

    videoJR->SetJobError(videoId);
    EXPECT_EQ(videoJR->GetJobUnLocked(videoId)->GetCurStatus(), VideoJobStatus::ERROR);
    videoJR->SetJobPause(videoId);
    EXPECT_EQ(videoJR->GetJobUnLocked(videoId)->GetCurStatus(), VideoJobStatus::PAUSE);
    videoJR->ClearCatch();
    EXPECT_TRUE(videoJR->jobQueue_->heap_.empty());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS