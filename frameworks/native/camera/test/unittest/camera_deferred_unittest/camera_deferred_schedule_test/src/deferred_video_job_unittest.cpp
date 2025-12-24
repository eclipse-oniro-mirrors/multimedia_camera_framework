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

#include "deferred_video_job_unittest.h"

#include <fcntl.h>

#include "deferred_utils_unittest.h"
#include "deferred_video_job.h"
#include "ipc_file_descriptor.h"
#include "video_job_queue.h"
#include "video_job_repository.h"


using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH = MEDIA_ROOT + "test_video_temp.mp4";
    const int32_t USER_ID = 0;
    const std::string VIDEO_ID_1 = "testVideo1";
    const std::string VIDEO_ID_2 = "testVideo2";
    const std::string VIDEO_ID_3 = "testVideo3";
    const std::string VIDEO_ID_4 = "testVideo4";
    constexpr int32_t WAIT_TIME_AFTER_CAPTURE = 10;
}

void DeferredVideoJobUnitTest::SetUpTestCase(void) {}

void DeferredVideoJobUnitTest::TearDownTestCase(void) {}

void DeferredVideoJobUnitTest::SetUp(void)
{
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    dtsFd_ = open(VIDEO_TEMP_PATH.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    jobQueue_ = std::make_unique<VideoJobQueue>(
        [] (const DeferredVideoJobPtr& a, const DeferredVideoJobPtr& b) {return *a > *b;});
}

void DeferredVideoJobUnitTest::TearDown(void)
{
    jobQueue_->Clear();
    if (srcFd_ > 0) {
        close(srcFd_);
    }
    if (dtsFd_ > 0) {
        close(dtsFd_);
    }
}

DeferredVideoJobPtr DeferredVideoJobUnitTest::CreateTestDeferredVideoJobPtr(
    const std::string& videoId, VideoJobState curStatus)
{
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, inputFd, outFd, nullptr, nullptr);
    if (jobPtr == nullptr) {
        return nullptr;
    }
    jobPtr->SetJobState(curStatus);
    return jobPtr;
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredVideoJob with test data to Push.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_001, TestSize.Level0)
{
    std::shared_ptr<DeferredVideoJob> videoJobA = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    std::shared_ptr<DeferredVideoJob> videoJobB = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(videoJobA);
    EXPECT_EQ(jobQueue_->GetSize(), 1);
    jobQueue_->Push(videoJobB);
    EXPECT_EQ(jobQueue_->GetSize(), 2);
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredVideoJob with test data to Pop.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_002, TestSize.Level0)
{
    std::shared_ptr<DeferredVideoJob> videoJob = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(videoJob);
    EXPECT_EQ(jobQueue_->GetSize(), 1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, videoJob);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, videoJob);
    EXPECT_EQ(jobQueue_->IsEmpty(), true);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch.
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_003, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_004, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);

    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    auto ret = jobQueue_->Contains(job2);
    EXPECT_EQ(ret, true);
    ret = jobQueue_->Contains(job4);
    EXPECT_EQ(ret, false);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_005, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);

    jobQueue_->Remove(job3);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    jobQueue_->Remove(job1);
    EXPECT_EQ(jobQueue_->GetSize(), 2);
    jobQueue_->Remove(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_006, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    
    jobQueue_->Remove(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);
    EXPECT_EQ(jobQueue_->GetSize(), 3);
    jobQueue_->Remove(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_007, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_008, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);

    job1->SetJobState(VideoJobState::COMPLETED);
    jobQueue_->Update(job1);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_009, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job2->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job4->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);

    job4->SetJobState(VideoJobState::COMPLETED);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    jobQueue_->Remove(job4);
    job4->SetJobState(VideoJobState::DELETED);
    EXPECT_EQ(jobQueue_->GetSize(), 3);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_010, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job2->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job2->SetJobPriority(JobPriority::NORMAL);
    jobQueue_->Update(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_011, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job2->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job2->SetJobPriority(JobPriority::NORMAL);
    jobQueue_->Update(job2);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, job1);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, job3);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, job4);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, job2);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_012, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job4->SetJobState(VideoJobState::FAILED);
    jobQueue_->Update(job4);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);

    jobQueue_->Pop();
    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_013, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job1->SetJobState(VideoJobState::ERROR);
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    jobQueue_->Pop();
    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_014, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    job->SetJobState(VideoJobState::RUNNING);
    jobQueue_->Update(job);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_015, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    job1->SetJobState(VideoJobState::RUNNING);
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job2->SetJobState(VideoJobState::COMPLETED);
    jobQueue_->Update(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job1->SetJobState(VideoJobState::COMPLETED);
    jobQueue_->Update(job1);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job4->SetJobState(VideoJobState::RUNNING);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobQueue in normal branch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobQueue in normal branch
 */
HWTEST_F(DeferredVideoJobUnitTest, deferred_video_job_unittest_016, TestSize.Level0)
{
    DeferredVideoJobPtr job1 = CreateTestDeferredVideoJobPtr(VIDEO_ID_1, VideoJobState::NONE);
    jobQueue_->Push(job1);
    job1->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job1);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job2 = CreateTestDeferredVideoJobPtr(VIDEO_ID_2, VideoJobState::NONE);
    jobQueue_->Push(job2);
    job2->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job2);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job3 = CreateTestDeferredVideoJobPtr(VIDEO_ID_3, VideoJobState::NONE);
    jobQueue_->Push(job3);
    job3->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job3);
    DeferredUtilsUnitTest::mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredVideoJobPtr job4 = CreateTestDeferredVideoJobPtr(VIDEO_ID_4, VideoJobState::NONE);
    jobQueue_->Push(job4);
    job4->SetJobState(VideoJobState::PENDING);
    jobQueue_->Update(job4);

    auto job = jobQueue_->Peek();
    job->SetJobState(VideoJobState::RUNNING);
    jobQueue_->Update(job);
    EXPECT_EQ(job, job1);

    job = jobQueue_->Peek();
    job->SetJobState(VideoJobState::COMPLETED);
    jobQueue_->Update(job);
    EXPECT_EQ(job, job2);

    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job4->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in AddVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in AddVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_001, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    EXPECT_EQ(repository->jobQueue_->GetSize(), 1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in AddMovieVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in AddMovieVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_002, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DpsFdPtr movieFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr movieCopyFd = std::make_shared<DpsFd>(dup(srcFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd, movieFd, movieCopyFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    EXPECT_EQ(repository->jobQueue_->GetSize(), 1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RequestJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RequestJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_003, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RequestJob(VIDEO_ID_1);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurPriority(), JobPriority::HIGH);
    repository->CancelJob(VIDEO_ID_1);
    EXPECT_EQ(job->GetCurPriority(), JobPriority::NORMAL);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RequestJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RequestJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_004, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RequestJob(VIDEO_ID_2);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurPriority(), JobPriority::NORMAL);
    repository->CancelJob(VIDEO_ID_2);
    EXPECT_EQ(job->GetCurPriority(), JobPriority::NORMAL);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RemoveVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RemoveVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_005, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RemoveVideoJob(VIDEO_ID_1, true);
    EXPECT_EQ(repository->jobQueue_->GetSize(), 1);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::DELETED);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RemoveVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RemoveVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_006, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RemoveVideoJob(VIDEO_ID_1, false);
    EXPECT_EQ(repository->jobQueue_->GetSize(), 0);
    auto job = repository->GetJob();
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RemoveVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RemoveVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_007, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RemoveVideoJob(VIDEO_ID_2, false);
    EXPECT_EQ(repository->jobQueue_->GetSize(), 1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in RestoreVideoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in RestoreVideoJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_008, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->RemoveVideoJob(VIDEO_ID_1, true);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::DELETED);
    repository->RestoreVideoJob(VIDEO_ID_1);
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobPending.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobPending
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_009, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobPending(VIDEO_ID_1);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobPending.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobPending
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_010, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobPending(VIDEO_ID_2);
    auto job = repository->GetJob();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobRunning.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobRunning
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_011, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobRunning(VIDEO_ID_1);
    auto job = repository->GetJob();
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobRunning.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobRunning
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_012, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobRunning(VIDEO_ID_2);
    auto job = repository->GetJob();
    EXPECT_NE(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobCompleted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobCompleted
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_013, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobCompleted(VIDEO_ID_1);
    auto job = repository->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::COMPLETED);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobCompleted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobCompleted
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_014, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobCompleted(VIDEO_ID_2);
    auto job = repository->GetJobUnLocked(VIDEO_ID_2);
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobCompleted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobCompleted
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_015, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobFailed(VIDEO_ID_1);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::FAILED);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobCompleted.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobCompleted
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_016, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobFailed(VIDEO_ID_2);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobPause.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobPause
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_017, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobPause(VIDEO_ID_1);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PAUSE);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobPause.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobPause
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_018, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobPause(VIDEO_ID_2);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobError.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobError
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_019, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobError(VIDEO_ID_1);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::ERROR);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in SetJobError.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in SetJobError
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_020, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobError(VIDEO_ID_2);
    auto job = repository->jobQueue_->Pop();
    EXPECT_EQ(job->GetCurStatus(), VideoJobState::PENDING);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in GetJobUnLocked.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in GetJobUnLocked
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_021, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    auto job = repository->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_NE(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in GetJobUnLocked.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in GetJobUnLocked
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_022, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    auto job = repository->GetJobUnLocked(VIDEO_ID_1);
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in GetJobTimerId.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in GetJobTimerId
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_023, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobPending(VIDEO_ID_1);
    auto job = repository->GetJob();
    job->SetTimerId(1);
    auto id = repository->GetJobTimerId(VIDEO_ID_1);
    EXPECT_EQ(id, 1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in GetJobTimerId.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in GetJobTimerId
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_024, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    auto id = repository->GetJobTimerId(VIDEO_ID_2);
    EXPECT_EQ(id, INVALID_TIMERID);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in GetRunningJobList.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in GetRunningJobList
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_025, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobRunning(VIDEO_ID_1);
    std::vector<std::string> list;
    repository->GetRunningJobList(list);
    EXPECT_EQ(list.size(), 1);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in HasRunningJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in HasRunningJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_026, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    EXPECT_EQ(repository->HasRunningJob(), false);
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID_1, info);
    repository->SetJobRunning(VIDEO_ID_1);
    repository->HasRunningJob();
    EXPECT_EQ(repository->HasRunningJob(), true);
}

/*
 * Feature: Framework
 * Function: Test functions of class VideoJobRepository in HasRunningJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class VideoJobRepository in HasRunningJob
 */
HWTEST_F(DeferredVideoJobUnitTest, video_job_repository_unittest_027, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(USER_ID);
    repository->NotifyJobChangedUnLocked(VIDEO_ID_1);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(VIDEO_ID_1, inputFd, outFd, nullptr, nullptr);
    jobPtr->SetJobState(VideoJobState::RUNNING);
    repository->UpdateRunningCountUnLocked(true, jobPtr);
    EXPECT_EQ(repository->runningSet_.size(), 1);

    jobPtr->SetJobState(VideoJobState::COMPLETED);
    repository->UpdateRunningCountUnLocked(true, jobPtr);
    EXPECT_EQ(repository->runningSet_.size(), 0);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS