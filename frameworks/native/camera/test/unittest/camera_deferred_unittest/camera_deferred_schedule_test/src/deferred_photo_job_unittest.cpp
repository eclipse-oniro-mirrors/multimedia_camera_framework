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

#include "deferred_photo_job_unittest.h"

#include "basic_definitions.h"
#include "dp_utils.h"
#include "gtest/gtest.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t USER_ID = 0;
    const std::string TEST_IMAGE_1 = "testImage1";
    const std::string TEST_IMAGE_2 = "testImage2";
    const std::string TEST_IMAGE_3 = "testImage3";
    const std::string TEST_IMAGE_4 = "testImage4";
    constexpr int32_t WAIT_TIME_AFTER_CAPTURE = 10;
}

void DeferredPhotoJobUnitTest::SetUpTestCase(void) {}

void DeferredPhotoJobUnitTest::TearDownTestCase(void) {}

void DeferredPhotoJobUnitTest::SetUp(void)
{
    jobQueue_ = std::make_unique<PhotoJobQueue>(
        [] (const DeferredPhotoJobPtr& a, const DeferredPhotoJobPtr& b) {return *a > *b;});
}

void DeferredPhotoJobUnitTest::TearDown(void) {}

void mssleep(unsigned long ms)
{
	struct timespec ts = {
		.tv_sec  = (long int) (ms / 1000),
		.tv_nsec = (long int) (ms % 1000) * 1000000ul
	};
	nanosleep(&ts, 0);
}

class JobStateChangeListenerMock : public IJobStateChangeListener {
public:
    JobStateChangeListenerMock() = default;
    ~JobStateChangeListenerMock() = default;

    void UpdateRunningJob(const std::string& imageId, bool running)
    {
        DP_DEBUG_LOG("entered.");
    }

    void UpdatePriorityJob(JobPriority cur, JobPriority pre)
    {
        DP_DEBUG_LOG("entered.");
    }

    void UpdateJobSize()
    {
        DP_DEBUG_LOG("entered.");
    }

    void TryDoNextJob(const std::string& imageId, bool isTyrDo)
    {
        DP_DEBUG_LOG("entered.");
    }
};

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_001, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    EXPECT_EQ(jobQueue_->GetSize(), 1);
    jobQueue_->Push(job2);
    EXPECT_EQ(jobQueue_->GetSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_002, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    EXPECT_EQ(jobQueue_->GetSize(), 1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    job = jobQueue_->Pop();
    EXPECT_EQ(job, job1);
    EXPECT_EQ(jobQueue_->IsEmpty(), true);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_003, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_004, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    auto ret = jobQueue_->Contains(job2);
    EXPECT_EQ(ret, true);
    ret = jobQueue_->Contains(job4);
    EXPECT_EQ(ret, false);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_005, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
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

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_006, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);

    jobQueue_->Remove(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);
    EXPECT_EQ(jobQueue_->GetSize(), 3);
    jobQueue_->Remove(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_007, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);

    job1->Prepare();
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_008, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);

    job1->Complete();
    jobQueue_->Update(job1);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_009, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    job2->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    mssleep(WAIT_TIME_AFTER_CAPTURE);
    job4->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);

    job4->Complete();
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);

    jobQueue_->Remove(job4);
    job4->Delete();
    EXPECT_EQ(jobQueue_->GetSize(), 3);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_010, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    job2->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job2);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job2->SetJobPriority(JobPriority::LOW);
    jobQueue_->Update(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_011, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    job4->Fail();
    jobQueue_->Update(job4);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);

    jobQueue_->Pop();
    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_012, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    job1->Error();
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    jobQueue_->Pop();
    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_013, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job1);
    job->Start(1);
    jobQueue_->Update(job);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    jobQueue_->Pop();
    jobQueue_->Pop();
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_014, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    job1->Start(1);
    jobQueue_->Update(job1);
    auto job = jobQueue_->Peek();
    EXPECT_EQ(job, job2);

    job2->Complete();
    jobQueue_->Update(job2);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job1->Complete();
    jobQueue_->Update(job1);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job4->Start(2);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_queue_unittest_015, TestSize.Level0)
{
    auto listener = std::make_shared<JobStateChangeListenerMock>();
    DeferredPhotoJobPtr job1 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_1, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job1);
    job1->Prepare();
    jobQueue_->Update(job1);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job2 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_2, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job2);
    job2->Prepare();
    jobQueue_->Update(job2);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job3 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_3, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job3);
    job3->Prepare();
    jobQueue_->Update(job3);
    mssleep(WAIT_TIME_AFTER_CAPTURE);
    DeferredPhotoJobPtr job4 = std::make_shared<DeferredPhotoJob>(TEST_IMAGE_4, PhotoJobType::OFFLINE, true, listener);
    jobQueue_->Push(job4);
    job4->Prepare();
    jobQueue_->Update(job4);

    auto job = jobQueue_->Peek();
    job->Start(1);
    jobQueue_->Update(job);
    EXPECT_EQ(job, job1);

    job = jobQueue_->Peek();
    job->Complete();
    jobQueue_->Update(job);
    EXPECT_EQ(job, job2);

    job = jobQueue_->Peek();
    EXPECT_EQ(job, job3);

    job4->SetJobPriority(JobPriority::HIGH);
    jobQueue_->Update(job4);
    job = jobQueue_->Peek();
    EXPECT_EQ(job, job4);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_001, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_002, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->backgroundJobMap_.size(), 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_003, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_3, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_004, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RequestJob(TEST_IMAGE_2);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::HIGH)->second, 1);
    repository->CancelJob(TEST_IMAGE_2);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::HIGH)->second, 0);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_005, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RequestJob(TEST_IMAGE_1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::HIGH)->second, 1);
    repository->CancelJob(TEST_IMAGE_2);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::HIGH)->second, 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_006, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RequestJob(TEST_IMAGE_3);
    repository->CancelJob(TEST_IMAGE_3);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_007, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_1, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_008, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_3, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_009, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_1, false);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::HIGH)->second, 0);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_010, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_3, false);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_011, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_1, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 1);
    repository->RemoveDeferredJob(TEST_IMAGE_1, false);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_012, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_3, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    repository->RemoveDeferredJob(TEST_IMAGE_3, false);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_013, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_1, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 1);
    repository->RestoreJob(TEST_IMAGE_1);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_014, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 2);
    repository->RemoveDeferredJob(TEST_IMAGE_3, true);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    repository->RestoreJob(TEST_IMAGE_3);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::LOW)->second, 0);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_015, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    EXPECT_EQ(repository->offlineJobQueue_->GetSize(), 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_016, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->priotyToNum_.find(JobPriority::NORMAL)->second, 1);
    auto job = repository->GetJob();
    ASSERT_NE(job, nullptr);
    job->Start(1);
    job = repository->GetJob();
    ASSERT_EQ(job, nullptr);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_017, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_3, true, metadata);
    auto job1 = repository->GetJob();
    ASSERT_NE(job1, nullptr);
    job1->Start(1);
    EXPECT_EQ(job1->GetCurStatus(), JobState::RUNNING);
    auto job2 = repository->GetJob();
    job2->Complete();
    EXPECT_EQ(job2->GetCurStatus(), JobState::COMPLETED);
    ASSERT_NE(job1, job2);
    auto job3 = repository->GetJob();
    EXPECT_EQ(job3->GetImageId(), TEST_IMAGE_3);
    EXPECT_EQ(job3->GetCurPriority(), JobPriority::NORMAL);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_018, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_3, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_4, true, metadata);
    repository->RequestJob(TEST_IMAGE_1);
    auto job1 = repository->GetJob();
    EXPECT_EQ(job1->GetImageId(), TEST_IMAGE_1);
    job1->Fail();
    EXPECT_EQ(job1->GetCurStatus(), JobState::FAILED);
    auto job2 = repository->GetJob();
    EXPECT_EQ(job2->GetImageId(), TEST_IMAGE_2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_019, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_3, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_4, true, metadata);
    repository->RequestJob(TEST_IMAGE_2);
    auto job1 = repository->GetJob();
    EXPECT_EQ(job1->GetImageId(), TEST_IMAGE_2);

    mssleep(WAIT_TIME_AFTER_CAPTURE);
    repository->RequestJob(TEST_IMAGE_1);
    auto job2 = repository->GetJob();
    EXPECT_EQ(job2->GetImageId(), TEST_IMAGE_1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_020, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    auto job1 = repository->GetJob();
    ASSERT_EQ(job1, nullptr);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_021, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    auto job1 = repository->GetJobUnLocked(TEST_IMAGE_1);
    ASSERT_NE(job1, nullptr);

    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    auto job2 = repository->GetJobUnLocked(TEST_IMAGE_2);
    ASSERT_NE(job2, nullptr);

    auto job3 = repository->GetJobUnLocked(TEST_IMAGE_3);
    ASSERT_EQ(job3, nullptr);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_022, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);

    auto state = repository->GetJobState(TEST_IMAGE_1);
    EXPECT_EQ(state, JobState::PENDING);
    state = repository->GetJobState(TEST_IMAGE_2);
    EXPECT_EQ(state, JobState::PENDING);
    state = repository->GetJobState(TEST_IMAGE_3);
    EXPECT_EQ(state, JobState::NONE);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_023, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);

    auto priority = repository->GetJobPriority(TEST_IMAGE_1);
    EXPECT_EQ(priority, JobPriority::NORMAL);
    priority = repository->GetJobPriority(TEST_IMAGE_2);
    EXPECT_EQ(priority, JobPriority::HIGH);
    priority = repository->GetJobPriority(TEST_IMAGE_3);
    EXPECT_EQ(priority, JobPriority::NONE);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_024, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);

    auto priority = repository->GetJobPriority(TEST_IMAGE_1);
    EXPECT_EQ(priority, JobPriority::NORMAL);
    priority = repository->GetJobPriority(TEST_IMAGE_2);
    EXPECT_EQ(priority, JobPriority::HIGH);
    priority = repository->GetJobPriority(TEST_IMAGE_3);
    EXPECT_EQ(priority, JobPriority::NONE);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_025, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);

    auto priority = repository->GetJobRunningPriority(TEST_IMAGE_1);
    EXPECT_EQ(priority, JobPriority::NORMAL);
    priority = repository->GetJobRunningPriority(TEST_IMAGE_2);
    EXPECT_EQ(priority, JobPriority::NORMAL);
    priority = repository->GetJobRunningPriority(TEST_IMAGE_3);
    EXPECT_EQ(priority, JobPriority::NONE);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_026, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    auto timeId = repository->GetJobTimerId(TEST_IMAGE_1);
    EXPECT_EQ(timeId, 0);
    auto job = repository->GetJob();
    job->Start(1);
    timeId = repository->GetJobTimerId(TEST_IMAGE_1);
    EXPECT_EQ(timeId, 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_027, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    auto size = repository->GetBackgroundJobSize();
    EXPECT_EQ(size, 1);
    size = repository->GetOfflineJobSize();
    EXPECT_EQ(size, 1);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_028, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_3, true, metadata);
    repository->AddDeferredJob(TEST_IMAGE_4, true, metadata);
    auto job1 = repository->GetJobUnLocked(TEST_IMAGE_1);
    job1->Complete();
    auto job2 = repository->GetJobUnLocked(TEST_IMAGE_2);
    job2->Delete();
    EXPECT_EQ(repository->GetOfflineJobSize(), 4);
    EXPECT_EQ(repository->GetOfflineIdleJobSize(), 2);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_029, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->IsBackgroundJob(TEST_IMAGE_1), false);
    EXPECT_EQ(repository->IsBackgroundJob(TEST_IMAGE_2), true);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_030, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    repository->AddDeferredJob(TEST_IMAGE_2, true, metadata);
    EXPECT_EQ(repository->HasUnCompletedBackgroundJob(), true);
    auto job = repository->GetJobUnLocked(TEST_IMAGE_2);
    job->Complete();
    EXPECT_EQ(repository->HasUnCompletedBackgroundJob(), false);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_031, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    auto job = repository->GetJob();
    job->Start(1);
    EXPECT_EQ(repository->IsHighJob(TEST_IMAGE_1), false);
    EXPECT_EQ(repository->IsNeedInterrupt(), true);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_032, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->RequestJob(TEST_IMAGE_1);
    auto job = repository->GetJob();
    job->Start(1);
    EXPECT_EQ(repository->IsHighJob(TEST_IMAGE_1), true);
    EXPECT_EQ(repository->IsNeedInterrupt(), false);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_033, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(repository->IsRunningJob(TEST_IMAGE_1), false);
    auto job = repository->GetJob();
    job->Start(1);
    EXPECT_EQ(repository->IsRunningJob(TEST_IMAGE_1), true);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_034, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->UpdateRunningJobUnLocked(TEST_IMAGE_1, true);
    EXPECT_EQ(repository->runningJob_.size(), 1);
    repository->UpdateRunningJobUnLocked(TEST_IMAGE_1, false);
    EXPECT_EQ(repository->runningJob_.size(), 0);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_035, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    repository->UpdatePriotyNumUnLocked(JobPriority::NORMAL, JobPriority::NONE);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::NORMAL], 1);
    repository->UpdatePriotyNumUnLocked(JobPriority::HIGH, JobPriority::NORMAL);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::HIGH], 1);
    repository->UpdatePriotyNumUnLocked(JobPriority::LOW, JobPriority::HIGH);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::LOW], 1);

    repository->UpdatePriotyNumUnLocked(JobPriority::NONE, JobPriority::LOW);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::LOW], 0);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::HIGH], 0);
    EXPECT_EQ(repository->priotyToNum_[JobPriority::NORMAL], 0);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_036, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    repository->UpdateJobSizeUnLocked();
    repository->NotifyJobChanged(TEST_IMAGE_1, true);
    repository->NotifyJobChanged(TEST_IMAGE_1, false);
    EXPECT_EQ(repository->runningJob_.size(), 0);
}

HWTEST_F(DeferredPhotoJobUnitTest, photo_job_repository_unittest_037, TestSize.Level0)
{
    auto repository = PhotoJobRepository::Create(USER_ID);
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    repository->AddDeferredJob(TEST_IMAGE_1, true, metadata);
    auto job = repository->GetJob();
    repository->ReportEvent(nullptr, IDeferredPhotoProcessingSessionIpcCode::COMMAND_BEGIN_SYNCHRONIZE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_END_SYNCHRONIZE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_ADD_IMAGE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_REMOVE_IMAGE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_RESTORE_IMAGE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_PROCESS_IMAGE);
    repository->ReportEvent(job, IDeferredPhotoProcessingSessionIpcCode::COMMAND_CANCEL_PROCESS_IMAGE);
    EXPECT_EQ(repository->GetOfflineJobSize(), 1);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS