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

#include "deferred_photo_controller.h"
#include "deferred_photo_job_unittest.h"
#include "iphoto_job_repository_listener.h"
#include "photo_job_repository.h"


using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

const int DEFAULT_PHOTO_JOB_TYPE = 0;
const int TEST_PHOTO_JOB_TYPE = 1;
const std::string TEST_IMAGE_ID = "testImageId";
const int32_t USER_ID = 0;
void DeferredPhotoJobUnitTest::SetUpTestCase(void) {}

void DeferredPhotoJobUnitTest::TearDownTestCase(void) {}

void DeferredPhotoJobUnitTest::SetUp(void) {}

void DeferredPhotoJobUnitTest::TearDown(void)
{
    sessionManager_ = nullptr;
    callbacks_ = nullptr;
    taskManager_ = nullptr;
    photoProcessor_ = nullptr;
    photoController_ = nullptr;
}

void DeferredPhotoJobUnitTest::TestRegisterJobListener(
    std::shared_ptr<PhotoJobRepository> photoJR, const int32_t userId)
{
    std::string taskName = "test_taskmgr";
    uint32_t defaultThreadNumber = 4;

    sessionManager_ = SessionManager::Create();
    ASSERT_NE(sessionManager_, nullptr);
    callbacks_ = sessionManager_->GetImageProcCallbacks();
    ASSERT_NE(callbacks_, nullptr);
    taskManager_ = std::make_shared<TaskManager>(taskName, defaultThreadNumber, false);
    ASSERT_NE(taskManager_, nullptr);
    photoProcessor_ = std::make_shared<DeferredPhotoProcessor>(userId, taskManager_.get(), photoJR, callbacks_);
    ASSERT_NE(photoProcessor_, nullptr);
    photoController_ = std::make_shared<DeferredPhotoController>(userId, photoJR, photoProcessor_);
    ASSERT_NE(photoController_, nullptr);
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredPhotoJob.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredPhotoJob with test data to ensure the correctness.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_001, TestSize.Level0)
{
    bool testDiscardable = false;
    int32_t testSetDpsMetadataVal = 5;
    int32_t testGetDpsMetadataVal = 0;

    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, testSetDpsMetadataVal);
    metadata.Get(DEFERRED_PROCESSING_TYPE_KEY, testGetDpsMetadataVal);
    EXPECT_EQ(testGetDpsMetadataVal, testSetDpsMetadataVal);
    std::shared_ptr<DeferredPhotoJob> derferredPhotoJob =
        std::make_shared<DeferredPhotoJob>(TEST_IMAGE_ID, testDiscardable, metadata);

    ASSERT_NE(derferredPhotoJob, nullptr);
    EXPECT_EQ(derferredPhotoJob->GetDiscardable(), testDiscardable);
    EXPECT_EQ(derferredPhotoJob->GetImageId(), TEST_IMAGE_ID);

    EXPECT_EQ(derferredPhotoJob->GetCurPriority(), PhotoJobPriority::NONE);
    EXPECT_EQ(derferredPhotoJob->GetRunningPriority(), PhotoJobPriority::NONE);
    EXPECT_EQ(derferredPhotoJob->GetPrePriority(), PhotoJobPriority::NONE);

    EXPECT_FALSE(derferredPhotoJob->SetJobPriority(PhotoJobPriority::NONE));
    EXPECT_TRUE(derferredPhotoJob->SetJobPriority(PhotoJobPriority::LOW));
    EXPECT_EQ(derferredPhotoJob->GetCurPriority(), PhotoJobPriority::LOW);
    EXPECT_EQ(derferredPhotoJob->GetPrePriority(), PhotoJobPriority::NONE);
    derferredPhotoJob->RecordJobRunningPriority();
    EXPECT_EQ(derferredPhotoJob->GetRunningPriority(), PhotoJobPriority::LOW);

    EXPECT_EQ(derferredPhotoJob->GetCurStatus(), PhotoJobStatus::NONE);
    EXPECT_EQ(derferredPhotoJob->GetPreStatus(), PhotoJobStatus::NONE);

    EXPECT_FALSE(derferredPhotoJob->SetJobStatus(PhotoJobStatus::NONE));
    EXPECT_TRUE(derferredPhotoJob->SetJobStatus(PhotoJobStatus::RUNNING));
    EXPECT_EQ(derferredPhotoJob->GetCurStatus(), PhotoJobStatus::RUNNING);
    EXPECT_EQ(derferredPhotoJob->GetPreStatus(), PhotoJobStatus::NONE);

    EXPECT_EQ(derferredPhotoJob->GetPhotoJobType(), DEFAULT_PHOTO_JOB_TYPE);
    derferredPhotoJob->SetPhotoJobType(TEST_PHOTO_JOB_TYPE);
    EXPECT_EQ(derferredPhotoJob->GetPhotoJobType(), TEST_PHOTO_JOB_TYPE);

    EXPECT_EQ(derferredPhotoJob->GetDeferredProcType(), testSetDpsMetadataVal);
}

/*
 * Feature: Framework
 * Function: Test functions in class DeferredPhotoWork.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate the functions in class DeferredPhotoWork with test data to ensure the correctness.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_002, TestSize.Level0)
{
    bool testDiscardable = false;

    std::shared_ptr<DpsMetadata> metadata = std::make_shared<DpsMetadata>();
    ASSERT_NE(metadata, nullptr);
    std::shared_ptr<DeferredPhotoJob> derferredPhotoJob =
        std::make_shared<DeferredPhotoJob>(TEST_IMAGE_ID, testDiscardable, *metadata);
    ASSERT_NE(derferredPhotoJob, nullptr);
    derferredPhotoJob->SetPhotoJobType(TEST_PHOTO_JOB_TYPE);
    EXPECT_EQ(derferredPhotoJob->GetPhotoJobType(), TEST_PHOTO_JOB_TYPE);

    DeferredPhotoWorkPtr deferredPhotoWork =
        std::make_shared<DeferredPhotoWork>(derferredPhotoJob, ExecutionMode::HIGH_PERFORMANCE);
    ASSERT_NE(deferredPhotoWork, nullptr);

    EXPECT_EQ(deferredPhotoWork->GetExecutionMode(), ExecutionMode::HIGH_PERFORMANCE);
    EXPECT_EQ(deferredPhotoWork->GetDeferredPhotoJob()->GetPhotoJobType(), TEST_PHOTO_JOB_TYPE);
}

/*
 * Feature: Framework
 * Function: Test PhotoJobRepository::RegisterJobListener.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Register a listener to the job queue.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_003, TestSize.Level0)
{
    TestPhotoJob jobTest("image_test", DeferredProcessingType::DPS_OFFLINE);

    std::shared_ptr<PhotoJobRepository> photoJR = std::make_shared<PhotoJobRepository>(USER_ID);
    ASSERT_NE(photoJR, nullptr);
    EXPECT_EQ(photoJR->GetRunningJobCounts(), 0);
    EXPECT_EQ(photoJR->GetBackgroundJobSize(), 0);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 0);
    EXPECT_FALSE(photoJR->IsOfflineJob(TEST_IMAGE_ID));
    EXPECT_FALSE(photoJR->HasUnCompletedBackgroundJob());

    TestRegisterJobListener(photoJR, USER_ID);
    ASSERT_NE(photoJR, nullptr);
    EXPECT_NE(photoJR->jobListeners_.size(), 0);

    photoJR->AddDeferredJob(jobTest.imageId_, false, jobTest.metadata_);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 1);
}

/*
 * Feature: Framework
 * Function: Test functions in class PhotoJobRepository when there is no defeferred job.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test functions in class PhotoJobRepository in abnormal condition, no deferred job added.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_004, TestSize.Level0)
{
    std::shared_ptr<PhotoJobRepository> photoJR = std::make_shared<PhotoJobRepository>(USER_ID);
    ASSERT_NE(photoJR, nullptr);

    EXPECT_EQ(photoJR->GetJobUnLocked(TEST_IMAGE_ID), nullptr);
    photoJR->RemoveDeferredJob(TEST_IMAGE_ID, true);
    photoJR->RequestJob(TEST_IMAGE_ID);
    photoJR->CancelJob(TEST_IMAGE_ID);
    photoJR->RestoreJob(TEST_IMAGE_ID);
    photoJR->SetJobPending(TEST_IMAGE_ID);
    photoJR->SetJobRunning(TEST_IMAGE_ID);
    photoJR->SetJobCompleted(TEST_IMAGE_ID);
    photoJR->SetJobFailed(TEST_IMAGE_ID);
    EXPECT_EQ(photoJR->GetJobStatus(TEST_IMAGE_ID), PhotoJobStatus::NONE);
    EXPECT_EQ(photoJR->GetJobRunningPriority(TEST_IMAGE_ID), PhotoJobPriority::NONE);
    EXPECT_EQ(photoJR->GetJobPriority(TEST_IMAGE_ID), PhotoJobPriority::NONE);
    EXPECT_EQ(photoJR->GetJobUnLocked(TEST_IMAGE_ID), nullptr);
}

/*
 * Feature: Framework
 * Function: Test AddDeferredJob and RemoveDeferredJob in class PhotoJobRepository.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate AddDeferredJob and RemoveDeferredJob with test data,
 *                  DeferredProcessingType is DPS_OFFLINE, to ensure the correctness.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_005, TestSize.Level0)
{
    TestPhotoJob jobTest("image_test", DeferredProcessingType::DPS_OFFLINE);
    std::shared_ptr<PhotoJobRepository> photoJR = std::make_shared<PhotoJobRepository>(USER_ID);
    ASSERT_NE(photoJR, nullptr);

    photoJR->AddDeferredJob(jobTest.imageId_, false, jobTest.metadata_);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 1);
    photoJR->AddDeferredJob(jobTest.imageId_, false, jobTest.metadata_);
    EXPECT_NE(photoJR->GetJobUnLocked(jobTest.imageId_), nullptr);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 1);
    EXPECT_TRUE(photoJR->IsOfflineJob(jobTest.imageId_));
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::NORMAL);

    photoJR->RemoveDeferredJob(jobTest.imageId_, true);
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::LOW);
    std::shared_ptr<DeferredPhotoJob> jobPtr;
    jobPtr = photoJR->GetLowPriorityJob();
    ASSERT_NE(jobPtr, nullptr);
    EXPECT_EQ(photoJR->GetNormalPriorityJob(), nullptr);
    EXPECT_EQ(jobPtr->GetCurStatus(), PhotoJobStatus::PENDING);
    EXPECT_EQ(jobPtr->GetCurPriority(), PhotoJobPriority::LOW);
    jobPtr->SetJobStatus(PhotoJobStatus::FAILED);
    jobPtr = photoJR->GetLowPriorityJob();
    ASSERT_NE(jobPtr, nullptr);
    EXPECT_EQ(jobPtr->GetImageId(), jobTest.imageId_);
    photoJR->SetJobCompleted(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobStatus(jobTest.imageId_), PhotoJobStatus::COMPLETED);
    EXPECT_EQ(photoJR->GetLowPriorityJob(), nullptr);

    photoJR->offlineJobList_.clear();
    photoJR->RemoveDeferredJob(jobTest.imageId_, false);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 0);
}

/*
 * Feature: Framework
 * Function: Test RestoreJob, RequestJob and CancelJob in class PhotoJobRepository.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate RestoreJob, RequestJob and CancelJob with test data,
 *                  DeferredProcessingType is DPS_OFFLINE, to ensure the correctness.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_006, TestSize.Level0)
{
    TestPhotoJob jobTest("image_test", DeferredProcessingType::DPS_OFFLINE);
    std::shared_ptr<PhotoJobRepository> photoJR = std::make_shared<PhotoJobRepository>(USER_ID);
    ASSERT_NE(photoJR, nullptr);

    photoJR->jobListeners_.push_back(std::weak_ptr<IPhotoJobRepositoryListener>());
    photoJR->AddDeferredJob(jobTest.imageId_, false, jobTest.metadata_);
    photoJR->RemoveDeferredJob(jobTest.imageId_, true);
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::LOW);

    photoJR->RestoreJob(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::NORMAL);
    photoJR->SetJobPending(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobStatus(jobTest.imageId_), PhotoJobStatus::PENDING);
    std::shared_ptr<DeferredPhotoJob> jobPtr;
    jobPtr = photoJR->GetNormalPriorityJob();
    ASSERT_NE(jobPtr, nullptr);
    EXPECT_EQ(jobPtr->GetImageId(), jobTest.imageId_);
    photoJR->SetJobFailed(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobStatus(jobTest.imageId_), PhotoJobStatus::FAILED);
    jobPtr = photoJR->GetNormalPriorityJob();
    ASSERT_NE(jobPtr, nullptr);
    EXPECT_EQ(jobPtr->GetImageId(), jobTest.imageId_);

    EXPECT_EQ(photoJR->GetJobRunningPriority(jobTest.imageId_), PhotoJobPriority::NONE);
    photoJR->SetJobRunning(jobTest.imageId_);
    EXPECT_EQ(photoJR->runningNum_, 1);
    photoJR->SetJobRunning(jobTest.imageId_);
    EXPECT_EQ(photoJR->runningNum_, 1);
    EXPECT_EQ(photoJR->GetJobRunningPriority(jobTest.imageId_), PhotoJobPriority::NORMAL);
    EXPECT_EQ(photoJR->GetNormalPriorityJob(), nullptr);

    photoJR->RequestJob(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::HIGH);
    EXPECT_EQ(jobPtr = photoJR->GetHighPriorityJob(), nullptr);
    photoJR->SetJobPending(jobTest.imageId_);
    EXPECT_EQ(photoJR->runningNum_, 0);
    photoJR->SetJobPending(jobTest.imageId_);
    EXPECT_EQ(photoJR->runningNum_, 0);
    jobPtr = photoJR->GetHighPriorityJob();
    ASSERT_NE(jobPtr, nullptr);
    EXPECT_EQ(jobPtr->GetImageId(), jobTest.imageId_);
    photoJR->SetJobFailed(jobTest.imageId_);
    photoJR->RequestJob(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobStatus(jobTest.imageId_), PhotoJobStatus::PENDING);
    photoJR->RequestJob(jobTest.imageId_);
    ASSERT_NE(photoJR->jobQueue_.front(), nullptr);
    EXPECT_EQ(photoJR->jobQueue_.front()->GetImageId(), jobTest.imageId_);

    photoJR->CancelJob(jobTest.imageId_);
    EXPECT_EQ(photoJR->GetJobPriority(jobTest.imageId_), PhotoJobPriority::NORMAL);
    photoJR->RemoveDeferredJob(jobTest.imageId_, false);
    EXPECT_EQ(photoJR->GetOfflineJobSize(), 0);
}

/*
 * Feature: Framework
 * Function: Test AddDeferredJob and RemoveDeferredJob in class PhotoJobRepository.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate AddDeferredJob and RemoveDeferredJob with test data,
 *                  DeferredProcessingType is DPS_BACKGROUND, to ensure the correctness.
 */
HWTEST_F(DeferredPhotoJobUnitTest, deferred_photo_job_unittest_007, TestSize.Level0)
{
    TestPhotoJob jobTest("image_test", DeferredProcessingType::DPS_BACKGROUND);

    std::shared_ptr<PhotoJobRepository> photoJR = std::make_shared<PhotoJobRepository>(USER_ID);
    ASSERT_NE(photoJR, nullptr);

    photoJR->AddDeferredJob(jobTest.imageId_, false, jobTest.metadata_);
    EXPECT_EQ(photoJR->GetBackgroundJobSize(), 1);
    EXPECT_FALSE(photoJR->IsOfflineJob(jobTest.imageId_));
    
    EXPECT_TRUE(photoJR->HasUnCompletedBackgroundJob());
    photoJR->RemoveDeferredJob(jobTest.imageId_, false);
    EXPECT_FALSE(photoJR->HasUnCompletedBackgroundJob());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS