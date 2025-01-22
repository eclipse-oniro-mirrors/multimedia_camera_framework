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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "dp_utils.h"
#include "ievents_listener.h"
#include "deferred_photo_controller.h"
#include "deferred_photo_processor.h"
#include "deferred_photo_processor_unittest.h"
#include "dps_metadata_info.h"
#include "basic_definitions.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

class DeferredPhotoProcessorCallbacks : public IImageProcessCallbacks {
public:
    explicit DeferredPhotoProcessorCallbacks() {}

    ~DeferredPhotoProcessorCallbacks() override {}

    void OnProcessDone(const int32_t userId, const std::string& imageId,
        const std::shared_ptr<BufferInfo>& bufferInfo) override {}

    void OnProcessDoneExt(int userId, const std::string& imageId,
        const std::shared_ptr<BufferInfoExt>& bufferInfo) override {}

    void OnError(const int userId, const std::string& imageId, DpsError errorCode) override {}

    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override {}
};

void DeferredPhotoProcessorUnittest::SetUpTestCase(void) {}

void DeferredPhotoProcessorUnittest::TearDownTestCase(void) {}

void DeferredPhotoProcessorUnittest::SetUp()
{
    NativeAuthorization();
}

void DeferredPhotoProcessorUnittest::TearDown() {}

void DeferredPhotoProcessorUnittest::NativeAuthorization()
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
 * Feature: Deferred
 * Function: Test eventsListener OnEventChange
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test after initialize eventsListener, backgroundStrategy status can be set by OnEventChange.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_001, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    auto listener = reinterpret_cast<IEventsListener*>(controller->eventsListener_.get());
    EXPECT_NE(listener, nullptr);
    controller->backgroundStrategy_->NotifyPressureLevelChanged(FAIR);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, NORMAL_CAMERA_CLOSED);
    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MEDIA_LIBRARY_AVAILABLE);
    EXPECT_EQ(controller->backgroundStrategy_->systemPressureLevel_, FAIR);
    listener->OnEventChange(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_OPEN);
    listener->OnEventChange(EventType::HDI_STATUS_EVENT, HDI_DISCONNECTED);
    listener->OnEventChange(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_DISCONNECTED);
    listener->OnEventChange(EventType::SCREEN_STATUS_EVENT, SCREEN_ON);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, SYSTEM_CAMERA_OPEN);
    EXPECT_EQ(controller->backgroundStrategy_->hdiStatus_, HDI_DISCONNECTED);
    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MEDIA_LIBRARY_DISCONNECTED);
}

/*
 * Feature: Deferred
 * Function: Test deferredPhotoController NotifyMediaLibStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the backgroundStrategy mediaLibraryStatus can be set by NotifyMediaLibStatusChanged.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_002, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MEDIA_LIBRARY_AVAILABLE);
    controller->NotifyMediaLibStatusChanged(MEDIA_LIBRARY_DISCONNECTED);
    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MEDIA_LIBRARY_DISCONNECTED);
    controller->NotifyMediaLibStatusChanged(MEDIA_LIBRARY_AVAILABLE);
    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MEDIA_LIBRARY_AVAILABLE);
}

/*
 * Feature: Deferred
 * Function: Test deferredPhotoController NotifyCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the backgroundStrategy cameraSessionStatus can be set by NotifyCameraStatusChanged.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_003, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, NORMAL_CAMERA_CLOSED);
    controller->NotifyCameraStatusChanged(SYSTEM_CAMERA_OPEN);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, SYSTEM_CAMERA_OPEN);
    controller->NotifyCameraStatusChanged(NORMAL_CAMERA_OPEN);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, NORMAL_CAMERA_OPEN);
    controller->NotifyCameraStatusChanged(SYSTEM_CAMERA_CLOSED);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, SYSTEM_CAMERA_CLOSED);
    controller->NotifyCameraStatusChanged(NORMAL_CAMERA_CLOSED);
    EXPECT_EQ(controller->backgroundStrategy_->cameraSessionStatus_, NORMAL_CAMERA_CLOSED);
}

/*
 * Feature: Deferred
 * Function: Test deferredPhotoController OnPhotoJobChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the deferredPhotoController isWaitForUser status can be set by OnPhotoJobChanged.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_004, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    auto metadata = std::make_shared<DpsMetadata>();
    EXPECT_NE(metadata, nullptr);
    auto job = std::make_shared<DeferredPhotoJob>("PhotoJob_imageid_" + std::to_string(userId_), true, *metadata);
    EXPECT_NE(job, nullptr);
    job->prePriority_ = PhotoJobPriority::NONE;
    job->preStatus_ = PhotoJobStatus::NONE;
    controller->OnPhotoJobChanged(false, false, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    controller->OnPhotoJobChanged(false, true, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    controller->OnPhotoJobChanged(true, false, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    controller->OnPhotoJobChanged(true, true, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    job->prePriority_ = PhotoJobPriority::NONE;
    job->preStatus_ = PhotoJobStatus::RUNNING;
    controller->OnPhotoJobChanged(true, true, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    job->prePriority_ = PhotoJobPriority::HIGH;
    job->preStatus_ = PhotoJobStatus::NONE;
    controller->OnPhotoJobChanged(true, true, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
    job->prePriority_ = PhotoJobPriority::HIGH;
    job->preStatus_ = PhotoJobStatus::RUNNING;
    controller->OnPhotoJobChanged(true, true, job);
    sleep(SLEEP_TIME_FOR_WATCH_DOG);
}

/*
 * Feature: Deferred
 * Function: Test deferredPhotoController NotifyScheduleState
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the deferredPhotoController scheduleState status can be set by NotifyScheduleState.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_005, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    auto metadata = std::make_shared<DpsMetadata>();
    EXPECT_NE(metadata, nullptr);
    auto job = std::make_shared<DeferredPhotoJob>("PhotoJob_imageid_" + std::to_string(userId_), true, *metadata);
    EXPECT_NE(job, nullptr);
    controller->photoJobRepository_->offlineJobMap_.emplace("PhotoJob_imageid_" + std::to_string(userId_), job);
    controller->backgroundStrategy_->NotifyHdiStatusChanged(HDI_DISCONNECTED);
    controller->photoJobRepository_->runningNum_ = 0;
    controller->photoJobRepository_->offlineJobMap_.clear();
    controller->photoJobRepository_->offlineJobMap_.emplace("PhotoJob_imageid_" + std::to_string(userId_), job);
    controller->backgroundStrategy_->NotifyHdiStatusChanged(HDI_READY);
}

/*
 * Feature: Deferred
 * Function: Test deferredPhotoController TryDoSchedule
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the deferredPhotoController scheduleState status can be set by TryDoSchedule.
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_006, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    controller->TryDoSchedule();
    controller->photoJobRepository_->runningNum_ = 1;
    controller->TryDoSchedule();
    auto metadata = std::make_shared<DpsMetadata>();
    EXPECT_NE(metadata, nullptr);
    auto job = std::make_shared<DeferredPhotoJob>("PhotoJob_imageid_" + std::to_string(userId_), true, *metadata);
    EXPECT_NE(job, nullptr);
    job->curStatus_ = PhotoJobStatus::PENDING;
    controller->photoJobRepository_->jobQueue_.push_front(job);
    controller->TryDoSchedule();
    controller->photoJobRepository_->runningNum_ = 1;
    controller->TryDoSchedule();
}

/*
 * Feature: Deferred
 * Function: Test DeferredPhotoProcessor IsFatalError
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsFatalError for different errorCode
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_007, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    DpsError errorCode = DpsError::DPS_ERROR_IMAGE_PROC_FAILED;
    EXPECT_TRUE(processor->IsFatalError(errorCode));
    errorCode = DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
    EXPECT_TRUE(processor->IsFatalError(errorCode));
    errorCode = DpsError::DPS_ERROR_SESSION_SYNC_NEEDED;
    EXPECT_FALSE(processor->IsFatalError(errorCode));
}

/*
 * Feature: Deferred
 * Function: Test NotifyMediaLibStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test NotifyMediaLibStatusChanged
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_008, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    auto controller = CreateShared<DeferredPhotoController>(userId_, repository, processor);
    ASSERT_NE(controller, nullptr);
    controller->Initialize();

    controller->NotifyMediaLibStatusChanged(MediaLibraryStatus::MEDIA_LIBRARY_DISCONNECTED);
    controller->NotifyMediaLibStatusChanged(MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE);
    EXPECT_EQ(controller->userInitiatedStrategy_->mediaLibraryStatus_, MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE);
    EXPECT_EQ(controller->backgroundStrategy_->mediaLibraryStatus_, MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE);
}

/*
 * Feature: Deferred
 * Function: Test process image and cancel process image
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test process image and cancel process image
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_009, TestSize.Level0)
{
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto callback = std::make_shared<DeferredPhotoProcessorCallbacks>();
    ASSERT_NE(callback, nullptr);
    auto postProcessor = CreateShared<PhotoPostProcessor>(userId_);
    ASSERT_NE(postProcessor, nullptr);
    auto processor = CreateShared<DeferredPhotoProcessor>(userId_, repository, postProcessor, callback);
    ASSERT_NE(processor, nullptr);
    processor->Initialize();
    std::string imageId = "test1";
    DpsMetadata metadata;
    bool discardable = true;
    processor->AddImage(imageId, discardable, metadata);
    std::string appName = "com.cameraFwk.ut";
    processor->ProcessImage(appName, imageId);
    processor->CancelProcessImage(imageId);
    EXPECT_TRUE(processor->requestedImages_.empty());
}

} // CameraStandard
} // OHOS