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

#include "deferred_photo_processor_unittest.h"

#include "camera_log_detector.h"
#include "deferred_photo_processing_session_callback_stub.h"
#include "deferred_processing_service.h"
#include "dps.h"
#include "gmock/gmock.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t USER_ID = 100;

    const std::string TEST_IMAGE_1 = "testImage1";
    const std::string TEST_IMAGE_2 = "testImage2";
    const std::string TEST_IMAGE_3 = "testImage3";
}

class MockPhotoProcessSession : public HDI::Camera::V1_2::IImageProcessSession {
public:
    MOCK_METHOD(int32_t, GetCoucurrency, (OHOS::HDI::Camera::V1_2::ExecutionMode mode, int32_t& taskCount), (override));
    MOCK_METHOD(int32_t, GetPendingImages, (std::vector<std::string>& imageIds), (override));
    MOCK_METHOD(int32_t, SetExecutionMode, (OHOS::HDI::Camera::V1_2::ExecutionMode mode), (override));
    MOCK_METHOD(int32_t, ProcessImage, (const std::string& imageId), (override));
    MOCK_METHOD(int32_t, RemoveImage, (const std::string& imageId), (override));
    MOCK_METHOD(int32_t, Interrupt, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));

    MockPhotoProcessSession()
    {
        ON_CALL(*this, GetCoucurrency).WillByDefault(Return(OK));
        ON_CALL(*this, GetPendingImages).WillByDefault(Return(OK));
        ON_CALL(*this, SetExecutionMode).WillByDefault(Return(OK));
        ON_CALL(*this, ProcessImage).WillByDefault(Return(OK));
        ON_CALL(*this, RemoveImage).WillByDefault(Return(OK));
        ON_CALL(*this, Interrupt).WillByDefault(Return(OK));
        ON_CALL(*this, Reset).WillByDefault(Return(OK));
    }
};

class PhotoProcessingSessionCallbackMock : public DeferredPhotoProcessingSessionCallbackStub {
public:
    MOCK_METHOD4(OnProcessImageDone, ErrCode(const std::string& imageId,
        const sptr<IPCFileDescriptor>& ipcFd, int64_t bytes, uint32_t cloudImageEnhanceFlag));
    MOCK_METHOD2(OnDeliveryLowQualityImage, ErrCode(const std::string& imageId,
        const std::shared_ptr<PictureIntf>& picture));
    MOCK_METHOD3(OnProcessImageDone, ErrCode(const std::string& imageId,
        const std::shared_ptr<PictureIntf>& picture, uint32_t cloudImageEnhanceFlag));
    MOCK_METHOD2(OnError, ErrCode(const std::string& imageId, ErrorCode errorCode));
    MOCK_METHOD1(OnStateChanged, ErrCode(StatusCode status));
    MOCK_METHOD4(CallbackParcel, int32_t(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option));
};

void DeferredPhotoProcessorUnittest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void DeferredPhotoProcessorUnittest::TearDownTestCase(void)
{
    auto scheduler = DPS_GetSchedulerManager();
    scheduler->GetPhotoProcessor(USER_ID)->postProcessor_->session_ = nullptr;
    scheduler->photoController_.erase(USER_ID);
}

void DeferredPhotoProcessorUnittest::SetUp()
{
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) PhotoProcessingSessionCallbackMock();
    DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(USER_ID, callback);
    sleep(1);
    scheduler_ = DPS_GetSchedulerManager();
    ASSERT_NE(scheduler_, nullptr);
    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    controller->photoStrategyCenter_->HandleTemperatureEvent(0);
    process_ = scheduler_->GetPhotoProcessor(USER_ID);
    auto session = sptr<MockPhotoProcessSession>::MakeSptr();
    process_->postProcessor_->session_ = session;
    process_->result_->cacheMap_.clear();
}

void DeferredPhotoProcessorUnittest::TearDown()
{
    process_->RemoveImage(TEST_IMAGE_1, false);
    process_->RemoveImage(TEST_IMAGE_2, false);
    process_->RemoveImage(TEST_IMAGE_3, false);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_001, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_002, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto manager = DPS_GetSessionManager();
    manager->DeletePhotoSession(USER_ID);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_003, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto info = std::make_unique<ImageInfo>();
    process_->result_->RecordResult(TEST_IMAGE_1, std::move(info), false);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_004, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->RemoveImage(TEST_IMAGE_1, true);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_005, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->RemoveImage(TEST_IMAGE_1, false);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_006, TestSize.Level1)
{
    process_->RemoveImage(TEST_IMAGE_2, true);
    process_->RemoveImage(TEST_IMAGE_2, false);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_007, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->RemoveImage(TEST_IMAGE_1, true);
    process_->RestoreImage(TEST_IMAGE_1);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_008, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->ProcessImage("testApp", TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->highImages_.size(), 1);
    process_->CancelProcessImage(TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->highImages_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_009, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->ProcessImage("testApp", TEST_IMAGE_2);
    EXPECT_EQ(process_->result_->highImages_.size(), 0);
    process_->CancelProcessImage(TEST_IMAGE_2);
    EXPECT_EQ(process_->result_->highImages_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_010, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->ProcessImage("testApp", TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->highImages_.size(), 0);
    process_->CancelProcessImage(TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->highImages_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_011, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    auto job = process_->repository_->GetJob();
    process_->DoProcess(job);
    ASSERT_NE(job, nullptr);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_012, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    auto info = std::make_unique<ImageInfo>();
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_1, std::move(info));

    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_1, std::move(info));

    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_1, std::move(info));

    info = std::make_unique<ImageInfo>();
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    process_->RemoveImage(TEST_IMAGE_1, false);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_013, TestSize.Level1)
{
    process_->result_->cacheMap_.clear();
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->OnProcessError(USER_ID, TEST_IMAGE_1, DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    process_->OnProcessError(USER_ID, TEST_IMAGE_1, DPS_ERROR_VIDEO_PROC_FAILED);
    process_->OnProcessError(USER_ID, TEST_IMAGE_1, DPS_ERROR_VIDEO_PROC_TIMEOUT);
    process_->OnProcessError(USER_ID, TEST_IMAGE_1, DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);

    process_->OnProcessError(USER_ID, TEST_IMAGE_2, DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    process_->OnProcessError(USER_ID, TEST_IMAGE_2, DPS_ERROR_VIDEO_PROC_FAILED);
    process_->OnProcessError(USER_ID, TEST_IMAGE_2, DPS_ERROR_VIDEO_PROC_TIMEOUT);
    process_->OnProcessError(USER_ID, TEST_IMAGE_2, DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    EXPECT_EQ(process_->result_->cacheMap_.size(), 1);
    process_->RemoveImage(TEST_IMAGE_1, false);
    process_->result_->cacheMap_.clear();
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_014, TestSize.Level1)
{
    auto jepg = std::make_unique<ImageInfo>();
    jepg->SetType(CallbackType::IMAGE_PROCESS_DONE);
    process_->result_->cacheMap_.emplace(TEST_IMAGE_1, std::move(jepg));
    process_->ProcessCatchResults(TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->cacheMap_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_015, TestSize.Level1)
{
    auto yuv = std::make_unique<ImageInfo>();
    yuv->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->result_->cacheMap_.emplace(TEST_IMAGE_1, std::move(yuv));
    process_->ProcessCatchResults(TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->cacheMap_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_016, TestSize.Level1)
{
    auto error = std::make_unique<ImageInfo>();
    error->SetType(CallbackType::IMAGE_ERROR);
    process_->result_->cacheMap_.emplace(TEST_IMAGE_1, std::move(error));
    process_->ProcessCatchResults(TEST_IMAGE_1);
    EXPECT_EQ(process_->result_->cacheMap_.size(), 0);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_017, TestSize.Level1)
{
    auto callback = process_->GetCallback();
    ASSERT_NE(callback, nullptr);
}

/*
 * Feature: Framework
 * Function: Test BPCache normal job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_018, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    DeferredPhotoJobPtr job = controller->photoStrategyCenter_->GetJob();
    std::string imageId = job->GetImageId();
    // 模拟底层返回高质量图场景
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, imageId, std::move(info));
    ASSERT_EQ(imageId, TEST_IMAGE_1);
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    sleep(1);
    // 模拟底层返回第二张高质量图，没有收到媒体库开始处理的通知
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    // 缓存当前高质量图
    ASSERT_EQ(process_->result_->cachePhotoId_, TEST_IMAGE_2);

    // 模拟第三次调度高质量任务，不允许调度
    ASSERT_EQ(controller->photoStrategyCenter_->isNeedStop_, true);
    job = controller->photoStrategyCenter_->GetJob();
    ASSERT_EQ(job, nullptr);
}

/*
 * Feature: Framework
 * Function: Test BPCache normal job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_019, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    DeferredPhotoJobPtr job = controller->photoStrategyCenter_->GetJob();
    std::string imageId = job->GetImageId();
    // 模拟底层返回高质量图场景
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, imageId, std::move(info));
    ASSERT_EQ(imageId, TEST_IMAGE_1);
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    // 模拟媒体库通知开始调度
    sleep(1);
    EventsInfo::GetInstance().SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);
    process_->ProcessBPCache();

    // 模拟底层返回第二张高质量图
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    CameraLogDetector logDetector;
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    sleep(1);
    // 模拟第三次调度高质量任务，允许调度
    ASSERT_EQ(controller->photoStrategyCenter_->isNeedStop_, false);
    EXPECT_TRUE(logDetector.IsLogContains("Process photo to ive, imageId: testImage3"));
}

/*
 * Feature: Framework
 * Function: Test BPCache normal job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_020, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    DeferredPhotoJobPtr job = controller->photoStrategyCenter_->GetJob();
    std::string imageId = job->GetImageId();
    // 模拟底层返回高质量图场景
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, imageId, std::move(info));
    ASSERT_EQ(imageId, TEST_IMAGE_1);
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    sleep(1);
    // 模拟底层返回第二张高质量图，没有收到媒体库开始处理的通知
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    // 缓存当前高质量图
    ASSERT_EQ(process_->result_->cachePhotoId_, TEST_IMAGE_2);

    // 模拟第三次调度高质量任务，不允许调度
    ASSERT_EQ(controller->photoStrategyCenter_->isNeedStop_, true);
    job = controller->photoStrategyCenter_->GetJob();
    ASSERT_EQ(job, nullptr);

    CameraLogDetector logDetector;
    // 模拟媒体库通知开始调度
    EventsInfo::GetInstance().SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);
    process_->ProcessBPCache();
    EXPECT_TRUE(logDetector.IsLogContains("ProcessCatchResults imageId"));
}

/*
 * Feature: Framework
 * Function: Test BPCache high job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_021, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    DeferredPhotoJobPtr job = controller->photoStrategyCenter_->GetJob();
    std::string imageId = job->GetImageId();
    // 模拟底层返回高质量图场景
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, imageId, std::move(info));
    ASSERT_EQ(imageId, TEST_IMAGE_1);
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    sleep(1);
    // 模拟底层返回第二张高质量图，没有收到媒体库开始处理的通知
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    // 缓存当前高质量图
    ASSERT_EQ(process_->result_->cachePhotoId_, TEST_IMAGE_2);

    // 模拟第三次调度高优先级任务，正常调度
    ASSERT_EQ(controller->photoStrategyCenter_->isNeedStop_, true);
    process_->ProcessImage("deferred_photo_processor_unittest_021", TEST_IMAGE_3);
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    CameraLogDetector logDetector;
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_3, std::move(info));
    EXPECT_TRUE(logDetector.IsLogContains("HandleSuccess"));
}

/*
 * Feature: Framework
 * Function: Test BPCache high job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_022, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    // 模拟请求高优先级任务场景：TEST_IMAGE_3
    process_->ProcessImage("deferred_photo_processor_unittest_022", TEST_IMAGE_3);
    sleep(1);
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_3, std::move(info));
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    // 模拟请求高优先级任务场景：TEST_IMAGE_2
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->ProcessImage("deferred_photo_processor_unittest_022", TEST_IMAGE_2);
    sleep(1);
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    {
        CameraLogDetector logDetector;
        process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
        EXPECT_TRUE(logDetector.IsLogContains("HandleSuccess"));
    }

    process_->AddImage(TEST_IMAGE_1, true, metadata);
    // 模拟请求普通优先级任务场景：TEST_IMAGE_1
    auto controller = scheduler_->GetPhotoController(USER_ID);
    ASSERT_NE(controller, nullptr);
    DeferredPhotoJobPtr job = controller->photoStrategyCenter_->GetJob();
    ASSERT_EQ(job->GetImageId(), TEST_IMAGE_1);
}

/*
 * Feature: Framework
 * Function: Test BPCache high job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_023, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    // 模拟请求高优先级任务场景：TEST_IMAGE_3
    process_->ProcessImage("deferred_photo_processor_unittest_023", TEST_IMAGE_3);
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_3, std::move(info));
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    sleep(1);
    // 模拟请求低优先级任务场景：TEST_IMAGE_1
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_1, std::move(info));
    ASSERT_EQ(process_->result_->cachePhotoId_, TEST_IMAGE_1);

    sleep(1);
    // 模拟请求高优先级任务场景：TEST_IMAGE_2
    process_->ProcessImage("deferred_photo_processor_unittest_023", TEST_IMAGE_2);
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    CameraLogDetector logDetector;
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    EXPECT_TRUE(logDetector.IsLogContains("HandleSuccess"));
}

/*
 * Feature: Framework
 * Function: Test BPCache high job
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Validate functions of class DeferredPhotoProcessor in BPCache branch
 */
HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_024, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    process_->AddImage(TEST_IMAGE_2, true, metadata);
    process_->AddImage(TEST_IMAGE_3, true, metadata);

    // 模拟请求高优先级任务场景：TEST_IMAGE_3
    process_->ProcessImage("deferred_photo_processor_unittest_024", TEST_IMAGE_3);
    auto info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_3, std::move(info));
    // 返回给媒体库后当前媒体库处理状态为busy
    ASSERT_EQ(EventsInfo::GetInstance().IsMediaBusy(), true);

    sleep(1);
    // 模拟媒体库通知开始调度
    EventsInfo::GetInstance().SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);
    process_->ProcessBPCache();

    // 模拟请求低优先级任务场景：TEST_IMAGE_1
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_1, std::move(info));
    ASSERT_EQ(process_->result_->cachePhotoId_, "Null");

    sleep(1);
    // 模拟请求高优先级任务场景：TEST_IMAGE_2
    process_->ProcessImage("deferred_photo_processor_unittest_024", TEST_IMAGE_2);
    info = std::make_unique<ImageInfo>();
    info->SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
    CameraLogDetector logDetector;
    process_->OnProcessSuccess(USER_ID, TEST_IMAGE_2, std::move(info));
    EXPECT_TRUE(logDetector.IsLogContains("HandleSuccess"));
}
} // DeferredProcessing
} // CameraStandard
} // OHOS