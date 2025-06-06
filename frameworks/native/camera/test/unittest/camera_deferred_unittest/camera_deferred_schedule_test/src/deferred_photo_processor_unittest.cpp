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
}

class PhotoProcessingSessionCallbackMock : public DeferredPhotoProcessingSessionCallbackStub {
public:
    MOCK_METHOD3(OnProcessImageDone, int32_t(const std::string &imageId, std::shared_ptr<PictureIntf> picture,
        uint32_t cloudImageEnhanceFlag));
    MOCK_METHOD2(OnDeliveryLowQualityImage, int32_t(const std::string &imageId, std::shared_ptr<PictureIntf> picture));
    MOCK_METHOD4(OnProcessImageDone, int32_t(const std::string &imageId, sptr<IPCFileDescriptor> ipcFd, const long bytes,
        uint32_t cloudImageEnhanceFlag));
    MOCK_METHOD2(OnError, int32_t(const std::string &imageId, const ErrorCode errorCode));
    MOCK_METHOD1(OnStateChanged, int32_t(const StatusCode status));
};

void DeferredPhotoProcessorUnittest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void DeferredPhotoProcessorUnittest::TearDownTestCase(void) {}

void DeferredPhotoProcessorUnittest::SetUp()
{
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) PhotoProcessingSessionCallbackMock();
    DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(USER_ID, callback);
    sleep(1);
    auto schedule = DPS_GetSchedulerManager();
    ASSERT_NE(schedule, nullptr);
    process_ = schedule->GetPhotoProcessor(USER_ID);
    ASSERT_NE(process_, nullptr);
}

void DeferredPhotoProcessorUnittest::TearDown() {}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_001, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
    process_->RemoveImage(TEST_IMAGE_1, false);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_002, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto manager = DPS_GetSessionManager();
    manager->DeletePhotoSession(USER_ID);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    EXPECT_EQ(process_->repository_->GetOfflineJobSize(), 1);
    process_->RemoveImage(TEST_IMAGE_1, false);

}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_003, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto info = std::make_unique<ImageInfo>();
    process_->result_->RecordResult(TEST_IMAGE_1, std::move(info));
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
    process_->RemoveImage(TEST_IMAGE_1, false);
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
    process_->RemoveImage(TEST_IMAGE_1, false);
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
    process_->RemoveImage(TEST_IMAGE_1, false);
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
    process_->RemoveImage(TEST_IMAGE_1, false);
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
    process_->RemoveImage(TEST_IMAGE_1, false);
}

HWTEST_F(DeferredPhotoProcessorUnittest, deferred_photo_processor_unittest_011, TestSize.Level1)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    process_->AddImage(TEST_IMAGE_1, true, metadata);
    auto job = process_->repository_->GetJob();
    process_->DoProcess(job);
    ASSERT_NE(job, nullptr);
    sleep(1);
    process_->RemoveImage(TEST_IMAGE_1, false);
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
} // DeferredProcessing
} // CameraStandard
} // OHOS