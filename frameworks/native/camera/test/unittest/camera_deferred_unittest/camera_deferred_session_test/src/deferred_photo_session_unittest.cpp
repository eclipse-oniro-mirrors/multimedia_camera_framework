/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "deferred_photo_session_unittest.h"
#include "deferred_photo_processing_session_callback_stub.h"
#include "deferred_processing_service.h"
#include "dps.h"

using namespace testing::ext;
using namespace testing::mt;
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t USER_ID = 0;
    constexpr int32_t OTHER_USER_ID = 101;
}

void PhotoSessionUnitTest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void PhotoSessionUnitTest::TearDownTestCase(void) {}

void PhotoSessionUnitTest::SetUp() {}

void PhotoSessionUnitTest::TearDown()
{
    DeferredProcessingService::GetInstance().initialized_.store(true);
}

class PhotoProcessingSessionCallbackMock : public DeferredPhotoProcessingSessionCallbackStub {
public:
    ErrCode OnProcessImageDone(const std::string& imageId, const sptr<IPCFileDescriptor>& ipcFd,
        int64_t bytes, uint32_t cloudImageEnhanceFlag)
    {
        DP_DEBUG_LOG("entered.");
        return 0;
    }

    ErrCode OnDeliveryLowQualityImage(const std::string& imageId, const std::shared_ptr<PictureIntf>& picture)
    {
        DP_DEBUG_LOG("entered.");
        return 0;
    }

    ErrCode OnProcessImageDone(const std::string& imageId, const std::shared_ptr<PictureIntf>& picture,
        uint32_t cloudImageEnhanceFlag)
    {
        DP_DEBUG_LOG("entered.");
        return 0;
    }

    ErrCode OnError(const std::string& imageId, ErrorCode errorCode)
    {
        DP_DEBUG_LOG("entered.");
        return 0;
    }

    ErrCode OnStateChanged(StatusCode status)
    {
        DP_DEBUG_LOG("entered.");
        return 0;
    }

    int32_t CallbackParcel([[maybe_unused]] uint32_t code, [[maybe_unused]] MessageParcel& data,
        [[maybe_unused]] MessageParcel& reply, [[maybe_unused]] MessageOption& option)
    {
        return 0;
    }
};

sptr<IDeferredPhotoProcessingSession> GetDeferredPhotoProcessingSession()
{
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) PhotoProcessingSessionCallbackMock();
    DP_CHECK_ERROR_RETURN_RET_LOG(!callback, nullptr, "callback is nullptr.");
    auto photoProcessing = DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(USER_ID, callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(!photoProcessing, nullptr, "photoProcessing is nullptr.");
    return photoProcessing;
}

HWMTEST_F(PhotoSessionUnitTest, photo_session_unittest_001, TestSize.Level0, 3)
{
    sptr<IDeferredPhotoProcessingSession> deferredPhotoSession = GetDeferredPhotoProcessingSession();
    ASSERT_NE(deferredPhotoSession, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_002, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) PhotoProcessingSessionCallbackMock();
    ASSERT_NE(callback, nullptr);
    auto photoProcessing =
        DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(OTHER_USER_ID, callback);
    ASSERT_NE(photoProcessing, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_003, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) PhotoProcessingSessionCallbackMock();
    ASSERT_NE(callback, nullptr);
    DeferredProcessingService::GetInstance().initialized_.store(false);
    auto photoProcessing =
        DeferredProcessingService::GetInstance().CreateDeferredPhotoProcessingSession(USER_ID, callback);
    ASSERT_EQ(photoProcessing, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_004, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DeferredProcessingService::GetInstance().NotifyLowQualityImage(USER_ID, imageId, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_005, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DeferredProcessingService::GetInstance().initialized_.store(false);
    DeferredProcessingService::GetInstance().NotifyLowQualityImage(USER_ID, imageId, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_006, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DeferredProcessingService::GetInstance().NotifyLowQualityImage(OTHER_USER_ID, imageId, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_007, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_008, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_009, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RemoveImage(imageId, true);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RemoveImage(imageId, false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_010, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_BACKGROUND);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RemoveImage(imageId, false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_011, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RemoveImage(imageId, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RestoreImage(imageId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_012, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    std::string appName = "imagetest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->ProcessImage(appName, imageId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_013, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    std::string appName = "imagetest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->ProcessImage(appName, imageId);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->CancelProcessImage(imageId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_014, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    std::string imageId = "imageIdtest";
    std::string appName = "imagetest";
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    auto ret = photoProcessing->BeginSynchronize();
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->AddImage(imageId, metadata, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->ProcessImage(appName, imageId);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->CancelProcessImage(imageId);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RemoveImage(imageId, false);
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->RestoreImage(imageId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_015, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    auto ret = photoProcessing->BeginSynchronize();
    EXPECT_EQ(ret, 0);
    ret = photoProcessing->EndSynchronize();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_016, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    auto ret = photoProcessing->EndSynchronize();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_017, TestSize.Level0)
{
    sptr<IDeferredPhotoProcessingSession> photoProcessing = GetDeferredPhotoProcessingSession();
    ASSERT_NE(photoProcessing, nullptr);
    auto ret = photoProcessing->EndSynchronize();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_018, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    session->Start();
    session->Stop();
    session->photoSessionInfos_.clear();
    auto info = session->GetPhotoInfo(USER_ID);
    ASSERT_EQ(info, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_019, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredPhotoProcessingSessionCallback> callback = sptr<PhotoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(USER_ID, callback);
    session->AddPhotoSession(sessionInfo);
    auto info = session->GetPhotoInfo(USER_ID);
    ASSERT_NE(info, nullptr);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_020, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredPhotoProcessingSessionCallback> callback = sptr<PhotoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(USER_ID, callback);
    session->AddPhotoSession(sessionInfo);
    auto info = session->GetPhotoInfo(USER_ID);
    ASSERT_NE(info, nullptr);
    session->DeletePhotoSession(USER_ID);
    session->DeletePhotoSession(OTHER_USER_ID);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_021, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredPhotoProcessingSessionCallback> callback_ = sptr<PhotoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(USER_ID, callback_);
    session->AddPhotoSession(sessionInfo);
    auto callback = session->GetCallback(USER_ID);
    ASSERT_EQ(callback_, callback);
}

HWTEST_F(PhotoSessionUnitTest, photo_session_unittest_022, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredPhotoProcessingSessionCallback> callback_ = sptr<PhotoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(USER_ID, callback_);
    session->AddPhotoSession(sessionInfo);
    auto callback = session->GetCallback(OTHER_USER_ID);
    ASSERT_EQ(callback, nullptr);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS
