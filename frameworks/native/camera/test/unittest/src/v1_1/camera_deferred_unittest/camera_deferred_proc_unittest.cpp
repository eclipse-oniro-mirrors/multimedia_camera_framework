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

#include "camera_deferred_proc_unittest.h"

#include "input/camera_manager.h"
#include "pixel_map.h"
#include "picture.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace DeferredProcessing;

constexpr int32_t SIZE_WIDTH = 2;
constexpr int32_t SIZE_HEIGHT = 3;
constexpr int32_t BUFFER_LENGTH = 8;

void DeferredProcUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::SetUpTestCase started!");
}

void DeferredProcUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::TearDownTestCase started!");
}

void DeferredProcUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp testName:%{public}s",
        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    const uint32_t color[BUFFER_LENGTH] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    Media::InitializationOptions options;
    options.size.width = SIZE_WIDTH;
    options.size.height = SIZE_HEIGHT;
    options.srcPixelFormat = Media::PixelFormat::UNKNOWN;
    options.pixelFormat = Media::PixelFormat::UNKNOWN;
    options.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::shared_ptr<Media::PixelMap> pixelmap = Media::PixelMap::Create(color, BUFFER_LENGTH, options);
    EXPECT_NE(pixelmap, nullptr);
    picture_ = Media::Picture::Create(pixelmap);
}

void DeferredProcUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredProcUnitTest::TearDown started!");
}

void DeferredProcUnitTest::NativeAuthorization()
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
    g_tokenId_ = GetAccessTokenId(&infoInstance);
    g_uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(g_uid_, g_userId_);
    MEDIA_DEBUG_LOG("tokenId:%{public}" PRIu64 " uid:%{public}d userId:%{public}d",
        g_tokenId_, g_uid_, g_userId_);
    SetSelfTokenID(g_tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test is that the class calls the function function correctly and functions properly.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test is that the class calls the function function correctly and functions properly.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_001, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        g_userId_, std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);
    deferredProcSession->BeginSynchronize();

    std::string imageId = "testImageId";
    DpsMetadata metadata;
    bool discardable = true;
    deferredProcSession->AddImage(imageId, metadata, discardable);

    bool restorable = true;
    deferredProcSession->RemoveImage(imageId, restorable);

    deferredProcSession->RestoreImage(imageId);

    std::string appName = "com.cameraFwk.ut";
    deferredProcSession->ProcessImage(appName, imageId);

    deferredProcSession->CancelProcessImage(imageId);

    deferredProcSession->EndSynchronize();

    pid_t pid = 0;
    deferredProcSession->CameraServerDied(pid);

    auto callback = deferredProcSession->GetCallback();
    EXPECT_NE(callback, nullptr);
}

/*
 * Feature: Framework
 * Function: Test exception constructs the function that calls the function properly.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test exception constructs the function that calls the function properly.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_002, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession =
        new(std::nothrow) DeferredPhotoProcSession(g_userId_, std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_EQ(deferredProcSession->remoteSession_, nullptr);
    deferredProcSession->BeginSynchronize();

    std::string imageId = "testImageId";
    DpsMetadata metadata;
    bool discardable = true;
    deferredProcSession->AddImage(imageId, metadata, discardable);

    bool restorable = true;
    deferredProcSession->RemoveImage(imageId, restorable);

    deferredProcSession->RestoreImage(imageId);

    std::string appName = "com.cameraFwk.ut";
    deferredProcSession->ProcessImage(appName, imageId);

    deferredProcSession->CancelProcessImage(imageId);

    deferredProcSession->EndSynchronize();

    pid_t pid = 0;
    deferredProcSession->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test the construction class calls the listener function, and the function functions normally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the construction class calls the listener function, and the function functions normally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_003, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        g_userId_, std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_NE(deferredProcSession->remoteSession_, nullptr);
    auto remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredProcSession);

    std::string imageId = "testImageId";
    bool restorable = true;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessImageDone(imageId, nullptr, restorable);
    EXPECT_EQ(ret, 0);

    ret = remoteCallback->OnProcessImageDone(imageId, picture_, restorable);
    EXPECT_EQ(ret, 0);

    ret = remoteCallback->OnDeliveryLowQualityImage(imageId, picture_);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::ErrorCode errorCode = DeferredProcessing::ErrorCode::ERROR_SESSION_SYNC_NEEDED;
    ret = remoteCallback->OnError(imageId, errorCode);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::StatusCode status = DeferredProcessing::StatusCode::SESSION_STATE_IDLE;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: When the callback is not implemented, the callback function is called normally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When the callback is not implemented, the callback function is called normally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_004, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        g_userId_, nullptr);
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_NE(deferredProcSession->remoteSession_, nullptr);
    auto remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredProcSession);

    std::string imageId = "testImageId";
    bool restorable = true;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessImageDone(imageId, picture_, restorable);
    EXPECT_EQ(ret, 0);

    ret = remoteCallback->OnDeliveryLowQualityImage(imageId, nullptr);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::ErrorCode errorCode = DeferredProcessing::ErrorCode::ERROR_SESSION_SYNC_NEEDED;
    ret = remoteCallback->OnError(imageId, errorCode);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::StatusCode status = DeferredProcessing::StatusCode::SESSION_STATE_IDLE;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: When the test does not implement the callback, the function call is normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When the test does not implement the callback, the function call is normal.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_005, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        g_userId_, std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_NE(deferredProcSession->remoteSession_, nullptr);
    auto remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback();

    std::string imageId = "testImageId";
    bool restorable = true;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessImageDone(imageId, picture_, restorable);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::ErrorCode errorCode = DeferredProcessing::ErrorCode::ERROR_SESSION_SYNC_NEEDED;
    ret = remoteCallback->OnError(imageId, errorCode);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::StatusCode status = DeferredProcessing::StatusCode::SESSION_STATE_IDLE;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: The test function is returned abnormally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test function is returned abnormally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_006, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredPhotoProcessingSession(
        g_userId_, nullptr);
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_NE(deferredProcSession->remoteSession_, nullptr);
    auto remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback();

    std::string imageId = "testImageId";
    bool restorable = true;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessImageDone(imageId, picture_, restorable);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::ErrorCode errorCode = DeferredProcessing::ErrorCode::ERROR_SESSION_SYNC_NEEDED;
    ret = remoteCallback->OnError(imageId, errorCode);
    EXPECT_EQ(ret, 0);

    DeferredProcessing::StatusCode status = DeferredProcessing::StatusCode::SESSION_STATE_IDLE;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test is that the class calls the function function correctly and functions properly.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test is that the class calls the function function correctly and functions properly.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_007, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        g_userId_, std::make_shared<TestDeferredVideoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);

    deferredProcSession->BeginSynchronize();

    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> srcFd;
    const sptr<IPCFileDescriptor> dstFd;
    deferredProcSession->AddVideo(videoId, srcFd, dstFd);

    bool restorable = true;
    deferredProcSession->RemoveVideo(videoId, restorable);

    deferredProcSession->RestoreVideo(videoId);

    deferredProcSession->EndSynchronize();

    pid_t pid = 0;
    deferredProcSession->CameraServerDied(pid);

    auto callback = deferredProcSession->GetCallback();
    EXPECT_NE(callback, nullptr);
}

/*
 * Feature: Framework
 * Function: Test exception constructs the function that calls the function properly.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test exception constructs the function that calls the function properly.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_008, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession =
        new(std::nothrow) DeferredVideoProcSession(g_userId_, std::make_shared<TestDeferredVideoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    EXPECT_EQ(deferredProcSession->remoteSession_, nullptr);

    deferredProcSession->BeginSynchronize();

    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> srcFd;
    const sptr<IPCFileDescriptor> dstFd;
    deferredProcSession->AddVideo(videoId, srcFd, dstFd);

    bool restorable = true;
    deferredProcSession->RemoveVideo(videoId, restorable);

    deferredProcSession->RestoreVideo(videoId);

    deferredProcSession->EndSynchronize();

    pid_t pid = 0;
    deferredProcSession->CameraServerDied(pid);
}

/*
 * Feature: Framework
 * Function: Test the construction class calls the listener function, and the function functions normally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the construction class calls the listener function, and the function functions normally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_009, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        g_userId_, std::make_shared<TestDeferredVideoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);

    auto remoteCallback = new(std::nothrow) DeferredVideoProcessingSessionCallback(deferredProcSession);
    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> ipcFileDescriptor;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessVideoDone(videoId, ipcFileDescriptor);
    EXPECT_EQ(ret, 0);

    int32_t errorCode = 0;
    ret = remoteCallback->OnError(videoId, errorCode);
    EXPECT_EQ(ret, 0);

    int32_t status = 0;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: When the callback is not implemented, the callback function is called normally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When the callback is not implemented, the callback function is called normally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_010, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        g_userId_, std::make_shared<TestDeferredVideoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);

    auto remoteCallback = new(std::nothrow) DeferredVideoProcessingSessionCallback();
    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> ipcFileDescriptor;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessVideoDone(videoId, ipcFileDescriptor);
    EXPECT_EQ(ret, 0);

    int32_t errorCode = 0;
    ret = remoteCallback->OnError(videoId, errorCode);
    EXPECT_EQ(ret, 0);

    int32_t status = 0;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: When the test does not implement the callback, the function call is normal.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When the test does not implement the callback, the function call is normal.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_011, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        g_userId_, nullptr);
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);

    auto remoteCallback = new(std::nothrow) DeferredVideoProcessingSessionCallback(deferredProcSession);
    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> ipcFileDescriptor;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessVideoDone(videoId, ipcFileDescriptor);
    EXPECT_EQ(ret, 0);

    int32_t errorCode = 0;
    ret = remoteCallback->OnError(videoId, errorCode);
    EXPECT_EQ(ret, 0);

    int32_t status = 0;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: The test function is returned abnormally.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test function is returned abnormally.
 */
HWTEST_F(DeferredProcUnitTest, camera_deferred_proc_unittest_012, TestSize.Level0)
{
    sptr<DeferredVideoProcSession> deferredProcSession = {nullptr};
    deferredProcSession = deferredProcSession = CameraManager::GetInstance()->CreateDeferredVideoProcessingSession(
        g_userId_, nullptr);
    ASSERT_NE(deferredProcSession, nullptr);
    ASSERT_NE(deferredProcSession->remoteSession_, nullptr);

    auto remoteCallback = new(std::nothrow) DeferredVideoProcessingSessionCallback();
    std::string videoId = "testVideoId";
    sptr<IPCFileDescriptor> ipcFileDescriptor;
    int32_t ret = 0;
    ret = remoteCallback->OnProcessVideoDone(videoId, ipcFileDescriptor);
    EXPECT_EQ(ret, 0);

    int32_t errorCode = 0;
    ret = remoteCallback->OnError(videoId, errorCode);
    EXPECT_EQ(ret, 0);

    int32_t status = 0;
    ret = remoteCallback->OnStateChanged(status);
    EXPECT_EQ(ret, 0);
}
} // CameraStandard
} // OHOS
