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

#include "camera_deferred_session_unittest.h"

#include "session_coordinator.h"
#include "deferred_photo_processor.h"
#include "deferred_proc_session/deferred_photo_proc_session.h"
#include "deferred_proc_session/deferred_video_proc_session.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "session/photo_session/deferred_photo_processing_session.h"
#include "session/video_session/deferred_video_processing_session.h"
#include "session/video_session/video_session_info.h"
#include "utils/dp_log.h"
#include "ideferred_photo_processing_session_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr int VIDEO_REQUEST_FD_ID = 1;
constexpr int VIDEO_REQUEST_FD_TEMP = 8;
void CameraDeferredSessionUnitTest::SetUpTestCase(void) {}

void CameraDeferredSessionUnitTest::TearDownTestCase(void) {}

void CameraDeferredSessionUnitTest::SetUp()
{
    int32_t uid = 0;
    uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId_);
    sessionManagerPtr_ = SessionManager::Create();
    ASSERT_NE(sessionManagerPtr_, nullptr);
}

void CameraDeferredSessionUnitTest::TearDown()
{
    if (sessionManagerPtr_ != nullptr) {
        sessionManagerPtr_ = nullptr;
    }
}

sptr<IDeferredPhotoProcessingSession> CameraDeferredSessionUnitTest::GetDeferredPhotoProcessingSession()
{
    sptr<DeferredPhotoProcessingSessionCallback> callback = new (std::nothrow) DeferredPhotoProcessingSessionCallback();
    DP_CHECK_ERROR_RETURN_RET_LOG(!callback, nullptr, "callback is nullptr.");
    sessionManagerPtr_->photoSessionInfos_.clear();
    sptr<IDeferredPhotoProcessingSession> deferredPhotoSession =
        sessionManagerPtr_->CreateDeferredPhotoProcessingSession(userId_, callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(!deferredPhotoSession, nullptr, "deferredPhotoSession is nullptr.");
    return deferredPhotoSession;
}

sptr<IDeferredVideoProcessingSession> CameraDeferredSessionUnitTest::GetDeferredVideoProcessingSession()
{
    sptr<DeferredVideoProcessingSessionCallback> callback = new (std::nothrow) DeferredVideoProcessingSessionCallback();
    DP_CHECK_ERROR_RETURN_RET_LOG(!callback, nullptr, "callback is nullptr.");
    sessionManagerPtr_->videoSessionInfos_.clear();
    sptr<IDeferredVideoProcessingSession> deferredVideoSession =
        sessionManagerPtr_->CreateDeferredVideoProcessingSession(userId_, callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(!deferredVideoSession, nullptr, "deferredVideoSession is nullptr.");
    return deferredVideoSession;
}

/*
 * Feature: Framework
 * Function: Test the normal process of Class DeferredPhotoProcessingSession.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal process of Class DeferredPhotoProcessingSession.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_001, TestSize.Level1)
{
    sptr<DeferredPhotoProcessingSession> deferredPhotoSession;
    sptr<IDeferredPhotoProcessingSession> deferredPhotoSessionTemp = GetDeferredPhotoProcessingSession();
    if (deferredPhotoSessionTemp) {
        deferredPhotoSession = static_cast<DeferredPhotoProcessingSession *>(deferredPhotoSessionTemp.GetRefPtr());
    } else {
        deferredPhotoSession = new (std::nothrow) DeferredPhotoProcessingSession(userId_);
    }
    ASSERT_NE(deferredPhotoSession, nullptr);
    EXPECT_NE(sessionManagerPtr_->GetCallback(userId_), nullptr);
    int32_t ret = deferredPhotoSession->BeginSynchronize();
    EXPECT_TRUE(deferredPhotoSession->inSync_);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->EndSynchronize();
    EXPECT_FALSE(deferredPhotoSession->inSync_.load());

    std::string imageId = "testImageId";
    DpsMetadata metadata;
    bool discardable = true;
    ret = deferredPhotoSession->AddImage(imageId, metadata, discardable);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(deferredPhotoSession->imageIds_.size(), 0);

    bool restorable = true;
    ret = deferredPhotoSession->RemoveImage(imageId, restorable);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->RestoreImage(imageId);
    EXPECT_EQ(ret, 0);

    std::string appName = "com.cameraFwk.ut";
    ret = deferredPhotoSession->ProcessImage(appName, imageId);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->CancelProcessImage(imageId);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test fuctions of Class DeferredPhotoProcessingSession during sync process.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test fuctions of Class DeferredPhotoProcessingSession during sync process.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_002, TestSize.Level1)
{
    sptr<IDeferredPhotoProcessingSession> deferredPhotoSessionTemp = GetDeferredPhotoProcessingSession();
    sptr<DeferredPhotoProcessingSession> deferredPhotoSession;
    if (deferredPhotoSessionTemp) {
        deferredPhotoSession = static_cast<DeferredPhotoProcessingSession *>(deferredPhotoSessionTemp.GetRefPtr());
    } else {
        deferredPhotoSession = new (std::nothrow) DeferredPhotoProcessingSession(userId_);
    }
    ASSERT_NE(deferredPhotoSession, nullptr);
    int32_t ret = deferredPhotoSession->BeginSynchronize();
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(deferredPhotoSession->inSync_);

    std::string imageId = "testImageId";
    DpsMetadata metadata;
    bool discardable = true;
    ret = deferredPhotoSession->AddImage(imageId, metadata, discardable);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(deferredPhotoSession->imageIds_.size(), 0);

    bool restorable = true;
    ret = deferredPhotoSession->RemoveImage(imageId, restorable);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->RestoreImage(imageId);
    EXPECT_EQ(ret, 0);

    std::string appName = "com.camera.ut";
    ret = deferredPhotoSession->ProcessImage(appName, imageId);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->CancelProcessImage(imageId);
    EXPECT_EQ(ret, 0);

    ret = deferredPhotoSession->EndSynchronize();
    EXPECT_FALSE(deferredPhotoSession->inSync_);
}

/*
 * Feature: Framework
 * Function: Test AddVideo after sync process.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AddVideo after sync process.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_003, TestSize.Level1)
{
    sptr<DeferredVideoProcessingSession> deferredVideoSession;
    sptr<IDeferredVideoProcessingSession> deferredVideoSessionTemp = GetDeferredVideoProcessingSession();
    if (deferredVideoSessionTemp) {
        deferredVideoSession = static_cast<DeferredVideoProcessingSession *>(deferredVideoSessionTemp.GetRefPtr());
    } else {
        deferredVideoSession = new (std::nothrow) DeferredVideoProcessingSession(userId_);
    }
    ASSERT_NE(deferredVideoSession, nullptr);
    int32_t ret = deferredVideoSession->BeginSynchronize();
    EXPECT_EQ(ret, DP_OK);
    EXPECT_TRUE(deferredVideoSession->inSync_.load());

    ret = deferredVideoSession->EndSynchronize();
    EXPECT_FALSE(deferredVideoSession->inSync_.load());

    std::string videoId = "testVideo";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_TEMP));
    ret = deferredVideoSession->AddVideo(videoId, srcFd, dstFd);
    EXPECT_EQ(deferredVideoSession->videoIds_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_004, TestSize.Level1)
{
    sptr<DeferredVideoProcessingSession> deferredVideoSession;
    sptr<IDeferredVideoProcessingSession> deferredVideoSessionTemp = GetDeferredVideoProcessingSession();
    if (deferredVideoSessionTemp) {
        deferredVideoSession = static_cast<DeferredVideoProcessingSession *>(deferredVideoSessionTemp.GetRefPtr());
    } else {
        deferredVideoSession = new (std::nothrow) DeferredVideoProcessingSession(userId_);
    }
    ASSERT_NE(deferredVideoSession, nullptr);
    int32_t ret = deferredVideoSession->BeginSynchronize();
    EXPECT_EQ(ret, DP_OK);
    EXPECT_TRUE(deferredVideoSession->inSync_.load());

    std::string videoId = "testVideo";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_TEMP));
    ret = deferredVideoSession->AddVideo(videoId, srcFd, dstFd);
    EXPECT_EQ(ret, DP_OK);
    EXPECT_NE(deferredVideoSession->videoIds_.size(), 0);

    ret = deferredVideoSession->RemoveVideo(videoId, true);
    EXPECT_EQ(ret, DP_OK);

    ret = deferredVideoSession->RestoreVideo(videoId);
    EXPECT_EQ(ret, DP_OK);

    ret = deferredVideoSession->EndSynchronize();
    EXPECT_FALSE(deferredVideoSession->inSync_.load());
}

/*
 * Feature: Framework
 * Function: Test the normal process of Class SessionCoordinator.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal process of Class SessionCoordinator.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_005, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);

    uint32_t numThreads = 1;
    std::shared_ptr<TaskManager> taskManager =
        std::make_shared<TaskManager>("CameraDeferredSessionUnitTest_userid_" + std::to_string(userId_),
        numThreads, true);
    ASSERT_NE(taskManager, nullptr);
    sptr<DeferredPhotoProcessingSessionCallback> callback =
        new (std::nothrow) DeferredPhotoProcessingSessionCallback();
    ASSERT_NE(callback, nullptr);
    sessionCoordinator->photoCallbackMap_.clear();
    sptr<PhotoSessionInfo> photoInfo = sptr<PhotoSessionInfo>::MakeSptr(userId_, callback);
    sessionCoordinator->AddPhotoSession(photoInfo);
    std::string imageId = "testImageId";
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sessionCoordinator->OnProcessDone(userId_, imageId, ipcFd, 1, false);
    sessionCoordinator->OnError(userId_, imageId, DPS_ERROR_UNKNOW);
    sessionCoordinator->OnStateChanged(userId_, DPS_SESSION_STATE_IDLE);
    sessionCoordinator->DeletePhotoSession(userId_);
    EXPECT_EQ(sessionCoordinator->photoCallbackMap_.size(), 0);

    sptr<DeferredVideoProcessingSessionCallback> videoCallback =
        new (std::nothrow) DeferredVideoProcessingSessionCallback();
    ASSERT_NE(videoCallback, nullptr);
    std::string videoId = "testVideo";
    sessionCoordinator->OnVideoProcessDone(userId_, videoId, ipcFd);
    sessionCoordinator->OnVideoError(userId_, videoId, DPS_ERROR_UNKNOW);
    sessionCoordinator->DeleteVideoSession(userId_);
    EXPECT_EQ(sessionCoordinator->videoCallbackMap_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test ProcessVideoResults when callbackType is ON_PROCESS_DONE/ON_ERROR/ON_STATE_CHANGED.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessVideoResults when callbackType is ON_PROCESS_DONE/ON_ERROR/ON_STATE_CHANGED.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_006, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);

    std::string imageId = "testImageId";
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sessionCoordinator->OnProcessDone(userId_, imageId, ipcFd, 1, false);
    sessionCoordinator->OnError(userId_, imageId, DPS_ERROR_UNKNOW);
    sessionCoordinator->OnStateChanged(userId_, DPS_SESSION_STATE_IDLE);

    sptr<DeferredVideoProcessingSessionCallback> videoCallback =
        new (std::nothrow) DeferredVideoProcessingSessionCallback();
    ASSERT_NE(videoCallback, nullptr);
    sessionCoordinator->videoCallbackMap_.clear();
    sptr<VideoSessionInfo> sessionInfo = sptr<VideoSessionInfo>::MakeSptr(userId_, videoCallback);
    sessionCoordinator->AddVideoSession(sessionInfo);
    sessionCoordinator->DeleteVideoSession(userId_);
    EXPECT_EQ(sessionCoordinator->videoCallbackMap_.size(), 0);
    std::string videoId = "testVideo";
    sessionCoordinator->OnVideoProcessDone(userId_, videoId, ipcFd);
    sessionCoordinator->OnVideoError(userId_, videoId, DPS_ERROR_UNKNOW);
    SessionCoordinator::RequestResult testRequestResult = {
        SessionCoordinator::CallbackType::ON_PROCESS_DONE,
        userId_,
        "testRequestId",
        ipcFd,
        1,
        DPS_ERROR_UNKNOW,
        DPS_SESSION_STATE_IDLE
    };
    sessionCoordinator->pendingRequestResults_.clear();
    sessionCoordinator->pendingRequestResults_.push_back(testRequestResult);
    testRequestResult.callbackType = SessionCoordinator::CallbackType::ON_ERROR;
    sessionCoordinator->pendingRequestResults_.push_back(testRequestResult);
    testRequestResult.callbackType = SessionCoordinator::CallbackType::ON_STATE_CHANGED;
    sessionCoordinator->pendingRequestResults_.push_back(testRequestResult);
    EXPECT_NE(sessionCoordinator->pendingRequestResults_.size(), 0);
    sessionCoordinator->ProcessVideoResults(videoCallback);
    EXPECT_EQ(sessionCoordinator->pendingRequestResults_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test ProcessPendingResults when callbackType is ON_PROCESS_DONE/ON_ERROR/ON_STATE_CHANGED.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ProcessPendingResults when callbackType is ON_PROCESS_DONE/ON_ERROR/ON_STATE_CHANGED.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_007, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);
    std::string imageId = "testImageId";
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));

    sptr<DeferredPhotoProcessingSessionCallback> callback =
        new (std::nothrow) DeferredPhotoProcessingSessionCallback();
    ASSERT_NE(callback, nullptr);
    SessionCoordinator::ImageResult testImageResult = {
        SessionCoordinator::CallbackType::ON_PROCESS_DONE,
        userId_,
        imageId,
        ipcFd,
        1,
        DPS_ERROR_UNKNOW,
        DPS_SESSION_STATE_IDLE,
        0
    };
    sessionCoordinator->pendingImageResults_.clear();
    sessionCoordinator->pendingImageResults_.push_back(testImageResult);
    testImageResult.callbackType = SessionCoordinator::CallbackType::ON_ERROR;
    sessionCoordinator->pendingImageResults_.push_back(testImageResult);
    testImageResult.callbackType = SessionCoordinator::CallbackType::ON_STATE_CHANGED;
    sessionCoordinator->pendingImageResults_.push_back(testImageResult);
    EXPECT_NE(sessionCoordinator->pendingImageResults_.size(), 0);
    sessionCoordinator->ProcessPendingResults(callback);
    EXPECT_EQ(sessionCoordinator->pendingImageResults_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the different branch of OnError.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the different branch of OnError.
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_008, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);

    sptr<DeferredPhotoProcessingSessionCallback> callback =
        new (std::nothrow) DeferredPhotoProcessingSessionCallback();
    ASSERT_NE(callback, nullptr);
    sessionCoordinator->photoCallbackMap_.clear();
    sptr<PhotoSessionInfo> photoInfo = sptr<PhotoSessionInfo>::MakeSptr(userId_, callback);
    sessionCoordinator->AddPhotoSession(photoInfo);
    std::string imageId = "testImageId";
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sessionCoordinator->OnProcessDone(userId_, imageId, ipcFd, 1, false);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_SESSION_SYNC_NEEDED);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT);
    sessionCoordinator->OnError(userId_, imageId, DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    sessionCoordinator->OnStateChanged(userId_, DPS_SESSION_STATE_IDLE);
    sessionCoordinator->DeletePhotoSession(userId_);
    EXPECT_EQ(sessionCoordinator->photoCallbackMap_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test the different branch of OnStateChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the different branch of OnStateChanged
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_009, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);

    sptr<DeferredPhotoProcessingSessionCallback> callback =
        new (std::nothrow) DeferredPhotoProcessingSessionCallback();
    ASSERT_NE(callback, nullptr);
    sessionCoordinator->photoCallbackMap_.clear();
    sptr<PhotoSessionInfo> photoInfo = sptr<PhotoSessionInfo>::MakeSptr(userId_, callback);
    sessionCoordinator->AddPhotoSession(photoInfo);
    std::string imageId = "testImageId";
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    sessionCoordinator->OnProcessDone(userId_, imageId, ipcFd, 1, false);
    sessionCoordinator->OnStateChanged(userId_, DpsStatus::DPS_SESSION_STATE_IDLE);
    sessionCoordinator->OnStateChanged(userId_, DpsStatus::DPS_SESSION_STATE_RUNNALBE);
    sessionCoordinator->OnStateChanged(userId_, DpsStatus::DPS_SESSION_STATE_RUNNING);
    sessionCoordinator->OnStateChanged(userId_, DpsStatus::DPS_SESSION_STATE_SUSPENDED);
    sessionCoordinator->OnStateChanged(userId_, static_cast<DpsStatus>(-1));
    sessionCoordinator->DeletePhotoSession(userId_);
    EXPECT_EQ(sessionCoordinator->photoCallbackMap_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test video process with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video process with abnormal branch
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_010, TestSize.Level1)
{
    std::shared_ptr<SessionCoordinator> sessionCoordinator = sessionManagerPtr_->GetSessionCoordinator();
    ASSERT_NE(sessionCoordinator, nullptr);
    sptr<DeferredVideoProcessingSessionCallback> videoCallback =
        new (std::nothrow) DeferredVideoProcessingSessionCallback();
    ASSERT_NE(videoCallback, nullptr);
    sessionCoordinator->videoCallbackMap_.clear();

    sptr<VideoSessionInfo> sessionInfo = sptr<VideoSessionInfo>::MakeSptr(userId_, videoCallback);
    sessionCoordinator->AddVideoSession(sessionInfo);
    sptr<IPCFileDescriptor> ipcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));

    std::string videoId = "testVideo";
    sessionCoordinator->OnVideoProcessDone(userId_, videoId, ipcFd);
    sessionCoordinator->OnVideoError(userId_, videoId, DPS_ERROR_UNKNOW);
    sessionCoordinator->OnVideoStateChanged(userId_, DPS_SESSION_STATE_IDLE);
}

/*
 * Feature: Framework
 * Function: Test GetCallback when photoSessionInfos_ is empty
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCallback when photoSessionInfos_ is empty
 */
HWTEST_F(CameraDeferredSessionUnitTest, camera_deferred_session_unittest_011, TestSize.Level1)
{
    sessionManagerPtr_->photoSessionInfos_.clear();
    sptr<IDeferredPhotoProcessingSessionCallback> photoSessionCb = sessionManagerPtr_->GetCallback(userId_);
    EXPECT_EQ(photoSessionCb, nullptr);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS
