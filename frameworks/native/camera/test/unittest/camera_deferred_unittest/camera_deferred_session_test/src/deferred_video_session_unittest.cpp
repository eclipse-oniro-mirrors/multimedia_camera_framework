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

#include "deferred_videosession_unittest.h"

#include <fcntl.h>

#include "gmock/gmock.h"
#include "deferred_processing_service.h"
#include "deferred_video_proc_session.h"
#include "dps.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "video_session_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH = MEDIA_ROOT + "test_video_temp.mp4";
    constexpr int32_t USER_ID = 0;
    constexpr int32_t OTHER_USER_ID = 101;
}

void VideoSessionUnitTest::SetUpTestCase(void)
{
    DeferredProcessingService::GetInstance().Initialize();
}

void VideoSessionUnitTest::TearDownTestCase(void) {}

void VideoSessionUnitTest::SetUp()
{
    int32_t uid = 0;
    uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId_);
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    dtsFd_ = open(VIDEO_TEMP_PATH.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
}

void VideoSessionUnitTest::TearDown()
{
    if (srcFd_ > 0) {
        close(srcFd_);
    }
    if (dtsFd_ > 0) {
        close(dtsFd_);
    }
}

class VideoProcessingSessionCallbackMock : public DeferredVideoProcessingSessionCallbackStub {
public:
    MOCK_METHOD(ErrCode, OnProcessVideoDone, (const std::string &videoId), (override));
    MOCK_METHOD(ErrCode, OnError, (const std::string& videoId, ErrorCode errorCode));
    MOCK_METHOD(ErrCode, OnStateChanged, (StatusCode status), (override));
    MOCK_METHOD(ErrCode, OnProcessingProgress, (const std::string& videoId, float progress), (override));

    VideoProcessingSessionCallbackMock()
    {
        ON_CALL(*this, OnProcessVideoDone).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnError).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnStateChanged).WillByDefault(Return(ERR_OK));
        ON_CALL(*this, OnProcessingProgress).WillByDefault(Return(ERR_OK));
    }
};

sptr<IDeferredVideoProcessingSession> GetDeferredVideoProcessingSession()
{
    sptr<IDeferredVideoProcessingSessionCallback> callback = new (std::nothrow) VideoProcessingSessionCallbackMock();
    sptr<IDeferredVideoProcessingSession> deferredVideoSession =
        DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(USER_ID, callback);
    DP_CHECK_ERROR_RETURN_RET_LOG(!deferredVideoSession, nullptr, "deferredVideoSession is nullptr.");
    return deferredVideoSession;
}

/*
 * Feature: Framework
 * Function: Test BeginSynchronize and EndSynchronize.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test BeginSynchronize and EndSynchronize.
 */
HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_001, TestSize.Level0)
{
    auto deferredVideoSession = GetDeferredVideoProcessingSession();
    ASSERT_NE(deferredVideoSession, nullptr);
    int32_t ret = deferredVideoSession->BeginSynchronize();
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->EndSynchronize();
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: Framework
 * Function: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 */
HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_002, TestSize.Level0)
{
    auto deferredVideoSession = GetDeferredVideoProcessingSession();
    ASSERT_NE(deferredVideoSession, nullptr);
    int32_t ret = deferredVideoSession->BeginSynchronize();
    EXPECT_EQ(ret, DP_OK);
    std::string videoId = "testVideo";
    std::string appName = "testapp";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(dup(dtsFd_));
    sptr<IPCFileDescriptor> movieFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    sptr<IPCFileDescriptor> movieCopyFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    std::vector<sptr<IPCFileDescriptor>> fds {srcFd, dstFd, movieFd, movieCopyFd};
    ret = deferredVideoSession->AddVideo(videoId, srcFd, dstFd);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->AddVideo(videoId, fds);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->RemoveVideo(videoId, true);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->RestoreVideo(videoId);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->ProcessVideo(appName, videoId);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->CancelProcessVideo(videoId);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->EndSynchronize();
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: Framework
 * Function: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test fuctions of Class DeferredVideoProcessingSession during sync process.
 */
HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_003, TestSize.Level0)
{
    auto deferredVideoSession = GetDeferredVideoProcessingSession();
    ASSERT_NE(deferredVideoSession, nullptr);
    std::string videoId = "testVideo";
    std::string appName = "testapp";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(dup(dtsFd_));
    sptr<IPCFileDescriptor> movieFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    sptr<IPCFileDescriptor> movieCopyFd = sptr<IPCFileDescriptor>::MakeSptr(dup(srcFd_));
    std::vector<sptr<IPCFileDescriptor>> fds {srcFd, dstFd, movieFd, movieCopyFd};
    auto ret = deferredVideoSession->AddVideo(videoId, srcFd, dstFd);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->AddVideo(videoId, fds);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->RemoveVideo(videoId, true);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->RestoreVideo(videoId);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->ProcessVideo(appName, videoId);
    EXPECT_EQ(ret, DP_OK);
    ret = deferredVideoSession->CancelProcessVideo(videoId);
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: Framework
 * Function: Test fuctions of GetVideoInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test fuctions of GetVideoInfo
 */
HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_004, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    session->Start();
    session->Stop();
    session->videoSessionInfos_.clear();
    auto info = session->GetVideoInfo(USER_ID);
    ASSERT_EQ(info, nullptr);
}

HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_005, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredVideoProcessingSessionCallback> callback = sptr<VideoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<VideoSessionInfo>::MakeSptr(USER_ID, callback);
    session->AddVideoSession(sessionInfo);
    auto info = session->GetVideoInfo(USER_ID);
    ASSERT_NE(info, nullptr);
}

HWTEST_F(VideoSessionUnitTest, camera_deferred_session_unittest_006, TestSize.Level0)
{
    auto session = DPS_GetSessionManager();
    sptr<IDeferredVideoProcessingSessionCallback> callback = sptr<VideoProcessingSessionCallbackMock>::MakeSptr();
    auto sessionInfo = sptr<VideoSessionInfo>::MakeSptr(USER_ID, callback);
    session->AddVideoSession(sessionInfo);
    auto info = session->GetVideoInfo(USER_ID);
    ASSERT_NE(info, nullptr);
    session->DeleteVideoSession(USER_ID);
    session->DeleteVideoSession(OTHER_USER_ID);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS
