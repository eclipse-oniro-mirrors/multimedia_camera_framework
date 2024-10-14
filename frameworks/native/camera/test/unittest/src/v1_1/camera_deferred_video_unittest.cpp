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

#include "camera_deferred_video_unittest.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "basic_definitions.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "events_monitor.h"
#include "camera_log.h"
#include "deferred_processing_service.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
ErrCode TestDeferredVideoProcSessionCallback::OnProcessVideoDone(const std::string& videoId,
    const sptr<IPCFileDescriptor>& ipcFd)
{
    MEDIA_INFO_LOG("TestDeferredVideoProcSessionCallback OnProcessVideoDone.");
    return ERR_OK;
}

ErrCode TestDeferredVideoProcSessionCallback::OnError(const std::string& videoId, int32_t errorCode)
{
    MEDIA_INFO_LOG("TestDeferredVideoProcSessionCallback OnError.");
    return ERR_OK;
}

ErrCode TestDeferredVideoProcSessionCallback::OnStateChanged(int32_t status)
{
    MEDIA_INFO_LOG("TestDeferredVideoProcSessionCallback OnStateChanged.");
    return ERR_OK;
}

void DeferredVideoUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredUnitTest::SetUpTestCase started!");
}

void DeferredVideoUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredUnitTest::TearDownTestCase started!");
}

void DeferredVideoUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp testName:%{public}s",
        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    NativeAuthorization();
    auto callback = sptr<TestDeferredVideoProcSessionCallback>::MakeSptr();
    session_ = DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(g_userId_, callback);
    sessionManager_ = DPS_GetSessionManager();
    schedulerManager_ = DPS_GetSchedulerManager();
    jobRepository_ = schedulerManager_->videoController_[g_userId_]->videoJobRepository_;
}

void DeferredVideoUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredUnitTest::TearDown started!");
}

void DeferredVideoUnitTest::NativeAuthorization()
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

void DeferredVideoUnitTest::BeginSchedule(bool isCharging)
{
    if (isCharging) {
        EventsMonitor::GetInstance().NotifyChargingStatus(CHARGING);
        EventsMonitor::GetInstance().NotifyBatteryLevel(BATTERY_LEVEL_OKAY);
    } else {
        EventsMonitor::GetInstance().NotifyChargingStatus(DISCHARGING);
        EventsMonitor::GetInstance().NotifyBatteryStatus(BATTERY_OKAY);
    }
    EventsMonitor::GetInstance().NotifyMediaLibraryStatus(true);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(HDI_READY);
    EventsMonitor::GetInstance().NotifyThermalLevel(LEVEL_0);
    EventsMonitor::GetInstance().NotifyScreenStatus(SCREEN_OFF);
}

void DeferredVideoUnitTest::PauseSchedule()
{
    EventsMonitor::GetInstance().NotifyScreenStatus(SCREEN_ON);
}

constexpr int VIDEO_REQUEST_FD_ID1 = 111;
// constexpr int VIDEO_REQUEST_FD_ID2 = 222;
// constexpr int VIDEO_REQUEST_FD_ID3 = 333;
constexpr int VIDEO_REQUEST_FD_TEMP = 888;

constexpr int64_t TIME_PROCESS = 200;
constexpr int64_t TIME_TEST_WAIT = 1000;

HWTEST_F(DeferredVideoUnitTest, AddJob, TestSize.Level0)
{
    std::string videoId = "video1";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId, srcFd, dstFd);
    BeginSchedule(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 1);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

HWTEST_F(DeferredVideoUnitTest, AddJob_C, TestSize.Level0)
{
    std::string videoId = "video1";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId, srcFd, dstFd);
    BeginSchedule(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 1);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

HWTEST_F(DeferredVideoUnitTest, PauseJob, TestSize.Level0)
{
    std::string videoId = "video1";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId, srcFd, dstFd);
    BeginSchedule(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 1);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    EventsMonitor::GetInstance().NotifyBatteryStatus(BATTERY_LOW);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 0);
    taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::PAUSE);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

HWTEST_F(DeferredVideoUnitTest, PauseJob_C, TestSize.Level0)
{
    std::string videoId = "video1";
    sptr<IPCFileDescriptor> srcFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId, srcFd, dstFd);
    BeginSchedule(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 1);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    EventsMonitor::GetInstance().NotifyBatteryLevel(BATTERY_LEVEL_LOW);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    num = jobRepository_->GetRunningJobCounts();
    ASSERT_EQ(num, 0);
    taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::PAUSE);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

HWTEST_F(DeferredVideoUnitTest, DeleteJob, TestSize.Level0)
{
    std::string videoId_1 = "video1";
    sptr<IPCFileDescriptor> srcFd_1 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd_1 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId_1, srcFd_1, dstFd_1);
    std::string videoId_2 = "video2";
    sptr<IPCFileDescriptor> srcFd_2 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd_2 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId_2, srcFd_2, dstFd_2);
    BeginSchedule(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto jobQueue = jobRepository_->jobQueue_;
    ASSERT_NE(jobQueue, nullptr);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    session_->RemoveVideo(videoId_2, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    jobQueue = jobRepository_->jobQueue_;
    ASSERT_NE(jobQueue, nullptr);
    taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);


    taskVideo = jobRepository_->GetJobUnLocked(videoId_2);
    EXPECT_EQ(taskVideo, nullptr);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

HWTEST_F(DeferredVideoUnitTest, DeleteJob_R, TestSize.Level0)
{
    std::string videoId_1 = "video1";
    sptr<IPCFileDescriptor> srcFd_1 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd_1 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId_1, srcFd_1, dstFd_1);
    std::string videoId_2 = "video2";
    sptr<IPCFileDescriptor> srcFd_2 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_ID1);
    sptr<IPCFileDescriptor> dstFd_2 = sptr<IPCFileDescriptor>::MakeSptr(VIDEO_REQUEST_FD_TEMP);
    session_->AddVideo(videoId_2, srcFd_2, dstFd_2);
    BeginSchedule(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    auto jobQueue = jobRepository_->jobQueue_;
    ASSERT_NE(jobQueue, nullptr);
    auto taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    session_->RemoveVideo(videoId_2, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_PROCESS));
    jobQueue = jobRepository_->jobQueue_;
    ASSERT_NE(jobQueue, nullptr);
    taskVideo = jobRepository_->GetJob();
    ASSERT_NE(taskVideo, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video1");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::RUNNING);

    taskVideo = jobRepository_->GetJobUnLocked(videoId_2);
    ASSERT_NE(jobQueue, nullptr);
    EXPECT_EQ(taskVideo->GetVideoId(), "video2");
    EXPECT_EQ(taskVideo->GetCurStatus(), VideoJobStatus::DELETED);

    PauseSchedule();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_TEST_WAIT));
}

} // CameraStandard
} // OHOS
