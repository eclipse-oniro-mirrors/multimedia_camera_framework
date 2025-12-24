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

#include "deferred_video_processor_stratety_unittest.h"

#include "basic_definitions.h"
#include "istate.h"
#include "video_camera_state.h"
#include "video_charging_state.h"
#include "video_hal_state.h"
#include "video_job_repository.h"
#include "video_media_library_state.h"
#include "video_photo_process_state.h"
#include "video_screen_state.h"
#include "video_strategy_center.h"
#include "video_temperature_state.h"
#include "gtest/gtest.h"
#include "test_token.h"
#include <fcntl.h>

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
const std::string MEDIA_ROOT = "/data/test/media/";
const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
const std::string VIDEO_TEMP_PATH = MEDIA_ROOT + "test_video_temp.mp4";
const std::string VIDEO_ID = "videoTest";

void DeferredVideoProcessorStratetyUnittest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void DeferredVideoProcessorStratetyUnittest::TearDownTestCase(void) {}

void DeferredVideoProcessorStratetyUnittest::SetUp()
{
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    dtsFd_ = open(VIDEO_TEMP_PATH.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
}

void DeferredVideoProcessorStratetyUnittest::TearDown()
{
    if (srcFd_ > 0) {
        close(srcFd_);
    }
    if (dtsFd_ > 0) {
        close(dtsFd_);
    }
}

/*
 * Feature: Deferred
 * Function: Test initialize videoStrategyCenter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test after initialize videoStrategyCenter, eventsListener is not nullptr.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_001, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    EXPECT_NE(strategyCenter->eventsListener_, nullptr);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetJob
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetJob.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_002, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID, info);
    strategyCenter->isNeedStop_ = false;
    strategyCenter->isCharging_ = true;
    auto job = strategyCenter->GetJob();
    EXPECT_EQ(job->videoId_, VIDEO_ID);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetJob
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetJob.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_003, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    auto job = strategyCenter->GetJob();
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetJob
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetJob.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_004, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    DpsFdPtr outFd = std::make_shared<DpsFd>(dup(dtsFd_));
    auto info = std::make_shared<VideoInfo>(inputFd, outFd);
    repository->AddVideoJob(VIDEO_ID, info);
    auto job = strategyCenter->GetJob();
    EXPECT_EQ(job, nullptr);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_005, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isCharging_ = true;
    strategyCenter->isNeedStop_ = false;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_006, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isCharging_ = true;
    strategyCenter->isNeedStop_ = true;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_007, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isCharging_ = false;
    strategyCenter->isNeedStop_ = false;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_008, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isCharging_ = false;
    strategyCenter->isNeedStop_ = true;
    strategyCenter->isTimeOk_ |= 0b0;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter UpdateSingleTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the time ready status can be set by UpdateSingleTime.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_009, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    auto timeReady = strategyCenter->IsTimeReady();
    EXPECT_TRUE(timeReady);
    strategyCenter->UpdateSingleTime(false);
    timeReady = strategyCenter->IsTimeReady();
    EXPECT_FALSE(timeReady);
    strategyCenter->UpdateSingleTime(true);
    EXPECT_EQ(strategyCenter->singleTime_, ONCE_PROCESS_TIME);
    timeReady = strategyCenter->IsTimeReady();
    EXPECT_TRUE(timeReady);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter UpdateAvailableTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the available time status can be set by UpdateAvailableTime.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_010, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);

    auto availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, TOTAL_PROCESS_TIME);
    strategyCenter->UpdateAvailableTime(1000);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, TOTAL_PROCESS_TIME - 1000);
    strategyCenter->UpdateAvailableTime(-1);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, TOTAL_PROCESS_TIME);
    strategyCenter->UpdateAvailableTime(TOTAL_PROCESS_TIME);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, 0);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetAvailableTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the available time status can be set by GetAvailableTime.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_011, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->UpdateAvailableTime(1000);
    EXPECT_EQ(strategyCenter->availableTime_, TOTAL_PROCESS_TIME - 1000);
    EXPECT_EQ(strategyCenter->singleTime_, ONCE_PROCESS_TIME - 1000);
    auto time = strategyCenter->GetAvailableTime();
    EXPECT_EQ(time, ONCE_PROCESS_TIME - 1000);
    strategyCenter->UpdateAvailableTime(ONCE_PROCESS_TIME);
    time = strategyCenter->GetAvailableTime();
    EXPECT_EQ(time, 0);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter HandleEventChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HandleEventChanged VIDEO_HDI_STATUS_EVENT.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_012, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter->HandleEventChanged(EventType::VIDEO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    if (!strategyCenter->isNeedStop_) {
        EXPECT_FALSE(strategyCenter->isNeedStop_);
    }
    EXPECT_NE(strategyCenter, nullptr);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter HandleEventChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HandleEventChanged VIDEO_HDI_STATUS_EVENT.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_013, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->HandleEventChanged(EventType::VIDEO_HDI_STATUS_EVENT, HDI_DISCONNECTED);
    EXPECT_TRUE(strategyCenter->isNeedStop_);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter HandleEventChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HandleEventChanged VIDEO_HDI_STATUS_EVENT.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_014, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_DISCONNECTED);
    EXPECT_TRUE(strategyCenter->isNeedStop_);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter ReevaluateSchedulerInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReevaluateSchedulerInfo.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_015, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    SchedulerInfo SchedulerInfo = strategyCenter->ReevaluateSchedulerInfo();
    EXPECT_TRUE(SchedulerInfo.isNeedStop);

    strategyCenter->HandleHalEvent(HDI_READY);
    strategyCenter->HandleCameraEvent(SYSTEM_CAMERA_CLOSED);
    strategyCenter->HandleMedialLibraryEvent(MEDIA_LIBRARY_AVAILABLE);
    strategyCenter->HandleScreenEvent(SCREEN_OFF);
    strategyCenter->HandleBatteryEvent(BATTERY_OKAY);
    strategyCenter->HandleBatteryLevelEvent(BATTERY_LEVEL_OKAY);
    strategyCenter->HandleTemperatureEvent(LEVEL_0);
    strategyCenter->HandlePhotoProcessEvent(0);
    
    strategyCenter->HandleChargingEvent(CHARGING);
    SchedulerInfo = strategyCenter->ReevaluateSchedulerInfo();
    EXPECT_FALSE(SchedulerInfo.isNeedStop);

    strategyCenter->HandleBatteryLevelEvent(BATTERY_LEVEL_LOW);
    SchedulerInfo = strategyCenter->ReevaluateSchedulerInfo();
    EXPECT_TRUE(SchedulerInfo.isNeedStop);

    strategyCenter->HandleChargingEvent(DISCHARGING);
    SchedulerInfo = strategyCenter->ReevaluateSchedulerInfo();
    EXPECT_FALSE(SchedulerInfo.isNeedStop);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode HIGH
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_016, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isNeedStop_ = false;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::HIGH);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode HIGH
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_017, TestSize.Level0)
{
    auto repository = VideoJobRepository::Create(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = VideoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter, nullptr);
    strategyCenter->isNeedStop_ = true;
    auto mode = strategyCenter->GetExecutionMode(JobPriority::HIGH);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}
} // CameraStandard
} // OHOS