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

#include "deferred_video_processor_stratety_unittest.h"
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

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

void DeferredVideoProcessorStratetyUnittest::SetUpTestCase(void) {}

void DeferredVideoProcessorStratetyUnittest::TearDownTestCase(void) {}

void DeferredVideoProcessorStratetyUnittest::SetUp()
{
    NativeAuthorization();
}

void DeferredVideoProcessorStratetyUnittest::TearDown() {}

void DeferredVideoProcessorStratetyUnittest::NativeAuthorization()
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
 * Function: Test initialize videoStrategyCenter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test after initialize videoStrategyCenter, eventsListener is not nullptr.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_001, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    EXPECT_NE(strategyCenter->eventsListener_, nullptr);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter HandleEventChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the event schedule state value can be set by HandleEventChanged.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_002, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->HandleEventChanged(CAMERA_SESSION_STATUS_EVENT, SYSTEM_PRESSURE_LEVEL_EVENT_VALUE);
    auto scheduleState = strategyCenter->GetSchedulerState(SchedulerType::VIDEO_CAMERA_STATE);
    EXPECT_EQ(scheduleState->stateValue_, SYSTEM_PRESSURE_LEVEL_EVENT_VALUE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the default execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_003, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while strategy center is ready, execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_004, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->isNeedStop_ = false;
    auto isReady = strategyCenter->IsReady();
    EXPECT_TRUE(isReady);
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while charging status is DISCHARGING, execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_005, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->HandleChargingEvent(ChargingStatus::DISCHARGING);
    EXPECT_EQ(strategyCenter->isCharging_, ChargingStatus::DISCHARGING);
    strategyCenter->isNeedStop_ = true;
    auto isReady = strategyCenter->IsReady();
    EXPECT_FALSE(isReady);
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while charging status is DISCHARGING, strategy center and time is ready,
 *                  execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_006, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->HandleChargingEvent(ChargingStatus::DISCHARGING);
    EXPECT_EQ(strategyCenter->isCharging_, ChargingStatus::DISCHARGING);
    strategyCenter->isNeedStop_ = false;
    auto isReady = strategyCenter->IsReady();
    EXPECT_TRUE(isReady);
    auto timeReady = strategyCenter->IsTimeReady();
    EXPECT_TRUE(timeReady);
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while charging status is DISCHARGING, but time is not ready, execution mode is DUMMY.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_007, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->HandleChargingEvent(ChargingStatus::DISCHARGING);
    EXPECT_EQ(strategyCenter->isCharging_, ChargingStatus::DISCHARGING);
    strategyCenter->isNeedStop_ = false;
    auto isReady = strategyCenter->IsReady();
    EXPECT_TRUE(isReady);
    strategyCenter->UpdateSingleTime(false);
    auto timeReady = strategyCenter->IsTimeReady();
    EXPECT_FALSE(timeReady);
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetWork
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while execution mode is DUMMY, work is nullptr.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_008, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    strategyCenter->isNeedStop_ = false;
    auto isReady = strategyCenter->IsReady();
    EXPECT_TRUE(isReady);
    auto mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
    auto job = strategyCenter->GetJob();
    auto work = strategyCenter->GetWork();
    if (job) {
        EXPECT_NE(work, nullptr);
    } else {
        EXPECT_EQ(work, nullptr);
    }
    strategyCenter->isNeedStop_ = true;
    isReady = strategyCenter->IsReady();
    EXPECT_FALSE(isReady);
    mode = strategyCenter->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    EXPECT_EQ(work, nullptr);
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
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    auto timeReady = strategyCenter->IsTimeReady();
    EXPECT_TRUE(timeReady);
    strategyCenter->UpdateSingleTime(false);
    timeReady = strategyCenter->IsTimeReady();
    EXPECT_FALSE(timeReady);
    strategyCenter->UpdateSingleTime(true);
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
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    auto availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, TOTAL_PROCESS_TIME);
    strategyCenter->UpdateAvailableTime(false, ONCE_PROCESS_TIME);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, ONCE_PROCESS_TIME);
    strategyCenter->UpdateAvailableTime(false, ONCE_PROCESS_TIME);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, 0);
    strategyCenter->UpdateAvailableTime(true, TOTAL_PROCESS_TIME);
    availableTime = strategyCenter->availableTime_;
    EXPECT_EQ(availableTime, TOTAL_PROCESS_TIME);
}

/*
 * Feature: Deferred
 * Function: Test videoStrategyCenter GetSchedulerInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while GetSchedulerInfo type is not supported, default schedule info will be returned.
 */
HWTEST_F(DeferredVideoProcessorStratetyUnittest, deferred_video_processor_stratety_unittest_011, TestSize.Level0)
{
    auto repository = std::make_shared<VideoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategyCenter = std::make_shared<VideoStrategyCenter>(repository);
    ASSERT_NE(strategyCenter, nullptr);

    strategyCenter->Initialize();
    SchedulerInfo scheduleInfo = strategyCenter->GetSchedulerInfo(SchedulerType::NORMAL_TIME_STATE);
    EXPECT_TRUE(scheduleInfo.isNeedStop);
    EXPECT_FALSE(scheduleInfo.isCharging);
}
} // CameraStandard
} // OHOS