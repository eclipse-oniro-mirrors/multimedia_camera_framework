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

#include "camera_deferred_base_unittest.h"
#include <cstdint>
#include <vector>
#include "camera_manager.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "ipc_skeleton.h"
#include "test_common.h"

#include "time_broker.h"
#include "shared_buffer.h"
#include "task_manager/thread_pool.h"
#include "steady_clock.h"
#include "timer_core.h"
#include "basic_definitions.h"
#include "dps.h"
#include "session_manager.h"
#include "scheduler_manager.h"
#include "task_manager.h"

#include "command_server.h"
#include "command_server_impl.h"
#include "command.h"
#include "image_info.h"
#include "media_progress_notifier.h"
#include "picture_interface.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

const uint32_t EXPIREATION_TIME_MILLI_SECONDS = 12 * 60 * 1000;
const uint32_t ADD_TIME_MILLI_SECONDS = 10000;

namespace OHOS {
namespace CameraStandard {

void DeferredBaseUnitTest::SetUpTestCase(void) {}

void DeferredBaseUnitTest::TearDownTestCase(void) {}

void DeferredBaseUnitTest::SetUp() {}

void DeferredBaseUnitTest::TearDown() {}

/*
 * Feature: Framework
 * Function: Test gets the size and fd of sharebuffer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test gets the size and fd of sharebuffer
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_001, TestSize.Level0)
{
    int32_t dataSize = 1;
    std::shared_ptr<SharedBuffer> sharedBuffer = std::make_shared<SharedBuffer>(dataSize);
    ASSERT_NE(sharedBuffer, nullptr);
    sharedBuffer->Initialize();
    EXPECT_NE(sharedBuffer->GetSize(), -1);
    EXPECT_NE(sharedBuffer->GetFd(), -1);
    sharedBuffer->DeallocAshmem();
    sharedBuffer->ashmem_ = nullptr;
    EXPECT_EQ(sharedBuffer->GetFd(), -1);
    EXPECT_EQ(sharedBuffer->GetSize(), -1);
}

/*
 * Feature: Framework
 * Function: Test create delayed task group, when taskRegistry is empty,
 * the task group is deregistered, tasks are submitted, and all tasks are canceled
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create delayed task group, when taskRegistry is empty,
 * the task group is deregistered, tasks are submitted, and all tasks are canceled
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_002, TestSize.Level0)
{
    int32_t numThreads = 1;
    std::shared_ptr<TaskManager> taskManager =
        std::make_shared<TaskManager>("camera_deferred_base", numThreads, false);
    ASSERT_NE(taskManager, nullptr);
    if (taskManager->delayedTaskHandle_ != INVALID_TASK_GROUP_HANDLE) {
        taskManager->CreateDelayedTaskGroupIfNeed();
    } else {
        taskManager->delayedTaskHandle_ = INVALID_TASK_GROUP_HANDLE;
        taskManager->CreateDelayedTaskGroupIfNeed();
    }
    taskManager->IsEmpty();
    taskManager->taskRegistry_ = nullptr;
    EXPECT_FALSE(taskManager->DeregisterTaskGroup("defaultTaskGroup", *(taskManager->defaultTaskHandle_)));

    std::any param1 = 1;
    EXPECT_FALSE(taskManager->SubmitTask(*(taskManager->defaultTaskHandle_), param1));
    taskManager->CancelAllTasks();
    EXPECT_TRUE(taskManager->IsEmpty());
}

/*
 * Feature: Framework
 * Function: Test get task group
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get task group
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_003, TestSize.Level0)
{
    int32_t numThreads = 1;
    std::shared_ptr<TaskManager> taskManager =
        std::make_shared<TaskManager>("camera_deferred_base", numThreads, false);
    auto it = taskManager->taskRegistry_->registry_.find(taskManager->delayedTaskHandle_);
    if (it == taskManager->taskRegistry_->registry_.end()) {
        EXPECT_EQ(taskManager->taskRegistry_->GetTaskCount(taskManager->delayedTaskHandle_), 0);
    } else {
        taskManager->taskRegistry_->GetTaskCount(taskManager->delayedTaskHandle_);
    }
}

/*
 * Feature: Framework
 * Function: Tests creating a thread pool when numThreads is 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Tests creating a thread pool when numThreads is 0
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_004, TestSize.Level0)
{
    uint32_t numThreads = 0;
    std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>("camera_deferred_base", numThreads);
    ASSERT_NE(threadPool, nullptr);
    EXPECT_NE(threadPool->numThreads_, 0);
}

/*
 * Feature: Framework
 * Function: Test the creation of the time broker and test
 * the registration and deregistration callbacks of the time broker
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the creation of the time broker and test
 * the registration and deregistration callbacks of the time broker
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_005, TestSize.Level0)
{
    std::shared_ptr<TimeBroker> timeBroker = TimeBroker::Create("camera_deferred_base");
    ASSERT_NE(timeBroker, nullptr);
    timeBroker->Initialize();
    EXPECT_NE(timeBroker->timer_, nullptr);
    uint32_t delayTimeMs = 1;
    uint32_t handle = timeBroker->GenerateHandle();
    std::function<void(uint32_t handle)> timerCallback = timeBroker->GetExpiredFunc(handle);
    bool registerCallbackRet = false;
    if (timeBroker->GetNextHandle(handle)) {
        registerCallbackRet = timeBroker->RegisterCallback(delayTimeMs, timerCallback, handle);
        EXPECT_TRUE(registerCallbackRet);
    } else {
        registerCallbackRet = timeBroker->RegisterCallback(delayTimeMs, timerCallback, handle);
        EXPECT_FALSE(registerCallbackRet);
    }
    timeBroker->DeregisterCallback(handle);
}

/*
 * Feature: Framework
 * Function: Test timer expiration and restart timer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test timer expiration and restart timer
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_006, TestSize.Level0)
{
    std::shared_ptr<TimeBroker> timeBroker = TimeBroker::Create("camera_deferred_base");
    ASSERT_NE(timeBroker, nullptr);
    timeBroker->Initialize();
    EXPECT_NE(timeBroker->timer_, nullptr);
    uint32_t delayTimeMs = 1;
    uint32_t handle = timeBroker->GenerateHandle();
    std::function<void(uint32_t handle)> timerCallback = timeBroker->GetExpiredFunc(handle);
    timeBroker->RegisterCallback(delayTimeMs, timerCallback, handle);
    timeBroker->TimerExpired();
    bool force = true;
    if (!(timeBroker->timeline_.empty() || (timeBroker->timer_->IsActive()))) {
        EXPECT_EQ(timeBroker->RestartTimer(force), timeBroker->timer_->StartAt(timeBroker->timeline_.top()));
    } else {
        force = false;
        EXPECT_TRUE(timeBroker->RestartTimer(force));
    }
}

/*
 * Feature: Framework
 * Function: Test registration and deregistration timer core callbacks,
 * and succeeds when valid parameters are entered
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration timer core callbacks,
 * and succeeds when valid parameters are entered
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_007, TestSize.Level0)
{
    std::shared_ptr<TimerCore> timerCore = std::make_shared<TimerCore>();
    ASSERT_NE(timerCore, nullptr);
    timerCore->Initialize();
    uint64_t timestampMs = 0;
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::ONCE, 0, timerCallback);
    EXPECT_TRUE(timerCore->RegisterTimer(timestampMs, timer));
    timerCore->GetNextExpirationTimeUnlocked();
    EXPECT_TRUE(timerCore->DeregisterTimer(timestampMs, timer));
}

/*
 * Feature: Framework
 * Function: Test registration and deregistration timer core callbacks,
 * registration failed when invalid parameters were entered
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration timer core callbacks,
 * registration failed when invalid parameters were entered
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_008, TestSize.Level0)
{
    std::shared_ptr<TimerCore> timerCore = std::make_shared<TimerCore>();
    ASSERT_NE(timerCore, nullptr);
    timerCore->Initialize();
    uint64_t timestampMs = 0;
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::ONCE, 0, timerCallback);
    timerCore->active_ = false;
    EXPECT_FALSE(timerCore->RegisterTimer(timestampMs, timer));
    EXPECT_TRUE(timerCore->DeregisterTimer(timestampMs, timer));
}

/*
 * Feature: Framework
 * Function: Test registration and deregistration timer core callbacks,
 * and failed when invalid parameters were entered
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration timer core callbacks,
 * and failed when invalid parameters were entered
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_009, TestSize.Level0)
{
    std::shared_ptr<TimerCore> timerCore = std::make_shared<TimerCore>();
    ASSERT_NE(timerCore, nullptr);
    timerCore->Initialize();
    uint64_t timestampMs = 0;
    std::function<void()> timerCallback;
    std::shared_ptr<Timer> temp;
    const std::shared_ptr<Timer>& timer = temp;
    timerCore->active_ = true;
    EXPECT_FALSE(timerCore->RegisterTimer(timestampMs, timer));
    EXPECT_FALSE(timerCore->DeregisterTimer(timestampMs, timer));
}

/*
 * Feature: Framework
 * Function: Test DoTimeout and GetNextExpirationTimeUnlocked hooks When the timerTime is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DoTimeout and GetNextExpirationTimeUnlocked hooks When the timerTime is null
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_010, TestSize.Level0)
{
    std::shared_ptr<TimerCore> timerCore = std::make_shared<TimerCore>();
    ASSERT_NE(timerCore, nullptr);
    timerCore->timeline_ = std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>>();
    timerCore->DoTimeout();
    EXPECT_EQ(timerCore->GetNextExpirationTimeUnlocked(), std::chrono::milliseconds(EXPIREATION_TIME_MILLI_SECONDS));
}

/*
 * Feature: Framework
 * Function: Test repeated initialization
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test repeated initialization
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_011, TestSize.Level0)
{
    DeferredProcessing::DPS_Destroy();
    DeferredProcessing::DPS_GetCommandServer();
    DeferredProcessing::DPS_GetSessionManager();
    DeferredProcessing::DPS_GetSchedulerManager();
    EXPECT_EQ(DeferredProcessing::DPS_Initialize(), 0);
}

/*
 * Feature: Framework
 * Function: Test different branches of GetElapsedTimeMs
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test different branches of GetElapsedTimeMs
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_012, TestSize.Level0)
{
    uint64_t startMs = 1;
    uint64_t diff = DeferredProcessing::SteadyClock::GetElapsedTimeMs(startMs);
    EXPECT_NE(diff, 0);
    uint64_t curtime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    diff = DeferredProcessing::SteadyClock::GetElapsedTimeMs((curtime + ADD_TIME_MILLI_SECONDS));
    EXPECT_EQ(diff, 0);
}

/*
 * Feature: Framework
 * Function: Test the abnormal branch of DeregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal branch of DeregisterCallback
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_013, TestSize.Level0)
{
    std::shared_ptr<TimeBroker> timeBroker = TimeBroker::Create("camera_deferred_base");
    ASSERT_NE(timeBroker, nullptr);
    timeBroker->Initialize();
    EXPECT_NE(timeBroker->timer_, nullptr);
    uint32_t delayTimeMs = 1;
    uint32_t handle = timeBroker->GenerateHandle();
    std::function<void(uint32_t handle)> timerCallback = timeBroker->GetExpiredFunc(handle);
    timeBroker->RegisterCallback(delayTimeMs, timerCallback, handle);
    handle = 0;
    timeBroker->DeregisterCallback(handle);
    EXPECT_NE(timeBroker->timerInfos_.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test TimerExpired when timeline is empty
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TimerExpired when timeline is empty
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_014, TestSize.Level0)
{
    std::shared_ptr<TimeBroker> timeBroker = TimeBroker::Create("camera_deferred_base");
    ASSERT_NE(timeBroker, nullptr);
    timeBroker->Initialize();
    timeBroker->timeline_ = std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>>();
    EXPECT_TRUE((timeBroker->timeline_.empty()));
    timeBroker->TimerExpired();
}

/*
 * Feature: Framework
 * Function: Test the branch when the active of timer is true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the branch when the active of timer is true
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_015, TestSize.Level0)
{
    uint64_t timestampMs = 0;
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::ONCE, 0, timerCallback);
    ASSERT_NE(timer, nullptr);
    timer->active_ = true;
    timer->StartAtUnlocked(timestampMs);
    EXPECT_EQ(timer->expiredTimeMs_, 0);
}

/*
 * Feature: Framework
 * Function: Test TimerExpired
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TimerExpired
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_016, TestSize.Level0)
{
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::ONCE, 0, timerCallback);
    ASSERT_NE(timer, nullptr);
    timer->active_ = false;
    timer->TimerExpired();
    timer->active_ = true;
    timer->TimerExpired();
    EXPECT_FALSE(timer->active_);
}

/*
 * Feature: Framework
 * Function: Test the different branches of TimerExpired
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the different branches of TimerExpired
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_017, TestSize.Level0)
{
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::PERIODIC, 0, timerCallback);
    ASSERT_NE(timer, nullptr);
    timer->active_ = true;
    timer->TimerExpired();
    EXPECT_TRUE(timer->active_);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_018, TestSize.Level0) {
    DpsStatus statusCode = DpsStatus::DPS_SESSION_STATE_IDLE;
    StatusCode result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_IDLE);
    statusCode = DpsStatus::DPS_SESSION_STATE_RUNNABLE;
    result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_RUNNABLE);
    statusCode = DpsStatus::DPS_SESSION_STATE_RUNNING;
    result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_RUNNING);
    statusCode = DpsStatus::DPS_SESSION_STATE_SUSPENDED;
    result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_SUSPENDED);
    statusCode = DpsStatus::DPS_SESSION_STATE_PREEMPTED;
    result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_PREEMPTED);
    statusCode = static_cast<DpsStatus>(100); // 假设 100 是一个无效的 DpsStatus 值
    result = MapDpsStatus(statusCode);
    EXPECT_EQ(result, StatusCode::SESSION_STATE_IDLE);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_019, TestSize.Level0) {
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID;
    DpsError result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS;
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT;
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE;
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL;
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL);
    errorCode = OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT;
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED);
    errorCode = static_cast<OHOS::HDI::Camera::V1_2::ErrorCode>(999); // 999 是一个未定义的错误码
    result = MapHdiError(errorCode);
    EXPECT_EQ(result, DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_020, TestSize.Level0) {
    ExecutionMode input = ExecutionMode::HIGH_PERFORMANCE;
    OHOS::HDI::Camera::V1_2::ExecutionMode expected = OHOS::HDI::Camera::V1_2::ExecutionMode::HIGH_PREFORMANCE;
    OHOS::HDI::Camera::V1_2::ExecutionMode result = MapToHdiExecutionMode(input);
    EXPECT_EQ(result, expected);
    input = ExecutionMode::LOAD_BALANCE;
    expected = OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED;
    result = MapToHdiExecutionMode(input);
    EXPECT_EQ(result, expected);
    input = ExecutionMode::LOW_POWER;
    expected = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
    result = MapToHdiExecutionMode(input);
    EXPECT_EQ(result, expected);
    input = static_cast<ExecutionMode>(999); // 假设999是一个无效的枚举值
    expected = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER; // 预期结果,具体值不重要
    result = MapToHdiExecutionMode(input);
    EXPECT_EQ(result, expected);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_021, TestSize.Level0) {
    OHOS::HDI::Camera::V1_2::SessionStatus statusCode = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY;
    HdiStatus result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_READY);
    statusCode = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED;
    result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_READY_SPACE_LIMIT_REACHED);
    statusCode = OHOS::HDI::Camera::V1_2::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY;
    result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_NOT_READY_TEMPORARILY);
    statusCode = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT;
    result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_NOT_READY_OVERHEAT);
    statusCode = OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED;
    result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_NOT_READY_PREEMPTED);
    statusCode = static_cast<OHOS::HDI::Camera::V1_2::SessionStatus>(999); // 假设999是一个无效的statusCode
    result = MapHdiStatus(statusCode);
    EXPECT_EQ(result, HdiStatus::HDI_DISCONNECTED);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_022, TestSize.Level0) {
    int32_t level = ThermalLevel::LEVEL_0;
    VideoThermalLevel result = ConvertVideoThermalLevel(level);
    EXPECT_EQ(result, VideoThermalLevel::COOL);
    level = ThermalLevel::LEVEL_1; // 假设LEVEL_1是其他级别
    result = ConvertVideoThermalLevel(level);
    EXPECT_EQ(result, VideoThermalLevel::HOT);
    level = ThermalLevel::LEVEL_2;
    result = ConvertVideoThermalLevel(level);
    EXPECT_EQ(result, VideoThermalLevel::HOT);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_023, TestSize.Level0) {
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_SESSION_SYNC_NEEDED), ErrorCode::ERROR_SESSION_SYNC_NEEDED);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY), ErrorCode::ERROR_SESSION_NOT_READY_TEMPORARILY);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID), ErrorCode::ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_FAILED), ErrorCode::ERROR_IMAGE_PROC_FAILED);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT), ErrorCode::ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL), ErrorCode::ERROR_IMAGE_PROC_ABNORMAL);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED), ErrorCode::ERROR_IMAGE_PROC_INTERRUPTED);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID), ErrorCode::ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_FAILED), ErrorCode::ERROR_VIDEO_PROC_FAILED);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT), ErrorCode::ERROR_VIDEO_PROC_TIMEOUT);
    EXPECT_EQ(MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED), ErrorCode::ERROR_VIDEO_PROC_INTERRUPTED);
}

/*
 * Feature: Framework
 * Function: Test the ConvertPhotoThermalLevel
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the ConvertPhotoThermalLevel
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_024, TestSize.Level0) {
    int32_t level = 5;
    EXPECT_EQ(ConvertPhotoThermalLevel(level), SystemPressureLevel::SEVERE);
}

namespace {
class TestCommand : public Command {
    DECLARE_CMD_CLASS(TestCommand)
    int32_t Executing() override { return 0; }
};
} // namespace

/*
 * Feature: CommandServer
 * Function: Test Initialize creates the server instance
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After Initialize, SendCommand should return DP_OK
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_025, TestSize.Level0)
{
    CommandServer cmdServer;
    int32_t ret = cmdServer.Initialize("TestCmdServer");
    EXPECT_EQ(ret, DP_OK);

    auto cmd = std::make_shared<TestCommand>();
    ret = cmdServer.SendCommand(cmd);
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: CommandServer
 * Function: Test Initialize idempotent (re-initialization)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Calling Initialize twice should not crash and return DP_OK both times
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_026, TestSize.Level0)
{
    CommandServer cmdServer;
    int32_t ret = cmdServer.Initialize("TestCmdServer");
    EXPECT_EQ(ret, DP_OK);

    ret = cmdServer.Initialize("TestCmdServer");
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: CommandServer
 * Function: Test SendCommand without Initialize returns DP_INIT_FAIL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendCommand should return DP_INIT_FAIL when server is not initialized
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_027, TestSize.Level0)
{
    CommandServer cmdServer;
    auto cmd = std::make_shared<TestCommand>();
    int32_t ret = cmdServer.SendCommand(cmd);
    EXPECT_EQ(ret, DP_INIT_FAIL);
}

/*
 * Feature: CommandServer
 * Function: Test SendUrgentCommand with valid server
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendUrgentCommand should return DP_OK when server is initialized
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_028, TestSize.Level0)
{
    CommandServer cmdServer;
    int32_t ret = cmdServer.Initialize("TestCmdServer");
    EXPECT_EQ(ret, DP_OK);

    auto cmd = std::make_shared<TestCommand>();
    ret = cmdServer.SendUrgentCommand(cmd);
    EXPECT_EQ(ret, DP_OK);
}

/*
 * Feature: CommandServer
 * Function: Test SendUrgentCommand without Initialize returns DP_INIT_FAIL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendUrgentCommand should return DP_INIT_FAIL when server is not initialized
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_029, TestSize.Level0)
{
    CommandServer cmdServer;
    auto cmd = std::make_shared<TestCommand>();
    int32_t ret = cmdServer.SendUrgentCommand(cmd);
    EXPECT_EQ(ret, DP_INIT_FAIL);
}

/*
 * Feature: CommandServer
 * Function: Test SetThreadPriority and GetThreadPriority
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetThreadPriority and GetThreadPriority should work when server is initialized
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_030, TestSize.Level0)
{
    CommandServer cmdServer;
    int32_t ret = cmdServer.Initialize("TestCmdServer");
    EXPECT_EQ(ret, DP_OK);

    cmdServer.SetThreadPriority(10);
    int32_t priority = cmdServer.GetThreadPriority();
    EXPECT_EQ(priority, 10);
}

/*
 * Feature: CommandServer
 * Function: Test GetThreadPriority without Initialize returns DP_INIT_FAIL
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThreadPriority should return DP_INIT_FAIL when server is not initialized
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_032, TestSize.Level0)
{
    CommandServer cmdServer;
    int32_t priority = cmdServer.GetThreadPriority();
    EXPECT_EQ(priority, DP_INIT_FAIL);
}

/*
 * Feature: ImageInfo
 * Function: Test default constructor initializes members correctly
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Default constructor should set dataSize_ to 0, isHighQuality_ to false,
 * and type_ to CallbackType::NONE
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_033, TestSize.Level0)
{
    ImageInfo imageInfo;
    EXPECT_EQ(imageInfo.GetDataSize(), 0);
    EXPECT_FALSE(imageInfo.IsHighQuality());

    EXPECT_EQ(imageInfo.GetCloudFlag(), 0U);
    EXPECT_EQ(imageInfo.GetCaptureFlag(), 0U);
    EXPECT_EQ(imageInfo.GetType(), CallbackType::NONE);
    EXPECT_EQ(imageInfo.GetErrorCode(), DpsError::DPS_NO_ERROR);
}

/*
 * Feature: ImageInfo
 * Function: Test parameterized constructor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Parameterized constructor should set all members correctly
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_034, TestSize.Level0)
{
    int32_t dataSize = 1024;
    bool isHighQuality = true;
    uint32_t cloudFlag = 1;
    uint32_t captureFlag = 2;
    DpsMetadata metadata;

    ImageInfo imageInfo(dataSize, isHighQuality, cloudFlag, captureFlag, metadata);
    EXPECT_EQ(imageInfo.GetDataSize(), dataSize);
    EXPECT_TRUE(imageInfo.IsHighQuality());
    EXPECT_EQ(imageInfo.GetCloudFlag(), cloudFlag);
    EXPECT_EQ(imageInfo.GetCaptureFlag(), captureFlag);
}

/*
 * Feature: ImageInfo
 * Function: Test SetBuffer changes type to IMAGE_PROCESS_DONE
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetBuffer should set the shared buffer and change callback type
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_035, TestSize.Level0)
{
    ImageInfo imageInfo;
    int32_t dataSize = 128;
    auto sharedBuffer = std::make_unique<SharedBuffer>(dataSize);
    sharedBuffer->Initialize();
    ASSERT_NE(sharedBuffer, nullptr);

    imageInfo.SetBuffer(std::move(sharedBuffer));
    EXPECT_EQ(imageInfo.GetType(), CallbackType::IMAGE_PROCESS_DONE);
}

/*
 * Feature: ImageInfo
 * Function: Test SetError changes type to IMAGE_ERROR
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetError should set the error code and change callback type to IMAGE_ERROR
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_036, TestSize.Level0)
{
    ImageInfo imageInfo;
    imageInfo.SetError(DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    EXPECT_EQ(imageInfo.GetType(), CallbackType::IMAGE_ERROR);
    EXPECT_EQ(imageInfo.GetErrorCode(), DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
}

/*
 * Feature: ImageInfo
 * Function: Test GetIPCFileDescriptor returns nullptr when sharedBuffer is null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIPCFileDescriptor should return nullptr when no buffer is set
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_037, TestSize.Level0)
{
    ImageInfo imageInfo;
    auto ipcFd = imageInfo.GetIPCFileDescriptor();
    EXPECT_EQ(ipcFd, nullptr);
}

/*
 * Feature: ImageInfo
 * Function: Test GetIPCFileDescriptor returns nullptr when fd is -1
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIPCFileDescriptor should return nullptr when buffer fd is invalid
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_038, TestSize.Level0)
{
    ImageInfo imageInfo;
    auto sharedBuffer = std::make_unique<SharedBuffer>(0);
    imageInfo.SetBuffer(std::move(sharedBuffer));
    auto ipcFd = imageInfo.GetIPCFileDescriptor();
    EXPECT_EQ(ipcFd, nullptr);
}

/*
 * Feature: ImageInfo
 * Function: Test GetIPCFileDescriptor returns valid fd
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIPCFileDescriptor should return a valid IPCFileDescriptor when buffer is valid
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_039, TestSize.Level0)
{
    ImageInfo imageInfo;
    int32_t dataSize = 256;

    auto sharedBuffer = std::make_unique<SharedBuffer>(dataSize);
    sharedBuffer->Initialize();
    ASSERT_NE(sharedBuffer->GetFd(), -1);

    imageInfo.SetBuffer(std::move(sharedBuffer));
    auto ipcFd = imageInfo.GetIPCFileDescriptor();
    EXPECT_NE(ipcFd, nullptr);
}

/*
 * Feature: ImageInfo
 * Function: Test GetPicture returns nullptr when no picture is set
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPicture should return nullptr by default
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_040, TestSize.Level0)
{
    ImageInfo imageInfo;
    auto picture = imageInfo.GetPicture();
    EXPECT_EQ(picture, nullptr);
}

/*
 * Feature: ImageInfo
 * Function: Test SetError with different error codes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetError should correctly set all error code types
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_041, TestSize.Level0)
{
    ImageInfo imageInfo;
    imageInfo.SetError(DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(imageInfo.GetErrorCode(), DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    EXPECT_EQ(imageInfo.GetType(), CallbackType::IMAGE_ERROR);

    ImageInfo imageInfo2;
    imageInfo2.SetError(DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
    EXPECT_EQ(imageInfo2.GetErrorCode(), DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
}

/*
 * Feature: ImageInfo
 * Function: Test GetMetaData returns the metadata
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMetaData should return the metadata set in constructor
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_042, TestSize.Level0)
{
    DpsMetadata metadata;
    metadata.Set(DEFERRED_PROCESSING_TYPE_KEY, DPS_OFFLINE);
    ImageInfo imageInfo(0, false, 0, 0, metadata);

    auto result = imageInfo.GetMetaData();
    int32_t value = 0;
    result.Get(DEFERRED_PROCESSING_TYPE_KEY, value);
    EXPECT_EQ(value, DPS_OFFLINE);
}

/*
 * Feature: MediaProgressNotifier
 * Function: Test constructor initializes members correctly
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Constructor should set notifyInterval and nextNotifyPts
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_043, TestSize.Level0)
{
    int64_t notifyInterval = 1000;
    MediaProgressNotifier notifier(notifyInterval);
    EXPECT_FALSE(notifier.isCompletedProcess());
}

/*
 * Feature: MediaProgressNotifier
 * Function: Test SetTotalDuration and CheckNotify skip when currentPts < nextNotifyPts
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CheckNotify should skip notification when currentPts is below threshold
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_044, TestSize.Level0)
{
    int64_t notifyInterval = 100;
    MediaProgressNotifier notifier(notifyInterval);
    notifier.SetTotalDuration(1000);

    notifier.CheckNotify(50);
    EXPECT_FALSE(notifier.isCompletedProcess());
}

/*
 * Feature: MediaProgressNotifier
 * Function: Test CheckNotify triggers notification when currentPts reaches threshold
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CheckNotify should send notification and advance nextNotifyPts
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_045, TestSize.Level0)
{
    int64_t notifyInterval = 100;
    MediaProgressNotifier notifier(notifyInterval);
    notifier.SetTotalDuration(1000);

    notifier.CheckNotify(100);
    EXPECT_FALSE(notifier.isCompletedProcess());
}

/*
 * Feature: MediaProgressNotifier
 * Function: Test CheckNotify marks completed when nextNotifyPts >= total
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CheckNotify should set isCompleted_ to true when progress reaches end
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_046, TestSize.Level0)
{
    int64_t notifyInterval = 100;
    MediaProgressNotifier notifier(notifyInterval);
    notifier.SetTotalDuration(500);

    notifier.CheckNotify(100);
    notifier.CheckNotify(200);
    notifier.CheckNotify(300);
    notifier.CheckNotify(400);
    notifier.CheckNotify(500);
    EXPECT_TRUE(notifier.isCompletedProcess());
}

/*
 * Feature: MediaProgressNotifier
 * Function: Test SetNotifyCallback binds callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetNotifyCallback should store the callback without error
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_047, TestSize.Level0)
{
    MediaProgressNotifier notifier(100);
    std::shared_ptr<ProgressCallback> callback = nullptr;
    notifier.SetNotifyCallback(callback);
    EXPECT_FALSE(notifier.isCompletedProcess());
}
} // CameraStandard
} // OHOS
