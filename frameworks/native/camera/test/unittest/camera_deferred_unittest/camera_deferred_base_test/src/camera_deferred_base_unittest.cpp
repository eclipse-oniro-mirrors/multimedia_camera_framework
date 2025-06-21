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
#include "camera_util.h"
#include "gmock/gmock.h"
#include "ipc_skeleton.h"

#include "session_manager.h"
#include "shared_buffer.h"
#include "thread_pool.h"
#include "timer/core/timer_core.h"
#include "timer/steady_clock.h"
#include "timer/time_broker.h"
#include "basic_definitions.h"
#include "dps.h"
#include "session_manager.h"
#include "scheduler_manager.h"
#include "session_coordinator.h"
#include "scheduler_coordinator.h"

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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_001, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_002, TestSize.Level1)
{
    int32_t numThreads = 1;
    std::shared_ptr<DeferredProcessing::TaskManager> taskManager =
        std::make_shared<DeferredProcessing::TaskManager>("camera_deferred_base", numThreads, false);
    ASSERT_NE(taskManager, nullptr);
    taskManager->Initialize();
    if (taskManager->delayedTaskHandle_ != INVALID_TASK_GROUP_HANDLE) {
        taskManager->CreateDelayedTaskGroupIfNeed();
    } else {
        taskManager->delayedTaskHandle_ = INVALID_TASK_GROUP_HANDLE;
        taskManager->CreateDelayedTaskGroupIfNeed();
    }
    taskManager->IsEmpty();
    taskManager->taskRegistry_ = nullptr;
    EXPECT_FALSE(taskManager->DeregisterTaskGroup("defaultTaskGroup", taskManager->defaultTaskHandle_));

    std::any param1 = 1;
    EXPECT_FALSE(taskManager->SubmitTask(taskManager->defaultTaskHandle_, param1));
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_003, TestSize.Level1)
{
    int32_t numThreads = 1;
    std::shared_ptr<DeferredProcessing::TaskManager> taskManager =
        std::make_shared<DeferredProcessing::TaskManager>("camera_deferred_base", numThreads, false);
    taskManager->Initialize();
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_004, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_005, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_006, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_007, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_008, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_009, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_010, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_011, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_012, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_013, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_014, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_015, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_016, TestSize.Level1)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_017, TestSize.Level1)
{
    std::function<void()> timerCallback;
    const std::shared_ptr<Timer>& timer = Timer::Create("camera_deferred_base", TimerType::PERIODIC, 0, timerCallback);
    ASSERT_NE(timer, nullptr);
    timer->active_ = true;
    timer->TimerExpired();
    EXPECT_TRUE(timer->active_);
}

HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_024, TestSize.Level0) {
    int32_t level = 5;
    EXPECT_EQ(ConvertPhotoThermalLevel(level), SystemPressureLevel::SEVERE);
}
} // CameraStandard
} // OHOS
