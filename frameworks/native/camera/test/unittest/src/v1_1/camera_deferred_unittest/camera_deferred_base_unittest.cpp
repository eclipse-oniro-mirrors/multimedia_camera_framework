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

#include "camera_deferred_base_unittest.h"
#include <cstdint>
#include <vector>
#include "hcamera_service.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "ipc_skeleton.h"
#include "test_common.h"

#include "time_broker.h"
#include "session_manager.h"
#include "shared_buffer.h"
#include "thread_pool.h"
#include "steady_clock.h"
#include "timer_core.h"
#include "basic_definitions.h"
#include "dps.h"
#include "session_manager.h"
#include "scheduler_manager.h"
#include "session_coordinator.h"
#include "scheduler_coordinator.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

void DeferredBaseUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredBaseUnitTest::SetUpTestCase started!");
}

void DeferredBaseUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("DeferredBaseUnitTest::TearDownTestCase started!");
}

void DeferredBaseUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
}

void DeferredBaseUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("DeferredBaseUnitTest::TearDown started!");
}

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
    std::shared_ptr<DeferredProcessing::TaskManager> taskManager =
        std::make_shared<DeferredProcessing::TaskManager>("camera_deferred_base", numThreads, false);
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_003, TestSize.Level0)
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
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_004, TestSize.Level0)
{
    uint32_t numThreads = 0;
    std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>("camera_deferred_base", numThreads);
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
    timeBroker->Initialize();
    EXPECT_NE(timeBroker->timer_, nullptr);
    uint32_t delayTimeMs = 1;
    uint32_t handle = timeBroker->GenerateHandle();
    std::function<void(uint32_t handle)> timerCallback = timeBroker->GetExpiredFunc(handle);
    timeBroker->RegisterCallback(delayTimeMs, timerCallback, handle);
    timeBroker->TimerExpired();
    bool force = true;
    if (!(timeBroker->timeline_.empty() || (timeBroker->timer_->IsActive()))) {
        timeBroker->RestartTimer(force);
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
    timerCore->timeline_ = std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>>();
    timerCore->DoTimeout();
    EXPECT_EQ(timerCore->GetNextExpirationTimeUnlocked(), std::chrono::milliseconds(720000));
}

/*
 * Feature: Framework
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: 
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_011, TestSize.Level0)
{
    DeferredProcessing::SystemPressureLevel eventLevel = NOMINAL;
    eventLevel = DeferredProcessing::MapEventThermalLevel(static_cast<DeferredProcessing::ThermalLevel>(-1));
    EXPECT_EQ(eventLevel, DeferredProcessing::SystemPressureLevel::SEVERE);
    eventLevel = DeferredProcessing::MapEventThermalLevel(DeferredProcessing::ThermalLevel::LEVEL_2);
    EXPECT_EQ(eventLevel, DeferredProcessing::SystemPressureLevel::FAIR);
    eventLevel = DeferredProcessing::MapEventThermalLevel(DeferredProcessing::ThermalLevel::LEVEL_5);
    EXPECT_EQ(eventLevel, DeferredProcessing::SystemPressureLevel::SEVERE);
} //3

/*
 * Feature: Framework
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(DeferredBaseUnitTest, camera_deferred_base_unittest_012, TestSize.Level0)
{
    DeferredProcessing::DPS_Destroy(); //1
    DeferredProcessing::DPS_GetCommandServer(); //1
    DeferredProcessing::DPS_GetSessionManager(); //1
    DeferredProcessing::DPS_GetSchedulerManager(); //1
    EXPECT_EQ(DeferredProcessing::DPS_Initialize(), 0);
    EXPECT_EQ(DeferredProcessing::DPS_Initialize(), 0); //1
}

} // CameraStandard
} // OHOS
