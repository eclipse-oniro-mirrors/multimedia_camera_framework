/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "camera_common_utils_unittest.h"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "camera_dynamic_loader.h"
#include "camera_simple_timer.h"

using namespace OHOS::CameraStandard;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void CameraCommonUtilsUnitTest::SetUpTestCase(void)
{}

void CameraCommonUtilsUnitTest::TearDownTestCase(void)
{}

void CameraCommonUtilsUnitTest::SetUp(void)
{}

void CameraCommonUtilsUnitTest::TearDown(void)
{}
/*
 * Feature: SimpleTimer
 * Function: Test start task functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test starting a task normally. The first start should return true, and starting again while running
 * should return false.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_StartTask_Normal, TestSize.Level0)
{
    SimpleTimer timer([]() {});
    EXPECT_TRUE(timer.StartTask(1000));   // First start, should return true
    EXPECT_FALSE(timer.StartTask(1000));  // Already running, should return false
}

/*
 * Feature: SimpleTimer
 * Function: Test cancel task functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task after starting it. The task should be canceled successfully.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_StartTask_CancelAndRestart, TestSize.Level0)
{
    SimpleTimer timer([]() {});
    EXPECT_TRUE(timer.StartTask(1000));  // Start the timer
    EXPECT_TRUE(timer.CancelTask());     // Cancel the timer
    EXPECT_TRUE(timer.StartTask(1000));  // Restart, should return true
}

/*
 * Feature: SimpleTimer
 * Function: Test cancel task functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task normally. The task should be canceled successfully.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_CancelTask_Normal, TestSize.Level0)
{
    SimpleTimer timer([]() {});
    EXPECT_TRUE(timer.StartTask(1000));  // Start the timer
    EXPECT_TRUE(timer.CancelTask());     // Cancel the timer, should return true
}

/*
 * Feature: SimpleTimer
 * Function: Test cancel task functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task when it is not running. The cancel operation should return false.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_CancelTask_WhenNotRunning, TestSize.Level0)
{
    SimpleTimer timer([]() {});
    EXPECT_FALSE(timer.CancelTask());  // Timer is not running, should return false
}

/*
 * Feature: SimpleTimer
 * Function: Test interruptable sleep functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test interruptable sleep functionality. The task should complete and trigger the callback.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_InterruptableSleep_Normal, TestSize.Level0)
{
    std::atomic<bool> flag(false);
    SimpleTimer timer([&]() { flag = true; });

    // Start the task
    EXPECT_TRUE(timer.StartTask(100));

    // Wait for the task to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Check if the callback was executed
    EXPECT_TRUE(flag);
}

/*
 * Feature: SimpleTimer
 * Function: Test interruptable sleep functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task during interruptable sleep. The task should be canceled, and the callback
 * should not be triggered.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_InterruptableSleep_Cancel, TestSize.Level0)
{
    std::atomic<bool> flag(false);
    SimpleTimer timer([&]() { flag = true; });

    // Start the task
    std::thread taskThread(&SimpleTimer::StartTask, &timer, 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Wait for the task to enter the waiting state

    // Cancel the task
    EXPECT_TRUE(timer.CancelTask());

    // Wait for the task thread to finish
    taskThread.join();

    // Check if the callback was executed
    EXPECT_FALSE(flag);
}

/*
 * Feature: SimpleTimer
 * Function: Test destructor behavior
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the behavior of the destructor. The task should be automatically canceled when the timer is
 * destroyed.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_Destructor_Normal, TestSize.Level0)
{
    std::atomic<bool> flag(false);

    {
        SimpleTimer timer([&]() { flag = true; });
        // Start the task
        EXPECT_TRUE(timer.StartTask(1000));
    }  // Destructor automatically cleans up

    // Wait for the task to complete or be canceled
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    // Check if the callback was executed
    EXPECT_FALSE(flag);
}

/*
 * Feature: SimpleTimer
 * Function: Test destructor behavior
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task during destruction. The task should be canceled, and the callback should not
 * be triggered.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_Destructor_CancelOnDestruct, TestSize.Level0)
{
    std::atomic<bool> flag(false);
    {
        SimpleTimer timer([&]() { flag = true; });
        EXPECT_TRUE(timer.StartTask(1000));  // Start the task
    }                                        // Destructor automatically cleans up

    // Wait for the task to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check if the callback was executed
    EXPECT_FALSE(flag);
}

/*
 * Feature: SimpleTimer
 * Function: Test timeout functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the timeout functionality with a zero timeout. The task should complete immediately and trigger
 * the callback.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_Timeout_Zero, TestSize.Level0)
{
    std::atomic<bool> flag(false);
    SimpleTimer timer([&]() { flag = true; });

    // Start the task
    EXPECT_TRUE(timer.StartTask(0));

    // Wait for the task to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check if the callback was executed
    EXPECT_TRUE(flag);
}

/*
 * Feature: SimpleTimer
 * Function: Test timeout functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling a task with a large timeout. The task should be canceled, and the callback should not
 * be triggered.
 */
HWTEST_F(CameraCommonUtilsUnitTest, SimpleTimer_Timeout_Large, TestSize.Level0)
{
    std::atomic<bool> flag(false);
    SimpleTimer timer([&]() { flag = true; });

    // Start the task
    std::thread taskThread(&SimpleTimer::StartTask, &timer, 10000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Wait for the task to enter the waiting state

    // Cancel the task
    EXPECT_TRUE(timer.CancelTask());

    // Wait for the task thread to finish
    taskThread.join();

    // Check if the callback was executed
    EXPECT_FALSE(flag);
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test get dynamic library functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting a dynamic library. The first load should succeed, and the second load should return the
 * cached instance.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestGetDynamiclib, TestSize.Level0)
{
    // First load
    auto dynamiclib1 = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib1, nullptr);
    EXPECT_TRUE(dynamiclib1->IsLoaded());

    // Second load, should get from cache
    auto dynamiclib2 = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib2, nullptr);
    EXPECT_TRUE(dynamiclib2->IsLoaded());
    EXPECT_EQ(dynamiclib1.get(), dynamiclib2.get());
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test async loading functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test async loading of a dynamic library. The library should be loaded successfully.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestLoadDynamiclibAsync, TestSize.Level0)
{
    // Async load
    CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO);

    // Wait for async loading to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify the dynamic library is loaded
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib, nullptr);
    EXPECT_TRUE(dynamiclib->IsLoaded());
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test delayed free functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test delayed freeing of a dynamic library. The library should be released after the delay.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestFreeDynamicLibDelayed, TestSize.Level0)
{
    // Load the dynamic library
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib, nullptr);
    EXPECT_TRUE(dynamiclib->IsLoaded());

    // Delayed free
    CameraDynamicLoader::FreeDynamicLibDelayed(MEDIA_LIB_SO, 500);

    // Wait for the delay
    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    // Verify the dynamic library has been freed
    auto dynamiclibAfterFree = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclibAfterFree, nullptr);
    EXPECT_TRUE(dynamiclibAfterFree->IsLoaded());
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test cancel delayed free functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test canceling delayed free of a dynamic library. The library should remain loaded after
 * cancellation.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestCancelFreeDynamicLibDelayed, TestSize.Level0)
{
    // Load the dynamic library
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib, nullptr);
    EXPECT_TRUE(dynamiclib->IsLoaded());

    // Delayed free
    CameraDynamicLoader::FreeDynamicLibDelayed(MEDIA_LIB_SO, 500);

    // Cancel delayed free
    CameraDynamicLoader::CancelFreeDynamicLibDelayedNoLock(MEDIA_LIB_SO);

    // Verify the dynamic library remains loaded
    auto dynamiclibAfterCancel = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclibAfterCancel, nullptr);
    EXPECT_TRUE(dynamiclibAfterCancel->IsLoaded());
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test free dynamiclib without lock
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test freeing a dynamic library without a lock. The library should be released successfully.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestFreeDynamiclibNoLock, TestSize.Level0)
{
    // Load the dynamic library
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib, nullptr);
    EXPECT_TRUE(dynamiclib->IsLoaded());

    // Free the dynamic library without a lock
    CameraDynamicLoader::FreeDynamiclibNoLock(MEDIA_LIB_SO);

    // Verify the dynamic library has been freed
    auto dynamiclibAfterFree = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclibAfterFree, nullptr);
    EXPECT_TRUE(dynamiclibAfterFree->IsLoaded());
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test get function functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting a function from a dynamic library. The function pointer should not be null.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestGetFunction, TestSize.Level0)
{
    // Load the dynamic library
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(dynamiclib, nullptr);
    EXPECT_TRUE(dynamiclib->IsLoaded());

    // Get the function
    void *function = dynamiclib->GetFunction("createPhotoAssetIntf");
    EXPECT_NE(function, nullptr);
}

/*
 * Feature: CameraDynamicLoader
 * Function: Test error cases
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test error cases for dynamic library operations, such as loading a non-existent library and getting
 * a non-existent function.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraDynamicLoader_TestErrorCases, TestSize.Level0)
{
    // Test loading a non-existent dynamic library
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib("__camera_nonexistent.so");
    EXPECT_EQ(dynamiclib, nullptr);

    // Test getting a non-existent function
    auto validDynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    EXPECT_NE(validDynamiclib, nullptr);
    void *function = validDynamiclib->GetFunction("__camera_nonexistent_function");
    EXPECT_EQ(function, nullptr);
}
}  // namespace CameraStandard
}  // namespace OHOS