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
#include <fcntl.h>
#include <gtest/gtest.h>
#include <thread>

#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "dp_log.h"
#include "camera_simple_timer.h"
#include "av_codec_proxy.h"
#include "av_codec_adapter.h"
#include "dps_fd.h"
#include "sample_info.h"
#include "media_manager_proxy.h"
#include "ipc_file_descriptor.h"
#ifdef CAMERA_CAPTURE_YUV
#include "ipc_skeleton.h"
#include "photo_asset_proxy.h"
#include "photo_asset_interface.h"
#endif
#include "moving_photo_proxy.h"
#include "camera_server_photo_proxy.h"
#include "picture_proxy.h"
#include "frame_record.h"

using namespace OHOS::CameraStandard;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
constexpr int VIDEO_REQUEST_FD_ID = 1;
static const int64_t VIDEO_FRAMERATE = 1280;
constexpr int64_t VIDEO_HIGH = 1080;
constexpr int64_t VIDEO_WIDTH = 1920;

void CameraCommonUtilsUnitTest::SetUpTestCase(void) {}

void CameraCommonUtilsUnitTest::TearDownTestCase(void) {}

void CameraCommonUtilsUnitTest::SetUp(void) {}

void CameraCommonUtilsUnitTest::TearDown(void) {}

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
    EXPECT_TRUE(timer.StartTask(1000));  // First start, should return true
    EXPECT_FALSE(timer.StartTask(1000)); // Already running, should return false
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
    EXPECT_TRUE(timer.StartTask(1000)); // Start the timer
    EXPECT_TRUE(timer.CancelTask());    // Cancel the timer
    EXPECT_TRUE(timer.StartTask(1000)); // Restart, should return true
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
    EXPECT_TRUE(timer.StartTask(1000)); // Start the timer
    EXPECT_TRUE(timer.CancelTask());    // Cancel the timer, should return true
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
    EXPECT_FALSE(timer.CancelTask()); // Timer is not running, should return false
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait for the task to enter the waiting state

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
    } // Destructor automatically cleans up

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
        EXPECT_TRUE(timer.StartTask(1000)); // Start the task
    }                                       // Destructor automatically cleans up

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
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait for the task to enter the waiting state

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
    CameraDynamicLoader::CancelFreeDynamicLibDelayed(MEDIA_LIB_SO);

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
    void* function = dynamiclib->GetFunction("createPhotoAssetIntf");
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
    void* function = validDynamiclib->GetFunction("__camera_nonexistent_function");
    EXPECT_EQ(function, nullptr);
}

/*
 * Feature: MovingPhotoVideoCacheProxy
 * Function: Test GetFrameCachedResult
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetFrameCachedResult
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_001 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    ASSERT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);

    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_001 End");
}

/*
 * Feature: MovingPhotoVideoCacheProxy
 * Function: Test OnDrainFrameRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test OnDrainFrameRecord
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_002 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);

    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_002 End");
}

/*
 * Feature: AudioCapturerSessionProxy
 * Function: Test StartAudioCapture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test StartAudioCapture
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_003 Start");
    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    audioCapturerSessionProxy->StartAudioCapture();
    audioCapturerSessionProxy->StopAudioCapture();

    audioCapturerSessionProxy->audioCapturerSessionIntf_ = nullptr;
    audioCapturerSessionProxy->CreateAudioSession();
    int32_t ret = audioCapturerSessionProxy->StartAudioCapture();
    EXPECT_EQ(ret, false);
    audioCapturerSessionProxy->StopAudioCapture();
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_003 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test TaskManagerInsertEndTime
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test TaskManagerInsertEndTime
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_004 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    int32_t captureId = 0;
    int64_t startTimeStamp = 0;
    int64_t endTimeStamp = 1;
    bool ret = aVCodecTaskManagerProxy->TaskManagerInsertStartTime(captureId, startTimeStamp);
    EXPECT_TRUE(ret);
    ret = aVCodecTaskManagerProxy->TaskManagerInsertEndTime(captureId, endTimeStamp);
    EXPECT_TRUE(ret);

    aVCodecTaskManagerProxy->avcodecTaskManagerIntf_ = nullptr;
    ret = aVCodecTaskManagerProxy->TaskManagerInsertStartTime(captureId, startTimeStamp);
    EXPECT_FALSE(ret);
    ret = aVCodecTaskManagerProxy->TaskManagerInsertEndTime(captureId, endTimeStamp);
    EXPECT_FALSE(ret);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_004 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test isEmptyVideoFdMap
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test isEmptyVideoFdMap
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_005 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    auto ret = aVCodecTaskManagerProxy->isEmptyVideoFdMap();
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_005 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test AvcodecTaskManager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AvcodecTaskManager when param is noraml.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_006 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    std::vector<sptr<FrameRecord>> frameRecords;
    int32_t captureId = 0;
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(videoBuffer, timestamp, graphicType);
    uint32_t preBufferCount = 0;
    uint32_t postBufferCount = 0;
    aVCodecTaskManagerProxy->SetVideoBufferDuration(preBufferCount, postBufferCount);
    timestamp = 0;
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy;
    captureId = 0;
    aVCodecTaskManagerProxy->SetVideoFd(timestamp, photoAssetProxy, captureId);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_006 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test AvcodecTaskManager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AvcodecTaskManager when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_019 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);

    aVCodecTaskManagerProxy->avcodecTaskManagerIntf_ = nullptr;
    std::vector<sptr<FrameRecord>> frameRecords;
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy;
    aVCodecTaskManagerProxy->SetVideoFd(0, photoAssetProxy, 0);
    aVCodecTaskManagerProxy->SetVideoBufferDuration(0, 0);
    int32_t ret = aVCodecTaskManagerProxy->isEmptyVideoFdMap();
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_007 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test SetVideoId
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetVideoId
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_005 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);
    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    int captureId = 1;
    string videoId = "1";
    aVCodecTaskManagerProxy->SetVideoId(captureId, videoId);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_008 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test SetDeferredVideoEnhanceFlag and GetDeferredVideoEnhanceFlag
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetDeferredVideoEnhanceFlag and GetDeferredVideoEnhanceFlag
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_009 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);
    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    int captureId = 1;
    uint32_t deferredVideoEnhanceFlag = 2;
    aVCodecTaskManagerProxy->SetDeferredVideoEnhanceFlag(captureId, deferredVideoEnhanceFlag);
    uint32_t result = aVCodecTaskManagerProxy->GetDeferredVideoEnhanceFlag(captureId);
    EXPECT_EQ(result, deferredVideoEnhanceFlag);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_009 End");
}

/*
 * Feature: AvcodecTaskManagerProxy
 * Function: Test RecordVideoType 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RecordVideoType
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMovingPhotoProxy_Test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_010 Start");
    auto aVCodecTaskManagerProxy = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy();
    ASSERT_NE(aVCodecTaskManagerProxy, nullptr);
    EXPECT_NE(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_, nullptr);
    auto audioCapturerSessionProxy = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy();
    ASSERT_NE(audioCapturerSessionProxy, nullptr);
    EXPECT_NE(audioCapturerSessionProxy->audioCapturerSessionIntf_, nullptr);
    VideoCodecType type = static_cast<VideoCodecType>(0);
    int32_t retCode = audioCapturerSessionProxy->CreateAudioSession();
    EXPECT_EQ(retCode, 0);
    int32_t colorSpace = 0;
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    int captureId = 1;
    VideoType videoType = static_cast<VideoType>(XT_ORIGIN_VIDEO);
    aVCodecTaskManagerProxy->RecordVideoType(captureId, videoType);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_010 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test MpegManager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegManager when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_001 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);

    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = { "test1", "test2" };
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = std::make_shared<DeferredProcessing::DpsFd>(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd, VIDEO_WIDTH, VIDEO_HIGH);
    EXPECT_EQ(mediaManagerProxy->MpegRelease(), DP_OK);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_001 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test MpegManager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegManager when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_002 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);
    mediaManagerProxy->mediaManagerIntf_ = nullptr;
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = { "test1", "test2" };
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = std::make_shared<DeferredProcessing::DpsFd>(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd, VIDEO_WIDTH, VIDEO_HIGH);

    int32_t ret = mediaManagerProxy->MpegUnInit(1);
    EXPECT_EQ(ret, DP_ERR);
    EXPECT_EQ(mediaManagerProxy->MpegRelease(), DP_ERR);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_002 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test CreateImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateImageSource when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_003 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);
    mediaManagerProxy->mediaManagerIntf_ = nullptr;
    auto fd = mediaManagerProxy->MpegGetResultFd();
    EXPECT_EQ(fd, nullptr);

    sptr<Surface> surface = mediaManagerProxy->MpegGetSurface();
    EXPECT_EQ(surface, nullptr);
    surface = mediaManagerProxy->MpegGetMakerSurface();
    EXPECT_EQ(surface, nullptr);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_003 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test CreateImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateImageSource when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_004 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);
    uint8_t randomNum = 1;
    std::vector<std::string> testStrings = { "test1", "test2" };
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    auto inputFd = std::make_shared<DeferredProcessing::DpsFd>(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd, VIDEO_WIDTH, VIDEO_HIGH);
    std::unique_ptr<DeferredProcessing::MediaUserInfo> userInfo = std::make_unique<DeferredProcessing::MediaUserInfo>();
    mediaManagerProxy->MpegAddUserMeta(std::move(userInfo));

    uint64_t ret = mediaManagerProxy->MpegGetProcessTimeStamp();
    EXPECT_EQ(ret, DP_OK);
    EXPECT_EQ(mediaManagerProxy->MpegRelease(), DP_OK);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_004 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test CreateImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateImageSource when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_005 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);
    mediaManagerProxy->mediaManagerIntf_ = nullptr;
    std::unique_ptr<DeferredProcessing::MediaUserInfo> userInfo = std::make_unique<DeferredProcessing::MediaUserInfo>();
    mediaManagerProxy->MpegAddUserMeta(std::move(userInfo));

    uint64_t ret = mediaManagerProxy->MpegGetProcessTimeStamp();
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_005 End");
}

/*
 * Feature: MediaManagerProxy
 * Function: Test MpegGetDuration
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetDuration
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraMediaManagerProxy_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_005 Start");
    auto mediaManagerProxy = DeferredProcessing::MediaManagerProxy::CreateMediaManagerProxy();
    ASSERT_NE(mediaManagerProxy, nullptr);
    uint32_t duration = mediaManagerProxy->MpegGetDuration();
    EXPECT_EQ(duration, 0);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_006 End");
}

/*
 * Feature: PictureProxy
 * Function: Test PictureProxy related interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PictureProxy related interface when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraPictureProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraPictureProxy_Test_001 Start");
    auto pictureProxy = PictureProxy::CreatePictureProxy();
    ASSERT_NE(pictureProxy, nullptr);

    pictureProxy->pictureIntf_ = nullptr;
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    pictureProxy->SetAuxiliaryPicture(surfaceBuffer, static_cast<CameraAuxiliaryPictureType>(0));

    Parcel data;
    bool isMarshalling = pictureProxy->Marshalling(data);
    EXPECT_FALSE(isMarshalling);

    pictureProxy->UnmarshallingPicture(data);
    MEDIA_INFO_LOG("CameraPictureProxy_Test_001 End");
}

/*
 * Feature: PictureProxy
 * Function: Test SetExifMetadata and SetMaintenanceData
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetExifMetadata and SetMaintenanceData when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraPictureProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraPictureProxy_Test_002 Start");
    auto pictureProxy = PictureProxy::CreatePictureProxy();
    ASSERT_NE(pictureProxy, nullptr);
    pictureProxy->pictureIntf_ = nullptr;
    sptr<SurfaceBuffer> surfaceBuffer1 = SurfaceBuffer::Create();
    int32_t retCode = pictureProxy->SetExifMetadata(surfaceBuffer1);
    EXPECT_EQ(retCode, -1);
    sptr<SurfaceBuffer> surfaceBuffer2 = SurfaceBuffer::Create();
    bool ret = pictureProxy->SetMaintenanceData(surfaceBuffer2);
    EXPECT_FALSE(ret);
    pictureProxy->RotatePicture();
    MEDIA_INFO_LOG("CameraPictureProxy_Test_002 End");
}

/*
 * Feature: PictureProxy
 * Function: Test SetExifMetadata and SetMaintenanceData
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetExifMetadata and SetMaintenanceData when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraPictureProxy_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraPictureProxy_Test_003 Start");
    auto pictureProxy = PictureProxy::CreatePictureProxy();
    ASSERT_NE(pictureProxy, nullptr);
    ASSERT_NE(pictureProxy->pictureIntf_, nullptr);

    sptr<SurfaceBuffer> pictureSurfaceBuffer = SurfaceBuffer::Create();
    pictureProxy->Create(pictureSurfaceBuffer);

    sptr<SurfaceBuffer> surfaceBuffer1 = SurfaceBuffer::Create();
    pictureProxy->SetExifMetadata(surfaceBuffer1);
    sptr<SurfaceBuffer> surfaceBuffer2 = SurfaceBuffer::Create();
    bool ret = pictureProxy->SetMaintenanceData(surfaceBuffer2);
    EXPECT_TRUE(ret);
    pictureProxy->RotatePicture();
    MEDIA_INFO_LOG("CameraPictureProxy_Test_003 End");
}

/*
 * Feature: PictureProxy
 * Function: Test PictureProxy related interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PictureProxy related interface when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraPictureProxy_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraPictureProxy_Test_004 Start");
    auto pictureProxy = PictureProxy::CreatePictureProxy();
    ASSERT_NE(pictureProxy, nullptr);
    ASSERT_NE(pictureProxy->pictureIntf_, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    EXPECT_NE(surfaceBuffer, nullptr);
    pictureProxy->Create(surfaceBuffer);
    pictureProxy->SetAuxiliaryPicture(surfaceBuffer, static_cast<CameraAuxiliaryPictureType>(0));

    Parcel data;
    pictureProxy->Marshalling(data);
    pictureProxy->UnmarshallingPicture(data);
    MEDIA_INFO_LOG("CameraPictureProxy_Test_004 End");
}

#ifdef CAMERA_CAPTURE_YUV
/*
 * Feature: PhotoAssetProxy
 * Function: Test GetBundleName interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBundleName interface.
 */
HWTEST_F(CameraCommonUtilsUnitTest, PhotoAssetProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("PhotoAssetProxy_Test_001 Start");

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = PhotoAssetProxy::GetBundleName(callingUid);
    EXPECT_TRUE(bundleName.empty());

    MEDIA_INFO_LOG("PhotoAssetProxy_Test_001 End");
}

/*
 * Feature: MediaLibraryManagerProxy
 * Function: RegisterPhotoStateCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: mediaLibraryManagerIntf_ is not null, RegisterPhotoStateCallback can be called normally.
 */
HWTEST_F(CameraCommonUtilsUnitTest, MediaLibraryManagerProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManagerProxy_Test_001 Start");
    MediaLibraryManagerProxy::LoadMediaLibraryDynamiclibAsync();
    auto proxy = MediaLibraryManagerProxy::GetMediaLibraryManagerProxy();
    ASSERT_NE(proxy, nullptr);
    ASSERT_NE(proxy->mediaLibraryManagerIntf_, nullptr);
    ASSERT_NE(proxy->mediaLibraryLib_, nullptr);

    auto callback = [](int32_t state) {
        MEDIA_INFO_LOG("MediaLibraryManagerProxy_Test_001 callback, state = %{public}d", state);
    };

    proxy->RegisterPhotoStateCallback(callback);
    proxy->UnregisterPhotoStateCallback();
    MediaLibraryManagerProxy::FreeMediaLibraryDynamiclibDelayed();
    MEDIA_INFO_LOG("PhotoAssetPrMediaLibraryManagerProxy_Test_001oxy_Test_002 End");
}

/*
 * Feature: MediaLibraryManagerProxy
 * Function: UnregisterPhotoStateCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: mediaLibraryManagerIntf_ is null, UnregisterPhotoStateCallback should return
 * immediately without crash.
 */
HWTEST_F(CameraCommonUtilsUnitTest, MediaLibraryManagerProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManagerProxy_Test_002 Start");
    MediaLibraryManagerProxy::LoadMediaLibraryDynamiclibAsync();
    auto proxy = MediaLibraryManagerProxy::GetMediaLibraryManagerProxy();
    ASSERT_NE(proxy, nullptr);

    proxy->mediaLibraryManagerIntf_.reset();

    auto callback = [](int32_t state) {
        MEDIA_INFO_LOG("MediaLibraryManagerProxy_Test_002 callback, state = %{public}d", state);
    };

    proxy->RegisterPhotoStateCallback(callback);
    proxy->UnregisterPhotoStateCallback();

    EXPECT_EQ(proxy->mediaLibraryManagerIntf_, nullptr);
    MediaLibraryManagerProxy::FreeMediaLibraryDynamiclibDelayed();
    MEDIA_INFO_LOG("MediaLibraryManagerProxy_Test_002 End");
}
#endif
}  // namespace CameraStandard
}  // namespace OHOS
