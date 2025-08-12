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
#include "camera_log.h"
#include "dp_log.h"
#include "camera_simple_timer.h"
#include "av_codec_proxy.h"
#include "av_codec_adapter.h"
#include "sample_info.h"
#include "image_source_proxy.h"
#include "media_manager_proxy.h"
#include "ipc_file_descriptor.h"
#include "moving_photo_proxy.h"
#include "camera_server_photo_proxy.h"
#include "picture_proxy.h"

using namespace OHOS::CameraStandard;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

constexpr uint32_t MAX_SOURCE_SIZE = 300 * 1024 * 1024;
constexpr int VIDEO_REQUEST_FD_ID = 1;
static const int64_t VIDEO_FRAMERATE = 1280;

void CameraCommonUtilsUnitTest::SetUpTestCase(void)
{}

void CameraCommonUtilsUnitTest::TearDownTestCase(void)
{}

void CameraCommonUtilsUnitTest::SetUp(void)
{}

void CameraCommonUtilsUnitTest::TearDown(void)
{}

class CoderCallback : public MediaCodecCallback {
public:
    CoderCallback() {}
    ~CoderCallback() {}
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) {}
    void OnOutputFormatChanged(const Format &format) {}
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) {}
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) {}
};

class AVSourceTest : public AVSource {
public:
    AVSourceTest() {}
    ~AVSourceTest() {}
    int32_t GetSourceFormat(OHOS::Media::Format &format)
    {
        return 0;
    }
    int32_t GetTrackFormat(OHOS::Media::Format &format, uint32_t trackIndex)
    {
        return 0;
    }
    int32_t GetUserMeta(OHOS::Media::Format &format)
    {
        return 0;
    }
};

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

/*
 * Feature: AVCodecProxy
 * Function: Test AVMuxerSetParameter and AVMuxerSetUserMeta
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVMuxerSetParameter and AVMuxerSetUserMeta when AVMuter create fail.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_001 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    avCodecProxy->CreateAVMuxer(-1, static_cast<Media::Plugins::OutputFormat>(0));
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    int32_t ret = avCodecProxy->AVMuxerSetParameter(param);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVMuxerSetUserMeta(param);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_001 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVMuxerSetParameter
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVMuxerSetParameter when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_002 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<Meta> param = nullptr;
    int32_t ret = avCodecProxy->AVMuxerSetParameter(param);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    avCodecProxy->avcodecIntf_ = nullptr;
    ret = avCodecProxy->AVMuxerSetParameter(param);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_002 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVMuxerSetUserMeta
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVMuxerSetUserMeta when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_003 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<Meta> param = nullptr;
    int32_t ret = avCodecProxy->AVMuxerSetUserMeta(param);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    avCodecProxy->avcodecIntf_ = nullptr;
    ret = avCodecProxy->AVMuxerSetUserMeta(param);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_003 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVMuxer related interfaces
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVMuxer related interfaces when AVMuter create fail.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_004 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    avCodecProxy->CreateAVMuxer(-1, static_cast<Media::Plugins::OutputFormat>(0));

    std::shared_ptr<Meta> trackDesc = std::make_shared<Meta>();
    int32_t ret = avCodecProxy->AVMuxerStart();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    int32_t trackIndex = 1;
    ret = avCodecProxy->AVMuxerAddTrack(trackIndex, trackDesc);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    std::shared_ptr<AVBuffer> sample = std::make_shared<AVBuffer>();
    ret = avCodecProxy->AVMuxerWriteSample(1, sample);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVMuxerStop();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_004 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVMuxer related interfaces
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVMuxer related interfaces when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_005 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<Meta> trackDesc = nullptr;
    int32_t trackIndex = 1;
    int32_t ret = avCodecProxy->AVMuxerAddTrack(trackIndex, trackDesc);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    std::shared_ptr<AVBuffer> sample = nullptr;
    ret = avCodecProxy->AVMuxerWriteSample(1, sample);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    avCodecProxy->avcodecIntf_ = nullptr;
    ret = avCodecProxy->AVMuxerStart();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVMuxerAddTrack(trackIndex, trackDesc);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVMuxerWriteSample(1, sample);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVMuxerStop();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_005 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when AVCodecVideoEncoder has not been created.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_006 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->AVCodecVideoEncoderStart();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderStop();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_006 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when paramenter is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_007 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->CreateAVCodecVideoEncoder(MIME_VIDEO_AVC.data());
    EXPECT_EQ(ret, AV_ERR_OK);
    ret = avCodecProxy->AVCodecVideoEncoderPrepare();
    EXPECT_EQ(ret, AV_ERR_OK);
    bool isExisted = avCodecProxy->IsVideoEncoderExisted();
    EXPECT_TRUE(isExisted);
    ret = avCodecProxy->AVCodecVideoEncoderRelease();
    EXPECT_EQ(ret, AV_ERR_OK);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_007 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Test AVCodecVideoEncoder when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_008 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->CreateAVCodecVideoEncoder(MIME_VIDEO_AVC.data());
    EXPECT_EQ(ret, AV_ERR_OK);
    avCodecProxy->avcodecIntf_ = nullptr;
    bool isExisted = avCodecProxy->IsVideoEncoderExisted();
    EXPECT_FALSE(isExisted);
    ret = avCodecProxy->AVCodecVideoEncoderPrepare();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVCodecVideoEncoderStart();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVCodecVideoEncoderStop();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVCodecVideoEncoderRelease();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_008 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when AVCodecVideoEncoder has not been created.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_009 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    bool isExisted = avCodecProxy->IsVideoEncoderExisted();
    EXPECT_FALSE(isExisted);
    int32_t ret = avCodecProxy->AVCodecVideoEncoderPrepare();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderStart();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderStop();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderRelease();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_009 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when AVCodecVideoEncoder has not been created.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_010 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    sptr<Surface> surface = avCodecProxy->CreateInputSurface();
    EXPECT_EQ(surface, nullptr);
    int32_t ret = avCodecProxy->QueueInputBuffer(1);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderNotifyEos();
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->ReleaseOutputBuffer(1);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_010 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_011 start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->CreateAVCodecVideoEncoder(MIME_VIDEO_AVC.data());
    EXPECT_EQ(ret, AV_ERR_OK);
    avCodecProxy->avcodecIntf_ = nullptr;
    sptr<Surface> surface = avCodecProxy->CreateInputSurface();
    EXPECT_EQ(surface, nullptr);
    ret = avCodecProxy->QueueInputBuffer(1);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVCodecVideoEncoderNotifyEos();
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->ReleaseOutputBuffer(1);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_011 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoderSetCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoderSetCallback when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_012 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->CreateAVCodecVideoEncoder(MIME_VIDEO_AVC.data());
    EXPECT_EQ(ret, AV_ERR_OK);
    std::shared_ptr<MediaCodecCallback> callback = std::make_shared<CoderCallback>();
    ret = avCodecProxy->AVCodecVideoEncoderSetCallback(callback);
    EXPECT_EQ(ret, AV_ERR_OK);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_012 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when parameter is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_013 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    int32_t ret = avCodecProxy->CreateAVCodecVideoEncoder(MIME_VIDEO_AVC.data());
    EXPECT_EQ(ret, AV_ERR_OK);
    avCodecProxy->avcodecIntf_ = nullptr;
    Format format;
    ret = avCodecProxy->AVCodecVideoEncoderSetParameter(format);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVCodecVideoEncoderConfigure(format);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    std::shared_ptr<MediaCodecCallback> callback = std::make_shared<CoderCallback>();
    ret = avCodecProxy->AVCodecVideoEncoderSetCallback(callback);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_013 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVCodecVideoEncoder
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVCodecVideoEncoder when AVCodecVideoEncoder has not been created.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_014 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    Format format;
    int32_t ret = avCodecProxy->AVCodecVideoEncoderSetParameter(format);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVCodecVideoEncoderConfigure(format);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    std::shared_ptr<MediaCodecCallback> callback = std::make_shared<CoderCallback>();
    ret = avCodecProxy->AVCodecVideoEncoderSetCallback(callback);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_014 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVSource when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_015 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    avCodecProxy->avcodecIntf_ = nullptr;
    Format format;
    int32_t ret = avCodecProxy->AVSourceGetSourceFormat(format);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVSourceGetUserMeta(format);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVSourceGetTrackFormat(format, 1);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_015 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVSource when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_016 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<AVSource> source = std::make_shared<AVSourceTest>();
    ASSERT_NE(source, nullptr);
    std::shared_ptr<AVBuffer> sample = std::make_shared<AVBuffer>();
    ASSERT_NE(sample, nullptr);
    source->mediaDemuxer = std::make_shared<Media::MediaDemuxer>();
    ASSERT_NE(source->mediaDemuxer, nullptr);
    avCodecProxy->CreateAVDemuxer(source);
    int32_t ret = avCodecProxy->AVDemuxerSeekToTime(1, static_cast<SeekMode>(0));
    EXPECT_EQ(ret, AV_ERR_OK);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_016 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVDemuxer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVDemuxer when param is nullptr.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_017 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<AVSource> source = std::make_shared<AVSourceTest>();
    ASSERT_NE(source, nullptr);
    avCodecProxy->CreateAVDemuxer(source);
    std::shared_ptr<AVBuffer> sample = nullptr;
    int32_t ret = avCodecProxy->ReadSampleBuffer(1, sample);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);

    sample = std::make_shared<AVBuffer>();
    ASSERT_NE(sample, nullptr);
    avCodecProxy->avcodecIntf_ = nullptr;
    avCodecProxy->CreateAVDemuxer(source);
    ret = avCodecProxy->ReadSampleBuffer(1, sample);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVDemuxerSeekToTime(1, static_cast<SeekMode>(0));
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = avCodecProxy->AVDemuxerSelectTrackByID(1);
    EXPECT_EQ(ret, AV_ERR_INVALID_VAL);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_017 End");
}

/*
 * Feature: AVCodecProxy
 * Function: Test AVDemuxer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test AVDemuxer when not CreateAVMuxer
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraAVCodecProxy_Test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_018 Start");
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    ASSERT_NE(avCodecProxy, nullptr);
    std::shared_ptr<AVSource> source = std::make_shared<AVSourceTest>();
    ASSERT_NE(source, nullptr);
    std::shared_ptr<AVBuffer> sample = std::make_shared<AVBuffer>();
    ASSERT_NE(sample, nullptr);
    int32_t ret = avCodecProxy->ReadSampleBuffer(1, sample);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVDemuxerSeekToTime(1, static_cast<SeekMode>(0));
    EXPECT_EQ(ret, AV_ERR_FAILED);
    ret = avCodecProxy->AVDemuxerSelectTrackByID(1);
    EXPECT_EQ(ret, AV_ERR_FAILED);
    MEDIA_INFO_LOG("CameraAVCodecProxy_Test_018 End");
}

/*
 * Feature: ImageSourceProxy
 * Function: Test ImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ImageSource when param is normal.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraImageSourceProxy_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_001 Start");
    auto imageSourceProxy = ImageSourceProxy::CreateImageSourceProxy();
    ASSERT_NE(imageSourceProxy, nullptr);

    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    size_t width = 256;
    size_t height = 256;
    size_t blockNum = ((width + 4 - 1) / 4) * ((height + 4 - 1) / 4);
    size_t size = blockNum * 16 + 16;
    uint8_t* data = (uint8_t*)malloc(size);
    int32_t ret = imageSourceProxy->CreateImageSource(data, size, opts, errorCode);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(errorCode, 0);
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_001 End");
}

/*
 * Feature: ImageSourceProxy
 * Function: Test ImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ImageSource when ImageSource not be Created;
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraImageSourceProxy_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_002 Start");
    auto imageSourceProxy = ImageSourceProxy::CreateImageSourceProxy();
    ASSERT_NE(imageSourceProxy, nullptr);

    uint32_t errorCode = 0;
    Media::DecodeOptions decodeOpts;
    std::unique_ptr<Media::PixelMap> pixelMap = imageSourceProxy->CreatePixelMap(decodeOpts, errorCode);
    EXPECT_EQ(pixelMap, nullptr);
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_002 End");
}


/*
 * Feature: ImageSourceProxy
 * Function: Test ImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ImageSource when param is nullptr;
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraImageSourceProxy_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_003 Start");
    auto imageSourceProxy = ImageSourceProxy::CreateImageSourceProxy();
    ASSERT_NE(imageSourceProxy, nullptr);
    imageSourceProxy->imageSourceIntf_ = nullptr;
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    size_t width = 256;
    size_t height = 256;
    size_t blockNum = ((width + 4 - 1) / 4) * ((height + 4 - 1) / 4);
    size_t size = blockNum * 16 + 16;
    uint8_t* data = (uint8_t*)malloc(size);
    int32_t ret = imageSourceProxy->CreateImageSource(data, size, opts, errorCode);
    EXPECT_EQ(ret, -1);
    Media::DecodeOptions decodeOpts;
    std::unique_ptr<Media::PixelMap> pixelMap = imageSourceProxy->CreatePixelMap(decodeOpts, errorCode);
    EXPECT_EQ(pixelMap, nullptr);
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_003 End");
}

/*
 * Feature: ImageSourceProxy
 * Function: Test CreateImageSource
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateImageSource when size is too large.
 */
HWTEST_F(CameraCommonUtilsUnitTest, CameraImageSourceProxy_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_004 Start");
    auto imageSourceProxy = ImageSourceProxy::CreateImageSourceProxy();
    ASSERT_NE(imageSourceProxy, nullptr);
    imageSourceProxy->imageSourceIntf_ = nullptr;
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    size_t size = MAX_SOURCE_SIZE + 1;
    uint8_t* data = (uint8_t*)malloc(size);
    int32_t ret = imageSourceProxy->CreateImageSource(data, size, opts, errorCode);
    EXPECT_EQ(ret, -1);
    MEDIA_INFO_LOG("CameraImageSourceProxy_Test_004 End");
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
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd);
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
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd);

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
    sptr<IPCFileDescriptor> fd = mediaManagerProxy->MpegGetResultFd();
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
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string requestId(testStrings[randomNum % testStrings.size()]);
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(dup(VIDEO_REQUEST_FD_ID));
    ASSERT_NE(inputFd, nullptr);
    mediaManagerProxy->MpegAcquire(requestId, inputFd);
    std::unique_ptr<DeferredProcessing::MediaUserInfo> userInfo = std::make_unique<DeferredProcessing::MediaUserInfo>();
    mediaManagerProxy->MpegAddUserMeta(std::move(userInfo));

    uint64_t ret = mediaManagerProxy->MpegGetProcessTimeStamp();
    EXPECT_EQ(ret, DP_OK);
    mediaManagerProxy->MpegSetMarkSize(1);
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
    mediaManagerProxy->MpegSetMarkSize(1);
    MEDIA_INFO_LOG("CameraMediaManagerProxy_Test_005 End");
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
    auto movingPhotoVideoCacheProxy = MovingPhotoVideoCacheProxy::CreateMovingPhotoVideoCacheProxy();
    ASSERT_NE(movingPhotoVideoCacheProxy, nullptr);
    EXPECT_NE(movingPhotoVideoCacheProxy->movingPhotoVideoCacheIntf_, nullptr);
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
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(
        audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);

    retCode = movingPhotoVideoCacheProxy->CreateMovingPhotoVideoCache(
        aVCodecTaskManagerProxy);
    EXPECT_EQ(retCode, 0);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 0;
    int32_t rotation = 0;
    int32_t captureId = 0;
    movingPhotoVideoCacheProxy->GetFrameCachedResult(frameRecords, taskName, rotation, captureId);
    EXPECT_NE(frameRecords.empty(), false);

    movingPhotoVideoCacheProxy->movingPhotoVideoCacheIntf_ = nullptr;
    movingPhotoVideoCacheProxy->CreateMovingPhotoVideoCache(aVCodecTaskManagerProxy->avcodecTaskManagerIntf_);
    movingPhotoVideoCacheProxy->GetFrameCachedResult(frameRecords, taskName, rotation, captureId);
    EXPECT_EQ(frameRecords.empty(), true);
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
    auto movingPhotoVideoCacheProxy = MovingPhotoVideoCacheProxy::CreateMovingPhotoVideoCacheProxy();
    ASSERT_NE(movingPhotoVideoCacheProxy, nullptr);
    EXPECT_NE(movingPhotoVideoCacheProxy->movingPhotoVideoCacheIntf_, nullptr);
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
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(
        audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);

    int32_t ret = movingPhotoVideoCacheProxy->CreateMovingPhotoVideoCache(
        aVCodecTaskManagerProxy);
    EXPECT_EQ(ret, 0);
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    int64_t timestamp = 0;
    GraphicTransformType types = GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
    sptr<FrameRecord> frame = new FrameRecord(videoBuffer, timestamp, types);
    movingPhotoVideoCacheProxy->OnDrainFrameRecord(frame);

    movingPhotoVideoCacheProxy->movingPhotoVideoCacheIntf_ = nullptr;
    movingPhotoVideoCacheProxy->OnDrainFrameRecord(frame);
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
    bool ret = audioCapturerSessionProxy->StartAudioCapture();
    EXPECT_EQ(ret, true);
    audioCapturerSessionProxy->StopAudioCapture();

    audioCapturerSessionProxy->audioCapturerSessionIntf_ = nullptr;
    audioCapturerSessionProxy->CreateAudioSession();
    ret = audioCapturerSessionProxy->StartAudioCapture();
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
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(
        audioCapturerSessionProxy, type, colorSpace);
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
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(
        audioCapturerSessionProxy, type, colorSpace);
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
    retCode = aVCodecTaskManagerProxy->CreateAvcodecTaskManager(
        audioCapturerSessionProxy, type, colorSpace);
    EXPECT_EQ(retCode, 0);
    std::vector<sptr<FrameRecord>> frameRecords;
    uint64_t taskName = 0;
    int32_t rotation = 0;
    int32_t captureId = 0;
    aVCodecTaskManagerProxy->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType graphicType = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, graphicType);
    CacheCbFunc cacheCallback;
    aVCodecTaskManagerProxy->EncodeVideoBuffer(frameRecord, cacheCallback);
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
    aVCodecTaskManagerProxy->DoMuxerVideo(frameRecords, 0, 0, 0);
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    ASSERT_NE(videoBuffer, nullptr);
    int64_t timestamp = VIDEO_FRAMERATE;
    GraphicTransformType type = GRAPHIC_ROTATE_90;
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type);
    CacheCbFunc cacheCallback;
    aVCodecTaskManagerProxy->EncodeVideoBuffer(frameRecord, cacheCallback);
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy;
    aVCodecTaskManagerProxy->SetVideoFd(0, photoAssetProxy, 0);
    aVCodecTaskManagerProxy->SetVideoBufferDuration(0, 0);
    int32_t ret = aVCodecTaskManagerProxy->isEmptyVideoFdMap();
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("CameraMovingPhotoProxy_Test_007 End");
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
    pictureProxy->CreateWithDeepCopySurfaceBuffer(surfaceBuffer);
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

    sptr<SurfaceBuffer> pictureSurfaceBuffer = SurfaceBuffer::Create();
    pictureProxy->Create(pictureSurfaceBuffer);

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    pictureProxy->CreateWithDeepCopySurfaceBuffer(surfaceBuffer);
    pictureProxy->SetAuxiliaryPicture(surfaceBuffer, static_cast<CameraAuxiliaryPictureType>(0));

    Parcel data;
    pictureProxy->Marshalling(data);
    pictureProxy->UnmarshallingPicture(data);
    MEDIA_INFO_LOG("CameraPictureProxy_Test_004 End");
}
}  // namespace CameraStandard
}  // namespace OHOS