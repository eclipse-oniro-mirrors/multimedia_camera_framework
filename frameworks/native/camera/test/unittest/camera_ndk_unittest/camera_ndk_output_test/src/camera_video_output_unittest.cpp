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

#include "camera_video_output_unittest.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "surface_utils.h"
#include "test_token.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraVideoOutputUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void CameraVideoOutputUnitTest::TearDownTestCase(void) {}

void CameraVideoOutputUnitTest::SetUp(void)
{
    InitCamera();
}

void CameraVideoOutputUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test get active profile of video output and delete profile of video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of video output and delete profile of video output
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_001, TestSize.Level0)
{
    Camera_VideoProfile* videoProfile = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    ret = OH_VideoOutput_GetActiveProfile(videoOutput, &videoProfile);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_VideoOutput_GetActiveProfile(nullptr, &videoProfile);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetActiveProfile(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    if (videoProfile != nullptr) {
        EXPECT_EQ(OH_VideoOutput_DeleteProfile(videoProfile), CAMERA_OK);
    }
    EXPECT_EQ(OH_VideoOutput_DeleteProfile(nullptr), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported framerates and delete framerates in video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported framerates and delete framerates in video output
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_002, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_VideoOutput_GetSupportedFrameRates(nullptr, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test to get and delete the current video output frame rate
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and delete the current video output frame rate,
 * when entered valid parameters, get and delete successfully
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_003, TestSize.Level0)
{
    Camera_FrameRateRange* activeframeRateRange = new Camera_FrameRateRange[1];
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_ErrorCode ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (activeframeRateRange != nullptr) {
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, activeframeRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test set framerate in video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set framerate in video output
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_004, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_VideoOutput_SetFrameRate(nullptr, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get active framerate in video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active framerate in video output
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_005, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(nullptr, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop video multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop video multiple times
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_006, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = CAMERA_OK;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test get video rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get video rotation,  when entered valid parameters, get success
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_007, TestSize.Level0)
{
    int deviceDegree = 0;
    Camera_ImageRotation imageRotation = IAMGE_ROTATION_180;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_VideoOutput_GetVideoRotation(videoOutput, deviceDegree, &imageRotation);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get video rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get video and photo rotation, an internal system error is
 * returned when the session is not committed
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_008, TestSize.Level0)
{
    int deviceDegree = 0;
    Camera_ImageRotation imageRotation = IAMGE_ROTATION_180;
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_ErrorCode ret = OH_VideoOutput_GetVideoRotation(videoOutput, deviceDegree, &imageRotation);
    EXPECT_NE(ret, CAMERA_OK);
    ret = OH_PhotoOutput_GetPhotoRotation(photoOutput, deviceDegree, &imageRotation);
    EXPECT_NE(ret, CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: RegisterCallback and UnregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterCallback and UnregisterCallback
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_009, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoOutputCallbacks = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };

    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterCallback with abnormal branch
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_010, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoOutputCallbacks = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };

    ret = OH_VideoOutput_RegisterCallback(nullptr, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_RegisterCallback(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onError = nullptr;
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onFrameEnd = nullptr;
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onFrameStart = nullptr;
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: UnregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnregisterCallback with abnormal branch
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_011, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoOutputCallbacks = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };

    ret = OH_VideoOutput_UnregisterCallback(nullptr, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_UnregisterCallback(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onError = nullptr;
    ret = OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onFrameEnd = nullptr;
    ret = OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setVideoOutputCallbacks.onFrameStart = nullptr;
    ret = OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoOutputCallbacks);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: IsMirrorSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMirrorSupported with abnormal branch
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_012, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_VideoOutput_IsMirrorSupported(nullptr, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_IsMirrorSupported(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: IsMirrorSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMirrorSupported
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_013, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_VideoOutput_IsMirrorSupported(videoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: EnableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enable mirror
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_014, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_VideoOutput_IsMirrorSupported(videoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_VideoOutput_EnableMirror(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_EnableMirror(videoOutput, true);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_VideoOutput_EnableMirror(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: EnableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test disable mirror
 */
HWTEST_F(CameraVideoOutputUnitTest, camera_video_output_unittest_015, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_VideoOutput_IsMirrorSupported(videoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_VideoOutput_EnableMirror(nullptr, false);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_EnableMirror(videoOutput, false);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_VideoOutput_EnableMirror(nullptr, false);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

} // CameraStandard
} // OHOS