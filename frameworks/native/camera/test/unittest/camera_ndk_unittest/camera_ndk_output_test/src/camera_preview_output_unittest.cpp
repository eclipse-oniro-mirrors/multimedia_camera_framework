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

#include "camera_preview_output_unittest.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraPreviewOutputUnitTest::SetUpTestCase(void) {}

void CameraPreviewOutputUnitTest::TearDownTestCase(void) {}

void CameraPreviewOutputUnitTest::SetUp(void)
{
    // set native token
    uint64_t tokenId;
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
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    InitCamera();
}

void CameraPreviewOutputUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop preview multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop preview multiple times
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_001, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test get active profile of priview output and delete profile of priview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of priview output and delete profile of priview output
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_002, TestSize.Level0)
{
    Camera_Profile *profile = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    ret = OH_PreviewOutput_GetActiveProfile(previewOutput, &profile);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_GetActiveProfile(nullptr, &profile);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetActiveProfile(previewOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Stop(previewOutput), CAMERA_OK);
    if (profile != nullptr) {
        EXPECT_EQ(OH_PreviewOutput_DeleteProfile(profile), CAMERA_OK);
    }
    EXPECT_EQ(OH_PreviewOutput_DeleteProfile(nullptr), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported framerates and delete framerates in preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported framerates delete framerates in preview output
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_003, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_GetSupportedFrameRates(nullptr, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test to get and delete the current preview output frame rate
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and delete the current preview output frame rate.
 * When a valid parameter is entered, the get and delete are successful
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_004, TestSize.Level0)
{
    Camera_FrameRateRange* activeframeRateRange = new Camera_FrameRateRange[1];
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    Camera_ErrorCode ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (activeframeRateRange != nullptr) {
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, activeframeRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test set framerate in preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set framerate in preview output
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_005, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_PreviewOutput_SetFrameRate(nullptr, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get active framerate in preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active framerate in preview output
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_006, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(nullptr, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ObtainAvailableFrameRate(activeframeRateRange, frameRateRange, size, minFps, maxFps);
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get and set preview rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get and set preview rotation, get and set successfully when valid parameters are entered
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_007, TestSize.Level0)
{
    int displayRotation = 0;
    Camera_ImageRotation imageRotation = IAMGE_ROTATION_180;
    bool isDisplayLocked = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_GetPreviewRotation(previewOutput, displayRotation, &imageRotation);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_SetPreviewRotation(previewOutput, IAMGE_ROTATION_180, isDisplayLocked);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get and set preview rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get and set preview rotation, get and set failed when session is null
 */
HWTEST_F(CameraPreviewOutputUnitTest, camera_preview_output_unittest_008, TestSize.Level0)
{
    int displayRotation = 0;
    Camera_ImageRotation imageRotation = IAMGE_ROTATION_180;
    bool isDisplayLocked = false;
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    Camera_ErrorCode ret = OH_PreviewOutput_GetPreviewRotation(previewOutput, displayRotation, &imageRotation);
    EXPECT_NE(ret, CAMERA_OK);
    ret = OH_PreviewOutput_SetPreviewRotation(previewOutput, IAMGE_ROTATION_180, isDisplayLocked);
    EXPECT_NE(ret, CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}


} // CameraStandard
} // OHOS