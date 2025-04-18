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

#include "camera_capture_session_unittest.h"
#include "camera/capture_session.h"
#include "camera_log.h"
#include "access_token.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "capture_session_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraCaptureSessionUnitTest::SetUpTestCase(void) {}

void CameraCaptureSessionUnitTest::TearDownTestCase(void) {}

void CameraCaptureSessionUnitTest::SetUp(void)
{
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

void CameraCaptureSessionUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test register and unregister capture session callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration captures session event callbacks
 * and expects successful registration and deregistration when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_001, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister capture session callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration captures session event callbacks
 * and expects registration and deregistration to fail when invalid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_002, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(nullptr, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RegisterCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterCallback(nullptr, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister smooth zoom information event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration smooth zoom information event callback.
 * Deregistration and registration are successful when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_003, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister smooth zoom information event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration smooth zoom information event callback.
 * Deregistration and registration are successful when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_004, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(nullptr, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(nullptr, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test set session mode
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test setting three different session modes (SECURE_PHOTO, NORMAL_VIDEO, NORMAL_PHOTO),
* when valid parameters are entered, the setting succeeds
*/
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_005, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, SECURE_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test set session mode
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test setting session mode. Setting failed when an invalid parameter was entered
*/
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_006, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(nullptr, SECURE_PHOTO);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetSessionMode(captureSession, static_cast<Camera_SceneMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test add a secure output to the capture session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: The test marks one of the PreviewOutput as a safe output,
* and when a valid parameter is passed, the mark is successful
*/
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_007, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, SECURE_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_SceneMode* sceneModes = nullptr;
    uint32_t size = 0;
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, &sceneModes, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    for (uint32_t i = 0; i < size; i++) {
        if (sceneModes[i] == SECURE_PHOTO) {
            EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_AddSecureOutput(captureSession, previewOutput), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
        }
    }
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test add a secure output to the capture session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test the one PreviewOutput marked as safe output,
* when the input invalid parameters, mark failed
*/
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_008, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddSecureOutput(nullptr, previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddSecureOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test add a secure output to the capture session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: The test marks one of the PreviewOutput as a safe output and
* will not support marking PreviewOutput as a safe output when the session is not configured
*/
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_009, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddSecureOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test capture session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the function of the test captures the normal flow of the session,
 * and each step is executed successfully when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_010, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Capture(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Stop(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test capture session
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the function of the test captures the abnormal flow of the session,
 * and each step is executed failed when invalid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_011, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CaptureSession_BeginConfig(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddInput(nullptr, cameraInput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddInput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(nullptr, photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CommitConfig(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Start(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Stop(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test delete camera input, delete successfully when a valid parameter is entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_012, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemoveInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test delete camera input, delete failed when invalid parameter was entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_013, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RemoveInput(nullptr, cameraInput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemoveInput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test deleting camera input，
 * deleting camera input is not supported when the session is not configured
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_014, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RemoveInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add preview, photo, and metadata output, remove photo output,
 * add video output and metadata output, when a valid parameter is entered, add and remove successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_015, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemoveVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add preview, photo, and metadata output, remove photo output,
 * add video output and metadata output, when a invalid parameter is entered, add and remove failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_016, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(nullptr, photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPreviewOutput(nullptr, previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddVideoOutput(nullptr, videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemoveVideoOutput(nullptr, videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemoveVideoOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemovePhotoOutput(nullptr, photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add preview, photo, and metadata output, remove photo output,
 * add video output and metadata output, when the session is not configured, This operation is not supported
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_017, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_RemoveVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add preview, photo, and metadata output, remove
 * preview output and metadata output, when a valid parameter is entered, add and remove successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_018, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemovePreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_MetadataOutput_Release(metadataOutput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add metadata output, remove preview output and metadata output,
 * when a invalid parameter is entered, add and remove failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_019, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_AddMetadataOutput(nullptr, metadataOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddMetadataOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemovePreviewOutput(nullptr, previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemovePreviewOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemoveMetadataOutput(nullptr, metadataOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RemoveMetadataOutput(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_MetadataOutput_Release(metadataOutput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test video add preview, photo, and metadata output,
 *           remove photo output, add video output and metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add metadata output, remove preview output and metadata output,
 *  when the session is not configured, This operation is not supported
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_020, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_AddMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_RemovePreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_CaptureSession_RemoveMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_MetadataOutput_Release(metadataOutput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Check whether the device has a flash and supports the specified flash mode,
 *           and obtain and set the flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the device has a flash. If yes, test whether the device supports
 * the specified flash mode, when entering valid parameters, get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_021, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool hasFlash = false;
    bool isSupported = false;
    Camera_FlashMode flashMode = Camera_FlashMode::FLASH_MODE_CLOSE;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_HasFlash(captureSession, &hasFlash);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flashMode, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetFlashMode(captureSession, &flashMode);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_CaptureSession_SetFlashMode(captureSession, flashMode);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_CaptureSession_SetFlashMode(captureSession, flashMode);
        EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    }
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Check whether the device has a flash and supports the specified flash mode,
 *           and obtain and set the flash mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the device has a flash and check whether the device supports
 * the specified flash mode, when entering invalid parameters, get and set failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_022, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool hasFlash = false;
    bool isSupported = false;
    Camera_FlashMode flashMode = Camera_FlashMode::FLASH_MODE_CLOSE;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_HasFlash(nullptr, &hasFlash);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(hasFlash, false);
    ret = OH_CaptureSession_HasFlash(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(hasFlash, false);
    ret = OH_CaptureSession_IsFlashModeSupported(nullptr, Camera_FlashMode::FLASH_MODE_OPEN, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    OH_CaptureSession_IsFlashModeSupported(captureSession, static_cast<Camera_FlashMode>(-1), &isSupported);
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, Camera_FlashMode::FLASH_MODE_OPEN, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFlashMode(nullptr, &flashMode);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFlashMode(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetFlashMode(nullptr, Camera_FlashMode::FLASH_MODE_AUTO);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetFlashMode(captureSession, static_cast<Camera_FlashMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Check whether the device has a flash and supports the specified flash mode,
 *           and obtain and set the flash mode with capture session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Check whether the device has a flash and supports the specified flash mode,
 * and obtain and set the flash mode, when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_023, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool hasFlash = false;
    bool isSupported = false;
    Camera_FlashMode flashMode = Camera_FlashMode::FLASH_MODE_CLOSE;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_HasFlash(captureSession, &hasFlash);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, Camera_FlashMode::FLASH_MODE_OPEN, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetFlashMode(captureSession, &flashMode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetFlashMode(captureSession, Camera_FlashMode::FLASH_MODE_AUTO);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test check if the specified exposure mode is supported
 *           and get and set the exposure mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified exposure mode is supported and obtains and
 * sets the exposure mode. When valid parameters are entered, it can be get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_024, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool isSupported = false;
    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_LOCKED;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, Camera_ExposureMode::EXPOSURE_MODE_LOCKED,
        &isSupported);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_GetExposureMode(captureSession, &exposureMode);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_SetExposureMode(captureSession, Camera_ExposureMode::EXPOSURE_MODE_LOCKED);
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
 * Function: Test check if the specified exposure mode is supported
 *           and get and set the exposure mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified exposure mode is supported and obtains and
 * sets the exposure mode. When invalid parameters are entered, get and set failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_025, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool isSupported = false;
    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_IsExposureModeSupported(nullptr, Camera_ExposureMode::EXPOSURE_MODE_LOCKED, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, static_cast<Camera_ExposureMode>(-1), &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, Camera_ExposureMode::EXPOSURE_MODE_LOCKED, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_GetExposureMode(nullptr, &exposureMode);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureMode(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetExposureMode(nullptr, Camera_ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetExposureMode(captureSession, static_cast<Camera_ExposureMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test check if the specified exposure mode is supported
 *           and get and set the exposure mode with capture session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified exposure mode is supported and obtains and
 * sets the exposure mode. When capture session is not commit, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_026, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool isSupported = false;
    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_LOCKED;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, Camera_ExposureMode::EXPOSURE_MODE_LOCKED,
        &isSupported);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_GetExposureMode(captureSession, &exposureMode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetExposureMode(captureSession, Camera_ExposureMode::EXPOSURE_MODE_LOCKED);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test SetMeteringPoint & GetMeteringPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get and set the center point of the metering area.
 * When valid parameters are entered, the get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_027, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_Point exposurePointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetMeteringPoint(captureSession, exposurePointSet);
    EXPECT_EQ(ret, 0);
    Camera_Point exposurePointGet = {0, 0};
    ret = OH_CaptureSession_GetMeteringPoint(captureSession, &exposurePointGet);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test SetMeteringPoint & GetMeteringPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get and set the center point of the metering area.
 * When invalid parameters are entered, the get and set failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_028, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Point exposurePointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetMeteringPoint(nullptr, exposurePointSet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    exposurePointSet = {-1.0, -2.0};
    ret = OH_CaptureSession_SetMeteringPoint(captureSession, exposurePointSet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    Camera_Point exposurePointGet = {0, 0};
    ret = OH_CaptureSession_GetMeteringPoint(nullptr, &exposurePointGet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetMeteringPoint(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test SetMeteringPoint & GetMeteringPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get and set the center point of the metering area.
 * When the session is not committed, the error that the session is not configured is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_029, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Point exposurePointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetMeteringPoint(captureSession, exposurePointSet);
    EXPECT_NE(ret, CAMERA_OK);
    Camera_Point exposurePointGet = {0, 0};
    ret = OH_CaptureSession_GetMeteringPoint(captureSession, &exposurePointGet);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue, GetExposureBiasRange and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test query exposure bias range, get bias and set exposure bias with value less than the range,
 * when input valid parameters, can be get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_030, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    ASSERT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    float exposureBiasValue = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(captureSession, &exposureBiasValue);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias-1.0);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_Capture(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(PhotoOutput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue, GetExposureBiasRange and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test query exposure bias range, get bias and set exposure bias with value between the range,
 * when input valid parameters, can be get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_031, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    float exposureBiasValue = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(captureSession, &exposureBiasValue);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias+1.0);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_Capture(PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue, GetExposureBiasRange and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test query exposure bias range, get bias and set exposure bias with value more than the range,
 * when input valid parameters, can be get and set successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_032, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    float exposureBiasValue = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(captureSession, &exposureBiasValue);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetExposureBias(captureSession, maxExposureBias+1.0);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_Capture(PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue, GetExposureBiasRange and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test query exposure bias range, get and set exposure bias,
 * when input invalid parameters, can be get and set failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_033, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(nullptr, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, nullptr, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, nullptr, &step);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    float exposureBiasValue = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(nullptr, &exposureBiasValue);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureBias(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetExposureBias(nullptr, minExposureBias);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test GetExposureValue, GetExposureBiasRange and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test query exposure bias range, get and set exposure bias,
 * when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_034, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    float exposureBiasValue = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(captureSession, &exposureBiasValue);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias-1.0);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias+1.0);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_SetExposureBias(captureSession, maxExposureBias+1.0);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified focus mode is supported,
 * gets and sets the focus mode, and gets and sets the focus mode successfully when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_035, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    bool isSupported = false;
    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_MANUAL;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    OH_CaptureSession_IsFocusModeSupported(captureSession, Camera_FocusMode::FOCUS_MODE_AUTO, &isSupported);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_GetFocusMode(captureSession, &focusMode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetFocusMode(captureSession, Camera_FocusMode::FOCUS_MODE_AUTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_Capture(PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified focus mode is supported,
 * gets and sets the focus mode, and gets and sets the focus mode failed when invalid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_036, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    bool isSupported = false;
    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_MANUAL;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_IsFocusModeSupported(nullptr, Camera_FocusMode::FOCUS_MODE_AUTO, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, static_cast<Camera_FocusMode>(-1), &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, Camera_FocusMode::FOCUS_MODE_CONTINUOUS_AUTO, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_GetFocusMode(nullptr, &focusMode);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFocusMode(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetFocusMode(nullptr, Camera_FocusMode::FOCUS_MODE_LOCKED);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetFocusMode(captureSession, static_cast<Camera_FocusMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test focus mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test check whether the specified focus mode is supported,
 * gets and sets the focus mode, when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_037, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    bool isSupported = false;
    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_MANUAL;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, Camera_FocusMode::FOCUS_MODE_AUTO, &isSupported);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_GetFocusMode(captureSession, &focusMode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetFocusMode(captureSession, Camera_FocusMode::FOCUS_MODE_LOCKED);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test SetFocusPoint & GetFousPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and set the focus, when entering valid parameters,
 * can successfully get and set the focus
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_038, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_Point FocusPointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetFocusPoint(captureSession, FocusPointSet);
    EXPECT_EQ(ret, 0);
    Camera_Point FocusPointGet = {0, 0};
    ret = OH_CaptureSession_GetFocusPoint(captureSession, &FocusPointGet);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Capture(PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test SetFocusPoint & GetFousPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and set the focus, when entering invalid parameters, can failed get and set the focus
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_039, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Point FocusPointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetFocusPoint(nullptr, FocusPointSet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    Camera_Point FocusPointGet = {0, 0};
    ret = OH_CaptureSession_GetFocusPoint(nullptr, &FocusPointGet);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFocusPoint(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test SetFocusPoint & GetFousPoint with capture session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and set the focus, when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_040, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Point FocusPointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetFocusPoint(captureSession, FocusPointSet);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    Camera_Point FocusPointGet = {0, 0};
    ret = OH_CaptureSession_GetFocusPoint(captureSession, &FocusPointGet);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get all the supported zoom ratio range and set the zoom ratio,
 * when the input of valid parameters, can successfully get and set the zoom ratio
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_041, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, CAMERA_OK);
    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(captureSession, zoom);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetZoomRatio(captureSession, &zoom);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get all the supported zoom ratio range and set the zoom ratio,
 * when the input of invalid parameters, can failed get and set the zoom ratio
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_042, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(nullptr, &minZoom, &maxZoom);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, nullptr, &maxZoom);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(nullptr, zoom);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get all the supported zoom ratio range and set the zoom ratio,
 * when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_043, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, CAMERA_OK);
    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(captureSession, zoom);
    EXPECT_NE(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetZoomRatio(captureSession, &zoom);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test capture session with Video Stabilization Mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Check whether the specified video stabilization mode is supported,
 * and obtain and set the video stabilization mode. When valid parameters are entered, the system can
 * obtain and set the video stabilization mode successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_044, TestSize.Level0)
{
    Camera_CaptureSession* captureSession;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_Input *cameraInput;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    bool isSupported=false;
    Camera_VideoStabilizationMode mode = STABILIZATION_MODE_AUTO;
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(captureSession, STABILIZATION_MODE_MIDDLE, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        ret = OH_CaptureSession_SetVideoStabilizationMode(captureSession, STABILIZATION_MODE_MIDDLE);
        EXPECT_EQ(ret, 0);
        ret = OH_CaptureSession_GetVideoStabilizationMode(captureSession, &mode);
    }
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    sleep(WAIT_TIME_AFTER_START);
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
 * Function: Test capture session with Video Stabilization Mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Check whether the specified video stabilization mode is supported,
 * and obtain and set the video stabilization mode. When invalid parameters are entered, the system can obtain
 * and set the video stabilization mode failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_045, TestSize.Level0)
{
    Camera_CaptureSession* captureSession;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    bool isSupported=false;
    Camera_VideoStabilizationMode mode = STABILIZATION_MODE_AUTO;
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(nullptr, STABILIZATION_MODE_MIDDLE, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(captureSession,
        static_cast<Camera_VideoStabilizationMode>(-1), &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(captureSession, STABILIZATION_MODE_MIDDLE, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSupported, false);
    ret = OH_CaptureSession_SetVideoStabilizationMode(nullptr, STABILIZATION_MODE_MIDDLE);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetVideoStabilizationMode(captureSession, static_cast<Camera_VideoStabilizationMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetVideoStabilizationMode(nullptr, &mode);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetVideoStabilizationMode(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session with Video Stabilization Mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Check whether the specified video stabilization mode is supported,
 * and obtain and set the video stabilization mode.
 * When the session is not committed, the error that the session is not configured is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_046, TestSize.Level0)
{
    Camera_CaptureSession* captureSession;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    bool isSupported=false;
    Camera_VideoStabilizationMode mode = STABILIZATION_MODE_AUTO;
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(captureSession, STABILIZATION_MODE_MIDDLE, &isSupported);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    ret = OH_CaptureSession_SetVideoStabilizationMode(captureSession, STABILIZATION_MODE_MIDDLE);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    ret = OH_CaptureSession_GetVideoStabilizationMode(captureSession, &mode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera input can be added to the session,
 * and if so, the camera input was successfully added to the session
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_047, TestSize.Level0)
{
    bool isSuccess = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccess, true);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera input can be added to the session.
 * The addition fails when an invalid parameter is entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_048, TestSize.Level0)
{
    bool isSuccess = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(cameraInput, nullptr);
    ret = OH_CaptureSession_CanAddInput(nullptr, cameraInput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccess, false);
    ret = OH_CaptureSession_CanAddInput(captureSession, nullptr, &isSuccess);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccess, false);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccess, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera input can be added to the session.
 * TTest whether you can add camera input to a session, which is not allowed when the session is not configured
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_049, TestSize.Level0)
{
    bool isSuccess = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(cameraInput, nullptr);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera preview output can be added to the session,
 * and if so, the camera preview output was successfully added to the session
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_050, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccessful), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, previewOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, true);
    EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera preview output can be added to the session,
 * the addition fails when an invalid parameter is entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_051, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_CanAddPreviewOutput(nullptr, previewOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, previewOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera preview output can be added to the session.
 * TTest whether you can add camera preview output to a session, which is not allowed when the session is not configured
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_052, TestSize.Level0)
{
    bool isSuccess = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, previewOutput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccess, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera photo output can be added to the session,
 * and if so, the camera photo output was successfully added to the session
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_053, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, true);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, true);
    EXPECT_EQ(OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera photo output can be added to the session,
 * the addition fails when an invalid parameter is entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_054, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_CanAddPhotoOutput(nullptr, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera photo output can be added to the session.
 * Test whether you can add camera photo output to a session, which is not allowed when the session is not configured
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_055, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera video output can be added to the session,
 * and if so, the camera video output was successfully added to the session
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_056, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, true);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, videoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, true);
    EXPECT_EQ(OH_CaptureSession_AddVideoOutput(captureSession, videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera video output can be added to the session,
 * the addition fails when an invalid parameter is entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_057, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_CanAddVideoOutput(nullptr, videoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(isSuccessful, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the camera video output can be added to the session,
 * Test whether you can add camera video output to a session, which is not allowed when the session is not configured
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_058, TestSize.Level0)
{
    bool isSuccessful = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, videoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccessful, false);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test can preconfig or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test checks whether the specified pre-configuration type is supported.
 * If yes, the pre-configuration type is set. When valid parameters are entered, the setting succeeds
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_059, TestSize.Level0)
{
    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char* surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    bool canPreconfig = false;
    Camera_PreconfigType preconfigType = Camera_PreconfigType::PRECONFIG_720P;
    ret = OH_CaptureSession_CanPreconfig(captureSession, preconfigType, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_OK);
    if (canPreconfig == true) {
        ret = OH_CaptureSession_Preconfig(captureSession, preconfigType);
        EXPECT_EQ(ret, CAMERA_OK);
        Camera_Input *cameraInput = nullptr;
        ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(&cameraInput, nullptr);
        EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
        ret = OH_CaptureSession_BeginConfig(captureSession);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
        Camera_PhotoOutput *photoOutput = nullptr;
        ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(cameraManager, surfaceId, &photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(photoOutput, nullptr);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
        EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test can preconfig or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test checks whether the specified pre-configuration type is supported. And
 * the pre-configuration type is set. When invalid parameters are entered, the setting fail
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_060, TestSize.Level0)
{
    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char* surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    bool canPreconfig = false;
    ret = OH_CaptureSession_CanPreconfig(nullptr, Camera_PreconfigType::PRECONFIG_720P, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanPreconfig(captureSession, static_cast<Camera_PreconfigType>(-1), &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanPreconfig(captureSession, Camera_PreconfigType::PRECONFIG_720P, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Preconfig(nullptr, Camera_PreconfigType::PRECONFIG_720P);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_Preconfig(captureSession, static_cast<Camera_PreconfigType>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(nullptr, surfaceId, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(cameraManager, nullptr, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(cameraManager, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(photoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test can preconfig or not with ratio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test checks whether the pre-configuration type with ratio is supported.
 * If yes, the pre-configuration type with ratio is set. When valid parameters are entered, the setting succeeds
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_061, TestSize.Level0)
{
    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char* surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    bool canPreconfig = false;
    Camera_PreconfigRatio preconfigRatio = PRECONFIG_RATIO_1_1;
    Camera_PreconfigType preconfigType = Camera_PreconfigType::PRECONFIG_720P;
    ret = OH_CaptureSession_CanPreconfigWithRatio(captureSession, preconfigType, preconfigRatio, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_OK);
    if (canPreconfig == true) {
        ret = OH_CaptureSession_PreconfigWithRatio(captureSession, preconfigType, preconfigRatio);
        EXPECT_EQ(ret, CAMERA_OK);
        Camera_Input *cameraInput = nullptr;
        ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(&cameraInput, nullptr);
        EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
        ret = OH_CaptureSession_BeginConfig(captureSession);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
        Camera_PhotoOutput *photoOutput = nullptr;
        ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(cameraManager, surfaceId, &photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(photoOutput, nullptr);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
        EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test can preconfig or not with ratio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test checks whether the pre-configuration type with ratio is supported and
 * the pre-configuration type with ratio is set. When inalid parameters are entered, the setting failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_062, TestSize.Level0)
{
    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char* surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);

    bool canPreconfig = false;
    Camera_PreconfigRatio preconfigRatio = PRECONFIG_RATIO_1_1;
    Camera_PreconfigType preconfigType = Camera_PreconfigType::PRECONFIG_720P;
    ret = OH_CaptureSession_CanPreconfigWithRatio(nullptr, preconfigType, preconfigRatio, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_FALSE(canPreconfig);
    ret = OH_CaptureSession_CanPreconfigWithRatio(captureSession,
        static_cast<Camera_PreconfigType>(-1), preconfigRatio, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_FALSE(canPreconfig);
    ret = OH_CaptureSession_CanPreconfigWithRatio(captureSession, preconfigType,
        static_cast<Camera_PreconfigRatio>(-1), &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_FALSE(canPreconfig);
    ret = OH_CaptureSession_CanPreconfigWithRatio(captureSession, preconfigType, preconfigRatio, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_FALSE(canPreconfig);
    ret = OH_CaptureSession_PreconfigWithRatio(nullptr, preconfigType, preconfigRatio);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_PreconfigWithRatio(captureSession, static_cast<Camera_PreconfigType>(-1), preconfigRatio);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_PreconfigWithRatio(captureSession, preconfigType, static_cast<Camera_PreconfigRatio>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get exposure value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get the exposure value. When valid parameters are entered,
 * the exposure value can be get successfully
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_063, TestSize.Level0)
{
    float exposureValue = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_GetExposureValue(captureSession, &exposureValue);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get exposure value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get the exposure value.
 * When invalid parameters are entered, the exposure value can be get failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_064, TestSize.Level0)
{
    float exposureValue = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetExposureValue(nullptr, &exposureValue);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureValue(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get exposure value with capture session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get exposure value.
 * When the session is not committed, the error that the session is not configured is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_065, TestSize.Level0)
{
    float exposureValue = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetExposureValue(captureSession, &exposureValue);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get focal length
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get the current focal length value,
 * and the focal length value value can be get successfully when valid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_066, TestSize.Level0)
{
    float focalLength = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_GetFocalLength(captureSession, &focalLength);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get focal length
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get the current focal length value,
 * and the focal length value value can not be get when invalid parameters are entered
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_067, TestSize.Level0)
{
    float focalLength = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetFocalLength(nullptr, &focalLength);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFocalLength(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get focal length with capture session is not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get the current focal length value,
 * when the session is not committed, the error that the session is not configured is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_068, TestSize.Level0)
{
    float focalLength = 0.0f;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetFocalLength(captureSession, &focalLength);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to obtain the supported color space list,
 * when the color space list can be obtained, enter valid parameters, you can successfully set the color space
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_069, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && colorSpace != nullptr) {
        ret = OH_CaptureSession_SetActiveColorSpace(captureSession, colorSpace[0]);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to obtain the supported color space list and set color space
 * when enter invalid parameters, will set the color space failed
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_070, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetSupportedColorSpaces(nullptr, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    OH_NativeBuffer_ColorSpace setColorSpace = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_FULL;
    ret = OH_CaptureSession_SetActiveColorSpace(nullptr, setColorSpace);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_SetActiveColorSpace(captureSession, static_cast<OH_NativeBuffer_ColorSpace>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and delete the current color space, when entering valid parameters,
 * can successfully get and delete the current color space
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_071, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_NativeBuffer_ColorSpace activeColorSpace;
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, &activeColorSpace);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && colorSpace != nullptr) {
        ret = OH_CaptureSession_DeleteColorSpaces(captureSession, colorSpace);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test to get and delete the current color space, when entered a valid parameter, delete and get successful
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and delete the current color space,
 * when entered a valid parameter, delete and get successful
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_072, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_NativeBuffer_ColorSpace* activeColorSpace = new OH_NativeBuffer_ColorSpace;
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, activeColorSpace);
    EXPECT_EQ(ret, CAMERA_OK);
    if (activeColorSpace != nullptr) {
        ret = OH_CaptureSession_DeleteColorSpaces(captureSession, activeColorSpace);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get and delete the current color space, when entering invalid parameters,
 * can not get and delete the current color space
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_073, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_NativeBuffer_ColorSpace activeColorSpace;
    ret = OH_CaptureSession_GetActiveColorSpace(nullptr, &activeColorSpace);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_DeleteColorSpaces(nullptr, colorSpace);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_DeleteColorSpaces(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to set and get the color space, When the session is not committed,
 * the error that the session is not configured is returned
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_074, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetActiveColorSpace(captureSession, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_FULL);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    OH_NativeBuffer_ColorSpace activeColorSpace;
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, &activeColorSpace);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test to query exposure bias ranges when there is no session configuration and session commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to query exposure bias ranges when there is no session configuration and session commit
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_075, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test set session mode with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set session mode with abnormal branch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_076, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, static_cast<Camera_SceneMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test remove metadata output with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test remove metadata output with abnormal branch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_077, TestSize.Level0)
{
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    ASSERT_NE(captureSession, nullptr);
    captureSession->innerCaptureSession_ = nullptr;
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_RemoveMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test photo session IsMacroSupported interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_photo_session_unittest_macro_001, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session IsMacroSupported interface
 * SubFunction: Test error code CAMERA_SESSION_NOT_CONFIG
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_photo_session_unittest_macro_002, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session EnableMacro interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_photo_session_unittest_macro_003, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    OH_CaptureSession_CommitConfig(captureSession);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupportedMacro) {
        ret = OH_CaptureSession_EnableMacro(captureSession, true);
        EXPECT_EQ(ret, CAMERA_OK);

        ret = OH_CaptureSession_EnableMacro(captureSession, false);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session EnableMacro interface
 * SubFunction: Test error code CAMERA_SESSION_NOT_CONFIG
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_photo_session_unittest_macro_004, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupportedMacro) {
        ret = OH_CaptureSession_EnableMacro(captureSession, true);
        EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    }
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session EnableMacro interface
 * SubFunction: Test error code CAMERA_OPERATION_NOT_ALLOWED
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_photo_session_unittest_macro_005, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_EnableMacro(captureSession, true);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test video session IsMacroSupported interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_video_session_unittest_macro_001, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test video session IsMacroSupported interface
 * SubFunction: Test error code CAMERA_SESSION_NOT_CONFIG
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_video_session_unittest_macro_002, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test video session EnableMacro interface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_video_session_unittest_macro_003, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    OH_CaptureSession_CommitConfig(captureSession);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupportedMacro) {
        ret = OH_CaptureSession_EnableMacro(captureSession, true);
        EXPECT_EQ(ret, CAMERA_OK);

        ret = OH_CaptureSession_EnableMacro(captureSession, false);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test video session EnableMacro interface
 * SubFunction: Test error code CAMERA_SESSION_NOT_CONFIG
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_video_session_unittest_macro_004, TestSize.Level0)
{
    Camera_Input* cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    OH_CaptureSession_BeginConfig(captureSession);
    OH_CaptureSession_AddInput(captureSession, cameraInput);
    OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);

    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupportedMacro) {
        ret = OH_CaptureSession_EnableMacro(captureSession, true);
        EXPECT_EQ(ret, CAMERA_SESSION_NOT_CONFIG);
    }
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test video session EnableMacro interface
 * SubFunction: Test error code CAMERA_OPERATION_NOT_ALLOWED
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_video_session_unittest_macro_005, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_EnableMacro(captureSession, true);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session IsMacroSupported interface
 * SubFunction: Test error code CAMERA_INVALID_ARGUMENT
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_macro_001, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    bool isSupportedMacro = false;
    Camera_ErrorCode ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test photo session IsMacroSupported interface
 * SubFunction: Test error code CAMERA_INVALID_ARGUMENT
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session IsMacroSupported interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_macro_002, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::SECURE_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupportedMacro = false;
    ret = OH_CaptureSession_IsMacroSupported(captureSession, &isSupportedMacro);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: Test photo session EnableMacro interface
 * SubFunction: Test error code CAMERA_INVALID_ARGUMENT
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_macro_003, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CaptureSession_EnableMacro(captureSession, true);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test photo session EnableMacro interface
 * SubFunction: Test error code CAMERA_INVALID_ARGUMENT
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo session EnableMacro interface
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_macro_004, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_NE(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, Camera_SceneMode::SECURE_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_EnableMacro(captureSession, true);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    OH_CaptureSession_Release(captureSession);
}

/*
 * Feature: Framework
 * Function: RegisterCallback and UnregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test registration and deregistration when parameters is nullptr
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_078, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = nullptr,
        .onError = nullptr
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterAutoDeviceSwitchStatusCallback and UnregisterAutoDeviceSwitchStatusCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterAutoDeviceSwitchStatusCallback and UnregisterAutoDeviceSwitchStatusCallback
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_079, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RegisterAutoDeviceSwitchStatusCallback(captureSession,
        CameraCaptureSessionAutoDeviceSwitchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterAutoDeviceSwitchStatusCallback(captureSession,
        CameraCaptureSessionAutoDeviceSwitchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterAutoDeviceSwitchStatusCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterAutoDeviceSwitchStatusCallback  with abnormal branch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_080, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_RegisterAutoDeviceSwitchStatusCallback(nullptr,
        CameraCaptureSessionAutoDeviceSwitchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RegisterAutoDeviceSwitchStatusCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: UnregisterAutoDeviceSwitchStatusCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnregisterAutoDeviceSwitchStatusCallback  with abnormal branch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_081, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_UnregisterAutoDeviceSwitchStatusCallback(nullptr,
        CameraCaptureSessionAutoDeviceSwitchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterAutoDeviceSwitchStatusCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: EnableAutoDeviceSwitch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enable auto device switch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_082, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_CaptureSession_IsAutoDeviceSwitchSupported(captureSession, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(captureSession, true);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(captureSession, true);
        EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
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
 * Function: EnableAutoDeviceSwitch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test disable auto device switch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_083, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_CaptureSession_IsAutoDeviceSwitchSupported(captureSession, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(nullptr, false);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(captureSession, false);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(nullptr, false);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_CaptureSession_EnableAutoDeviceSwitch(captureSession, false);
        EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
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
 * Function: IsAutoDeviceSwitchSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsAutoDeviceSwitchSupported with abnormal branch
 */
HWTEST_F(CameraCaptureSessionUnitTest, camera_capture_session_unittest_084, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSupported = false;
    ret = OH_CaptureSession_IsAutoDeviceSwitchSupported(nullptr, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
}

} // CameraStandard
} // OHOS