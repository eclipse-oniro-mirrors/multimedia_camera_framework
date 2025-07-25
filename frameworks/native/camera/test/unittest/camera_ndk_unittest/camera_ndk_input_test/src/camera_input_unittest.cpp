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

#include "camera_input_unittest.h"
#include "camera_log.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "test_token.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraInputUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraInputUnitTest::TearDownTestCase(void) {}

void CameraInputUnitTest::SetUp(void)
{
    InitCamera();
}

void CameraInputUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test register camera status change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register camera status change event callback
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_001, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    CameraInput_Callbacks setCameraInputResultCallback = {
        .onError = &OnCameraInputError
    };
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_RegisterCallback(cameraInput, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_RegisterCallback(nullptr, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraInput_RegisterCallback(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setCameraInputResultCallback.onError = nullptr;
    ret = OH_CameraInput_RegisterCallback(cameraInput, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test unregister camera state change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister camera state change event callback
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_002, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    CameraInput_Callbacks setCameraInputResultCallback = {
        .onError = &OnCameraInputError
    };
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_UnregisterCallback(cameraInput, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_UnregisterCallback(nullptr, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraInput_UnregisterCallback(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setCameraInputResultCallback.onError = nullptr;
    ret = OH_CameraInput_UnregisterCallback(cameraInput, &setCameraInputResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test open secure camera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test open secure camera
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_003, TestSize.Level0)
{
    uint64_t secureSeqId = 10;
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
    ASSERT_NE(cameraInput, nullptr);
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
            ret = OH_CameraInput_OpenSecureCamera(cameraInput, &secureSeqId);
            EXPECT_EQ(ret, CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_AddSecureOutput(captureSession, previewOutput), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
            EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
        }
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test open and close camera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test open and close capture session. When valid parameters are entered,
 * the camera open and close successfully
 */
HWTEST_F(CameraInputUnitTest, camera_input_unittest_004, TestSize.Level0)
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
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_Stop(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Close(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}
} // CameraStandard
} // OHOS