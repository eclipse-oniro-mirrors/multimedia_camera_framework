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

#include "camera_photo_output_unittest.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "photo_output_impl.h"
#include "test_token.h"
#include "capture_session_impl.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraPhotoOutputUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraPhotoOutputUnitTest::TearDownTestCase(void) {}

void CameraPhotoOutputUnitTest::SetUp(void)
{
    InitCamera();
}

void CameraPhotoOutputUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test register photo output capture start event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output capture start event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_001, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(nullptr, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo output capture start event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo output capture start event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_002, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(nullptr, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo output capture end event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output capture end event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_003, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureEndCallback(photoOutput, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterCaptureEndCallback(nullptr, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterCaptureEndCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureEndCallback(photoOutput, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo output capture end event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo output capture end event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_004, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureEndCallback(photoOutput, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureEndCallback(photoOutput, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureEndCallback(nullptr, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterCaptureEndCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo output shutter end event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output shutter end event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_005, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterFrameShutterEndCallback(photoOutput, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterFrameShutterEndCallback(nullptr, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterFrameShutterEndCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterFrameShutterEndCallback(photoOutput, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo output frame shutter end event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo output frame shutter end event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_006, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterFrameShutterEndCallback(photoOutput, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterFrameShutterEndCallback(photoOutput, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterFrameShutterEndCallback(nullptr, CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterFrameShutterEndCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo output capture ready event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output capture ready event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_007, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterCaptureReadyCallback(nullptr, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterCaptureReadyCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(nullptr, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo output capture ready event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo output capture ready event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_008, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(nullptr, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo output estimated capture duration event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output estimated capture duration event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_009, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(nullptr,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo output estimated capture duration event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo output estimated capture duration event callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_010, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(nullptr,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo available callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_011, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSuccessful = false;
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSuccessful == true) {
        ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(nullptr, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo available callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_012, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSuccessful = false;
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSuccessful == true) {
        ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
    } else {
        ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(nullptr, CameraPhotoOutptOnPhotoAvailableCb);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(photoOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister photo available callback,
 * register and unregister successfully when valid parameter was entered
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_013, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_PhotoOutput *photoOutput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test Abnormal branch register photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo available callback,
 * when using the photoOutput created without surfaceId, registration will still succeed, return CAMERA_OK
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_014, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo asset available callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_015, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    bool isSuccessful = false;
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSuccessful == true) {
        ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        ret = OH_PhotoOutput_UnregisterPhotoAssetAvailableCallback(photoOutput,
            CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister photo asset available callback,
 * register and unregister successfully when valid parameter was entered
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_016, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAssetAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterPhotoAssetAvailableCallback(photoOutput,
        CameraPhotoOutptOnPhotoAssetAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test register photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo asset available callback,
 * when using the photoOutput created without surfaceId, registration will still succeed, return CAMERA_OK
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_017, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_ErrorCode ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(photoOutput,
        CameraPhotoOutptOnPhotoAssetAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo asset available callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_018, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(photoOutput, nullptr);
    bool isSuccessful = false;
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSuccessful == true) {
        ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        ret = OH_PhotoOutput_UnregisterPhotoAssetAvailableCallback(photoOutput,
            CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test photo capture with photo settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with photo settings
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_019, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    ASSERT_NE(PhotoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_PhotoCaptureSetting capSettings;
    capSettings.quality = QUALITY_LEVEL_MEDIUM;
    capSettings.rotation = IAMGE_ROTATION_90;
    ret = OH_PhotoOutput_Capture_WithCaptureSetting(PhotoOutput, capSettings);
    EXPECT_EQ(ret, 0);
    OH_CaptureSession_RemovePhotoOutput(captureSession, PhotoOutput);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test photo capture with capture settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with preview output & capture settings
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_020, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_PhotoCaptureSetting capSettings;
    capSettings.quality = QUALITY_LEVEL_MEDIUM;
    capSettings.rotation = IAMGE_ROTATION_90;
    ret = OH_PhotoOutput_Capture_WithCaptureSetting(PhotoOutput, capSettings);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(PhotoOutput);
    EXPECT_EQ(ret, 0);
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
 * Function: Test get active profile of photo output and delete profile of photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of photo output and delete profile of photo output
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_021, TestSize.Level0)
{
    Camera_Profile* profile = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    ret = OH_PhotoOutput_GetActiveProfile(photooutput, &profile);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_GetActiveProfile(nullptr, &profile);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_GetActiveProfile(photooutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    if (profile != nullptr) {
        EXPECT_EQ(OH_PhotoOutput_DeleteProfile(profile), CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_DeleteProfile(nullptr), CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test moving photo supported or not
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test moving photo supported or not
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_022, TestSize.Level0)
{
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    bool isSupported = false;
    ret = OH_PhotoOutput_IsMovingPhotoSupported(photooutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported == true) {
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, true);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, false);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test enable moving photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enable moving photo
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_023, TestSize.Level0)
{
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    bool isSupported = false;
    ret = OH_PhotoOutput_IsMovingPhotoSupported(photooutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, true);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, false);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_PhotoOutput_EnableMovingPhoto(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test abnormal branch of enable moving photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enable moving photo, which returns an internal system error
 * when the device does not support moving photo
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_024, TestSize.Level0)
{
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    bool isSupported = false;
    ret = OH_PhotoOutput_IsMovingPhotoSupported(photooutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (!isSupported) {
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, true);
        EXPECT_NE(ret, CAMERA_OK);
        ret = OH_PhotoOutput_EnableMovingPhoto(photooutput, false);
        EXPECT_NE(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test enable moving photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test enable moving photo, when the session is not committed, an internal error is returned
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_025, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    Camera_ErrorCode ret = OH_PhotoOutput_EnableMovingPhoto(photoOutput, true);
    EXPECT_NE(ret, CAMERA_OK);
    ret = OH_PhotoOutput_EnableMovingPhoto(photoOutput, false);
    EXPECT_NE(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: The test checks whether mirror photography is supported.
* When a valid parameter is entered, the test returns whether the parameter is supported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: The test checks whether mirror photography is supported.
 * When a valid parameter is entered, the test returns whether the parameter is supported
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_026, TestSize.Level0)
{
    bool isSupported = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_IsMirrorSupported(photoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test get photo rotation
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get photo rotation,  when entered valid parameters, get success
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_027, TestSize.Level0)
{
    int deviceDegree = 0;
    Camera_ImageRotation imageRotation = IAMGE_ROTATION_180;
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    ret = OH_PhotoOutput_GetPhotoRotation(photoOutput, deviceDegree, &imageRotation);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test enable mirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether mirror photography is enabled.
 * If mirror photography is supported, it will be enabled successfully when valid parameters are entered
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_028, TestSize.Level0)
{
    bool isSupported = false;
    bool enabled = true;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_IsMirrorSupported(photoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_PhotoOutput_EnableMirror(photoOutput, enabled);
    }
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test release in photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test release in photo output
 * SubFunction: NA
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_029, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    photoOutput->photoNative_ = new OH_PhotoNative();
    ASSERT_NE(photoOutput->photoNative_, nullptr);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test register callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register callback
 * SubFunction: NA
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_030, TestSize.Level0)
{
    PhotoOutput_Callbacks setCameraPhotoOutputCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnCaptureEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    photoOutput->innerCallback_ = std::make_shared<InnerPhotoOutputCallback>(photoOutput);
    ASSERT_NE(photoOutput->innerCallback_, nullptr);
    Camera_ErrorCode ret = OH_PhotoOutput_RegisterCallback(photoOutput, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterCaptureEndCallback(photoOutput, CameraPhotoOutptOnCaptureEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_RegisterFrameShutterEndCallback(photoOutput,
        CameraPhotoOutptOnFrameShutterEndCb);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister photo available callback
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_031, TestSize.Level0)
{
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_PhotoOutput *photoOutput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterPhotoAvailableCallback(photoOutput, CameraPhotoOutptOnPhotoAvailableCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test create camera photo native
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister photo available callback,
 * register and unregister successfully when valid parameter was entered
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_032, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    std::shared_ptr<OHOS::Media::NativeImage> image = std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    photoOutput->photoNative_ = nullptr;
    OH_PhotoNative* photoNative = photoOutput->CreateCameraPhotoNative(image, false);
    ASSERT_NE(photoNative, nullptr);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister photo available callback,
 * register and unregister successfully when valid parameter was entered
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_033, TestSize.Level0)
{
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    std::shared_ptr<OHOS::Media::NativeImage> image = std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    photoOutput->photoNative_ = nullptr;
    OH_PhotoNative* photoNative = photoOutput->CreateCameraPhotoNative(image, true);
    ASSERT_NE(photoNative, nullptr);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterCallback and UnregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterCallback and UnregisterCallback
 * SubFunction: NA
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_034, TestSize.Level0)
{
    Camera_ErrorCode ret;
    PhotoOutput_Callbacks setCameraPhotoOutputCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnCaptureEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_PhotoOutput_RegisterCallback(photoOutput, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_PhotoOutput_UnregisterCallback(photoOutput, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RegisterCallback with abnormal branch
 * SubFunction: NA
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_035, TestSize.Level0)
{
    Camera_ErrorCode ret;
    PhotoOutput_Callbacks setCameraPhotoOutputCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnCaptureEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    ret = OH_PhotoOutput_RegisterCallback(nullptr, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_RegisterCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setCameraPhotoOutputCallback.onFrameStart = nullptr;
    setCameraPhotoOutputCallback.onFrameShutter = nullptr;
    setCameraPhotoOutputCallback.onFrameEnd = nullptr;
    setCameraPhotoOutputCallback.onError = nullptr;
    ret = OH_PhotoOutput_RegisterCallback(photoOutput, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: UnregisterCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UnregisterCallback with abnormal branch
 * SubFunction: NA
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_036, TestSize.Level0)
{
    Camera_ErrorCode ret;
    PhotoOutput_Callbacks setCameraPhotoOutputCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnCaptureEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);

    ret = OH_PhotoOutput_UnregisterCallback(nullptr, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_UnregisterCallback(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setCameraPhotoOutputCallback.onFrameStart = nullptr;
    setCameraPhotoOutputCallback.onFrameShutter = nullptr;
    setCameraPhotoOutputCallback.onFrameEnd = nullptr;
    setCameraPhotoOutputCallback.onError = nullptr;
    ret = OH_PhotoOutput_UnregisterCallback(photoOutput, &setCameraPhotoOutputCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: EnableMirror
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test mirror is disabled.
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_037, TestSize.Level0)
{
    bool isSupported = false;
    bool enabled = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_IsMirrorSupported(photoOutput, &isSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSupported) {
        ret = OH_PhotoOutput_EnableMirror(nullptr, enabled);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PhotoOutput_EnableMirror(photoOutput, enabled);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: RegisterCaptureStartWithInfoCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register callback when innerCallback_ is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_038, TestSize.Level0)
{
    Camera_ErrorCode ret;

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    photoOutput->innerCallback_ = std::make_shared<InnerPhotoOutputCallback>(photoOutput);
    ASSERT_NE(photoOutput->innerCallback_, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(photoOutput, CameraPhotoOutptOnCaptureStartWithInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterCaptureReadyCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register callback when innerCallback_ is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_039, TestSize.Level0)
{
    Camera_ErrorCode ret;

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    photoOutput->innerCallback_ = std::make_shared<InnerPhotoOutputCallback>(photoOutput);
    ASSERT_NE(photoOutput->innerCallback_, nullptr);
    ret = OH_PhotoOutput_RegisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterCaptureReadyCallback(photoOutput, CameraPhotoOutptOnCaptureReadyCb);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: RegisterEstimatedCaptureDurationCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register callback when innerCallback_ is not nullptr
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_040, TestSize.Level0)
{
    Camera_ErrorCode ret;

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    photoOutput->innerCallback_ = std::make_shared<InnerPhotoOutputCallback>(photoOutput);
    ASSERT_NE(photoOutput->innerCallback_, nullptr);
    ret = OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(photoOutput,
        CameraPhotoOutptEstimatedOnCaptureDurationCb);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: IsMirrorSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMirrorSupported with abnormal branch
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_041, TestSize.Level0)
{
    bool isSupported = false;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoOutput_IsMirrorSupported(nullptr, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoOutput_IsMirrorSupported(photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test SetPhotoQualityPrioritization
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPhotoQualityPrioritization with abnormal branch
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_042, TestSize.Level0)
{
    Camera_PhotoQualityPrioritization qualityPrioritization = CAMERA_PHOTO_QUALITY_PRIORITIZATION_SPEED;
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    photoOutput = nullptr;
    ret = OH_PhotoOutput_SetPhotoQualityPrioritization(photoOutput, qualityPrioritization);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test IsPhotoQualityPrioritizationSupported
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsPhotoQualityPrioritizationSupported with abnormal branch
 */
HWTEST_F(CameraPhotoOutputUnitTest, camera_photo_output_unittest_043, TestSize.Level0)
{
    bool isSupported = false;
    Camera_PhotoQualityPrioritization qualityPrioritization = CAMERA_PHOTO_QUALITY_PRIORITIZATION_SPEED;
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
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    photoOutput = nullptr;
    ret = OH_PhotoOutput_IsPhotoQualityPrioritizationSupported(photoOutput, qualityPrioritization, &isSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}
} // CameraStandard
} // OHOS