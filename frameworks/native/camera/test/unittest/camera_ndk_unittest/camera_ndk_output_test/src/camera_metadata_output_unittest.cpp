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

#include "camera_metadata_output_unittest.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "test_token.h"
#include "capture_session_impl.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraMetadataOutputUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken().GetAllCameraPermission());
}

void CameraMetadataOutputUnitTest::TearDownTestCase(void) {}

void CameraMetadataOutputUnitTest::SetUp(void)
{
    InitCamera();
}

void CameraMetadataOutputUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test register and unregister metadata output change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register and unregister metadata output change event callback,
 * when valid parameters are entered, registration and deregistration are successful
 */
HWTEST_F(CameraMetadataOutputUnitTest, camera_metadata_output_unittest_001, TestSize.Level0)
{
    Camera_MetadataObjectType type = Camera_MetadataObjectType::FACE_DETECTION;
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    MetadataOutput_Callbacks metadataOutputCb = {
        .onMetadataObjectAvailable = &CameraMetadataOutputOnMetadataObjectAvailableCb,
        .onError = &CameraMetadataOutputOnErrorCb
    };
    Camera_ErrorCode ret = OH_MetadataOutput_RegisterCallback(metadataOutput, &metadataOutputCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_MetadataOutput_UnregisterCallback(metadataOutput, &metadataOutputCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_MetadataOutput_Release(metadataOutput);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test abnormal branch stops metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test abnormal branch stops metadata output,
 * when the session starts metadata output without committing, it will fail to stop
 */
HWTEST_F(CameraMetadataOutputUnitTest, camera_metadata_output_unittest_002, TestSize.Level0)
{
    Camera_MetadataObjectType type = Camera_MetadataObjectType::FACE_DETECTION;
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
    EXPECT_EQ(CameraNdkCommon::DisMdmOpenCheck(cameraInput), CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_MetadataOutput* metadataOutput = CreateMetadataOutput(type);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_AddMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    OH_MetadataOutput_Start(metadataOutput);
    ret = OH_MetadataOutput_Stop(metadataOutput);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
    EXPECT_EQ(OH_MetadataOutput_Release(metadataOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

} // CameraStandard
} // OHOS