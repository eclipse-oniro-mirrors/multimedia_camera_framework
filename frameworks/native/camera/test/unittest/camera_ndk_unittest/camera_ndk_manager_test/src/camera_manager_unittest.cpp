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

#include "camera_manager_unittest.h"
#include "camera/camera_manager.h"
#include "camera_log.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "camera_util.h"
#include "camera_error_code.h"
#include "camera_output_capability.h"
#include "camera_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraManagerUnitTest::SetUpTestCase(void) {}

void CameraManagerUnitTest::TearDownTestCase(void) {}

void CameraManagerUnitTest::SetUp(void)
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

void CameraManagerUnitTest::TearDown(void)
{
    ReleaseCamera();
}

/*
 * Feature: Framework
 * Function: Test register and unregister camera status change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal function of the registered and
 * unregistered camera state change event callbacks when valid parameters are entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_001, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb
    };
    ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_UnregisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister camera status change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal branch of the register and unregister camera state change
 * event callback when an invalid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_002, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb
    };
    ret = OH_CameraManager_RegisterCallback(nullptr, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_RegisterCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterCallback(nullptr, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    setCameraManagerResultCallback.onCameraStatus = nullptr;
    ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test register and unregister torch status change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the normal function of registered and unregistered torch
 * status change event callback when an invalid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_003, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register and unregister torch status change event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the abnormal branch of the register and unregister
 * torch status change event callback when a valid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_004, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    ret = OH_CameraManager_RegisterTorchStatusCallback(nullptr, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(nullptr, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test get and delete supported cameras, supported cameras output capability, and camera manager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When enter a valid parameters, test get camera support,
 * get and delete support the camera output ability, and expect to get and deleted successfully
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_005, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_OutputCapability *OutputCapability = nullptr;

    ret = OH_CameraManager_GetSupportedCameras(cameraManager, &cameraDevice, &cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get and delete supported cameras, supported cameras output capability,
 * and camera manage for abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When valid parameters are entered, test get and delete supported cameras,
 * supported camera output capabilities, and camera manager, and expect get and delete to fail
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_006, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_OutputCapability *OutputCapability = nullptr;

    ret = OH_CameraManager_GetSupportedCameras(nullptr, &cameraDevice, &cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameras(cameraManager, nullptr, &cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameras(cameraManager, &cameraDevice, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_CameraManager_GetSupportedCameraOutputCapability(nullptr, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, nullptr, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_CameraManager_DeleteSupportedCameras(nullptr, cameraDevice, cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_DeleteSupportedCameras(cameraManager, nullptr, cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(nullptr, OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_Camera_DeleteCameraManager(nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test get supported output capabilities with scene mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When valid parameters are entered,, Test specified camera
 * can get supported capabilities in three modes (NORMAL_PHOTO, NORMAL_VIDEO, SECURE_PHOTO)
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_007, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_OutputCapability *OutputCapability = nullptr;
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, NORMAL_PHOTO,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(OutputCapability, nullptr);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, NORMAL_VIDEO,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(OutputCapability, nullptr);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, SECURE_PHOTO,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(OutputCapability, nullptr);
}

/*
 * Feature: Framework
 * Function: Test get supported output capabilities with scene mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When invalid parameters are entered, Test specified camera
 * can not get supported capabilities in three modes (NORMAL_PHOTO, NORMAL_VIDEO, SECURE_PHOTO)
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_008, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_OutputCapability *OutputCapability = nullptr;
    Camera_SceneMode mode = NORMAL_PHOTO;
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(nullptr, cameraDevice, mode,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OutputCapability, nullptr);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, nullptr, mode,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OutputCapability, nullptr);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice,
        static_cast<Camera_SceneMode>(-1), &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OutputCapability, nullptr);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, mode, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OutputCapability, nullptr);
}

/*
 * Feature: Framework
 * Function: Test cameramanager create input with position and type
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager create input with position and type,
 * failure is returned when an invalid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_009, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *camInputPosAndType = nullptr;
    Camera_Position cameraPosition = Camera_Position::CAMERA_POSITION_BACK;
    Camera_Type cameraType = Camera_Type::CAMERA_TYPE_DEFAULT;
    ret = OH_CameraManager_CreateCameraInput_WithPositionAndType(nullptr,
        cameraPosition, cameraType, &camInputPosAndType);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(camInputPosAndType, nullptr);
    ret = OH_CameraManager_CreateCameraInput_WithPositionAndType(cameraManager,
        static_cast<Camera_Position>(-1), cameraType, &camInputPosAndType);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(camInputPosAndType, nullptr);

    ret = OH_CameraManager_CreateCameraInput_WithPositionAndType(cameraManager,
        cameraPosition, cameraType, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(camInputPosAndType, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create a preview output instance when adding camera input, a valid camera input
 * instance can be created when valid parameters are entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_010, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);

    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
}

/*
 * Feature: Framework
 * Function: Test create preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When a preview output instance is created after adding camera input,
 * the preview output instance cannot be obtained when an invalid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_011, TestSize.Level0)
{
    uint32_t preview_width = PREVIEW_DEFAULT_WIDTH;
    uint32_t preview_height = PREVIEW_DEFAULT_HEIGHT;
    Camera_Format format = (Camera_Format)CAMERA_FORMAT_RGBA_8888;
    Camera_OutputCapability* OutputCapability = new Camera_OutputCapability;
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager,
                                                                               cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    preview_width = OutputCapability->previewProfiles[0]->size.width;
    preview_height = OutputCapability->previewProfiles[0]->size.height;
    format = OutputCapability->previewProfiles[0]->format;
    delete OutputCapability;
    Camera_Size previewSize = {
        .width = preview_width,
        .height = preview_height
    };
    Camera_Profile previewProfile = {
        .format = format,
        .size = previewSize
    };
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    int64_t surfaceIdInt = previewProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);
    Camera_PreviewOutput* previewOutput = nullptr;
    ret = OH_CameraManager_CreatePreviewOutput(nullptr, &previewProfile, surfaceId, &previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(previewOutput, nullptr);
    ret = OH_CameraManager_CreatePreviewOutput(cameraManager, nullptr, surfaceId, &previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(previewOutput, nullptr);
    ret = OH_CameraManager_CreatePreviewOutput(cameraManager, &previewProfile, nullptr, &previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(previewOutput, nullptr);
    ret = OH_CameraManager_CreatePreviewOutput(cameraManager, &previewProfile, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(previewOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create preview output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a preview output instance used in a pre-configured flow,
 * Create preview output instances for use in the pre-configured flow
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_012, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    int64_t surfaceIdInt = previewProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);
    Camera_PreviewOutput* previewOutput = nullptr;
    ret = OH_CameraManager_CreatePreviewOutputUsedInPreconfig(cameraManager, surfaceId, &previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(previewOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create preview output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a preview output instance used in a pre-configured flow,
 * a valid preview output instance cannot be created when an invalid parameter is entered, and the instance is null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_013, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    int64_t surfaceIdInt = previewProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);
    Camera_PreviewOutput* previewOutput = nullptr;
    ret = OH_CameraManager_CreatePreviewOutputUsedInPreconfig(nullptr, surfaceId, &previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(previewOutput, nullptr);
    ret = OH_CameraManager_CreatePreviewOutputUsedInPreconfig(cameraManager, nullptr, &previewOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(previewOutput, nullptr);
    ret = OH_CameraManager_CreatePreviewOutputUsedInPreconfig(cameraManager, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ASSERT_EQ(previewOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a photo output instance. When a valid parameter is entered,
 * a valid photo output instance can be created and the instance is not null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_014, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(cameraInput, nullptr);

    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test create photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When a photo output instance is created after adding camera input,
 * the photo output instance cannot be obtained when an invalid parameter is entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_015, TestSize.Level0)
{
    uint32_t photo_width = PHOTO_DEFAULT_WIDTH;
    uint32_t photo_height = PHOTO_DEFAULT_HEIGHT;
    Camera_Format format = (Camera_Format)CAMERA_FORMAT_JPEG;
    Camera_OutputCapability* OutputCapability = new Camera_OutputCapability;
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager,
                                                                               cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    photo_width = OutputCapability->photoProfiles[0]->size.width;
    photo_height = OutputCapability->photoProfiles[0]->size.height;
    format = OutputCapability->photoProfiles[0]->format;
    delete OutputCapability;
    Camera_Size photoSize = {
        .width = photo_width,
        .height = photo_height
    };
    Camera_Profile photoProfile = {
        .format = format,
        .size = photoSize
    };

    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char *surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    Camera_PhotoOutput* photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutput(nullptr, &photoProfile, surfaceId, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutput(cameraManager, nullptr, surfaceId, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutput(cameraManager, &photoProfile, nullptr, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutput(cameraManager, &photoProfile, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create photo output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output used in preconfig,
 * Create preview output instances for use in the pre-configured flow
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_016, TestSize.Level0)
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
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputUsedInPreconfig(cameraManager, surfaceId, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test create photo output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a preview output instance used in a pre-configured flow,
 * a valid preview output instance cannot be created when an invalid parameter is entered, and the instance is null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_017, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    imageReceiver = Media::ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT,
                                                              RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
    const char* surfaceId = nullptr;
    surfaceId = receiverKey.c_str();
    ASSERT_NE(surfaceId, nullptr);
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
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test create photo output without surface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a photo output instance that does not require surfaceId,
 * a valid photo output instance can be created when valid parameters are entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_018, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
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
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(photoOutput, nullptr);
    bool isSuccessful = false;
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isSuccessful == true) {
        ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test create photo output without surface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output instance without surfaceId，
 * when invalid parameters are entered, no valid photo output instance can be created and the instance is null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_019, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Size photoSize = {
        .width = 10,
        .height = 10
    };
    Camera_Profile profile = {
        .format = Camera_Format::CAMERA_FORMAT_JPEG,
        .size = photoSize
    };
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(nullptr, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, nullptr, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(photoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a video output instance. When entering valid parameters,
 * a valid video output instance can be created
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_020, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
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

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test create video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a video output instance. When invalid parameters are entered,
 * a valid video output instance cannot be created and the instance is null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_021, TestSize.Level0)
{
    uint32_t video_width = VIDEO_DEFAULT_WIDTH;
    uint32_t video_height = VIDEO_DEFAULT_HEIGHT;
    Camera_Format format = (Camera_Format)CAMERA_FORMAT_RGBA_8888;
    Camera_OutputCapability* OutputCapability = new Camera_OutputCapability;
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager,
                                                                               cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    video_width = OutputCapability->videoProfiles[0]->size.width;
    video_height = OutputCapability->videoProfiles[0]->size.height;
    format = OutputCapability->videoProfiles[0]->format;
    delete OutputCapability;
    Camera_Size videoSize = {
        .width = video_width,
        .height = video_height
    };
    Camera_FrameRateRange videoRange = {
        .min = 30,
        .max = 30
    };
    Camera_VideoProfile videoProfile = {
        .format = format,
        .size = videoSize,
        .range = videoRange
    };
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    int64_t surfaceIdInt = videoProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    Camera_VideoOutput* videoOutput = nullptr;
    ret = OH_CameraManager_CreateVideoOutput(nullptr, &videoProfile, surfaceId, &videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
    ret = OH_CameraManager_CreateVideoOutput(cameraManager, nullptr, surfaceId, &videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
    ret = OH_CameraManager_CreateVideoOutput(cameraManager, &videoProfile, nullptr, &videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
    ret = OH_CameraManager_CreateVideoOutput(cameraManager, &videoProfile, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create video output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output used in preconfig,
 * Create preview output instances for use in the pre-configured flow
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_022, TestSize.Level0)
{
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    int64_t surfaceIdInt = videoProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_VideoOutput *videoOutput = nullptr;
    ret = OH_CameraManager_CreateVideoOutputUsedInPreconfig(cameraManager, surfaceId, &videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(videoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test create video output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a video output instance used in a pre-configured flow,
 * a valid video output instance can be created when valid parameters are entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_023, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    sptr<IConsumerSurface> videoSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = videoSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    int64_t surfaceIdInt = videoProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);
    Camera_VideoOutput *videoOutput = nullptr;
    ret = OH_CameraManager_CreateVideoOutputUsedInPreconfig(nullptr, surfaceId, &videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
    ret = OH_CameraManager_CreateVideoOutputUsedInPreconfig(cameraManager, nullptr, &videoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
    ret = OH_CameraManager_CreateVideoOutputUsedInPreconfig(cameraManager, surfaceId, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(videoOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test create metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a metadata output instance. When entering valid parameters,
 * a valid metadata output instance can be created
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_024, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
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
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_MetadataOutput *metadataOutput = nullptr;
    ret = OH_CameraManager_CreateMetadataOutput(cameraManager, &type, &metadataOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(metadataOutput, nullptr);
    ret = OH_CaptureSession_AddMetadataOutput(captureSession, metadataOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_MetadataOutput_Release(metadataOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test create metadata output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to create a metadata output instance，when invalid parameters are entered,
 * a valid metadata output instance cannot be created and the instance is null
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_025, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_MetadataObjectType type = FACE_DETECTION;
    Camera_MetadataOutput *metadataOutput = nullptr;
    ret = OH_CameraManager_CreateMetadataOutput(nullptr, &type, &metadataOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(metadataOutput, nullptr);
    ret = OH_CameraManager_CreateMetadataOutput(cameraManager, nullptr, &metadataOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(metadataOutput, nullptr);
    ret = OH_CameraManager_CreateMetadataOutput(cameraManager, &type, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(metadataOutput, nullptr);
}

/*
 * Feature: Framework
 * Function: Test Get supported scene modes and delete scene modes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get the scene mode supported by a specific camera and delete it,
 * if the scene mode can be obtained, delete the scene mode
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_026, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_SceneMode* sceneModes = nullptr;
    uint32_t size = 0;
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, &sceneModes, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(sceneModes, nullptr);
    if (sceneModes != nullptr) {
        ret = OH_CameraManager_DeleteSceneModes(cameraManager, sceneModes);
        EXPECT_EQ(ret, CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test Get supported scene modes and delete scene modes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to obtain and delete scene modes,
 * cannot obtain and delete scene modes when invalid parameters are entered
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_027, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_SceneMode* sceneModes = nullptr;
    uint32_t size = 0;
    ret = OH_CameraManager_GetSupportedSceneModes(nullptr, &sceneModes, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(sceneModes, nullptr);
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(sceneModes, nullptr);
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, &sceneModes, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(sceneModes, nullptr);
    ret = OH_CameraManager_DeleteSceneModes(nullptr, sceneModes);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_DeleteSceneModes(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test Torch supported or not and supported or not with torch mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test is Torch supported or not and supported or not with torch mode
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_028, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
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
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photooutput = CreatePhotoOutput();
    ASSERT_NE(photooutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photooutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    bool isTorchSupported = false;
    Camera_TorchMode torchMode = ON;
    ret = OH_CameraManager_IsTorchSupported(cameraManager, &isTorchSupported);
    EXPECT_EQ(ret, CAMERA_OK);
    if (isTorchSupported == true) {
        ret = OH_CameraManager_IsTorchSupportedByTorchMode(cameraManager, torchMode, &isTorchSupported);
        EXPECT_EQ(ret, CAMERA_OK);
        if (isTorchSupported == true) {
            ret = OH_CameraManager_SetTorchMode(cameraManager, torchMode);
            if (cameraDevice[CAMERA_DEVICE_INDEX].cameraPosition == Camera_Position::CAMERA_POSITION_FRONT) {
                EXPECT_EQ(ret, CAMERA_OK);
            } else if (cameraDevice[CAMERA_DEVICE_INDEX].cameraPosition == Camera_Position::CAMERA_POSITION_BACK) {
                EXPECT_EQ(ret, Camera_ErrorCode::CAMERA_OPERATION_NOT_ALLOWED);
            }
        } else {
            MEDIA_INFO_LOG("The device does not support specific torch modes");
        }
    } else {
        MEDIA_INFO_LOG("The device does not support torch");
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test Torch supported or not and supported or not with torch mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test whether the device is a torch and the abnormal branch of the torch mode.
 * When an invalid parameter is entered, the result cannot be returned through the parameter
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_029, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    bool isTorchSupported = false;
    ret = OH_CameraManager_IsTorchSupported(nullptr, &isTorchSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_IsTorchSupported(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_CameraManager_IsTorchSupportedByTorchMode(nullptr, Camera_TorchMode::ON, &isTorchSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_IsTorchSupportedByTorchMode(cameraManager,
        static_cast<Camera_TorchMode>(-1), &isTorchSupported);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_IsTorchSupportedByTorchMode(cameraManager, Camera_TorchMode::ON, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_CameraManager_SetTorchMode(nullptr, Camera_TorchMode::ON);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_SetTorchMode(cameraManager, static_cast<Camera_TorchMode>(-1));
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test whether camera is muted
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When a valid parameter is entered, test whether the camera is silent,
 * and return whether it is silent by the form of the parameter, when the input invalid
 * parameters, can't get if muted results through parameters
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_030, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    bool isCameraMuted = false;
    ret = OH_CameraManager_IsCameraMuted(cameraManager, &isCameraMuted);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_IsCameraMuted(nullptr, &isCameraMuted);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_FALSE(isCameraMuted);
}

/*
 * Feature: Framework
 * Function: Test different branches of error code
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test different branches of error code
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_031, TestSize.Level0)
{
    int32_t err = CameraErrorCode::NO_SYSTEM_APP_PERMISSION;
    Camera_ErrorCode ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_OPERATION_NOT_ALLOWED);
    err = CameraErrorCode::INVALID_ARGUMENT;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    err = CameraErrorCode::DEVICE_SETTING_LOCKED;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_DEVICE_SETTING_LOCKED);
    err = CameraErrorCode::CONFLICT_CAMERA;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_CONFLICT_CAMERA);
    err = CameraErrorCode::SESSION_NOT_RUNNING;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_SESSION_NOT_RUNNING);
    err = CameraErrorCode::DEVICE_DISABLED;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_DEVICE_DISABLED);
    err = CameraErrorCode::DEVICE_PREEMPTED;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_DEVICE_PREEMPTED);
    err = CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_UNRESOLVED_CONFLICTS_WITH_CURRENT_CONFIGURATIONS);
    err = CameraErrorCode::SESSION_CONFIG_LOCKED;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_SESSION_CONFIG_LOCKED);
    err = -1;
    ret = FrameworkToNdkCameraError(err);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported profile with abnormal branch
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported profile with abnormal branch
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_032, TestSize.Level0)
{
    Camera_OutputCapability* outputCapability = new Camera_OutputCapability;
    ASSERT_NE(outputCapability, nullptr);
    std::vector<Profile> photoProfiles;
    std::vector<Profile> previewProfiles;
    std::vector<MetadataObjectType> metadataTypeList;
    Camera_ErrorCode ret = cameraManager->GetSupportedPhotoProfiles(outputCapability, photoProfiles);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = cameraManager->GetSupportedPreviewProfiles(outputCapability, previewProfiles);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = cameraManager->GetSupportedMetadataTypeList(outputCapability, metadataTypeList);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    delete outputCapability;
}

/*
 * Feature: Framework
 * Function: Test to get remote device name and type
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test to get remote device name and type
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_unittest_033, TestSize.Level0)
{
    Camera_Device* cameras = nullptr;
    uint32_t size;
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameras(cameraManager, &cameras, &size);
    if (size == 0) {
        GTEST_SKIP();
    }
    EXPECT_EQ(ret, CAMERA_OK);
    char* name = nullptr;
    ret = OH_CameraDevice_GetHostDeviceName(cameraDevice, &name);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_HostDeviceType type = Camera_HostDeviceType::HOST_DEVICE_TYPE_UNKNOWN_TYPE;
    ret = OH_CameraDevice_GetHostDeviceType(cameraDevice, &type);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test cameraManager by registering multiple state callbacks,
 * then unregister the callback, and check for any leaked callback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager by registering multiple state callbacks,
 * then unregister the callback, and check for any leaked callback.
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_register_status_callback_unittest_001, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    CameraManager_Callbacks setCameraManagerResultCallback = { .onCameraStatus = &CameraManagerOnCameraStatusCb };
    auto statusListenerManager = cameraManager->cameraManager_->GetCameraStatusListenerManager();
    statusListenerManager->ClearListeners();
    ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 1);
    ret = OH_CameraManager_UnregisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 0);
    statusListenerManager->ClearListeners();
}

/*
 * Feature: Framework
 * Function: Test cameraManager by registering multiple torch state callbacks,
 * then unregister the callback, and check for any leaked callback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager by registering multiple torch state callbacks,
 * then unregister the callback, and check for any leaked callback.
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_register_torch_callback_unittest_001, TestSize.Level0)
{
    auto statusListenerManager = cameraManager->cameraManager_->GetTorchServiceListenerManager();
    statusListenerManager->ClearListeners();
    Camera_ErrorCode ret =
        OH_CameraManager_RegisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 1);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 0);
    statusListenerManager->ClearListeners();
}

/*
 * Feature: Framework
 * Function: Test cameraManager by registering multiple fold state callbacks,
 * then unregister the callback, and check for any leaked callback.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameraManager by registering multiple fold state callbacks,
 * then unregister the callback, and check for any leaked callback.
 */
HWTEST_F(CameraManagerUnitTest, camera_manager_register_callback_unittest_001, TestSize.Level0)
{
    auto statusListenerManager = cameraManager->cameraManager_->GetFoldStatusListenerManager();
    statusListenerManager->ClearListeners();
    Camera_ErrorCode ret =
        OH_CameraManager_RegisterFoldStatusInfoCallback(cameraManager, CameraManagerOnCameraFoldStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterFoldStatusInfoCallback(cameraManager, CameraManagerOnCameraFoldStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 1);
    ret = OH_CameraManager_UnregisterFoldStatusInfoCallback(cameraManager, CameraManagerOnCameraFoldStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(statusListenerManager->GetListenerCount(), 0);
    statusListenerManager->ClearListeners();
}
} // CameraStandard
} // OHOS