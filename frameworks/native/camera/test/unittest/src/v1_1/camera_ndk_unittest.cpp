/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera_ndk_unittest.h"
#include "camera_log.h"
#include "test_common.h"
#include "ipc_skeleton.h"
#include "access_token.h"
#include "hap_token_info.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "surface_utils.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
Camera_PhotoOutput* CameraNdkUnitTest::CreatePhotoOutput(int32_t width, int32_t height)
{
    uint32_t photo_width = width;
    uint32_t photo_height = height;
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
    ret = OH_CameraManager_CreatePhotoOutput(cameraManager, &photoProfile, surfaceId, &photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(photoOutput, nullptr);
    return photoOutput;
}

Camera_PreviewOutput* CameraNdkUnitTest::CreatePreviewOutput(int32_t width, int32_t height)
{
    uint32_t preview_width = width;
    uint32_t preview_height = height;
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
    EXPECT_NE(surfaceId, nullptr);
    Camera_PreviewOutput* previewOutput = nullptr;
    ret = OH_CameraManager_CreatePreviewOutput(cameraManager, &previewProfile, surfaceId, &previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(previewOutput, nullptr);
    return previewOutput;
}

Camera_VideoOutput* CameraNdkUnitTest::CreateVideoOutput(int32_t width, int32_t height)
{
    uint32_t video_width = width;
    uint32_t video_height = height;
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
    ret = OH_CameraManager_CreateVideoOutput(cameraManager, &videoProfile, surfaceId, &videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(videoOutput, nullptr);
    return videoOutput;
}

void CameraNdkUnitTest::SessionCommit(Camera_CaptureSession *captureSession)
{
    Camera_ErrorCode ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, 0);
}

void CameraNdkUnitTest::SessionControlParams(Camera_CaptureSession *captureSession)
{
    float minZoom = 0.0f, maxZoom = 0.0f;
    Camera_ErrorCode ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_SetZoomRatio(captureSession, minZoom);
    EXPECT_EQ(ret, CAMERA_OK);
    float minExposureBias = 0.0f, maxExposureBias = 0.0f, step = 0.0f;
    ret = OH_CaptureSession_GetExposureBiasRange(captureSession, &minExposureBias, &maxExposureBias, &step);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(minExposureBias, 0.0f);
    ASSERT_NE(maxExposureBias, 0.0f);
    ASSERT_NE(step, 0.0f);

    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    bool* isSupportedExposureMode = nullptr;
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, exposureMode, isSupportedExposureMode);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FlashMode flash = Camera_FlashMode::FLASH_MODE_ALWAYS_OPEN;
    ret = OH_CaptureSession_SetFlashMode(captureSession, flash);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FocusMode focus = Camera_FocusMode::FOCUS_MODE_AUTO;
    ret = OH_CaptureSession_SetFocusMode(captureSession, focus);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_ExposureMode exposure = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    ret = OH_CaptureSession_SetExposureMode(captureSession, exposure);
    EXPECT_EQ(ret, CAMERA_OK);

    float zoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatio(captureSession, &zoom);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(zoom, 0.0f);

    float exposureBias = 0.0f;
    ret = OH_CaptureSession_GetExposureBias(captureSession, &exposureBias);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(exposureBias, 0.0f);

    ret = OH_CaptureSession_GetFlashMode(captureSession, &flash);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(flash, (Camera_FlashMode)FLASH_MODE_ALWAYS_OPEN);

    ret = OH_CaptureSession_GetFocusMode(captureSession, &focus);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(focus, (Camera_FocusMode)FOCUS_MODE_AUTO);

    ret = OH_CaptureSession_GetExposureMode(captureSession, &exposure);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(exposure, (Camera_ExposureMode)EXPOSURE_MODE_AUTO);
}

void CameraNdkUnitTest::SetUpTestCase(void) {}

void CameraNdkUnitTest::TearDownTestCase(void) {}

void CameraNdkUnitTest::SetUp(void)
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

    Camera_ErrorCode ret = OH_Camera_GetCameraManager(&cameraManager);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraManager_GetSupportedCameras(cameraManager, &cameraDevice, &cameraDeviceSize);
    EXPECT_EQ(ret, 0);
}

void CameraNdkUnitTest::TearDown(void) {}

void CameraNdkUnitTest::ReleaseImageReceiver(void)
{
    if (imageReceiver != nullptr) {
        std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
        Media::ImageReceiverManager::ReleaseReceiverById(receiverKey);
    }
}

static void OnCameraInputError(const Camera_Input* cameraInput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraCaptureSessiononFocusStateChangeCb(Camera_CaptureSession* session, Camera_FocusState focusState)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraCaptureSessionOnErrorCb(Camera_CaptureSession* session, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraManagerOnCameraStatusCb(Camera_Manager* cameraManager, Camera_StatusInfo* status)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPreviewOutptOnFrameStartCb(Camera_PreviewOutput* previewOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPreviewOutptOnFrameEndCb(Camera_PreviewOutput* previewOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPreviewOutptOnErrorCb(Camera_PreviewOutput* previewOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnFrameStartCb(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnFrameShutterCb(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnFrameEndCb(Camera_PhotoOutput* photoOutput, int32_t timestamp)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnErrorCb(Camera_PhotoOutput* photoOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraVideoOutptOnFrameStartCb(Camera_VideoOutput* videoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraVideoOutptOnFrameEndCb(Camera_VideoOutput* videoOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraVideoOutptOnErrorCb(Camera_VideoOutput* videoOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

/*
 * Feature: Framework
 * Function: Test Capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Capture
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_001, TestSize.Level0)
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
    ret = OH_PhotoOutput_Capture(photoOutput);
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
 * Function: Test capture session with commit config multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with commit config multiple times
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_002, TestSize.Level0)
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
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_NE(ret, 0);
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
 * Function: Test create preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_004, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = CAMERA_OK;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;
    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);

    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);

    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Stop(previewOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
}

/*
 * Feature: Framework
 * Function: Test capture session start and stop preview multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop preview multiple times
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_006, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_NE(&cameraInput, nullptr);
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
 * Function: Test capture session start and stop video multiple times
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop video multiple times
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_007, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = CAMERA_OK;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
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
    ret = OH_PreviewOutput_Release(previewOutput);
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
 * Function: Test video add preview and photo output, remove photo output, add video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test video add preview and photo output, remove photo output, add video output
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_008, TestSize.Level0)
{
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
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test add preview,video and photo output, video start do capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add preview video and photo output, video start do capture
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_009, TestSize.Level0)
{
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

    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);

    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_PhotoOutput_Capture(photoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test add preview and video output, commitconfig remove video Output, add photo output, take photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add preview and video output, commitconfig remove video Output, add photo output, take photo
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_010, TestSize.Level0)
{
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

    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_RemoveVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_PhotoOutput_Capture(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test add preview and video output, commitconfig remove video Output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test do OH_CaptureSession_BeginConfig/OH_CaptureSession_CommitConfig again
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_013, TestSize.Level0)
{
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
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_RemoveVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
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
 * Function: Test add preview and photo output, commitconfig remove photo Output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test do OH_CaptureSession_BeginConfig/OH_CaptureSession_CommitConfig again
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_014, TestSize.Level0)
{
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

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_RemovePreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
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
 * Function: Test add two preview output and use
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add two preview output and use
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_017, TestSize.Level0)
{
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

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    Camera_PreviewOutput* previewOutput2 = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput2);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_EQ(ret, 0);

    ret = OH_PreviewOutput_Start(previewOutput2);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput2);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Release(previewOutput2);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding input
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_027, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 7400201);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_NE(ret, 0);
    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 7400201);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test capture session commit config without adding output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session commit config without adding output
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_028, TestSize.Level0)
{
    Camera_Input *cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
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
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_NE(ret, 0);
    ret = OH_CaptureSession_RemoveInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session without begin config
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session without begin config
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_029, TestSize.Level0)
{
    Camera_Input *cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);

    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_NE(ret, 0);

    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_NE(ret, 0);

    ret = OH_PhotoOutput_Capture(photoOutput);
    EXPECT_NE(ret, 0);

    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_Stop(captureSession);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_RemovePhotoOutput(captureSession, photoOutput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_RemoveInput(captureSession, cameraInput);
    EXPECT_NE(ret, 0);

    ret = OH_CaptureSession_RemovePreviewOutput(captureSession, previewOutput);
    EXPECT_NE(ret, 0);

    ret = OH_PreviewOutput_Release(previewOutput);
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
 * Function: Test capture session start and stop without adding preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session start and stop without adding preview output
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_030, TestSize.Level0)
{
    Camera_Input *cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
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
    ret = OH_CaptureSession_Stop(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test session with preview + photo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + photo
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_031, TestSize.Level0)
{
    Camera_Input *cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Capture(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Release(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test session with preview + video
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test session with preview + video
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_033, TestSize.Level0)
{
    Camera_Input *cameraInput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_EQ(ret, 0);
    sleep(WAIT_TIME_AFTER_START);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    sleep(WAIT_TIME_AFTER_START);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Stop(previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
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
 * Function: Test capture session remove input with null
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input with null
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_036, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
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
    OH_CaptureSession_CommitConfig(captureSession);
    OH_CaptureSession_Start(captureSession);
    Camera_Input *cameraInputNull=nullptr;
    ret = OH_CaptureSession_RemoveInput(captureSession, cameraInputNull);
    EXPECT_NE(ret, 0);
    ret = OH_CaptureSession_Stop(captureSession);
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
 * CaseDescription: Test capture session remove input
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_037, TestSize.Level0)
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
 * Function: Test photo capture with photo settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with photo settings
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_038, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
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
 * Function: Test SetMeteringPoint & GetMeteringPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetMeteringPoint & GetMeteringPoint
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_041, TestSize.Level0)
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
 * Function: Test SetFocusPoint & GetFousPoint
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetFocusPoint & GetFousPoint
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_042, TestSize.Level0)
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
 * Function: Test photo capture with location of capture settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with capture settings
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_053, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);

    Camera_PhotoCaptureSetting capSettings;
    capSettings.rotation = IAMGE_ROTATION_90;
    Camera_Location location = {1.0, 1.0, 1.0};
    capSettings.location = &location;
    ret = OH_PhotoOutput_Capture_WithCaptureSetting(PhotoOutput, capSettings);
    EXPECT_EQ(ret, 0);
    sleep(WAIT_TIME_AFTER_CAPTURE);
    location = {0, 0, 0};
    capSettings.location = &location;
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
 * Function: Test photo capture with capture settings
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test photo capture with preview output & capture settings
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_054, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
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
 * Function: Test capture session with Video Stabilization Mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session with Video Stabilization Mode
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_057, TestSize.Level0)
{
    Camera_CaptureSession* captureSession;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);

    Camera_Input *cameraInput;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_PreviewOutput_Start(previewOutput);
    EXPECT_EQ(ret, 0);
    bool isSupported=false;
    ret = OH_CaptureSession_IsVideoStabilizationModeSupported(captureSession, STABILIZATION_MODE_MIDDLE, &isSupported);

    if (isSupported) {
        ret = OH_CaptureSession_SetVideoStabilizationMode(captureSession, STABILIZATION_MODE_MIDDLE);
        EXPECT_EQ(ret, 0);
    }
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    sleep(WAIT_TIME_AFTER_START);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
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
 * Function: Test add preview,video and photo output,set location,video start do capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add preview video and photo output, video start do capture
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_058, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);

    Camera_PhotoCaptureSetting capSettings;
    capSettings.quality = QUALITY_LEVEL_MEDIUM;

    Camera_Location location = {1.0, 1.0, 1.0};
    capSettings.location = &location;
    ret = OH_PhotoOutput_Capture_WithCaptureSetting(photoOutput, capSettings);
    EXPECT_EQ(ret, 0);

    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test add preview,video and photo output, set mirror,video start do capture
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test add preview video and photo output, video start do capture
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_059, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&cameraInput, nullptr);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    Camera_PhotoOutput *photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Start(videoOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoCaptureSetting capSettings;
    capSettings.mirror = true;
    ret = OH_PhotoOutput_Capture_WithCaptureSetting(photoOutput, capSettings);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Stop(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_VideoOutput_Release(videoOutput);
    EXPECT_EQ(ret, 0);
    ret = OH_PhotoOutput_Release(photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test open flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test open flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_061, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);

    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_OPEN);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);

    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
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
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoResultCallback = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddVideoOutput(captureSession, videoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoResultCallback), 0);

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_Release(PhotoOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test close flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test close flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_065, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_OPEN);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    PreviewOutput_Callbacks setPreviewResultCallback = {
        .onFrameStart = &CameraPreviewOutptOnFrameStartCb,
        .onFrameEnd = &CameraPreviewOutptOnFrameEndCb,
        .onError = &CameraPreviewOutptOnErrorCb
    };

    ret = OH_PreviewOutput_RegisterCallback(previewOutput, &setPreviewResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_UnregisterCallback(previewOutput, &setPreviewResultCallback), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
}

/*
 * Feature: Framework
 * Function: Test close flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test close flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_066, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_OPEN);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    PhotoOutput_Callbacks setPhotoOutputResultCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnFrameEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    ret = OH_PhotoOutput_RegisterCallback(PhotoOutput, &setPhotoOutputResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_Capture(PhotoOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_UnregisterCallback(PhotoOutput, &setPhotoOutputResultCallback), 0);
    EXPECT_EQ(OH_PhotoOutput_Release(PhotoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test close flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test close flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_062, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_CLOSE);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
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
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoResultCallback = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddVideoOutput(captureSession, videoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_VideoOutput_UnregisterCallback(videoOutput, &setVideoResultCallback), 0);

    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_Release(PhotoOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test close flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test close flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_063, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_CLOSE);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);

    PreviewOutput_Callbacks setPreviewResultCallback = {
        .onFrameStart = &CameraPreviewOutptOnFrameStartCb,
        .onFrameEnd = &CameraPreviewOutptOnFrameEndCb,
        .onError = &CameraPreviewOutptOnErrorCb
    };

    ret = OH_PreviewOutput_RegisterCallback(previewOutput, &setPreviewResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_UnregisterCallback(previewOutput, &setPreviewResultCallback), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
}

/*
 * Feature: Framework
 * Function: Test close flash preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test close flash preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_064, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_FlashMode flash =static_cast<Camera_FlashMode>(FLASH_MODE_CLOSE);
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession, flash, &isSupported);
    EXPECT_EQ(ret, 0);
    if (isSupported) {
        EXPECT_EQ(OH_CaptureSession_SetFlashMode(captureSession, flash), 0);
    }
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, 0);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, 0);
    Camera_PhotoOutput* PhotoOutput = CreatePhotoOutput();
    EXPECT_NE(PhotoOutput, nullptr);
    PhotoOutput_Callbacks setPhotoOutputResultCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnFrameEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    ret = OH_PhotoOutput_RegisterCallback(PhotoOutput, &setPhotoOutputResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, PhotoOutput);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_Capture(PhotoOutput), 0);
    EXPECT_EQ(OH_PhotoOutput_UnregisterCallback(PhotoOutput, &setPhotoOutputResultCallback), 0);
    EXPECT_EQ(OH_PhotoOutput_Release(PhotoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test cameramanager create input with position and type
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager create input with position and type
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_001, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_Input *camInputPosAndType = nullptr;
    Camera_Position cameraPosition = Camera_Position::CAMERA_POSITION_BACK;
    Camera_Type cameraType = Camera_Type::CAMERA_TYPE_DEFAULT;
    ret = OH_CameraManager_CreateCameraInput_WithPositionAndType(cameraManager,
                                                                 cameraPosition, cameraType, &camInputPosAndType);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(&camInputPosAndType, nullptr);

    cameraPosition  = Camera_Position::CAMERA_POSITION_UNSPECIFIED;
    ret = OH_CameraManager_CreateCameraInput_WithPositionAndType(cameraManager,
                                                                 cameraPosition, cameraType, &camInputPosAndType);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test cameramanager delete supported cameras, output capability and manager
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager delete supported cameras, output capability and manager
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_002, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;

    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CameraManager_DeleteSupportedCameras(cameraManager, cameraDevice, cameraDeviceSize);
    EXPECT_EQ(ret, 0);

    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, OutputCapability);
    EXPECT_EQ(ret, 0);

    ret = OH_Camera_DeleteCameraManager(cameraManager);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test cameramanager delete supported without profiles
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager delete supported without profiles
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_004, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;

    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);

    OutputCapability->previewProfiles = nullptr;
    OutputCapability->photoProfiles = nullptr;
    OutputCapability->videoProfiles = nullptr;
    OutputCapability->supportedMetadataObjectTypes = nullptr;
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, OutputCapability);
    EXPECT_EQ(ret, 0);

    ret = OH_Camera_DeleteCameraManager(cameraManager);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test cameramanager delete supported without cameraDevice and cameraOutputCapability
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cameramanager delete supported without cameraDevice and cameraOutputCapability
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_005, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;

    ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager, cameraDevice, &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);

    cameraDevice = nullptr;
    ret = OH_CameraManager_DeleteSupportedCameras(cameraManager, cameraDevice, cameraDeviceSize);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    OutputCapability = nullptr;
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);

    ret = OH_Camera_DeleteCameraManager(cameraManager);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session about zoom and mode with not commit
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_008, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);

    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, 0);

    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(captureSession, zoom);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_AUTO;
    bool isSupportedFocusMode = true;
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, focusMode, &isSupportedFocusMode);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_FocusMode focus = Camera_FocusMode::FOCUS_MODE_AUTO;
    ret = OH_CaptureSession_SetFocusMode(captureSession, focus);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_Point FocusPointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetFocusPoint(captureSession, FocusPointSet);

    Camera_FlashMode flash = Camera_FlashMode::FLASH_MODE_ALWAYS_OPEN;
    ret = OH_CaptureSession_SetFlashMode(captureSession, flash);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    bool isSupportedExposureMode = true;
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, exposureMode, &isSupportedExposureMode);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_ExposureMode exposure = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    ret = OH_CaptureSession_SetExposureMode(captureSession, exposure);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_Point exposurePointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetMeteringPoint(captureSession, exposurePointSet);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    float minExposureBias = 0.0f;
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session about zoom and mode with commit
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_009, TestSize.Level0)
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

    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, 0);

    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(captureSession, zoom);
    EXPECT_EQ(ret, 0);

    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_MANUAL;
    bool isSupportedFocusMode = true;
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, focusMode, &isSupportedFocusMode);
    EXPECT_EQ(ret, 0);

    Camera_FocusMode focus = Camera_FocusMode::FOCUS_MODE_AUTO;
    ret = OH_CaptureSession_SetFocusMode(captureSession, focus);
    EXPECT_EQ(ret, 0);

    Camera_FlashMode flash = Camera_FlashMode::FLASH_MODE_ALWAYS_OPEN;
    ret = OH_CaptureSession_SetFlashMode(captureSession, flash);
    EXPECT_EQ(ret, 0);

    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    bool isSupportedExposureMode = true;
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, exposureMode, &isSupportedExposureMode);
    EXPECT_EQ(ret, 0);

    Camera_ExposureMode exposure = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    ret = OH_CaptureSession_SetExposureMode(captureSession, exposure);
    EXPECT_EQ(ret, 0);

    ret = OH_CaptureSession_Release(captureSession);
    EXPECT_EQ(ret, 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test capture session about zoom and mode with not commit
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session about zoom and mode with not commit
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_010, TestSize.Level0)
{
    Camera_ErrorCode ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(captureSession, nullptr);

    float minZoom = 0.0f, maxZoom = 0.0f;
    ret = OH_CaptureSession_GetZoomRatioRange(captureSession, &minZoom, &maxZoom);
    EXPECT_EQ(ret, 0);

    float zoom = 0.0f;
    ret = OH_CaptureSession_SetZoomRatio(captureSession, zoom);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_FocusMode focusMode = Camera_FocusMode::FOCUS_MODE_AUTO;
    bool isSupportedFocusMode = true;
    ret = OH_CaptureSession_IsFocusModeSupported(captureSession, focusMode, &isSupportedFocusMode);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_FocusMode focus = Camera_FocusMode::FOCUS_MODE_AUTO;
    ret = OH_CaptureSession_SetFocusMode(captureSession, focus);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_Point FocusPointSet = {1.0, 2.0};
    ret = OH_CaptureSession_SetFocusPoint(captureSession, FocusPointSet);

    Camera_FlashMode flash = Camera_FlashMode::FLASH_MODE_ALWAYS_OPEN;
    ret = OH_CaptureSession_SetFlashMode(captureSession, flash);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_ExposureMode exposureMode = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    bool isSupportedExposureMode = true;
    ret = OH_CaptureSession_IsExposureModeSupported(captureSession, exposureMode, &isSupportedExposureMode);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);

    Camera_ExposureMode exposure = Camera_ExposureMode::EXPOSURE_MODE_AUTO;
    ret = OH_CaptureSession_SetExposureMode(captureSession, exposure);
    EXPECT_EQ(ret, CAMERA_SERVICE_FATAL_ERROR);
}

/*
 * Feature: Framework
 * Function: Test capture session remove input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test capture session remove input
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_011, TestSize.Level0)
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
    ret = OH_CameraInput_Release(cameraInput);
    EXPECT_EQ(ret, 0);
    cameraInput = nullptr;
}

/*
 * Feature: Framework
 * Function: Test preview capture photo callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preview capture photo callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_012, TestSize.Level0)
{
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb,
    };
    Camera_ErrorCode ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    PreviewOutput_Callbacks setPreviewResultCallback = {
        .onFrameStart = &CameraPreviewOutptOnFrameStartCb,
        .onFrameEnd = &CameraPreviewOutptOnFrameEndCb,
        .onError = &CameraPreviewOutptOnErrorCb
    };
    ret = OH_PreviewOutput_RegisterCallback(previewOutput, &setPreviewResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    CameraInput_Callbacks cameraInputCallbacks = {
        .onError = OnCameraInputError
    };
    ret = OH_CameraInput_RegisterCallback(cameraInput, &cameraInputCallbacks);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);
    EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), 0);

    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    EXPECT_NE(photoOutput, nullptr);
    PhotoOutput_Callbacks setPhotoOutputResultCallback = {
        .onFrameStart = &CameraPhotoOutptOnFrameStartCb,
        .onFrameShutter = &CameraPhotoOutptOnFrameShutterCb,
        .onFrameEnd = &CameraPhotoOutptOnFrameEndCb,
        .onError = &CameraPhotoOutptOnErrorCb
    };
    ret = OH_PhotoOutput_RegisterCallback(photoOutput, &setPhotoOutputResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), 0);
    EXPECT_EQ(OH_PhotoOutput_Capture(photoOutput), 0);
    sleep(2);

    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Stop(previewOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    ReleaseImageReceiver();
}

/*
 * Feature: Framework
 * Function: Test preview capture video callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preview capture video callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_013, TestSize.Level0)
{
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb,
    };
    Camera_ErrorCode ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = CAMERA_OK;
    Camera_CaptureSession* captureSession = nullptr;
    EXPECT_EQ(OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession), 0);
    EXPECT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    EXPECT_NE(previewOutput, nullptr);
    PreviewOutput_Callbacks setPreviewResultCallback = {
        .onFrameStart = &CameraPreviewOutptOnFrameStartCb,
        .onFrameEnd = &CameraPreviewOutptOnFrameEndCb,
        .onError = &CameraPreviewOutptOnErrorCb
    };
    ret = OH_PreviewOutput_RegisterCallback(previewOutput, &setPreviewResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    CameraInput_Callbacks cameraInputCallbacks = {
        .onError = OnCameraInputError
    };
    ret = OH_CameraInput_RegisterCallback(cameraInput, &cameraInputCallbacks);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);
    EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), 0);

    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), 0);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    EXPECT_NE(videoOutput, nullptr);
    VideoOutput_Callbacks setVideoResultCallback = {
        .onFrameStart = &CameraVideoOutptOnFrameStartCb,
        .onFrameEnd = &CameraVideoOutptOnFrameEndCb,
        .onError = &CameraVideoOutptOnErrorCb
    };
    ret = OH_VideoOutput_RegisterCallback(videoOutput, &setVideoResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_AddVideoOutput(captureSession, videoOutput), 0);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), 0);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), 0);
    EXPECT_EQ(OH_VideoOutput_Start(videoOutput), 0);
    sleep(2);

    EXPECT_EQ(OH_VideoOutput_Stop(videoOutput), 0);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), 0);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), 0);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), 0);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), 0);
    ReleaseImageReceiver();
}
} // CameraStandard
} // OHOS