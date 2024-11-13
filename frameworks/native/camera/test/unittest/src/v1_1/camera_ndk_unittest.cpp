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
#include "native_buffer.h"
#include "native_image.h"
#include "image_kits.h"
#include "photo_native_impl.h"
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
static constexpr int32_t CAMERA_DEVICE_INDEX = 0;
static constexpr int32_t PREVIEW_WIDTH_480 = 480;
static constexpr int32_t PREVIEW_WIDTH_640 = 640;
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
    if (preview_width == PREVIEW_WIDTH_480) {
        preview_width = PREVIEW_WIDTH_640;
    }
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

static void CameraCaptureSessionOnSmoothZoomInfoCb(Camera_CaptureSession* session,
    Camera_SmoothZoomInfo* smoothZoomInfo)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraManagerOnCameraStatusCb(Camera_Manager* cameraManager, Camera_StatusInfo* status)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraManagerOnCameraTorchStatusCb(Camera_Manager* cameraManager, Camera_TorchStatusInfo* status)
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

static void CameraPhotoOutptOnCaptureEndCb(Camera_PhotoOutput* photoOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnCaptureStartWithInfoCb(Camera_PhotoOutput* photoOutput, Camera_CaptureStartInfo* Info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnFrameShutterEndCb(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* Info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnCaptureReadyCb(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptEstimatedOnCaptureDurationCb(Camera_PhotoOutput* photoOutput, int64_t duration)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnPhotoAvailableCb(Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

static void CameraPhotoOutptOnPhotoAssetAvailableCb(Camera_PhotoOutput* photoOutput, OH_MediaAsset* photoAsset)
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value less then the range
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_043, TestSize.Level0)
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
    ret = OH_CaptureSession_SetExposureBias(captureSession, minExposureBias-1.0);
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
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value between the range
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_044, TestSize.Level0)
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
 * Function: Test GetExposureValue and SetExposureBias
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetExposureValue and SetExposureBias with value more then the range
 */
HWTEST_F(CameraNdkUnitTest, camera_frameworkndk_unittest_045, TestSize.Level0)
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);

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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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

    cameraPosition  = Camera_Position::CAMERA_POSITION_FRONT;
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
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_VIDEO);
    EXPECT_EQ(ret, CAMERA_OK);
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

/*
 * Feature: Framework
 * Function: Test Get supported scene modes and delete scene modes
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Get supported scene modes and delete scene modes
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_014, TestSize.Level0)
{
    Camera_SceneMode* sceneModes = nullptr;
    uint32_t size = 0;
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, &sceneModes, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_GetSupportedSceneModes(nullptr, &sceneModes, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedSceneModes(cameraDevice, &sceneModes, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    if (sceneModes != nullptr) {
        ret = OH_CameraManager_DeleteSceneModes(cameraManager, sceneModes);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CameraManager_DeleteSceneModes(nullptr, sceneModes);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_DeleteSceneModes(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test get supported output capabilities with scene mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported output capabilities with scene mode
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_015, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_OutputCapability *OutputCapability = nullptr;
    Camera_SceneMode mode = NORMAL_PHOTO;
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, mode,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(nullptr, cameraDevice, mode,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, nullptr, mode,
        &OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_GetSupportedCameraOutputCapabilityWithSceneMode(cameraManager, cameraDevice, mode, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    if (OutputCapability != nullptr) {
        ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, OutputCapability);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(nullptr, OutputCapability);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test if a capture session can add a camera input
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if a capture session can add a camera input
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_016, TestSize.Level0)
{
    bool isSuccess = false;
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
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(isSuccess, true);
    ret = OH_CaptureSession_CanAddInput(nullptr, cameraInput, &isSuccess);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddInput(captureSession, nullptr, &isSuccess);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddInput(captureSession, cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test if a capture session can add a preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if a capture session can add a preview output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_017, TestSize.Level0)
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
    ret = OH_CaptureSession_CanAddPreviewOutput(nullptr, previewOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddPreviewOutput(captureSession, previewOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test if a capture session can add a photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if a capture session can add a photo output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_018, TestSize.Level0)
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
    ret = OH_CaptureSession_CanAddPhotoOutput(nullptr, photoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddPhotoOutput(captureSession, photoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test if a capture session can add a video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test if a capture session can add a video output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_019, TestSize.Level0)
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
    ret = OH_CaptureSession_CanAddVideoOutput(nullptr, videoOutput, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, nullptr, &isSuccessful);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanAddVideoOutput(captureSession, videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
* Function: Test set session mode in photo session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test set session mode in photo session
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_020, TestSize.Level0)
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
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
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
* Function: Test set session mode in video session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test set session mode in video session
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_021, TestSize.Level0)
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
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
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
* Function: Test set session mode in secure session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test set session mode in secure session
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_022, TestSize.Level0)
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
        } else {
            ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_AddSecureOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_CommitConfig(captureSession);
            ret = OH_CaptureSession_Start(captureSession);
            ret = OH_CaptureSession_Stop(captureSession);
        }
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test add a secure output to the capture session
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test add a secure output to the capture session
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_023, TestSize.Level0)
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
        } else {
            ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_AddSecureOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_CommitConfig(captureSession);
            ret = OH_CaptureSession_Start(captureSession);
            ret = OH_CaptureSession_Stop(captureSession);
        }
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register capture session callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register capture session callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_024, TestSize.Level0)
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
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_RegisterCallback(nullptr, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RegisterCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_BeginConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), CAMERA_OK);

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister capture session callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister capture session callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_025, TestSize.Level0)
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

    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput), CAMERA_OK);

    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    EXPECT_EQ(OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput), CAMERA_OK);

    EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Start(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Stop(captureSession), CAMERA_OK);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterCallback(nullptr, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test open secure camera
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test open secure camera
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_026, TestSize.Level0)
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
        } else {
            ret = OH_CameraInput_OpenSecureCamera(cameraInput, &secureSeqId);
            ret = OH_CameraInput_OpenSecureCamera(nullptr, &secureSeqId);
            EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
            ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_AddSecureOutput(captureSession, previewOutput);
            ret = OH_CaptureSession_CommitConfig(captureSession);
            ret = OH_CaptureSession_Start(captureSession);
            ret = OH_CaptureSession_Stop(captureSession);
        }
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
}


/*
 * Feature: Framework
 * Function: Test create preview output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create preview output used in preconfig
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_027, TestSize.Level0)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    sptr<IBufferProducer> previewProducer = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(previewProducer);
    int64_t surfaceIdInt = previewProducer->GetUniqueId();
    string surfaceIdStr = std::to_string(surfaceIdInt);
    const char *surfaceId = nullptr;
    surfaceId = surfaceIdStr.c_str();
    SurfaceUtils::GetInstance()->Add(surfaceIdInt, pSurface);
    ASSERT_NE(surfaceId, nullptr);

    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    bool canPreconfig = false;
    Camera_PreconfigType preconfigType = Camera_PreconfigType::PRECONFIG_720P;
    Camera_PreconfigRatio preconfigRatio = PRECONFIG_RATIO_1_1;
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
        EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), 0);
        Camera_PreviewOutput* previewOutput = nullptr;
        ret = OH_CameraManager_CreatePreviewOutputUsedInPreconfig(cameraManager, surfaceId, &previewOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(previewOutput, nullptr);
        ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        EXPECT_EQ(OH_PreviewOutput_Start(previewOutput), CAMERA_OK);
        EXPECT_EQ(OH_PreviewOutput_Stop(previewOutput), CAMERA_OK);
        EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
        EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
    }
}

/*
 * Feature: Framework
 * Function: Test create photo output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output used in preconfig
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_028, TestSize.Level0)
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
    Camera_PreconfigRatio preconfigRatio = PRECONFIG_RATIO_1_1;
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
 * Function: Test create video output used in preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create video output used in preconfig
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_029, TestSize.Level0)
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

    bool canPreconfig = false;
    Camera_PreconfigType preconfigType = Camera_PreconfigType::PRECONFIG_720P;
    Camera_PreconfigRatio preconfigRatio = PRECONFIG_RATIO_1_1;
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
        Camera_VideoOutput *videoOutput = nullptr;
        ret = OH_CameraManager_CreateVideoOutputUsedInPreconfig(cameraManager, surfaceId, &videoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        ASSERT_NE(videoOutput, nullptr);
        ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
        EXPECT_EQ(ret, CAMERA_OK);
        EXPECT_EQ(OH_CaptureSession_CommitConfig(captureSession), CAMERA_OK);
        EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
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
 * CaseDescription: Test can preconfig or not
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_030, TestSize.Level0)
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
    ret = OH_CaptureSession_CanPreconfig(nullptr, preconfigType, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanPreconfig(captureSession, preconfigType, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test can preconfig or not with ratio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test can preconfig or not with ratio
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_031, TestSize.Level0)
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
    ret = OH_CaptureSession_CanPreconfigWithRatio(nullptr, preconfigType, preconfigRatio, &canPreconfig);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_CanPreconfigWithRatio(captureSession, preconfigType, preconfigRatio, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test preconfig
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_032, TestSize.Level0)
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
    } else {
        ret = OH_CaptureSession_Preconfig(nullptr, preconfigType);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
}

/*
 * Feature: Framework
 * Function: Test preconfig with ratio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test preconfig with ratio
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_033, TestSize.Level0)
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
    } else {
        ret = OH_CaptureSession_PreconfigWithRatio(nullptr, preconfigType, preconfigRatio);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
}

/*
 * Feature: Framework
 * Function: Test get active profile of priview output and delete profile of priview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of priview output and delete profile of priview output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_034, TestSize.Level0)
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
 * Function: Test get active profile of photo output and delete profile of photo output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of photo output and delete profile of photo output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_035, TestSize.Level0)
{
    Camera_Profile* profile = nullptr;
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
 * Function: Test get active profile of video output and delete profile of video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active profile of video output and delete profile of video output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_036, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
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
 * Function: Test Torch supported or not and supported or not with torch mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test is Torch supported or not and supported or not with torch mode
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_038, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
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
            ret = OH_CameraManager_IsTorchSupportedByTorchMode(nullptr, torchMode, &isTorchSupported);
            EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
            ret = OH_CameraManager_IsTorchSupportedByTorchMode(cameraManager, torchMode, nullptr);
            EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
            ret = OH_CameraManager_SetTorchMode(cameraManager, torchMode);
        }
    } else {
        ret = OH_CameraManager_IsTorchSupported(nullptr, &isTorchSupported);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_CameraManager_IsTorchSupported(cameraManager, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test set torch mode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set torch mode
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_039, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
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
            ret = OH_CameraManager_SetTorchMode(nullptr, torchMode);
            EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
            ret = OH_CameraManager_SetTorchMode(cameraManager, torchMode);
        }
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test register camera manager callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register camera manager callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_040, TestSize.Level0)
{
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb
    };
    Camera_ErrorCode ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterTorchStatusCallback(nullptr, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister camera manager callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister camera manager callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_041, TestSize.Level0)
{
    CameraManager_Callbacks setCameraManagerResultCallback = {
        .onCameraStatus = &CameraManagerOnCameraStatusCb
    };
    Camera_ErrorCode ret = OH_CameraManager_RegisterCallback(cameraManager, &setCameraManagerResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_RegisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(nullptr, CameraManagerOnCameraTorchStatusCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_UnregisterTorchStatusCallback(cameraManager, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
}

/*
 * Feature: Framework
 * Function: Test get exposure value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get exposure value
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_042, TestSize.Level0)
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
    ret = OH_CaptureSession_GetExposureValue(nullptr, &exposureValue);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetExposureValue(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * CaseDescription: Test get focal length
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_043, TestSize.Level0)
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
    ret = OH_CaptureSession_GetFocalLength(nullptr, &focalLength);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetFocalLength(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test set smooth zoom
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set smooth zoom
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_044, TestSize.Level0)
{
    float targetZoom = 0.0f;
    Camera_SmoothZoomMode smoothZoomMode = Camera_SmoothZoomMode::NORMAL;
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
    ret = OH_CaptureSession_SetSmoothZoom(captureSession, targetZoom, smoothZoomMode);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_SetSmoothZoom(nullptr, targetZoom, smoothZoomMode);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test get supported color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported color space
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_045, TestSize.Level0)
{
    uint32_t size = 0;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    ret = OH_CaptureSession_SetSessionMode(captureSession, NORMAL_PHOTO);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetSupportedColorSpaces(nullptr, &colorSpace, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetSupportedColorSpaces(captureSession, &colorSpace, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
    if (size != 0 && colorSpace != nullptr) {
        ret = OH_CaptureSession_SetActiveColorSpace(captureSession, colorSpace[0]);
        EXPECT_EQ(ret, CAMERA_OK);
    }
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
 * Function: Test set active color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set active color space
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_046, TestSize.Level0)
{
    uint32_t size = 0;
    Camera_ErrorCode ret = CAMERA_OK;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
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
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PhotoOutput* photoOutput = CreatePhotoOutput();
    ASSERT_NE(photoOutput, nullptr);
    ret = OH_CaptureSession_AddPhotoOutput(captureSession, photoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && colorSpace != nullptr) {
        ret = OH_CaptureSession_SetActiveColorSpace(captureSession, colorSpace[0]);
        EXPECT_EQ(ret, CAMERA_OK);
        ret = OH_CaptureSession_SetActiveColorSpace(nullptr, colorSpace[0]);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
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
 * Function: Test get active color space
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get active color space
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_047, TestSize.Level0)
{
    uint32_t size = 0;
    Camera_ErrorCode ret = CAMERA_OK;
    OH_NativeBuffer_ColorSpace* colorSpace = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
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
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
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
    EXPECT_EQ(ret, CAMERA_OK);
    OH_NativeBuffer_ColorSpace activeColorSpace;
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, &activeColorSpace);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_GetActiveColorSpace(nullptr, &activeColorSpace);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_GetActiveColorSpace(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test register smooth zoom information event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register smooth zoom information event callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_048, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(nullptr, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister smooth zoom information event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister smooth zoom information event callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_049, TestSize.Level0)
{
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    CaptureSession_Callbacks setCaptureSessionResultCallback = {
        .onFocusStateChange = &CameraCaptureSessiononFocusStateChangeCb,
        .onError = &CameraCaptureSessionOnErrorCb
    };
    ret = OH_CaptureSession_RegisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_RegisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(captureSession, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(nullptr, CameraCaptureSessionOnSmoothZoomInfoCb);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterSmoothZoomInfoCallback(captureSession, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CaptureSession_UnregisterCallback(captureSession, &setCaptureSessionResultCallback);
    EXPECT_EQ(ret, CAMERA_OK);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_050, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    ASSERT_NE(cameraInput, nullptr);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_PreviewOutput_GetSupportedFrameRates(nullptr, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_DeleteFrameRates(nullptr, frameRateRange);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PreviewOutput_DeleteFrameRates(previewOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PreviewOutput_Release(previewOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test set framerate in preview output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set framerate in preview output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_051, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_SetFrameRate(nullptr, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_052, TestSize.Level0)
{
    uint32_t size = 0;
    int32_t minFps = 0;
    int32_t maxFps = 0;
    Camera_FrameRateRange* frameRateRange = nullptr;
    Camera_CaptureSession* captureSession = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateCaptureSession(cameraManager, &captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(captureSession, nullptr);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_PreviewOutput* previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);
    ret = OH_PreviewOutput_GetSupportedFrameRates(previewOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddPreviewOutput(captureSession, previewOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_PreviewOutput_SetFrameRate(previewOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_PreviewOutput_GetActiveFrameRate(nullptr, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PreviewOutput_GetActiveFrameRate(previewOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
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
 * Function: Test register photo output capture start event callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo output capture start event callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_053, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_054, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_055, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_056, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_057, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_058, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_059, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_060, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_061, TestSize.Level0)
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_062, TestSize.Level0)
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
 * Function: Test get supported framerates and delete framerates in video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test get supported framerates and delete framerates in video output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_063, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_VideoOutput_GetSupportedFrameRates(nullptr, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, nullptr, &size);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_DeleteFrameRates(nullptr, frameRateRange);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_DeleteFrameRates(videoOutput, frameRateRange);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_VideoOutput_Release(videoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test set framerate in video output
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test set framerate in video output
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_064, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, 0);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_SetFrameRate(nullptr, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_065, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CameraInput_Open(cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_VideoOutput* videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);
    ret = OH_VideoOutput_GetSupportedFrameRates(videoOutput, &frameRateRange, &size);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddInput(captureSession, cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_CaptureSession_AddVideoOutput(captureSession, videoOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    if (size != 0 && frameRateRange != nullptr) {
        ret = OH_VideoOutput_SetFrameRate(videoOutput, minFps, maxFps);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_FrameRateRange activeframeRateRange;
    ret = OH_VideoOutput_GetActiveFrameRate(nullptr, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_VideoOutput_GetActiveFrameRate(videoOutput, &activeframeRateRange);
    EXPECT_EQ(ret, CAMERA_OK);
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
 * Function: Test create photo output without surface
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test create photo output without surface
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_066, TestSize.Level0)
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
    ret = OH_CaptureSession_BeginConfig(captureSession);
    EXPECT_EQ(ret, CAMERA_OK);
    Camera_Input *cameraInput = nullptr;
    ret = OH_CameraManager_CreateCameraInput(cameraManager, cameraDevice, &cameraInput);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(&cameraInput, nullptr);
    EXPECT_EQ(OH_CameraInput_Open(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_AddInput(captureSession, cameraInput), CAMERA_OK);
    Camera_PhotoOutput *photoOutput = nullptr;
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(nullptr, &profile, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, nullptr, &photoOutput);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_CameraManager_CreatePhotoOutputWithoutSurface(cameraManager, &profile, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
 * Function: Test register photo available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo available callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_067, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_068, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
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
 * Function: Test register photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test register photo asset available callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_069, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
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
    } else {
        ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(photoOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PhotoOutput_RegisterPhotoAssetAvailableCallback(nullptr, CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
 * Feature: Framework
 * Function: Test unregister photo asset available callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test unregister photo asset available callback
 */
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_070, TestSize.Level0)
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
    EXPECT_EQ(ret, CAMERA_OK);
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
    } else {
        ret = OH_PhotoOutput_UnregisterPhotoAssetAvailableCallback(nullptr, CameraPhotoOutptOnPhotoAssetAvailableCb);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
        ret = OH_PhotoOutput_UnregisterPhotoAssetAvailableCallback(photoOutput, nullptr);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_PhotoOutput_Release(photoOutput), CAMERA_OK);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_071, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
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
    } else {
        ret = OH_PhotoOutput_IsMovingPhotoSupported(nullptr, &isSupported);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
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
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_072, TestSize.Level0)
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
    ASSERT_NE(&cameraInput, nullptr);
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
        ret = OH_PhotoOutput_EnableMovingPhoto(nullptr, true);
        EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    }
    EXPECT_EQ(OH_PhotoOutput_Release(photooutput), CAMERA_OK);
    EXPECT_EQ(OH_CameraInput_Release(cameraInput), CAMERA_OK);
    EXPECT_EQ(OH_CaptureSession_Release(captureSession), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test get main image in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test get main image in photo native
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_073, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    OH_ImageNative* mainImage = nullptr;
    Camera_ErrorCode ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoNative_GetMainImage(nullptr, &mainImage);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoNative_GetMainImage(photoNative, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    std::shared_ptr<OHOS::Media::NativeImage> mainImage_ = std::make_shared<OHOS::Media::NativeImage>(nullptr, nullptr);
    photoNative->SetMainImage(mainImage_);
    ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ASSERT_NE(mainImage, nullptr);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
}

/*
* Feature: Framework
* Function: Test release in photo native
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Test release in photo native
*/
HWTEST_F(CameraNdkUnitTest, camera_fwcoveragendk_unittest_074, TestSize.Level0)
{
    OH_PhotoNative* photoNative = new OH_PhotoNative();
    OH_ImageNative* mainImage = nullptr;
    Camera_ErrorCode ret = OH_PhotoNative_GetMainImage(photoNative, &mainImage);
    EXPECT_EQ(ret, CAMERA_OK);
    ret = OH_PhotoNative_GetMainImage(nullptr, &mainImage);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    ret = OH_PhotoNative_GetMainImage(photoNative, nullptr);
    EXPECT_EQ(ret, CAMERA_INVALID_ARGUMENT);
    EXPECT_EQ(OH_PhotoNative_Release(photoNative), CAMERA_OK);
    EXPECT_EQ(OH_PhotoNative_Release(nullptr), CAMERA_INVALID_ARGUMENT);
}
} // CameraStandard
} // OHOS