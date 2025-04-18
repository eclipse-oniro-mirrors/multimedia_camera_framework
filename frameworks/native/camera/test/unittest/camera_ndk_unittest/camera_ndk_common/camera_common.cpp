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

#include "camera_common.h"
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

void CameraNdkCommon::InitCamera(void)
{
    Camera_ErrorCode ret = OH_Camera_GetCameraManager(&cameraManager);
    EXPECT_EQ(ret, 0);
    ret = OH_CameraManager_GetSupportedCameras(cameraManager, &cameraDevice, &cameraDeviceSize);
    EXPECT_EQ(ret, 0);
}

void CameraNdkCommon::ReleaseCamera(void)
{
    Camera_ErrorCode ret = CAMERA_OK;
    if (cameraDevice != nullptr) {
        ret = OH_CameraManager_DeleteSupportedCameras(cameraManager, cameraDevice, cameraDeviceSize);
        EXPECT_EQ(ret, CAMERA_OK);
    }
    if (cameraManager != nullptr) {
        ret = OH_Camera_DeleteCameraManager(cameraManager);
        EXPECT_EQ(ret, CAMERA_OK);
    }
}

void CameraNdkCommon::ReleaseImageReceiver(void)
{
    if (imageReceiver != nullptr) {
        std::string receiverKey = imageReceiver->iraContext_->GetReceiverKey();
        Media::ImageReceiverManager::ReleaseReceiverById(receiverKey);
    }
}

void CameraNdkCommon::ObtainAvailableFrameRate(Camera_FrameRateRange activeframeRateRange,
                                               Camera_FrameRateRange*& frameRateRange, uint32_t size,
                                               int32_t &minFps, int32_t &maxFps)
{
    minFps = activeframeRateRange.min;
    maxFps = activeframeRateRange.max;
    CHECK_ERROR_RETURN_LOG(frameRateRange == nullptr, "frameRateRange is nullptr");
    bool flag = false;
    for (uint32_t i = 0; i < size; i++) {
        if (frameRateRange[i].min != activeframeRateRange.min ||
            frameRateRange[i].max != activeframeRateRange.max) {
            minFps = frameRateRange[i].min;
            maxFps = frameRateRange[i].max;
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (maxFps > minFps + 1) {
            minFps++;
        }
    }
    return;
}

Camera_PhotoOutput* CameraNdkCommon::CreatePhotoOutput(int32_t width, int32_t height)
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

Camera_PreviewOutput* CameraNdkCommon::CreatePreviewOutput(int32_t width, int32_t height)
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

Camera_VideoOutput* CameraNdkCommon::CreateVideoOutput(int32_t width, int32_t height)
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

Camera_MetadataOutput* CameraNdkCommon::CreateMetadataOutput(Camera_MetadataObjectType type)
{
    Camera_MetadataOutput* metadataOutput = nullptr;
    Camera_ErrorCode ret = OH_CameraManager_CreateMetadataOutput(cameraManager, &type, &metadataOutput);
    EXPECT_EQ(ret, CAMERA_OK);
    EXPECT_NE(metadataOutput, nullptr);
    return metadataOutput;
}

void CameraNdkCommon::SessionCommit(Camera_CaptureSession *captureSession)
{
    Camera_ErrorCode ret = OH_CaptureSession_CommitConfig(captureSession);
    EXPECT_EQ(ret, 0);
    ret = OH_CaptureSession_Start(captureSession);
    EXPECT_EQ(ret, 0);
}

void CameraNdkCommon::SessionControlParams(Camera_CaptureSession *captureSession)
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

void CameraNdkCommon::OnCameraInputError(const Camera_Input* cameraInput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraCaptureSessiononFocusStateChangeCb(Camera_CaptureSession* session,
    Camera_FocusState focusState)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraCaptureSessionOnErrorCb(Camera_CaptureSession* session, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraCaptureSessionOnSmoothZoomInfoCb(Camera_CaptureSession* session,
    Camera_SmoothZoomInfo* smoothZoomInfo)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraCaptureSessionAutoDeviceSwitchStatusCb(Camera_CaptureSession* session,
    Camera_AutoDeviceSwitchStatusInfo* autoDeviceSwitchStatusInfo)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraManagerOnCameraStatusCb(Camera_Manager* cameraManager, Camera_StatusInfo* status)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraManagerOnCameraTorchStatusCb(Camera_Manager* cameraManager, Camera_TorchStatusInfo* status)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraManagerOnCameraFoldStatusCb(Camera_Manager* cameraManager, Camera_FoldStatusInfo* status)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPreviewOutptOnFrameStartCb(Camera_PreviewOutput* previewOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPreviewOutptOnFrameEndCb(Camera_PreviewOutput* previewOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPreviewOutptOnErrorCb(Camera_PreviewOutput* previewOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnFrameStartCb(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnFrameShutterCb(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnFrameEndCb(Camera_PhotoOutput* photoOutput, int32_t timestamp)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnErrorCb(Camera_PhotoOutput* photoOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnCaptureEndCb(Camera_PhotoOutput* photoOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnCaptureStartWithInfoCb(Camera_PhotoOutput* photoOutput,
    Camera_CaptureStartInfo* Info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnFrameShutterEndCb(Camera_PhotoOutput* photoOutput,
    Camera_FrameShutterInfo* Info)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnCaptureReadyCb(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptEstimatedOnCaptureDurationCb(Camera_PhotoOutput* photoOutput, int64_t duration)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnPhotoAvailableCb(Camera_PhotoOutput* photoOutput, OH_PhotoNative* photo)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraPhotoOutptOnPhotoAssetAvailableCb(Camera_PhotoOutput* photoOutput,
    OH_MediaAsset* photoAsset)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraVideoOutptOnFrameStartCb(Camera_VideoOutput* videoOutput)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraVideoOutptOnFrameEndCb(Camera_VideoOutput* videoOutput, int32_t frameCount)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraVideoOutptOnErrorCb(Camera_VideoOutput* videoOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraMetadataOutputOnMetadataObjectAvailableCb(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObject* metadataObject, uint32_t size)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}

void CameraNdkCommon::CameraMetadataOutputOnErrorCb(Camera_MetadataOutput* metadataOutput, Camera_ErrorCode errorCode)
{
    MEDIA_DEBUG_LOG("fun:%s", __FUNCTION__);
}
} // CameraStandard
} // OHOS