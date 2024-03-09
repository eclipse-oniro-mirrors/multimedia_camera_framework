/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "cpp/camera_manager.h"

#define LOG_TAG "DEMO:"
#define LOG_DOMAIN 0x3200

namespace OHOS_NDK_CAMERA {
NDKCamera* NDKCamera::ndkCamera_ = nullptr;
std::mutex NDKCamera::mtx_;
const uint32_t NDKCamera::width_ = 1920;
const uint32_t NDKCamera::height_ = 1080;

NDKCamera::NDKCamera(char* str, uint32_t focusMode, uint32_t cameraDeviceIndex)
    : previewSurfaceId_(str), cameras_(nullptr), focusMode_(focusMode),
      cameraDeviceIndex_(cameraDeviceIndex),
      cameraOutputCapability_(nullptr), cameraInput_(nullptr),
      captureSession_(nullptr), size_(0),
      isCameraMuted_(nullptr), profile_(nullptr),
      photoSurfaceId_(nullptr), previewOutput_(nullptr), photoOutput_(nullptr),
      metaDataObjectType_(nullptr), metadataOutput_(nullptr), isExposureModeSupported_(false),
      isFocusModeSupported_(false), exposureMode_(EXPOSURE_MODE_LOCKED),
      minExposureBias_(0), maxExposureBias_(0), step_(0),
      videoProfile_(nullptr), videoOutput_(nullptr)
{
    valid_ = false;
    ReleaseCamera();
    Camera_ErrorCode ret = OH_Camera_GetCameraManager(&cameraManager_);
    if (cameraManager_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "Get CameraManager failed.");
    }
    
    ret = OH_CameraManager_CreateCaptureSession(cameraManager_, &captureSession_);
    if (captureSession_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "Create captureSession failed.");
    }
    CaptureSessionRegisterCallback();
    GetSupportedCameras();
    GetSupportedOutputCapability();
    CreatePreviewOutput();
    CreateCameraInput();
    CameraInputOpen();
    CameraManagerRegisterCallback();
    SessionFlowFn();
    valid_ = true;
}

NDKCamera::~NDKCamera()
{
    valid_ = false;
    OH_LOG_INFO(LOG_APP, "~NDKCamera");
    Camera_ErrorCode ret = CAMERA_OK;

    if (cameraManager_) {
        OH_LOG_ERROR(LOG_APP, "Release OH_CameraManager_DeleteSupportedCameras. enter");
        ret = OH_CameraManager_DeleteSupportedCameras(cameraManager_, cameras_, size_);
        if (ret != CAMERA_OK) {
            OH_LOG_ERROR(LOG_APP, "Delete Cameras failed.");
        } else {
            OH_LOG_ERROR(LOG_APP, "Release OH_CameraManager_DeleteSupportedCameras. ok");
        }

        ret = OH_CameraManager_DeleteSupportedCameraOutputCapability(cameraManager_, cameraOutputCapability_);
        if (ret != CAMERA_OK) {
            OH_LOG_ERROR(LOG_APP, "Delete CameraOutputCapability failed.");
        } else {
            OH_LOG_ERROR(LOG_APP, "Release OH_CameraManager_DeleteSupportedCameraOutputCapability. ok");
        }

        ret = OH_Camera_DeleteCameraManager(cameraManager_);
        if (ret != CAMERA_OK) {
            OH_LOG_ERROR(LOG_APP, "Delete CameraManager failed.");
        } else {
            OH_LOG_ERROR(LOG_APP, "Release OH_Camera_DeleteCameraManager. ok");
        }
        cameraManager_ = nullptr;
    }
    OH_LOG_INFO(LOG_APP, "~NDKCamera exit");
}

Camera_ErrorCode NDKCamera::ReleaseCamera(void)
{
    OH_LOG_INFO(LOG_APP, "ReleaseCamera enter.");
    if (previewOutput_) {
        (void)PreviewOutputStop();
        (void)PreviewOutputRelease();
        (void)OH_CaptureSession_RemovePreviewOutput(captureSession_, previewOutput_);
    }
    if (photoOutput_) {
        (void)PhotoOutputRelease();
    }
    if (captureSession_) {
        (void)SessionRealese();
    }
    if (cameraInput_) {
        (void)CameraInputClose();
    }
    OH_LOG_INFO(LOG_APP, "ReleaseCamera exit.");
    return CAMERA_OK;
}
Camera_ErrorCode NDKCamera::ReleaseSession(void)
{
    OH_LOG_INFO(LOG_APP, "ReleaseSession enter.");
    (void)PreviewOutputStop();
    (void)PhotoOutputRelease();
    (void)SessionRealese();
    OH_LOG_INFO(LOG_APP, "ReleaseSession exit.");
    return CAMERA_OK;
}
Camera_ErrorCode NDKCamera::SessionRealese(void)
{
    OH_LOG_INFO(LOG_APP, "SessionRealese enter.");
    Camera_ErrorCode ret = OH_CaptureSession_Release(captureSession_);
    captureSession_ = nullptr;
    OH_LOG_INFO(LOG_APP, "SessionRealese exit.");
    return ret;
}

Camera_ErrorCode NDKCamera::HasFlashFn(uint32_t mode)
{
    Camera_FlashMode flashMode = static_cast<Camera_FlashMode>(mode);
    // 检测是否有闪关灯
    bool hasFlash = false;
    Camera_ErrorCode ret = OH_CaptureSession_HasFlash(captureSession_, &hasFlash);
    if (captureSession_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_HasFlash failed.");
    }
    if (hasFlash) {
        OH_LOG_INFO(LOG_APP, "hasFlash succeeed");
    } else {
        OH_LOG_ERROR(LOG_APP, "hasFlash failed");
    }
    
    // 检测闪光灯模式是否支持
    bool isSupported = false;
    ret = OH_CaptureSession_IsFlashModeSupported(captureSession_, flashMode, &isSupported);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_IsFlashModeSupported failed.");
    }
    if (isSupported) {
        OH_LOG_INFO(LOG_APP, "isFlashModeSupported succeed");
    } else {
        OH_LOG_ERROR(LOG_APP, "isFlashModeSupported failed");
    }

    // 设置闪光灯模式
    ret = OH_CaptureSession_SetFlashMode(captureSession_, flashMode);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_SetFlashMode success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_SetFlashMode failed, ret = %{public}d.", ret);
    }

    // 获取当前设备的闪光灯模式
    ret = OH_CaptureSession_GetFlashMode(captureSession_, &flashMode);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_GetFlashMode success. flashMode：%{public}d ", flashMode);
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_GetFlashMode failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::IsVideoStabilizationModeSupportedFn(uint32_t mode)
{
    Camera_VideoStabilizationMode videoMode = static_cast<Camera_VideoStabilizationMode>(mode);
    // 查询是否支持指定的视频防抖模式
    bool isSupported = false;
    Camera_ErrorCode ret = OH_CaptureSession_IsVideoStabilizationModeSupported(
        captureSession_, videoMode, &isSupported);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_IsVideoStabilizationModeSupported failed.");
    }
    if (isSupported) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_IsVideoStabilizationModeSupported succeed");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_IsVideoStabilizationModeSupported failed");
    }

    // 设置视频防抖
    ret = OH_CaptureSession_SetVideoStabilizationMode(captureSession_, videoMode);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_SetVideoStabilizationMode success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_SetVideoStabilizationMode failed, ret = %{public}d.", ret);
    }

    ret = OH_CaptureSession_GetVideoStabilizationMode(captureSession_, &videoMode);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_GetVideoStabilizationMode success. videoMode：%{public}f ", videoMode);
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_GetVideoStabilizationMode failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::setZoomRatioFn(uint32_t zoomRatio)
{
    float zoom = float(zoomRatio);
    // 获取支持的变焦范围
    float minZoom;
    float maxZoom;
    Camera_ErrorCode ret = OH_CaptureSession_GetZoomRatioRange(captureSession_, &minZoom, &maxZoom);
    if (captureSession_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_GetZoomRatioRange failed.");
    } else {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_GetZoomRatioRange success. minZoom: %{public}f, maxZoom:%{public}f",
            minZoom, maxZoom);
    }
    
    // 设置变焦
    ret = OH_CaptureSession_SetZoomRatio(captureSession_, zoom);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_SetZoomRatio success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_SetZoomRatio failed, ret = %{public}d.", ret);
    }

    // 获取当前设备的变焦值
    ret = OH_CaptureSession_GetZoomRatio(captureSession_, &zoom);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_GetZoomRatio success. zoom：%{public}f ", zoom);
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_GetZoomRatio failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::SessionBegin(void)
{
    Camera_ErrorCode ret =  OH_CaptureSession_BeginConfig(captureSession_);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_BeginConfig success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_BeginConfig failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::SessionCommitConfig(void)
{
    Camera_ErrorCode ret =  OH_CaptureSession_CommitConfig(captureSession_);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_CommitConfig success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_CommitConfig failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::SessionStart(void)
{
    Camera_ErrorCode ret =  OH_CaptureSession_Start(captureSession_);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_Start success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_Start failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::SessionStop(void)
{
    Camera_ErrorCode ret =  OH_CaptureSession_Stop(captureSession_);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_CaptureSession_Stop success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_Stop failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::SessionFlowFn(void)
{
    OH_LOG_INFO(LOG_APP, "Start SessionFlowFn IN.");
    // 开始配置会话
    OH_LOG_INFO(LOG_APP, "Session beginConfig.");
    Camera_ErrorCode ret =  OH_CaptureSession_BeginConfig(captureSession_);

    // 把CameraInput加入到会话
    OH_LOG_INFO(LOG_APP, "Session addInput.");
    ret = OH_CaptureSession_AddInput(captureSession_, cameraInput_);

    // 把previewOutput加入到会话
    OH_LOG_INFO(LOG_APP, "Session add Preview Output.");
    ret = OH_CaptureSession_AddPreviewOutput(captureSession_, previewOutput_);

    // 把photoOutput加入到会话
    OH_LOG_INFO(LOG_APP, "Session add Photo Output.");

    // 提交配置信息
    OH_LOG_INFO(LOG_APP, "Session commitConfig");
    ret = OH_CaptureSession_CommitConfig(captureSession_);

    // 开始会话工作
    OH_LOG_INFO(LOG_APP, "Session start");
    ret = OH_CaptureSession_Start(captureSession_);
    OH_LOG_INFO(LOG_APP, "Session success");

    // 启动对焦
    OH_LOG_INFO(LOG_APP, "IsFocusMode start");
    ret = IsFocusMode(focusMode_);
    OH_LOG_INFO(LOG_APP, "IsFocusMode success");
    return ret;
}

Camera_ErrorCode NDKCamera::CreateCameraInput(void)
{
    OH_LOG_INFO(LOG_APP, "CreateCameraInput enter.");
    Camera_ErrorCode ret = OH_CameraManager_CreateCameraInput(cameraManager_, &cameras_[cameraDeviceIndex_],
        &cameraInput_);
    if (cameraInput_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CreateCameraInput failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "CreateCameraInput exit.");
    CameraInputRegisterCallback();
    return ret;
}

Camera_ErrorCode NDKCamera::CameraInputOpen(void)
{
    OH_LOG_INFO(LOG_APP, "CameraInputOpen enter.");
    Camera_ErrorCode ret = OH_CameraInput_Open(cameraInput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CameraInput_Open failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "CameraInputOpen exit.");
    return ret;
}

Camera_ErrorCode NDKCamera::CameraInputClose(void)
{
    OH_LOG_INFO(LOG_APP, "CameraInput_Close enter.");
    Camera_ErrorCode ret = OH_CameraInput_Close(cameraInput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CameraInput_Close failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "CameraInput_Close exit.");
    return ret;
}

Camera_ErrorCode NDKCamera::CameraInputRelease(void)
{
    OH_LOG_INFO(LOG_APP, "CameraInputRelease enter.");
    Camera_ErrorCode ret = OH_CameraInput_Release(cameraInput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CameraInput_Release failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "CameraInputRelease exit.");
    return ret;
}

Camera_ErrorCode NDKCamera::GetSupportedCameras(void)
{
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameras(cameraManager_, &cameras_, &size_);
    if (cameras_ == nullptr || &size_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "Get supported cameras failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    return ret;
}

Camera_ErrorCode NDKCamera::GetSupportedOutputCapability(void)
{
    Camera_ErrorCode ret = OH_CameraManager_GetSupportedCameraOutputCapability(cameraManager_,
        &cameras_[cameraDeviceIndex_], &cameraOutputCapability_);
    if (cameraOutputCapability_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetSupportedCameraOutputCapability failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    return ret;
}

Camera_ErrorCode NDKCamera::CreatePreviewOutput(void)
{
    for (int index = 0; index < cameraOutputCapability_->previewProfilesSize; index ++) {
        if (cameraOutputCapability_->previewProfiles[index]->size.height == height_ &&
            cameraOutputCapability_->previewProfiles[index]->size.width == width_) {
            profile_ = cameraOutputCapability_->previewProfiles[index];
            break;
            }
    }
    if (profile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get previewProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    Camera_ErrorCode ret = OH_CameraManager_CreatePreviewOutput(cameraManager_, profile_, previewSurfaceId_,
        &previewOutput_);
    if (previewSurfaceId_ == nullptr || previewOutput_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CreatePreviewOutput failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    PreviewOutputRegisterCallback();
    return ret;
}

Camera_ErrorCode NDKCamera::CreatePhotoOutput(char* photoSurfaceId)
{
    for (int index = 0; index < cameraOutputCapability_->photoProfilesSize; index++) {
        if (cameraOutputCapability_->photoProfiles[index]->size.height == height_ &&
            cameraOutputCapability_->photoProfiles[index]->size.width == width_) {
            profile_ = cameraOutputCapability_->photoProfiles[index];
            break;
        }
    }
    if (profile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get photoProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }

    if (photoSurfaceId == nullptr) {
        OH_LOG_ERROR(LOG_APP, "CreatePhotoOutput failed.");
        return CAMERA_INVALID_ARGUMENT;
    }

    Camera_ErrorCode ret = OH_CameraManager_CreatePhotoOutput(cameraManager_, profile_, photoSurfaceId, &photoOutput_);
    PhotoOutputRegisterCallback();
    return ret;
}

Camera_ErrorCode NDKCamera::CreateVideoOutput(char* videoId)
{
    for (size_t index = 0; index < cameraOutputCapability_->videoProfilesSize; index++) {
        if (cameraOutputCapability_->videoProfiles[index]->size.height == height_ &&
            cameraOutputCapability_->videoProfiles[index]->size.width == width_) {
            videoProfile_ = cameraOutputCapability_->videoProfiles[index];
            break;
        }
    }
    if (videoProfile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get videoProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    Camera_ErrorCode ret = OH_CameraManager_CreateVideoOutput(cameraManager_, videoProfile_, videoId, &videoOutput_);
    if (videoId == nullptr || videoOutput_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CreateVideoOutput failed.");
        return ret;
    }

    return CAMERA_OK;
}

Camera_ErrorCode NDKCamera::AddVideoOutput(void)
{
    Camera_ErrorCode ret = OH_CaptureSession_AddVideoOutput(captureSession_, videoOutput_);
    if (ret == CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_AddVideoOutput success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_AddVideoOutput failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::AddPhotoOutput()
{
    Camera_ErrorCode ret = OH_CaptureSession_AddPhotoOutput(captureSession_, photoOutput_);
    if (ret == CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_AddPhotoOutput success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_AddPhotoOutput failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::CreateMetadataOutput(void)
{
    metaDataObjectType_ = cameraOutputCapability_->supportedMetadataObjectTypes[0];
    if (metaDataObjectType_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get metaDataObjectType failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    Camera_ErrorCode ret = OH_CameraManager_CreateMetadataOutput(cameraManager_, metaDataObjectType_,
        &metadataOutput_);
    if (metadataOutput_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "CreateMetadataOutput failed.");
        return ret;
    }
    MetadataOutputRegisterCallback();
    return CAMERA_OK;
}

Camera_ErrorCode NDKCamera::IsCameraMuted(void)
{
    Camera_ErrorCode ret = OH_CameraManager_IsCameraMuted(cameraManager_, isCameraMuted_);
    if (isCameraMuted_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "IsCameraMuted failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::PreviewOutputStop(void)
{
    OH_LOG_INFO(LOG_APP, "PreviewOutputStop enter.");
    Camera_ErrorCode ret = OH_PreviewOutput_Stop(previewOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "PreviewOutputStop failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::PreviewOutputRelease(void)
{
    OH_LOG_INFO(LOG_APP, "PreviewOutputRelease enter.");
    Camera_ErrorCode ret = OH_PreviewOutput_Release(previewOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "PreviewOutputRelease failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::PhotoOutputRelease(void)
{
    OH_LOG_INFO(LOG_APP, "PhotoOutputRelease enter.");
    Camera_ErrorCode ret = OH_PhotoOutput_Release(photoOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "PhotoOutputRelease failed.");
    }
    return ret;
}
Camera_ErrorCode NDKCamera::StartVideo(char* videoId, char* photoId)
{
    OH_LOG_INFO(LOG_APP, "StartVideo begin.");
    Camera_ErrorCode ret = SessionStop();
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "Session stop success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "Session stop failed, ret = %{public}d.", ret);
    }
    ret = SessionBegin();
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "Session begin success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "Session begin failed, ret = %{public}d.", ret);
    }
    (void)OH_CaptureSession_RemovePhotoOutput(captureSession_, photoOutput_);
    (void)CreatePhotoOutput(photoId);
    (void)AddPhotoOutput();
    (void)CreateVideoOutput(videoId);
    (void)AddVideoOutput();
    (void)SessionCommitConfig();
    (void)SessionStart();
    (void)VideoOutputRegisterCallback();
    return ret;
}

Camera_ErrorCode NDKCamera::VideoOutputStart(void)
{
    OH_LOG_INFO(LOG_APP, "VideoOutputStart enter.");
    Camera_ErrorCode ret = OH_VideoOutput_Start(videoOutput_);
    if (ret == CAMERA_OK) {
        OH_LOG_INFO(LOG_APP, "OH_VideoOutput_Start success.");
    } else {
        OH_LOG_ERROR(LOG_APP, "OH_VideoOutput_Start failed, ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::StartPhoto(char* mSurfaceId)
{
    Camera_ErrorCode ret = CAMERA_OK;
    if (takePictureTimes == 0) {
        ret = SessionStop();
        OH_LOG_INFO(LOG_APP, "Start photo, SessionStop, ret = %{public}d.", ret);
        ret = SessionBegin();
        OH_LOG_INFO(LOG_APP, "Start photo, SessionBegin, ret = %{public}d.", ret);

        OH_LOG_DEBUG(LOG_APP, "Start photo begin.");
        ret = CreatePhotoOutput(mSurfaceId);
        OH_LOG_INFO(LOG_APP, "Start photo, CreatePhotoOutput ret = %{public}d.", ret);
        ret = OH_CaptureSession_AddPhotoOutput(captureSession_, photoOutput_);
        OH_LOG_INFO(LOG_APP, "Start photo, AddPhotoOutput ret = %{public}d.", ret);
        ret = SessionCommitConfig();

        OH_LOG_INFO(LOG_APP, "Start photo, SessionCommitConfig ret = %{public}d.", ret);
        ret = SessionStart();
        OH_LOG_INFO(LOG_APP, "Start photo, SessionStart ret = %{public}d.", ret);
    }
    ret = TakePicture();
    OH_LOG_INFO(LOG_APP, "Start photo, TakePicture ret = %{public}d.", ret);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "StartPhoto failed.");
        return ret;
    }
    takePictureTimes++;
    return ret;
}

// exposure mode
Camera_ErrorCode NDKCamera::IsExposureModeSupportedFn(uint32_t mode)
{
    OH_LOG_DEBUG(LOG_APP, "IsExposureModeSupportedFn enter.");
    exposureMode_ = static_cast<Camera_ExposureMode>(mode);
    Camera_ErrorCode ret = OH_CaptureSession_IsExposureModeSupported(captureSession_, exposureMode_,
        &isExposureModeSupported_);
    if (&isExposureModeSupported_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "IsExposureModeSupported failed.");
        return ret;
    }
    ret = OH_CaptureSession_SetExposureMode(captureSession_, exposureMode_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "SetExposureMode failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "SetExposureMode succeed.");
    ret = OH_CaptureSession_GetExposureMode(captureSession_, &exposureMode_);
    if (&exposureMode_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetExposureMode failed.");
        return ret;
    }
    OH_LOG_DEBUG(LOG_APP, "IsExposureModeSupportedFn end.");
    return ret;
}

Camera_ErrorCode NDKCamera::IsMeteringPoint(int x, int y)
{
    OH_LOG_DEBUG(LOG_APP, "IsMeteringPoint enter.");
    Camera_ErrorCode ret = OH_CaptureSession_GetExposureMode(captureSession_, &exposureMode_);
    if (&exposureMode_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetExposureMode failed.");
        return ret;
    }
    Camera_Point exposurePoint;
    exposurePoint.x = x;
    exposurePoint.y = y;
    ret = OH_CaptureSession_SetMeteringPoint(captureSession_, exposurePoint);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "SetMeteringPoint failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "SetMeteringPoint succeed.");
    ret = OH_CaptureSession_GetMeteringPoint(captureSession_, &exposurePoint);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetMeteringPoint failed.");
        return ret;
    }
    OH_LOG_DEBUG(LOG_APP, "IsMeteringPoint end.");
    return ret;
}

Camera_ErrorCode NDKCamera::IsExposureBiasRange(int exposureBias)
{
    OH_LOG_DEBUG(LOG_APP, "IsExposureBiasRange enter.");
    float exposureBiasValue = (float)exposureBias;
    Camera_ErrorCode ret = OH_CaptureSession_GetExposureBiasRange(captureSession_, &minExposureBias_,
        &maxExposureBias_, &step_);
    if (&minExposureBias_ == nullptr || &maxExposureBias_ == nullptr || &step_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetExposureBiasRange failed.");
        return ret;
    }
    ret = OH_CaptureSession_SetExposureBias(captureSession_, exposureBiasValue);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "SetExposureBias failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "SetExposureBias succeed.");
    ret = OH_CaptureSession_GetExposureBias(captureSession_, &exposureBiasValue);
    if (&exposureBiasValue == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetExposureBias failed.");
        return ret;
    }
    OH_LOG_DEBUG(LOG_APP, "IsExposureBiasRange end.");
    return ret;
}

// focus mode
Camera_ErrorCode NDKCamera::IsFocusModeSupported(uint32_t mode)
{
    Camera_FocusMode focusMode = static_cast<Camera_FocusMode>(mode);
    Camera_ErrorCode ret = OH_CaptureSession_IsFocusModeSupported(captureSession_, focusMode, &isFocusModeSupported_);
    if (&isFocusModeSupported_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "IsFocusModeSupported failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::IsFocusMode(uint32_t mode)
{
    OH_LOG_DEBUG(LOG_APP, "IsFocusMode enter.");
    Camera_FocusMode focusMode = static_cast<Camera_FocusMode>(mode);
    Camera_ErrorCode ret = OH_CaptureSession_IsFocusModeSupported(captureSession_, focusMode, &isFocusModeSupported_);
    if (&isFocusModeSupported_ == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "IsFocusModeSupported failed.");
        return ret;
    }
    ret = OH_CaptureSession_SetFocusMode(captureSession_, focusMode);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "SetFocusMode failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "SetFocusMode succeed.");
    ret = OH_CaptureSession_GetFocusMode(captureSession_, &focusMode);
    if (&focusMode == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetFocusMode failed.");
        return ret;
    }
    OH_LOG_DEBUG(LOG_APP, "IsFocusMode end.");
    return ret;
}

Camera_ErrorCode NDKCamera::IsFocusPoint(float x, float y)
{
    OH_LOG_DEBUG(LOG_APP, "IsFocusPoint enter.");
    Camera_Point focusPoint;
    focusPoint.x = x;
    focusPoint.y = y;
    Camera_ErrorCode ret = OH_CaptureSession_SetFocusPoint(captureSession_, focusPoint);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "SetFocusPoint failed.");
        return ret;
    }
    OH_LOG_INFO(LOG_APP, "SetFocusPoint succeed.");
    ret = OH_CaptureSession_GetFocusPoint(captureSession_, &focusPoint);
    if (&focusPoint == nullptr || ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "GetFocusPoint failed.");
        return ret;
    }
    OH_LOG_DEBUG(LOG_APP, "IsFocusPoint end.");
    return ret;
}
int32_t NDKCamera::GetVideoFrameWidth(void)
{
    videoProfile_ = cameraOutputCapability_->videoProfiles[0];
    if (videoProfile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get videoProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    return videoProfile_->size.width;
}

int32_t NDKCamera::GetVideoFrameHeight(void)
{
    videoProfile_ = cameraOutputCapability_->videoProfiles[0];
    if (videoProfile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get videoProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    return videoProfile_->size.height;
}

int32_t NDKCamera::GetVideoFrameRate(void)
{
    videoProfile_ = cameraOutputCapability_->videoProfiles[0];
    if (videoProfile_ == nullptr) {
        OH_LOG_ERROR(LOG_APP, "Get videoProfiles failed.");
        return CAMERA_INVALID_ARGUMENT;
    }
    return videoProfile_->range.min;
}

Camera_ErrorCode NDKCamera::VideoOutputStop(void)
{
    OH_LOG_INFO(LOG_APP, "enter VideoOutputStop.");
    Camera_ErrorCode ret = OH_VideoOutput_Stop(videoOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "VideoOutputStop failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::VideoOutputRelease(void)
{
    OH_LOG_INFO(LOG_APP, "enter VideoOutputRelease.");
    Camera_ErrorCode ret = OH_VideoOutput_Release(videoOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "VideoOutputRelease failed.");
    }
    return ret;
}

Camera_ErrorCode NDKCamera::TakePicture(void)
{
    Camera_ErrorCode ret = OH_PhotoOutput_Capture(photoOutput_);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "takePicture OH_PhotoOutput_Capture ret = %{public}d.", ret);
    }
    return ret;
}

Camera_ErrorCode NDKCamera::TakePictureWithPhotoSettings(Camera_PhotoCaptureSetting photoSetting)
{
    Camera_ErrorCode ret = OH_PhotoOutput_Capture_WithCaptureSetting(photoOutput_, photoSetting);
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "takePicture TakePictureWithPhotoSettings ret = %{public}d.", ret);
        return CAMERA_INVALID_ARGUMENT;
    } else {
        OH_LOG_INFO(LOG_APP, "TakePictureWithPhotoSettings get quality %{public}d, rotation %{public}d, "
            "mirror %{public}d, latitude, %{public}d, longitude %{public}d, altitude %{public}d",
            photoSetting.quality, photoSetting.rotation, photoSetting.mirror, photoSetting.location->latitude,
            photoSetting.location->longitude, photoSetting.location->altitude);
    }
    return CAMERA_OK;
}

// CameraManager Callback
void CameraManagerStatusCallback(Camera_Manager* cameraManager, Camera_StatusInfo* status)
{
    OH_LOG_INFO(LOG_APP, "CameraManagerStatusCallback");
}

CameraManager_Callbacks* NDKCamera::GetCameraManagerListener(void)
{
    static CameraManager_Callbacks cameraManagerListener = {
        .onCameraStatus = CameraManagerStatusCallback
    };
    return &cameraManagerListener;
}

Camera_ErrorCode NDKCamera::CameraManagerRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_CameraManager_RegisterCallback(cameraManager_, GetCameraManagerListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CameraManager_RegisterCallback failed.");
    }
    return ret;
}

// CameraInput Callback
void OnCameraInputError(const Camera_Input* cameraInput, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "OnCameraInput errorCode = %{public}d", errorCode);
}

CameraInput_Callbacks* NDKCamera::GetCameraInputListener(void)
{
    static CameraInput_Callbacks cameraInputCallbacks = {
        .onError = OnCameraInputError
    };
    return &cameraInputCallbacks;
}

Camera_ErrorCode NDKCamera::CameraInputRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_CameraInput_RegisterCallback(cameraInput_, GetCameraInputListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CameraInput_RegisterCallback failed.");
    }
    return ret;
}

// PreviewOutput Callback
void PreviewOutputOnFrameStart(Camera_PreviewOutput* previewOutput)
{
    OH_LOG_INFO(LOG_APP, "PreviewOutputOnFrameStart");
}

void PreviewOutputOnFrameEnd(Camera_PreviewOutput* previewOutput, int32_t frameCount)
{
    OH_LOG_INFO(LOG_APP, "PreviewOutput frameCount = %{public}d", frameCount);
}

void PreviewOutputOnError(Camera_PreviewOutput* previewOutput, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "PreviewOutput errorCode = %{public}d", errorCode);
}

PreviewOutput_Callbacks* NDKCamera::GetPreviewOutputListener(void)
{
    static PreviewOutput_Callbacks previewOutputListener = {
        .onFrameStart = PreviewOutputOnFrameStart,
        .onFrameEnd = PreviewOutputOnFrameEnd,
        .onError = PreviewOutputOnError
    };
    return &previewOutputListener;
}

Camera_ErrorCode NDKCamera::PreviewOutputRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_PreviewOutput_RegisterCallback(previewOutput_, GetPreviewOutputListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_PreviewOutput_RegisterCallback failed.");
    }
    return ret;
}

// PhotoOutput Callback
void PhotoOutputOnFrameStart(Camera_PhotoOutput* photoOutput)
{
    OH_LOG_INFO(LOG_APP, "PhotoOutputOnFrameStart");
}

void PhotoOutputOnFrameShutter(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* info)
{
    OH_LOG_INFO(LOG_APP, "PhotoOutputOnFrameShutter");
}

void PhotoOutputOnFrameEnd(Camera_PhotoOutput* photoOutput, int32_t frameCount)
{
    OH_LOG_INFO(LOG_APP, "PhotoOutput frameCount = %{public}d", frameCount);
}

void PhotoOutputOnError(Camera_PhotoOutput* photoOutput, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "PhotoOutput errorCode = %{public}d", errorCode);
}

PhotoOutput_Callbacks* NDKCamera::GetPhotoOutputListener(void)
{
    static PhotoOutput_Callbacks photoOutputListener = {
        .onFrameStart = PhotoOutputOnFrameStart,
        .onFrameShutter = PhotoOutputOnFrameShutter,
        .onFrameEnd = PhotoOutputOnFrameEnd,
        .onError = PhotoOutputOnError
    };
    return &photoOutputListener;
}

Camera_ErrorCode NDKCamera::PhotoOutputRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_PhotoOutput_RegisterCallback(photoOutput_, GetPhotoOutputListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_PhotoOutput_RegisterCallback failed.");
    }
    return ret;
}

// VideoOutput Callback
void VideoOutputOnFrameStart(Camera_VideoOutput* videoOutput)
{
    OH_LOG_INFO(LOG_APP, "VideoOutputOnFrameStart");
}

void VideoOutputOnFrameEnd(Camera_VideoOutput* videoOutput, int32_t frameCount)
{
    OH_LOG_INFO(LOG_APP, "VideoOutput frameCount = %{public}d", frameCount);
}

void VideoOutputOnError(Camera_VideoOutput* videoOutput, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "VideoOutput errorCode = %{public}d", errorCode);
}

VideoOutput_Callbacks* NDKCamera::GetVideoOutputListener(void)
{
    static VideoOutput_Callbacks videoOutputListener = {
        .onFrameStart = VideoOutputOnFrameStart,
        .onFrameEnd = VideoOutputOnFrameEnd,
        .onError = VideoOutputOnError
    };
    return &videoOutputListener;
}

Camera_ErrorCode NDKCamera::VideoOutputRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_VideoOutput_RegisterCallback(videoOutput_, GetVideoOutputListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_VideoOutput_RegisterCallback failed.");
    }
    return ret;
}

// Metadata Callback
void OnMetadataObjectAvailable(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObject* metadataObject, uint32_t size)
{
    OH_LOG_INFO(LOG_APP, "size = %{public}d", size);
}

void OnMetadataOutputError(Camera_MetadataOutput* metadataOutput, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "OnMetadataOutput errorCode = %{public}d", errorCode);
}

MetadataOutput_Callbacks* NDKCamera::GetMetadataOutputListener(void)
{
    static MetadataOutput_Callbacks metadataOutputListener = {
        .onMetadataObjectAvailable = OnMetadataObjectAvailable,
        .onError = OnMetadataOutputError
    };
    return &metadataOutputListener;
}

Camera_ErrorCode NDKCamera::MetadataOutputRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_MetadataOutput_RegisterCallback(metadataOutput_, GetMetadataOutputListener());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_MetadataOutput_RegisterCallback failed.");
    }
    return ret;
}

// Session Callback
void CaptureSessionOnFocusStateChange(Camera_CaptureSession* Session, Camera_FocusState focusState)
{
    OH_LOG_INFO(LOG_APP, "CaptureSessionOnFocusStateChange");
}

void CaptureSessionOnError(Camera_CaptureSession* Session, Camera_ErrorCode errorCode)
{
    OH_LOG_INFO(LOG_APP, "CaptureSession errorCode = %{public}d", errorCode);
}

CaptureSession_Callbacks* NDKCamera::GetCaptureSessionRegister(void)
{
    static CaptureSession_Callbacks captureSessionCallbacks = {
        .onFocusStateChange = CaptureSessionOnFocusStateChange,
        .onError = CaptureSessionOnError
    };
    return &captureSessionCallbacks;
}

Camera_ErrorCode NDKCamera::CaptureSessionRegisterCallback(void)
{
    Camera_ErrorCode ret = OH_CaptureSession_RegisterCallback(captureSession_, GetCaptureSessionRegister());
    if (ret != CAMERA_OK) {
        OH_LOG_ERROR(LOG_APP, "OH_CaptureSession_RegisterCallback failed.");
    }
    return ret;
}
} // OHOS_NDK_CAMERA