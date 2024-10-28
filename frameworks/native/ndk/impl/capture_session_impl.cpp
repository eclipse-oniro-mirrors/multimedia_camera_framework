/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "capture_session_impl.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_scene_const.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

const std::unordered_map<Camera_SceneMode, SceneMode> g_ndkToFwMode_ = {
    {Camera_SceneMode::NORMAL_PHOTO, SceneMode::CAPTURE},
    {Camera_SceneMode::NORMAL_VIDEO, SceneMode::VIDEO},
    {Camera_SceneMode::SECURE_PHOTO, SceneMode::SECURE},
};
const std::unordered_map<Camera_PreconfigType, PreconfigType> g_ndkToFwPreconfig = {
    {Camera_PreconfigType::PRECONFIG_720P, PreconfigType::PRECONFIG_720P},
    {Camera_PreconfigType::PRECONFIG_1080P, PreconfigType::PRECONFIG_1080P},
    {Camera_PreconfigType::PRECONFIG_4K, PreconfigType::PRECONFIG_4K},
    {Camera_PreconfigType::PRECONFIG_HIGH_QUALITY, PreconfigType::PRECONFIG_HIGH_QUALITY}
};
const std::unordered_map<Camera_PreconfigRatio, ProfileSizeRatio> g_ndkToFwPreconfigRatio = {
    {Camera_PreconfigRatio::PRECONFIG_RATIO_1_1, ProfileSizeRatio::RATIO_1_1},
    {Camera_PreconfigRatio::PRECONFIG_RATIO_4_3, ProfileSizeRatio::RATIO_4_3},
    {Camera_PreconfigRatio::PRECONFIG_RATIO_16_9, ProfileSizeRatio::RATIO_16_9}
};
const std::unordered_map<ColorSpace, OH_NativeBuffer_ColorSpace> g_fwToNdkColorSpace_ = {
    {ColorSpace::COLOR_SPACE_UNKNOWN, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE},
    {ColorSpace::DISPLAY_P3, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_FULL},
    {ColorSpace::SRGB, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_FULL},
    {ColorSpace::BT709, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_FULL},
    {ColorSpace::BT2020_HLG, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL},
    {ColorSpace::BT2020_PQ, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL},
    {ColorSpace::P3_HLG, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL},
    {ColorSpace::P3_PQ, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL},
    {ColorSpace::DISPLAY_P3_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_LIMIT},
    {ColorSpace::SRGB_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_LIMIT},
    {ColorSpace::BT709_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT},
    {ColorSpace::BT2020_HLG_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT},
    {ColorSpace::BT2020_PQ_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT},
    {ColorSpace::P3_HLG_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT},
    {ColorSpace::P3_PQ_LIMIT, OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT}
};
const std::unordered_map<OH_NativeBuffer_ColorSpace, ColorSpace> g_ndkToFwColorSpace_ = {
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE, ColorSpace::COLOR_SPACE_UNKNOWN},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_FULL, ColorSpace::DISPLAY_P3},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_FULL, ColorSpace::SRGB},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_FULL, ColorSpace::BT709},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL, ColorSpace::BT2020_HLG},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL, ColorSpace::BT2020_PQ},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL, ColorSpace::P3_HLG},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL, ColorSpace::P3_PQ},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_LIMIT, ColorSpace::DISPLAY_P3_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_LIMIT, ColorSpace::SRGB_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT, ColorSpace::BT709_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT, ColorSpace::BT2020_HLG_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT, ColorSpace::BT2020_PQ_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT, ColorSpace::P3_HLG_LIMIT},
    {OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT, ColorSpace::P3_PQ_LIMIT}
};

class InnerCaptureSessionCallback : public SessionCallback, public FocusCallback {
public:
    InnerCaptureSessionCallback(Camera_CaptureSession* captureSession, CaptureSession_Callbacks* callback)
        : captureSession_(captureSession), callback_(*callback) {}
    ~InnerCaptureSessionCallback() = default;

    void OnFocusState(FocusState state) override
    {
        MEDIA_DEBUG_LOG("OnFrameStarted is called!");
        if (captureSession_ != nullptr && callback_.onFocusStateChange != nullptr) {
            callback_.onFocusStateChange(captureSession_, static_cast<Camera_FocusState>(state));
        }
    }

    void OnError(const int32_t errorCode) override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        if (captureSession_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(captureSession_, FrameworkToNdkCameraError(errorCode));
        }
    }

private:
    Camera_CaptureSession* captureSession_;
    CaptureSession_Callbacks callback_;
};

class InnerCaptureSessionSmoothZoomInfoCallback : public SmoothZoomCallback {
public:
    InnerCaptureSessionSmoothZoomInfoCallback(Camera_CaptureSession* captureSession,
        OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback)
        : captureSession_(captureSession), smoothZoomInfoCallback_(smoothZoomInfoCallback) {};
    ~InnerCaptureSessionSmoothZoomInfoCallback() = default;

    void OnSmoothZoom(int32_t duration) override
    {
        MEDIA_DEBUG_LOG("OnSmoothZoom is called!");
        if (captureSession_ != nullptr && smoothZoomInfoCallback_ != nullptr) {
            Camera_SmoothZoomInfo info;
            info.duration = duration;
            smoothZoomInfoCallback_(captureSession_, &info);
        }
    }

private:
    Camera_CaptureSession* captureSession_;
    OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback_ = nullptr;
};

class InnerCaptureSessionAutoDeviceSwitchStatusCallback : public AutoDeviceSwitchCallback {
public:
    InnerCaptureSessionAutoDeviceSwitchStatusCallback(Camera_CaptureSession* captureSession,
        OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusCallback)
        : captureSession_(captureSession), autoDeviceSwitchStatusCallback_(autoDeviceSwitchStatusCallback) {};
    ~InnerCaptureSessionAutoDeviceSwitchStatusCallback() = default;

    void OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const override
    {
        MEDIA_DEBUG_LOG("OnAutoDeviceSwitchStatusChange is called!");
        if (captureSession_ != nullptr && autoDeviceSwitchStatusCallback_ != nullptr) {
            Camera_AutoDeviceSwitchStatusInfo info;
            info.isDeviceSwitched = isDeviceSwitched;
            info.isDeviceCapabilityChanged = isDeviceCapabilityChanged;
            autoDeviceSwitchStatusCallback_(captureSession_, &info);
        }
    }

private:
    Camera_CaptureSession* captureSession_;
    OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusCallback_ = nullptr;
};

Camera_CaptureSession::Camera_CaptureSession(sptr<CaptureSession> &innerCaptureSession)
    : innerCaptureSession_(innerCaptureSession)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession Constructor is called");
}

Camera_CaptureSession::~Camera_CaptureSession()
{
    MEDIA_DEBUG_LOG("~Camera_CaptureSession is called");
    if (innerCaptureSession_) {
        innerCaptureSession_ = nullptr;
    }
}

Camera_ErrorCode Camera_CaptureSession::RegisterCallback(CaptureSession_Callbacks* callback)
{
    shared_ptr<InnerCaptureSessionCallback> innerCallback =
        make_shared<InnerCaptureSessionCallback>(this, callback);
    CHECK_AND_RETURN_RET_LOG(innerCallback != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "create innerCallback failed!");
    if (callback->onError != nullptr) {
        innerCaptureSession_->SetCallback(innerCallback);
    }
    if (callback->onFocusStateChange != nullptr) {
        innerCaptureSession_->SetFocusCallback(innerCallback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::UnregisterCallback(CaptureSession_Callbacks* callback)
{
    if (callback->onError != nullptr) {
        innerCaptureSession_->SetCallback(nullptr);
    }
    if (callback->onFocusStateChange != nullptr) {
        innerCaptureSession_->SetFocusCallback(nullptr);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::RegisterSmoothZoomInfoCallback(
    OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback)
{
    shared_ptr<InnerCaptureSessionSmoothZoomInfoCallback> innerSmoothZoomInfoCallback =
        make_shared<InnerCaptureSessionSmoothZoomInfoCallback>(this, smoothZoomInfoCallback);
    CHECK_AND_RETURN_RET_LOG(innerSmoothZoomInfoCallback != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "create innerCallback failed!");
    innerCaptureSession_->SetSmoothZoomCallback(innerSmoothZoomInfoCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::UnregisterSmoothZoomInfoCallback(
    OH_CaptureSession_OnSmoothZoomInfo smoothZoomInfoCallback)
{
    innerCaptureSession_->SetSmoothZoomCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetSessionMode(Camera_SceneMode sceneMode)
{
    CHECK_AND_RETURN_RET_LOG(!innerCaptureSession_->IsSessionConfiged() && !innerCaptureSession_->IsSessionCommited(),
        CAMERA_OPERATION_NOT_ALLOWED, "Camera_Manager::SetSessionMode can not set sceneMode after BeginConfig!");
    auto itr = g_ndkToFwMode_.find(static_cast<Camera_SceneMode>(sceneMode));
    CHECK_AND_RETURN_RET_LOG(itr != g_ndkToFwMode_.end(), CAMERA_INVALID_ARGUMENT,
        "Camera_CaptureSession::SetSessionMode sceneMode not found!");
    SceneMode innerSceneMode = static_cast<SceneMode>(itr->second);
    switch (innerSceneMode) {
        case SceneMode::CAPTURE:
            innerCaptureSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::CAPTURE);
            break;
        case SceneMode::VIDEO:
            innerCaptureSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::VIDEO);
            break;
        case SceneMode::SECURE:
            innerCaptureSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::SECURE);
            break;
        default:
            MEDIA_ERR_LOG("Camera_CaptureSession::SetSessionMode sceneMode = %{public}d not supported", sceneMode);
            return CAMERA_INVALID_ARGUMENT;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::AddSecureOutput(Camera_PreviewOutput* previewOutput)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::AddSecureOutput is called");
    sptr<CaptureOutput> innerPreviewOutput = previewOutput->GetInnerPreviewOutput();
    int32_t ret = innerCaptureSession_->AddSecureOutput(innerPreviewOutput);
    return FrameworkToNdkCameraError(ServiceToCameraError(ret));
}

Camera_ErrorCode Camera_CaptureSession::BeginConfig()
{
    int32_t ret = innerCaptureSession_->BeginConfig();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::CommitConfig()
{
    int32_t ret = innerCaptureSession_->CommitConfig();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::AddInput(Camera_Input* cameraInput)
{
    sptr<CaptureInput> innerCameraInput = cameraInput->GetInnerCameraInput();
    int32_t ret = innerCaptureSession_->AddInput(innerCameraInput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RemoveInput(Camera_Input* cameraInput)
{
    sptr<CaptureInput> innerCameraInput = cameraInput->GetInnerCameraInput();
    int32_t ret = innerCaptureSession_->RemoveInput(innerCameraInput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::AddPreviewOutput(Camera_PreviewOutput* previewOutput)
{
    sptr<CaptureOutput> innerPreviewOutput = previewOutput->GetInnerPreviewOutput();
    int32_t ret = innerCaptureSession_->AddOutput(innerPreviewOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RemovePreviewOutput(Camera_PreviewOutput* previewOutput)
{
    sptr<CaptureOutput> innerPreviewOutput = previewOutput->GetInnerPreviewOutput();
    int32_t ret = innerCaptureSession_->RemoveOutput(innerPreviewOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::AddPhotoOutput(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::AddPhotoOutput is called");
    sptr<CaptureOutput> innerPhotoOutput = photoOutput->GetInnerPhotoOutput();
    int32_t ret = innerCaptureSession_->AddOutput(innerPhotoOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RemovePhotoOutput(Camera_PhotoOutput* photoOutput)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::RemovePhotoOutput is called");
    sptr<CaptureOutput> innerPhotoOutput = photoOutput->GetInnerPhotoOutput();
    int32_t ret = innerCaptureSession_->RemoveOutput(innerPhotoOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::AddMetaDataOutput(Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::AddMetaDataOutput is called");
    sptr<CaptureOutput> innerMetaDataOutput = metadataOutput->GetInnerMetadataOutput();
    int32_t ret = innerCaptureSession_->AddOutput(innerMetaDataOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RemoveMetaDataOutput(Camera_MetadataOutput* metadataOutput)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::RemoveMetaDataOutput is called");
    sptr<CaptureOutput> innerMetaDataOutput = metadataOutput->GetInnerMetadataOutput();
    int32_t ret = innerCaptureSession_->AddOutput(innerMetaDataOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::IsVideoStabilizationModeSupported(Camera_VideoStabilizationMode mode,
    bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::IsVideoStabilizationModeSupported is called");
    VideoStabilizationMode innerVideoStabilizationMode = static_cast<VideoStabilizationMode>(mode);
    int32_t ret = innerCaptureSession_->IsVideoStabilizationModeSupported(innerVideoStabilizationMode, *isSupported);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetVideoStabilizationMode(Camera_VideoStabilizationMode* mode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetVideoStabilizationMode is called");

    *mode = static_cast<Camera_VideoStabilizationMode>(innerCaptureSession_->GetActiveVideoStabilizationMode());
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetVideoStabilizationMode(Camera_VideoStabilizationMode mode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetVideoStabilizationMode is called");

    VideoStabilizationMode innerVideoStabilizationMode = static_cast<VideoStabilizationMode>(mode);
    int32_t ret = innerCaptureSession_->SetVideoStabilizationMode(innerVideoStabilizationMode);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetZoomRatioRange(float* minZoom, float* maxZoom)
{
    std::vector<float> vecZoomRatioList = innerCaptureSession_->GetZoomRatioRange();
    if (vecZoomRatioList.empty()) {
        MEDIA_ERR_LOG("Camera_CaptureSession::GetZoomRatioRange vecZoomRatioList  size is null ");
    } else {
        *minZoom = vecZoomRatioList[0];
        *maxZoom = vecZoomRatioList[1];
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::GetZoomRatio(float* zoom)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetZoomRatio is called");
    *zoom = innerCaptureSession_->GetZoomRatio();

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetZoomRatio(float zoom)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetZoomRatio is called");

    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetZoomRatio(zoom);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::IsFocusModeSupported(Camera_FocusMode focusMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::IsFocusModeSupported is called");
    FocusMode innerFocusMode = static_cast<FocusMode>(focusMode);
    int32_t ret = innerCaptureSession_->IsFocusModeSupported(innerFocusMode, *isSupported);
    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetFocusMode(Camera_FocusMode* focusMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetFocusMode is called");

    *focusMode = static_cast<Camera_FocusMode>(innerCaptureSession_->GetFocusMode());
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetFocusMode(Camera_FocusMode focusMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetFocusMode is called");

    FocusMode innerFocusMode = static_cast<FocusMode>(focusMode);
    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetFocusMode(innerFocusMode);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::SetFocusPoint(Camera_Point focusPoint)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetFocusPoint is called");

    Point innerFocusPoint;
    innerFocusPoint.x = focusPoint.x;
    innerFocusPoint.y = focusPoint.y;

    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetFocusPoint(innerFocusPoint);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetFocusPoint(Camera_Point* focusPoint)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetFocusPoint is called");
    Point innerFocusPoint = innerCaptureSession_->GetFocusPoint();
    (*focusPoint).x = innerFocusPoint.x;
    (*focusPoint).y = innerFocusPoint.y;

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::HasFlash(bool* hasFlash)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::HasFlash is called");

    *hasFlash = innerCaptureSession_->HasFlash();

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::IsFlashModeSupported(Camera_FlashMode flashMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::IsFlashModeSupported is called");
    FlashMode innerFlashMode = static_cast<FlashMode>(flashMode);

    *isSupported = innerCaptureSession_->IsFlashModeSupported(innerFlashMode);

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::GetFlashMode(Camera_FlashMode* flashMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetFlashMode is called");
    *flashMode = static_cast<Camera_FlashMode>(innerCaptureSession_->GetFlashMode());

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetFlashMode(Camera_FlashMode flashMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetFlashMode is called");

    FlashMode innerFlashMode = static_cast<FlashMode>(flashMode);
    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetFlashMode(innerFlashMode);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::IsExposureModeSupported(Camera_ExposureMode exposureMode, bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::IsExposureModeSupported is called");
    ExposureMode innerExposureMode = static_cast<ExposureMode>(exposureMode);
    int32_t ret = innerCaptureSession_->IsExposureModeSupported(innerExposureMode, *isSupported);
    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetExposureMode(Camera_ExposureMode* exposureMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetExposureMode is called");

    *exposureMode = static_cast<Camera_ExposureMode>(innerCaptureSession_->GetExposureMode());
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetExposureMode(Camera_ExposureMode exposureMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetExposureMode is called");

    ExposureMode innerExposureMode = static_cast<ExposureMode>(exposureMode);
    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetExposureMode(innerExposureMode);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetMeteringPoint(Camera_Point* point)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetMeteringPoint is called");

    Point innerFocusPoint = innerCaptureSession_->GetMeteringPoint();
    (*point).x = innerFocusPoint.x;
    (*point).y = innerFocusPoint.y;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetMeteringPoint(Camera_Point point)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetMeteringPoint is called");
    Point innerExposurePoint;
    innerExposurePoint.x = point.x;
    innerExposurePoint.y = point.y;

    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetMeteringPoint(innerExposurePoint);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetExposureBiasRange(float* minExposureBias,
    float* maxExposureBias, float* step)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetExposureBiasRange is called");

    std::vector<float> vecExposureBiasList = innerCaptureSession_->GetExposureBiasRange();
    constexpr int32_t ARGS_TWO = 2;
    if (!vecExposureBiasList.empty() && vecExposureBiasList.size() >= ARGS_TWO) {
        *minExposureBias = vecExposureBiasList[0];
        *maxExposureBias = vecExposureBiasList[1];
    } else {
        MEDIA_ERR_LOG("Camera_CaptureSession::GetExposureBiasRange vecZoomRatioList illegal.");
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetExposureBias(float exposureBias)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetExposureBias is called");

    innerCaptureSession_->LockForControl();
    int32_t ret = innerCaptureSession_->SetExposureBias(exposureBias);
    innerCaptureSession_->UnlockForControl();

    if (ret != CameraErrorCode::SUCCESS) {
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetExposureBias(float* exposureBias)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetExposureBias is called");

    *exposureBias = innerCaptureSession_->GetExposureValue();

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::AddVideoOutput(Camera_VideoOutput* videoOutput)
{
    sptr<CaptureOutput> innerVideoOutput = videoOutput->GetInnerVideoOutput();
    int32_t ret = innerCaptureSession_->AddOutput(innerVideoOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RemoveVideoOutput(Camera_VideoOutput* videoOutput)
{
    sptr<CaptureOutput> innerVideoOutput = videoOutput->GetInnerVideoOutput();
    int32_t ret = innerCaptureSession_->RemoveOutput(innerVideoOutput);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::Start()
{
    int32_t ret = innerCaptureSession_->Start();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::Stop()
{
    int32_t ret = innerCaptureSession_->Stop();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::Release()
{
    int32_t ret = innerCaptureSession_->Release();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::CanAddInput(Camera_Input* cameraInput, bool* isSuccessful)
{
    sptr<CaptureInput> innerCameraInput = cameraInput->GetInnerCameraInput();
    *isSuccessful = innerCaptureSession_->CanAddInput(innerCameraInput);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::CanAddPreviewOutput(Camera_PreviewOutput* previewOutput, bool* isSuccessful)
{
    sptr<CaptureOutput> innerPreviewOutput = previewOutput->GetInnerPreviewOutput();
    *isSuccessful = innerCaptureSession_->CanAddOutput(innerPreviewOutput);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::CanAddPhotoOutput(Camera_PhotoOutput* photoOutput, bool* isSuccessful)
{
    sptr<CaptureOutput> innerPhotoOutput = photoOutput->GetInnerPhotoOutput();
    *isSuccessful = innerCaptureSession_->CanAddOutput(innerPhotoOutput);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::CanAddVideoOutput(Camera_VideoOutput* videoOutput, bool* isSuccessful)
{
    sptr<CaptureOutput> innerVideoOutput = videoOutput->GetInnerVideoOutput();
    *isSuccessful = innerCaptureSession_->CanAddOutput(innerVideoOutput);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::CanPreconfig(Camera_PreconfigType preconfigType, bool* canPreconfig)
{
    auto itr = g_ndkToFwPreconfig.find(preconfigType);
    if (itr == g_ndkToFwPreconfig.end()) {
        MEDIA_ERR_LOG("Camera_CaptureSession::CanPreconfig preconfigType: [%{public}d] is invalid!", preconfigType);
        *canPreconfig = false;
        return CAMERA_INVALID_ARGUMENT;
    }

    *canPreconfig = innerCaptureSession_->CanPreconfig(itr->second, ProfileSizeRatio::UNSPECIFIED);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::CanPreconfigWithRatio(Camera_PreconfigType preconfigType,
    Camera_PreconfigRatio preconfigRatio, bool* canPreconfig)
{
    auto type = g_ndkToFwPreconfig.find(preconfigType);
    auto ratio = g_ndkToFwPreconfigRatio.find(preconfigRatio);
    if (type == g_ndkToFwPreconfig.end() || ratio == g_ndkToFwPreconfigRatio.end()) {
        MEDIA_ERR_LOG("Camera_CaptureSession::CanPreconfigWithRatio preconfigType: [%{public}d] "
            "or preconfigRatio: [%{public}d] is invalid!", preconfigType, preconfigRatio);
        *canPreconfig = false;
        return CAMERA_INVALID_ARGUMENT;
    }

    *canPreconfig = innerCaptureSession_->CanPreconfig(type->second, ratio->second);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::Preconfig(Camera_PreconfigType preconfigType)
{
    auto itr = g_ndkToFwPreconfig.find(preconfigType);
    CHECK_AND_RETURN_RET_LOG(itr != g_ndkToFwPreconfig.end(), CAMERA_INVALID_ARGUMENT,
        "Camera_CaptureSession::Preconfig preconfigType: [%{public}d] is invalid!", preconfigType);

    int32_t ret = innerCaptureSession_->Preconfig(itr->second, ProfileSizeRatio::UNSPECIFIED);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::PreconfigWithRatio(Camera_PreconfigType preconfigType,
    Camera_PreconfigRatio preconfigRatio)
{
    auto type = g_ndkToFwPreconfig.find(preconfigType);
    auto ratio = g_ndkToFwPreconfigRatio.find(preconfigRatio);
    CHECK_AND_RETURN_RET_LOG(type != g_ndkToFwPreconfig.end(), CAMERA_INVALID_ARGUMENT,
        "Camera_CaptureSession::PreconfigWithRatio preconfigType: [%{public}d] is invalid!", preconfigType);
    CHECK_AND_RETURN_RET_LOG(ratio != g_ndkToFwPreconfigRatio.end(), CAMERA_INVALID_ARGUMENT,
        "Camera_CaptureSession::PreconfigWithRatio preconfigRatio: [%{public}d] is invalid!", preconfigRatio);

    int32_t ret = innerCaptureSession_->Preconfig(type->second, ratio->second);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetExposureValue(float* exposureValue)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetExposureValue is called");

    int32_t ret = innerCaptureSession_->GetExposureValue(*exposureValue);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetFocalLength(float* focalLength)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetFocalLength is called");

    int32_t ret = innerCaptureSession_->GetFocalLength(*focalLength);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::SetSmoothZoom(float targetZoom, Camera_SmoothZoomMode smoothZoomMode)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetSmoothZoom is called");

    int32_t ret = innerCaptureSession_->SetSmoothZoom(targetZoom, static_cast<uint32_t>(smoothZoomMode));
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::GetSupportedColorSpaces(OH_NativeBuffer_ColorSpace** colorSpace,
    uint32_t* size)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetSupportedColorSpaces is called");

    auto colorSpaces = innerCaptureSession_->GetSupportedColorSpaces();
    if (colorSpaces.empty()) {
        MEDIA_ERR_LOG("Supported ColorSpace is empty!");
        *size = 0;
        return CAMERA_OK;
    }

    std::vector<OH_NativeBuffer_ColorSpace> cameraColorSpace;
    for (size_t i = 0; i < colorSpaces.size(); ++i) {
        auto itr = g_fwToNdkColorSpace_.find(colorSpaces[i]);
        if (itr != g_fwToNdkColorSpace_.end()) {
            cameraColorSpace.push_back(itr->second);
        }
    }

    if (cameraColorSpace.size() == 0) {
        MEDIA_ERR_LOG("Supported ColorSpace is empty!");
        *size = 0;
        return CAMERA_OK;
    }

    OH_NativeBuffer_ColorSpace* newColorSpace = new OH_NativeBuffer_ColorSpace[cameraColorSpace.size()];
    CHECK_AND_RETURN_RET_LOG(newColorSpace != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Failed to allocate memory for color space!");
    for (size_t index = 0; index < cameraColorSpace.size(); index++) {
        newColorSpace[index] = cameraColorSpace[index];
    }

    *size = cameraColorSpace.size();
    *colorSpace = newColorSpace;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::DeleteColorSpaces(OH_NativeBuffer_ColorSpace* colorSpace)
{
    if (colorSpace != nullptr) {
        delete[] colorSpace;
        colorSpace = nullptr;
    }

    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::GetActiveColorSpace(OH_NativeBuffer_ColorSpace* colorSpace)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::GetActiveColorSpace is called");

    ColorSpace innerColorSpace;
    int32_t ret = innerCaptureSession_->GetActiveColorSpace(innerColorSpace);
    if (ret != SUCCESS) {
        return FrameworkToNdkCameraError(ret);
    }
    auto itr = g_fwToNdkColorSpace_.find(innerColorSpace);
    if (itr != g_fwToNdkColorSpace_.end()) {
        *colorSpace = itr->second;
    } else {
        MEDIA_ERR_LOG("colorSpace[%{public}d] is invalid", innerColorSpace);
        return CAMERA_SERVICE_FATAL_ERROR;
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetActiveColorSpace(OH_NativeBuffer_ColorSpace colorSpace)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::SetActiveColorSpace is called");

    auto itr = g_ndkToFwColorSpace_.find(colorSpace);
    if (itr == g_ndkToFwColorSpace_.end()) {
        MEDIA_ERR_LOG("colorSpace[%{public}d] is invalid", colorSpace);
        return CAMERA_INVALID_ARGUMENT;
    }
    int32_t ret = innerCaptureSession_->SetColorSpace(itr->second);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_CaptureSession::RegisterAutoDeviceSwitchStatusCallback(
    OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusChange)
{
    shared_ptr<InnerCaptureSessionAutoDeviceSwitchStatusCallback> innerDeviceSwitchStatusCallback =
        make_shared<InnerCaptureSessionAutoDeviceSwitchStatusCallback>(this, autoDeviceSwitchStatusChange);
    CHECK_AND_RETURN_RET_LOG(innerDeviceSwitchStatusCallback != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "create innerCallback failed!");
    innerCaptureSession_->SetAutoDeviceSwitchCallback(innerDeviceSwitchStatusCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::UnregisterAutoDeviceSwitchStatusCallback(
    OH_CaptureSession_OnAutoDeviceSwitchStatusChange autoDeviceSwitchStatusChange)
{
    innerCaptureSession_->SetAutoDeviceSwitchCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::IsAutoDeviceSwitchSupported(bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::IsAutoDeviceSwitchSupported is called");
    *isSupported = innerCaptureSession_->IsAutoDeviceSwitchSupported();
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::EnableAutoDeviceSwitch(bool enabled)
{
    MEDIA_DEBUG_LOG("Camera_CaptureSession::EnableAutoDeviceSwitch is called");
    int32_t ret = innerCaptureSession_->EnableAutoDeviceSwitch(enabled);
    return FrameworkToNdkCameraError(ret);
}