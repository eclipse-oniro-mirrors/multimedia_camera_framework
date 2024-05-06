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

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;
const int32_t ARGS_TWO = 2;

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
    innerCaptureSession_->SetCallback(innerCallback);
    innerCaptureSession_->SetFocusCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::UnregisterCallback(CaptureSession_Callbacks* callback)
{
    innerCaptureSession_->SetCallback(nullptr);
    innerCaptureSession_->SetFocusCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::SetSessionMode(Camera_SceneMode sceneMode)
{
    SceneMode innerSceneMode = static_cast<SceneMode>(sceneMode);
    innerCaptureSession_->SetMode(innerSceneMode);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_CaptureSession::AddSecureOutput(Camera_PreviewOutput* previewOutput)
{
    sptr<CaptureOutput> innerPreviewOutput = previewOutput->GetInnerPreviewOutput();
    int32_t ret = innerCaptureSession_->AddSecureOutput(innerPreviewOutput);
    return FrameworkToNdkCameraError(ret);
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