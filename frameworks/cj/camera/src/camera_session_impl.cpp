/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdlib>
#include <iomanip>
#include <map>
#include <refbase.h>
#include <string>
#include <variant>
#include <vector>
#include "camera_log.h"
#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "securec.h"

#include "camera_session_impl.h"

using namespace OHOS::FFI;

namespace OHOS::CameraStandard {
CJSession::CJSession(sptr<CameraStandard::CaptureSession> session)
{
    session_ = session;
}

sptr<CameraStandard::CaptureSession> CJSession::GetCaptureSession()
{
    return session_;
}

int32_t CJSession::BeginConfig()
{
    return session_->BeginConfig();
}

int32_t CJSession::CommitConfig()
{
    return session_->CommitConfig();
}

bool CJSession::CanAddInput(sptr<CJCameraInput> cameraInput)
{
    sptr<CameraStandard::CaptureInput> captureInput = cameraInput->GetCameraInput();
    return session_->CanAddInput(captureInput);
}

int32_t CJSession::AddInput(sptr<CJCameraInput> cameraInput)
{
    sptr<CameraStandard::CaptureInput> captureInput = cameraInput->GetCameraInput();
    return session_->AddInput(captureInput);
}

int32_t CJSession::RemoveInput(sptr<CJCameraInput> cameraInput)
{
    sptr<CameraStandard::CaptureInput> captureInput = cameraInput->GetCameraInput();
    return session_->RemoveInput(captureInput);
}

bool CJSession::CanAddOutput(sptr<CameraOutput> cameraOutput)
{
    sptr<CameraStandard::CaptureOutput> captureOutput = cameraOutput->GetCameraOutput();
    return session_->CanAddOutput(captureOutput);
}

int32_t CJSession::AddOutput(sptr<CameraOutput> cameraOutput)
{
    sptr<CameraStandard::CaptureOutput> captureOutput = cameraOutput->GetCameraOutput();
    return session_->AddOutput(captureOutput);
}

int32_t CJSession::RemoveOutput(sptr<CameraOutput> cameraOutput)
{
    sptr<CameraStandard::CaptureOutput> captureOutput = cameraOutput->GetCameraOutput();
    return session_->RemoveOutput(captureOutput);
}

int32_t CJSession::Start()
{
    return session_->Start();
}

int32_t CJSession::Stop()
{
    return session_->Stop();
}

int32_t CJSession::Release()
{
    return session_->Release();
}

int32_t CJSession::CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio, bool &isSupported)
{
    isSupported = session_->CanPreconfig(preconfigType, preconfigRatio);

    return CameraErrorCode::SUCCESS;
}

int32_t CJSession::Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    return session_->Preconfig(preconfigType, preconfigRatio);
}

int32_t CJSession::AddSecureOutput(sptr<CameraOutput> cameraOutput)
{
    sptr<CameraStandard::CaptureOutput> captureOutput = cameraOutput->GetCameraOutput();
    return session_->AddSecureOutput(captureOutput);
}

int32_t CJSession::IsExposureModeSupported(ExposureMode mode, bool &isSupported)
{
    return session_->IsExposureModeSupported(mode, isSupported);
}

int32_t CJSession::GetExposureBiasRange(CArrFloat32 &cArr)
{
    std::vector<float> exposureBiasRange;
    int32_t ret = session_->GetExposureBiasRange(exposureBiasRange);

    cArr.size = exposureBiasRange.size();
    cArr.head = static_cast<float *>(malloc(sizeof(float) * cArr.size));
    for (int i = 0; i < cArr.size; i++) {
        cArr.head[i] = exposureBiasRange[i];
    }

    return ret;
}

int32_t CJSession::GetExposureMode(ExposureMode &mode)
{
    return session_->GetExposureMode(mode);
}

int32_t CJSession::SetExposureMode(ExposureMode mode)
{
    session_->LockForControl();
    int32_t ret = session_->SetExposureMode(mode);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::GetMeteringPoint(Point &point)
{
    session_->LockForControl();
    int32_t ret = session_->GetMeteringPoint(point);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::SetMeteringPoint(Point point)
{
    session_->LockForControl();
    int32_t ret = session_->SetMeteringPoint(point);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::SetExposureBias(float value)
{
    session_->LockForControl();
    int32_t ret = session_->SetExposureBias(value);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::GetExposureValue(float &value)
{
    return session_->GetExposureValue(value);
}

void CJSession::GetSupportedColorSpaces(CArrI32 &cArr)
{
    auto colorSpaces = session_->GetSupportedColorSpaces();

    cArr.size = colorSpaces.size();
    cArr.head = static_cast<int32_t *>(malloc(sizeof(int32_t) * cArr.size));
    for (int i = 0; i < cArr.size; i++) {
        cArr.head[i] = static_cast<int32_t>(colorSpaces[i]);
    }

    return;
}

int32_t CJSession::SetColorSpace(ColorSpace colorSpace)
{
    return session_->SetColorSpace(colorSpace);
}

int32_t CJSession::GetActiveColorSpace(ColorSpace &colorSpace)
{
    return session_->GetActiveColorSpace(colorSpace);
}

int32_t CJSession::IsFlashModeSupported(FlashMode mode, bool &isSupported)
{
    return session_->IsFlashModeSupported(mode, isSupported);
}

int32_t CJSession::HasFlash(bool &hasFlash)
{
    return session_->HasFlash(hasFlash);
}

int32_t CJSession::GetFlashMode(FlashMode &mode)
{
    return session_->GetFlashMode(mode);
}

int32_t CJSession::SetFlashMode(FlashMode mode)
{
    session_->LockForControl();
    int32_t ret = session_->SetFlashMode(mode);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::IsFocusModeSupported(FocusMode mode, bool &isSupported)
{
    return session_->IsFocusModeSupported(mode, isSupported);
}

int32_t CJSession::SetFocusMode(FocusMode mode)
{
    session_->LockForControl();
    int32_t ret = session_->SetFocusMode(mode);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::GetFocusMode(FocusMode &mode)
{
    session_->LockForControl();
    int32_t ret = session_->GetFocusMode(mode);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::SetFocusPoint(Point point)
{
    session_->LockForControl();
    int32_t ret = session_->SetFocusPoint(point);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::GetFocusPoint(Point &point)
{
    return session_->GetFocusPoint(point);
}

int32_t CJSession::GetFocalLength(float &focalLength)
{
    return session_->GetFocalLength(focalLength);
}

int32_t CJSession::IsVideoStabilizationModeSupported(VideoStabilizationMode mode, bool &isSupported)
{
    return session_->IsVideoStabilizationModeSupported(mode, isSupported);
}

int32_t CJSession::GetActiveVideoStabilizationMode(VideoStabilizationMode &mode)
{
    return session_->GetActiveVideoStabilizationMode(mode);
}

int32_t CJSession::SetVideoStabilizationMode(VideoStabilizationMode mode)
{
    return session_->SetVideoStabilizationMode(mode);
}

int32_t CJSession::GetZoomRatioRange(CArrFloat32 &ranges)
{
    std::vector<float> zoomRatioRange;
    int32_t ret = session_->GetZoomRatioRange(zoomRatioRange);

    ranges.size = zoomRatioRange.size();
    ranges.head = static_cast<float *>(malloc(sizeof(float) * ranges.size));
    for (int i = 0; i < ranges.size; i++) {
        ranges.head[i] = zoomRatioRange[i];
    }

    return ret;
}

int32_t CJSession::SetZoomRatio(float ratio)
{
    session_->LockForControl();
    int32_t ret = session_->SetZoomRatio(ratio);
    session_->UnlockForControl();
    return ret;
}

int32_t CJSession::GetZoomRatio(float &ratio)
{
    return session_->GetZoomRatio(ratio);
}

int32_t CJSession::SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType)
{
    return session_->SetSmoothZoom(targetZoomRatio, smoothZoomType);
}

void CJSession::OnSmoothZoom(int64_t callbackId)
{
    if (smoothZoomCallback_ == nullptr) {
        smoothZoomCallback_ = std::make_shared<CJSmoothZoomCallback>();
        session_->SetSmoothZoomCallback(smoothZoomCallback_);
    }

    // wrapper that helps us execute CJ callback according to the id
    auto callback = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callbackId));
    auto callbackRef = std::make_shared<CallbackRef<int32_t>>(callback, callbackId);
    smoothZoomCallback_->SaveCallbackRef(callbackRef);
}

void CJSession::OffSmoothZoom(int64_t callbackId)
{
    if (smoothZoomCallback_ == nullptr) {
        MEDIA_ERR_LOG("smoothZoomCallback is null");
        return;
    }
    smoothZoomCallback_->RemoveCallbackRef(callbackId);
}

void CJSession::OffAllSmoothZoom()
{
    if (smoothZoomCallback_ == nullptr) {
        MEDIA_ERR_LOG("smoothZoomCallback is null");
        return;
    }
    smoothZoomCallback_->RemoveAllCallbackRef();
}

void CJSession::OnError(int64_t callbackId)
{
    if (errorCallback_ == nullptr) {
        errorCallback_ = std::make_shared<CJSessionCallback>();
        session_->SetCallback(errorCallback_);
    }

    auto callback = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callbackId));
    auto callbackRef = std::make_shared<CallbackRef<int32_t>>(callback, callbackId);
    errorCallback_->SaveCallbackRef(callbackRef);
}

void CJSession::OffError(int64_t callbackId)
{
    if (errorCallback_ == nullptr) {
        MEDIA_ERR_LOG("errorCallback is null");
        return;
    }
    errorCallback_->RemoveCallbackRef(callbackId);
}

void CJSession::OffAllError()
{
    if (errorCallback_ == nullptr) {
        MEDIA_ERR_LOG("errorCallback is null");
        return;
    }
    errorCallback_->RemoveAllCallbackRef();
}

void CJSession::OnFocusStateChange(int64_t callbackId)
{
    if (focusStateCallback_ == nullptr) {
        focusStateCallback_ = std::make_shared<CJFocusStateCallback>();
        session_->SetFocusCallback(focusStateCallback_);
    }

    auto callback = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callbackId));
    auto callbackRef = std::make_shared<CallbackRef<int32_t>>(callback, callbackId);
    focusStateCallback_->SaveCallbackRef(callbackRef);
}

void CJSession::OffFocusStateChange(int64_t callbackId)
{
    if (focusStateCallback_ == nullptr) {
        MEDIA_ERR_LOG("focusStateCallback is null");
        return;
    }
    focusStateCallback_->RemoveCallbackRef(callbackId);
}

void CJSession::OffAllFocusStateChange()
{
    if (focusStateCallback_ == nullptr) {
        MEDIA_ERR_LOG("focusStateCallback is null");
        return;
    }
    focusStateCallback_->RemoveAllCallbackRef();
}

void CJSmoothZoomCallback::OnSmoothZoom(int32_t duration)
{
    MEDIA_DEBUG_LOG("OnSmoothZoomInfoAvailable is called");
    ExecuteCallback(duration);
}

void CJSessionCallback::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("OnError is called");
    ExecuteCallback(errorCode);
}

void CJFocusStateCallback::OnFocusState(FocusState state)
{
    MEDIA_DEBUG_LOG("OnFocusStateChange is called");
    // CJ callback expects int32_t
    ExecuteCallback(static_cast<int32_t>(state));
}

} // namespace OHOS::CameraStandard