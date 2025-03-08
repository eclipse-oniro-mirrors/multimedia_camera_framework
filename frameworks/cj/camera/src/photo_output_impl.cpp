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

#include "photo_output_impl.h"
#include "camera_error.h"
#include "camera_log.h"
#include "cj_lambda.h"

namespace OHOS {
namespace CameraStandard {

thread_local sptr<PhotoOutput> CJPhotoOutput::sPhotoOutput_ = nullptr;

void CJPhotoOutputCallback::OnCaptureStarted(const int32_t captureId) const
{
}

void CJPhotoOutputCallback::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const
{
    std::lock_guard<std::mutex> lock(captureStartedMutex);
    if (captureStartedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < captureStartedCallbackList.size(); i++) {
        if (captureStartedCallbackList[i] != nullptr) {
            captureStartedCallbackList[i]->ref(captureId, exposureTime);
        }
    }
}

void CJPhotoOutputCallback::OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const
{
    std::lock_guard<std::mutex> lock(captureEndedMutex);
    if (captureEndedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < captureEndedCallbackList.size(); i++) {
        if (captureEndedCallbackList[i] != nullptr) {
            captureEndedCallbackList[i]->ref(captureId, frameCount);
        }
    }
}

void CJPhotoOutputCallback::OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const
{
    std::lock_guard<std::mutex> lock(frameShutterMutex);
    if (frameShutterCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameShutterCallbackList.size(); i++) {
        if (frameShutterCallbackList[i] != nullptr) {
            frameShutterCallbackList[i]->ref(captureId, timestamp);
        }
    }
}

void CJPhotoOutputCallback::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const
{
    std::lock_guard<std::mutex> lock(frameShutterEndMutex);
    if (frameShutterEndCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameShutterEndCallbackList.size(); i++) {
        if (frameShutterEndCallbackList[i] != nullptr) {
            frameShutterEndCallbackList[i]->ref(captureId);
        }
    }
}

void CJPhotoOutputCallback::OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const
{
    std::lock_guard<std::mutex> lock(captureReadyMutex);
    if (captureReadyCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < captureReadyCallbackList.size(); i++) {
        if (captureReadyCallbackList[i] != nullptr) {
            captureReadyCallbackList[i]->ref();
        }
    }
}

void CJPhotoOutputCallback::OnCaptureError(const int32_t captureId, const int32_t errorCode) const
{
    std::lock_guard<std::mutex> lock(captureErrorMutex);
    if (captureErrorCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < captureErrorCallbackList.size(); i++) {
        if (captureErrorCallbackList[i] != nullptr) {
            captureErrorCallbackList[i]->ref(errorCode);
        }
    }
}

void CJPhotoOutputCallback::OnEstimatedCaptureDuration(const int32_t duration) const
{
    std::lock_guard<std::mutex> lock(estimatedCaptureDurationMutex);
    if (estimatedCaptureDurationCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < estimatedCaptureDurationCallbackList.size(); i++) {
        if (estimatedCaptureDurationCallbackList[i] != nullptr) {
            estimatedCaptureDurationCallbackList[i]->ref(duration);
        }
    }
}

void CJPhotoOutputCallback::OnOfflineDeliveryFinished(const int32_t captureId) const
{
    return;
}

CJPhotoOutput::CJPhotoOutput()
{
    photoOutput_ = sPhotoOutput_;
    sPhotoOutput_ = nullptr;
}

sptr<CameraStandard::CaptureOutput> CJPhotoOutput::GetCameraOutput()
{
    return photoOutput_;
}

int32_t CJPhotoOutput::Release()
{
    if (photoOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput_->Release();
}

int32_t CJPhotoOutput::CreatePhotoOutput()
{
    sptr<Surface> photoSurface;
    MEDIA_INFO_LOG("create surface as consumer");
    photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
    if (photoSurface == nullptr) {
        MEDIA_ERR_LOG("failed to get surface");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
    MEDIA_INFO_LOG("surface width: %{public}d, height: %{public}d", photoSurface->GetDefaultWidth(),
                   photoSurface->GetDefaultHeight());
    int retCode =
        CameraManager::GetInstance()->CreatePhotoOutputWithoutProfile(surfaceProducer, &sPhotoOutput_, photoSurface);
    if (sPhotoOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
    }
    return retCode;
}

int32_t CJPhotoOutput::CreatePhotoOutputWithProfile(Profile &profile)
{
    MEDIA_DEBUG_LOG("CreatePhotoOutput is called, profile CameraFormat= %{public}d", profile.GetCameraFormat());
    sptr<Surface> photoSurface;
    MEDIA_INFO_LOG("create surface as consumer");
    photoSurface = Surface::CreateSurfaceAsConsumer("photoOutput");
    if (photoSurface == nullptr) {
        MEDIA_ERR_LOG("failed to get surface");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    photoSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    sptr<IBufferProducer> surfaceProducer = photoSurface->GetProducer();
    MEDIA_INFO_LOG("profile width: %{public}d, height: %{public}d, format = %{public}d, "
                   "surface width: %{public}d, height: %{public}d",
                   profile.GetSize().width, profile.GetSize().height, static_cast<int32_t>(profile.GetCameraFormat()),
                   photoSurface->GetDefaultWidth(), photoSurface->GetDefaultHeight());
    int retCode =
        CameraManager::GetInstance()->CreatePhotoOutput(profile, surfaceProducer, &sPhotoOutput_, photoSurface);
    if (sPhotoOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create CreatePhotoOutput");
        return retCode;
    }
    sPhotoOutput_->SetNativeSurface(true);
    if (sPhotoOutput_->IsYuvOrHeifPhoto()) {
        sPhotoOutput_->CreateMultiChannel();
    }
    return retCode;
}

int32_t CJPhotoOutput::Capture()
{
    MEDIA_INFO_LOG("Capture is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput_->Capture();
}

int32_t CJPhotoOutput::Capture(CJPhotoCaptureSetting setting)
{
    MEDIA_INFO_LOG("Capture is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();
    if (capSettings == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    capSettings->SetQuality(static_cast<PhotoCaptureSetting::QualityLevel>(setting.quality));
    capSettings->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(setting.rotation));
    capSettings->SetMirror(setting.mirror);
    auto location = make_shared<Location>();
    location->latitude = setting.location.latitude;
    location->longitude = setting.location.longitude;
    location->altitude = setting.location.altitude;
    capSettings->SetLocation(location);
    return photoOutput_->Capture(capSettings);
}

bool CJPhotoOutput::IsMovingPhotoSupported(int32_t *errCode)
{
    MEDIA_INFO_LOG("IsMovingPhotoSupported is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    auto session = photoOutput_->GetSession();
    if (session == nullptr) {
        MEDIA_ERR_LOG("session is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    bool isSupported = session->IsMovingPhotoSupported();
    return isSupported;
}

int32_t CJPhotoOutput::EnableMovingPhoto(bool enabled)
{
    MEDIA_INFO_LOG("EnableMovingPhoto is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    auto session = photoOutput_->GetSession();
    if (session == nullptr) {
        MEDIA_ERR_LOG("session is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    session->LockForControl();
    int32_t retCode = session->EnableMovingPhoto(enabled);
    session->UnlockForControl();
    return retCode;
}

bool CJPhotoOutput::IsMirrorSupported(int32_t *errCode)
{
    MEDIA_INFO_LOG("IsMirrorSupported is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return false;
    }
    bool isSupported = photoOutput_->IsMirrorSupported();
    return isSupported;
}

int32_t CJPhotoOutput::EnableMirror(bool isMirror)
{
    MEDIA_INFO_LOG("EnableMirror is called!");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    auto session = photoOutput_->GetSession();
    if (session == nullptr) {
        MEDIA_ERR_LOG("session is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    auto isSessionConfiged = session->IsSessionCommited() || session->IsSessionStarted();
    return session->EnableMovingPhotoMirror(isMirror, isSessionConfiged);
}

int32_t CJPhotoOutput::SetMovingPhotoVideoCodecType(int32_t codecType)
{
    MEDIA_DEBUG_LOG("SetMovingPhotoVideoCodecType is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return photoOutput_->SetMovingPhotoVideoCodecType(codecType);
}

CJProfile CJPhotoOutput::GetActiveProfile(int32_t *errCode)
{
    MEDIA_DEBUG_LOG("GetActiveProfile is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJProfile{0};
    }
    auto profile = photoOutput_->GetPhotoProfile();
    if (profile == nullptr) {
        MEDIA_ERR_LOG("profile is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJProfile{0};
    }
    return CJProfile{
        .format = profile->GetCameraFormat(), .width = profile->GetSize().width, .height = profile->GetSize().height};
}

int32_t CJPhotoOutput::GetPhotoRotation(int32_t deviceDegree, int32_t *errCode)
{
    MEDIA_DEBUG_LOG("GetPhotoRotation is called");
    if (photoOutput_ == nullptr) {
        MEDIA_ERR_LOG("photooutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    int32_t retCode = photoOutput_->GetPhotoRotation(deviceDegree);
    if (retCode == CameraError::CAMERA_SERVICE_ERROR) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return retCode;
}

void CJPhotoOutput::OnCaptureStartWithInfo(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJCaptureStartInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t captureId, uint32_t exposureTime) -> void {
        lambda(CJCaptureStartInfo{captureId, exposureTime});
    };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t, uint32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureStartedMutex);
    photoOutputCallback_->captureStartedCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffCaptureStartWithInfo(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureStartedMutex);
    for (auto it = photoOutputCallback_->captureStartedCallbackList.begin();
        it != photoOutputCallback_->captureStartedCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->captureStartedCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllCaptureStartWithInfo()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureStartedMutex);
    photoOutputCallback_->captureStartedCallbackList.clear();
}

void CJPhotoOutput::OnFrameShutter(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJFrameShutterInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t captureId, const uint64_t timestamp) -> void {
        lambda(CJFrameShutterInfo{captureId, timestamp});
    };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t, const uint64_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterMutex);
    photoOutputCallback_->frameShutterCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffFrameShutter(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterMutex);
    for (auto it = photoOutputCallback_->frameShutterCallbackList.begin();
        it != photoOutputCallback_->frameShutterCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->frameShutterCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllFrameShutter()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterMutex);
    photoOutputCallback_->frameShutterCallbackList.clear();
}

void CJPhotoOutput::OnCaptureEnd(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJCaptureEndInfo info)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t captureId, const int32_t frameCount) -> void {
        lambda(CJCaptureEndInfo{captureId, frameCount});
    };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t, const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureEndedMutex);
    photoOutputCallback_->captureEndedCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffCaptureEnd(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureEndedMutex);
    for (auto it = photoOutputCallback_->captureEndedCallbackList.begin();
        it != photoOutputCallback_->captureEndedCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->captureEndedCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllCaptureEnd()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureEndedMutex);
    photoOutputCallback_->captureEndedCallbackList.clear();
}

void CJPhotoOutput::OnFrameShutterEnd(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t id)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t captureId) -> void { lambda(captureId); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterEndMutex);
    photoOutputCallback_->frameShutterEndCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffFrameShutterEnd(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterEndMutex);
    for (auto it = photoOutputCallback_->frameShutterEndCallbackList.begin();
        it != photoOutputCallback_->frameShutterEndCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->frameShutterEndCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllFrameShutterEnd()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->frameShutterEndMutex);
    photoOutputCallback_->frameShutterEndCallbackList.clear();
}

void CJPhotoOutput::OnCaptureReady(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    auto callbackRef = std::make_shared<CallbackRef<>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureReadyMutex);
    photoOutputCallback_->captureReadyCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffCaptureReady(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureReadyMutex);
    for (auto it = photoOutputCallback_->captureReadyCallbackList.begin();
        it != photoOutputCallback_->captureReadyCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->captureReadyCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllCaptureReady()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureReadyMutex);
    photoOutputCallback_->captureReadyCallbackList.clear();
}

void CJPhotoOutput::OnEstimatedCaptureDuration(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t duration)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t duration) -> void { lambda(duration); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->estimatedCaptureDurationMutex);
    photoOutputCallback_->estimatedCaptureDurationCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffEstimatedCaptureDuration(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->estimatedCaptureDurationMutex);
    for (auto it = photoOutputCallback_->estimatedCaptureDurationCallbackList.begin();
        it != photoOutputCallback_->estimatedCaptureDurationCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->estimatedCaptureDurationCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllEstimatedCaptureDuration()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->estimatedCaptureDurationMutex);
    photoOutputCallback_->estimatedCaptureDurationCallbackList.clear();
}

void CJPhotoOutput::OnError(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        photoOutputCallback_ = std::make_shared<CJPhotoOutputCallback>();
        if (photoOutputCallback_ == nullptr || photoOutput_ == nullptr) {
            return;
        }
        photoOutput_->SetCallback(photoOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t errorCode)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t errorCode) -> void { lambda(errorCode); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureErrorMutex);
    photoOutputCallback_->captureErrorCallbackList.push_back(callbackRef);
}

void CJPhotoOutput::OffError(int64_t callbackId)
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureErrorMutex);
    for (auto it = photoOutputCallback_->captureErrorCallbackList.begin();
        it != photoOutputCallback_->captureErrorCallbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            photoOutputCallback_->captureErrorCallbackList.erase(it);
            break;
        }
    }
}

void CJPhotoOutput::OffAllError()
{
    if (photoOutputCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(photoOutputCallback_->captureErrorMutex);
    photoOutputCallback_->captureErrorCallbackList.clear();
}

} // namespace CameraStandard
} // namespace OHOS