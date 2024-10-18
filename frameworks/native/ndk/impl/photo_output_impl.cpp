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

#include "photo_output_impl.h"

#include "camera_log.h"
#include "camera_util.h"
#include "inner_api/native/camera/include/session/capture_session.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;
const std::unordered_map<CameraFormat, Camera_Format> g_fwToNdkCameraFormat = {
    {CameraFormat::CAMERA_FORMAT_RGBA_8888, Camera_Format::CAMERA_FORMAT_RGBA_8888},
    {CameraFormat::CAMERA_FORMAT_YUV_420_SP, Camera_Format::CAMERA_FORMAT_YUV_420_SP},
    {CameraFormat::CAMERA_FORMAT_JPEG, Camera_Format::CAMERA_FORMAT_JPEG},
    {CameraFormat::CAMERA_FORMAT_YCBCR_P010, Camera_Format::CAMERA_FORMAT_YCBCR_P010},
    {CameraFormat::CAMERA_FORMAT_YCRCB_P010, Camera_Format::CAMERA_FORMAT_YCRCB_P010}
};

Camera_PhotoOutput::Camera_PhotoOutput(sptr<PhotoOutput> &innerPhotoOutput) : innerPhotoOutput_(innerPhotoOutput)
{
    MEDIA_DEBUG_LOG("Camera_PhotoOutput Constructor is called");
}

Camera_PhotoOutput::~Camera_PhotoOutput()
{
    MEDIA_DEBUG_LOG("~Camera_PhotoOutput is called");
    if (innerPhotoOutput_) {
        innerPhotoOutput_ = nullptr;
    }
    if (innerCallback_) {
        innerCallback_ = nullptr;
    }
    if (photoSurface_) {
        photoSurface_ = nullptr;
    }
    if (photoListener_) {
        photoListener_ = nullptr;
    }
    if (rawPhotoListener_) {
        rawPhotoListener_ = nullptr;
    }
    if (photoNative_) {
        delete photoNative_;
        photoNative_ = nullptr;
    }
}

Camera_ErrorCode Camera_PhotoOutput::RegisterCallback(PhotoOutput_Callbacks* callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    CHECK_AND_RETURN_RET_LOG(photoSurface_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "Photo surface is nullptr");

    if (photoListener_ == nullptr) {
        photoListener_ = new (std::nothrow) PhotoListener(this, photoSurface_);
        CHECK_AND_RETURN_RET_LOG(photoListener_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "Create photo listener failed");

        SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener_);
        CHECK_AND_RETURN_RET_LOG(ret == SURFACE_ERROR_OK, CAMERA_SERVICE_FATAL_ERROR,
            "Register surface consumer listener failed");
    }

    photoListener_->SetPhotoAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO;
    photoListener_->SetCallbackFlag(callbackFlag_);
    innerPhotoOutput_->SetCallbackFlag(callbackFlag_);

    // Preconfig can't support rawPhotoListener.
    return RegisterRawPhotoAvailableCallback(callback);
}

Camera_ErrorCode Camera_PhotoOutput::RegisterRawPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    std::shared_ptr<Profile> profile = innerPhotoOutput_->GetPhotoProfile();
    if (rawPhotoListener_ == nullptr && profile != nullptr &&
        profile->GetCameraFormat() == CAMERA_FORMAT_DNG &&
        innerPhotoOutput_->rawPhotoSurface_ != nullptr) {
        rawPhotoListener_ =
            new (std::nothrow) RawPhotoListener(this, innerPhotoOutput_->rawPhotoSurface_);
        CHECK_AND_RETURN_RET_LOG(rawPhotoListener_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "Create raw photo listener failed");

        SurfaceError ret = innerPhotoOutput_->rawPhotoSurface_->RegisterConsumerListener(
            (sptr<IBufferConsumerListener>&)rawPhotoListener_);
        CHECK_AND_RETURN_RET_LOG(ret == SURFACE_ERROR_OK, CAMERA_SERVICE_FATAL_ERROR,
            "Register surface consumer listener failed");
        rawPhotoListener_->SetCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback)
{
    CHECK_AND_RETURN_RET_LOG(photoSurface_ != nullptr, CAMERA_INVALID_ARGUMENT,
        "Photo surface is invalid");
    if (photoListener_ == nullptr) {
        photoListener_ = new (std::nothrow) PhotoListener(this, photoSurface_);
        CHECK_AND_RETURN_RET_LOG(photoListener_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "Create raw photo listener failed");

        SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener>&)photoListener_);
        CHECK_AND_RETURN_RET_LOG(ret == SURFACE_ERROR_OK, CAMERA_SERVICE_FATAL_ERROR,
            "Register surface consumer listener failed");
    }
    photoListener_->SetPhotoAssetAvailableCallback(callback);
    callbackFlag_ |= CAPTURE_PHOTO_ASSET;
    photoListener_->SetCallbackFlag(callbackFlag_);
    innerPhotoOutput_->SetCallbackFlag(callbackFlag_);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterCallback(PhotoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterCaptureStartWithInfoCallback(
    OH_PhotoOutput_CaptureStartWithInfo callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveCaptureStartWithInfoCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveCaptureStartWithInfoCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterCaptureStartWithInfoCallback(
    OH_PhotoOutput_CaptureStartWithInfo callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveCaptureStartWithInfoCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveCaptureEndCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveCaptureEndCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveCaptureEndCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveFrameShutterEndCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveFrameShutterEndCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveFrameShutterEndCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveCaptureReadyCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveCaptureReadyCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveCaptureReadyCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::RegisterEstimatedCaptureDurationCallback(
    OH_PhotoOutput_EstimatedCaptureDuration callback)
{
    if (innerCallback_ == nullptr) {
        innerCallback_ = make_shared<InnerPhotoOutputCallback>(this);
        CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_SERVICE_FATAL_ERROR,
            "create innerCallback_ failed!");
        innerCallback_->SaveEstimatedCaptureDurationCallback(callback);
        innerPhotoOutput_->SetCallback(innerCallback_);
    } else {
        innerCallback_->SaveEstimatedCaptureDurationCallback(callback);
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterEstimatedCaptureDurationCallback(
    OH_PhotoOutput_EstimatedCaptureDuration callback)
{
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, CAMERA_OPERATION_NOT_ALLOWED,
        "innerCallback_ is null! Please RegisterCallback first!");
    innerCallback_->RemoveEstimatedCaptureDurationCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    if (callback != nullptr) {
        if (photoListener_ != nullptr) {
            callbackFlag_ &= ~CAPTURE_PHOTO;
            photoListener_->SetCallbackFlag(callbackFlag_);
            photoListener_->UnregisterPhotoAvailableCallback(callback);
        }
        if (rawPhotoListener_ != nullptr) {
            rawPhotoListener_->UnregisterCallback(callback);
        }
    }
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback)
{
    if (callback != nullptr) {
        if (photoListener_ != nullptr) {
            callbackFlag_ &= ~CAPTURE_PHOTO_ASSET;
            photoListener_->SetCallbackFlag(callbackFlag_);
            photoListener_->UnregisterPhotoAssetAvailableCallback(callback);
        }
    }
    return CAMERA_OK;
}

void Camera_PhotoOutput::SetPhotoSurface(OHOS::sptr<OHOS::Surface> &photoSurface)
{
    photoSurface_ = photoSurface;
}

Camera_ErrorCode Camera_PhotoOutput::Capture()
{
    std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();
    capSettings->SetMirror(isMirrorEnable_);
    int32_t ret = innerPhotoOutput_->Capture(capSettings);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PhotoOutput::Capture_WithCaptureSetting(Camera_PhotoCaptureSetting setting)
{
    std::shared_ptr<PhotoCaptureSetting> capSettings = make_shared<PhotoCaptureSetting>();

    capSettings->SetQuality(static_cast<PhotoCaptureSetting::QualityLevel>(setting.quality));

    capSettings->SetRotation(static_cast<PhotoCaptureSetting::RotationConfig>(setting.rotation));

    if (setting.location != nullptr) {
        std::shared_ptr<Location> location = std::make_shared<Location>();
        location->latitude = setting.location->latitude;
        location->longitude = setting.location->longitude;
        location->altitude = setting.location->altitude;
        capSettings->SetLocation(location);
    }

    capSettings->SetMirror(setting.mirror);

    int32_t ret = innerPhotoOutput_->Capture(capSettings);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PhotoOutput::Release()
{
    int32_t ret = innerPhotoOutput_->Release();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PhotoOutput::IsMirrorSupported(bool* isSupported)
{
    *isSupported = innerPhotoOutput_->IsMirrorSupported();

    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::EnableMirror(bool enableMirror)
{
    int32_t ret = innerPhotoOutput_->EnableMirror(enableMirror);
    if (ret == napi_ok) {
        isMirrorEnable_ = enableMirror;
    }
    
    return FrameworkToNdkCameraError(ret);
}

sptr<PhotoOutput> Camera_PhotoOutput::GetInnerPhotoOutput()
{
    return innerPhotoOutput_;
}

OH_PhotoNative* Camera_PhotoOutput::CreateCameraPhotoNative(shared_ptr<Media::NativeImage> &image, bool isMain)
{
    if (!photoNative_) {
        photoNative_ = new(std::nothrow) OH_PhotoNative;
        CHECK_AND_RETURN_RET_LOG(photoNative_ != nullptr, nullptr, "Create camera photo native object failed");
    }

    if (isMain) {
        photoNative_->SetMainImage(image);
    } else {
        photoNative_->SetRawImage(image);
    }
    return photoNative_;
}

Camera_ErrorCode Camera_PhotoOutput::GetActiveProfile(Camera_Profile** profile)
{
    auto photoOutputProfile = innerPhotoOutput_->GetPhotoProfile();
    CHECK_AND_RETURN_RET_LOG(photoOutputProfile != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PhotoOutput::GetActiveProfile failed to get photo profile!");

    CameraFormat cameraFormat = photoOutputProfile->GetCameraFormat();
    auto itr = g_fwToNdkCameraFormat.find(cameraFormat);
    CHECK_AND_RETURN_RET_LOG(itr != g_fwToNdkCameraFormat.end(), CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PhotoOutput::GetActiveProfile unsupported camera format %{public}d", cameraFormat);

    Camera_Profile* newProfile = new Camera_Profile;
    CHECK_AND_RETURN_RET_LOG(newProfile != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PhotoOutput::GetActiveProfile failed to allocate memory for camera profile!");

    newProfile->format = itr->second;
    newProfile->size.width = photoOutputProfile->GetSize().width;
    newProfile->size.height = photoOutputProfile->GetSize().height;

    *profile = newProfile;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::IsMovingPhotoSupported(bool* isSupported)
{
    MEDIA_DEBUG_LOG("Camera_PhotoOutput IsMovingPhotoSupported is called");
    auto session = innerPhotoOutput_->GetSession();
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_SERVICE_FATAL_ERROR, "GetSession failed");

    *isSupported = session->IsMovingPhotoSupported();
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::EnableMovingPhoto(bool enableMovingPhoto)
{
    MEDIA_DEBUG_LOG("Camera_PhotoOutput EnableMovingPhoto is called");
    auto session = innerPhotoOutput_->GetSession();
    CHECK_AND_RETURN_RET_LOG(session != nullptr, CAMERA_SERVICE_FATAL_ERROR, "GetSession failed");

    session->LockForControl();
    int32_t ret = session->EnableMovingPhoto(enableMovingPhoto);
    session->UnlockForControl();

    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PhotoOutput::GetPhotoRotation(int32_t imageRotation, Camera_ImageRotation* cameraImageRotation)
{
    CHECK_AND_RETURN_RET_LOG(cameraImageRotation != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "GetCameraImageRotation failed");
    int32_t cameraOutputRotation = innerPhotoOutput_->GetPhotoRotation(imageRotation);
    CHECK_AND_RETURN_RET_LOG(cameraOutputRotation != CAMERA_SERVICE_FATAL_ERROR, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PhotoOutput::GetPhotoRotation failed to get photo profile! ret: %{public}d", cameraOutputRotation);
    *cameraImageRotation = static_cast<Camera_ImageRotation>(cameraOutputRotation);
    return CAMERA_OK;
}