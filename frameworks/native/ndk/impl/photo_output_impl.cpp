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

Camera_ErrorCode Camera_PhotoOutput::Capture()
{
    int32_t ret = innerPhotoOutput_->Capture();
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


sptr<PhotoOutput> Camera_PhotoOutput::GetInnerPhotoOutput()
{
    return innerPhotoOutput_;
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

Camera_ErrorCode Camera_PhotoOutput::GetPhotoRotation(int32_t imageRotation, Camera_ImageRotation* cameraImageRotation)
{
    int32_t cameraOutputRotation = innerPhotoOutput_->GetPhotoRotation(imageRotation);
    CHECK_AND_RETURN_RET_LOG(cameraOutputRotation == SERVICE_FATL_ERROR, SERVICE_FATL_ERROR,
        "Camera_PhotoOutput::GetPhotoRotation failed to get photo profile!");
    *cameraImageRotation = static_cast<Camera_ImageRotation>(cameraImageRotation);
    return CAMERA_OK;
}