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

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

class InnerPhotoOutputCallback : public PhotoStateCallback {
public:
    InnerPhotoOutputCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback)
        : photoOutput_(photoOutput), callback_(*callback) {}
    ~InnerPhotoOutputCallback() = default;

// need fix
    void OnCaptureStarted(const int32_t captureID) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
        if (photoOutput_ != nullptr && callback_.onFrameStart != nullptr) {
            callback_.onFrameStart(photoOutput_);
        }
    }

// need fix
    void OnCaptureStarted(const int32_t captureID, uint32_t exposureTime) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
        if (photoOutput_ != nullptr && callback_.onFrameStart != nullptr) {
            callback_.onFrameStart(photoOutput_);
        }
    }

// need fix
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override
    {
        MEDIA_DEBUG_LOG("onFrameShutter is called!, captureId: %{public}d", captureId);
        Camera_FrameShutterInfo info;
        info.captureId = captureId;
        info.timestamp = timestamp;
        if (photoOutput_ != nullptr && callback_.onFrameShutter != nullptr) {
            callback_.onFrameShutter(photoOutput_, &info);
        }
    }

// need fix
    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override
    {
        MEDIA_DEBUG_LOG("OnFrameShutterEnd is called!, captureId: %{public}d", captureId);
    }

// need fix
    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureReady is called!, captureId: %{public}d", captureId);
    }

// need fix
    void OnEstimatedCaptureDuration(const int32_t duration) const override
    {
        MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called!, duration: %{public}d", duration);
    }

// need fix
    void OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureEnded is called! captureID: %{public}d", captureID);
        MEDIA_DEBUG_LOG("OnCaptureEnded is called! framecount: %{public}d", frameCount);
        if (photoOutput_ != nullptr && callback_.onFrameEnd != nullptr) {
            callback_.onFrameEnd(photoOutput_, frameCount);
        }
    }

    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureError is called!, errorCode: %{public}d", errorCode);
        if (photoOutput_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(photoOutput_, FrameworkToNdkCameraError(errorCode));
        }
    }

private:
    Camera_PhotoOutput* photoOutput_;
    PhotoOutput_Callbacks callback_;
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
}

Camera_ErrorCode Camera_PhotoOutput::RegisterCallback(PhotoOutput_Callbacks* callback)
{
    shared_ptr<InnerPhotoOutputCallback> innerCallback =
                make_shared<InnerPhotoOutputCallback>(this, callback);
    innerPhotoOutput_->SetCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PhotoOutput::UnregisterCallback(PhotoOutput_Callbacks* callback)
{
    // call to member function 'SetCallback' is ambiguous
    shared_ptr<InnerPhotoOutputCallback> innerCallback = nullptr;
    innerPhotoOutput_->SetCallback(innerCallback);
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
        std::unique_ptr<Location> location = std::make_unique<Location>();
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