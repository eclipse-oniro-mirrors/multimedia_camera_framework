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

#ifndef OHOS_PHOTO_OUTPUT_IMPL_H
#define OHOS_PHOTO_OUTPUT_IMPL_H

#include <mutex>

#include "kits/native/include/camera/camera.h"
#include "kits/native/include/camera/photo_output.h"
#include "output/photo_output.h"
#include "camera_log.h"
#include "camera_util.h"
#include "photo_listener_impl.h"
#include "photo_native_impl.h"

class InnerPhotoOutputCallback : public OHOS::CameraStandard::PhotoStateCallback {
public:
    explicit InnerPhotoOutputCallback(Camera_PhotoOutput* photoOutput) : photoOutput_(photoOutput)
    {
        callback_.onFrameStart = nullptr;
        callback_.onFrameShutter = nullptr;
        callback_.onFrameEnd = nullptr;
        callback_.onError = nullptr;
    }
    ~InnerPhotoOutputCallback() = default;

    void SaveCallback(PhotoOutput_Callbacks* callback)
    {
        callback_ = *callback;
    }

    void SaveCaptureStartWithInfoCallback(OH_PhotoOutput_CaptureStartWithInfo callback)
    {
        captureStartWithInfoCallback_ = callback;
    }

    void SaveCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback)
    {
        captureEndCallback_ = callback;
    }

    void SaveFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback)
    {
        frameShutterEndCallback_ = callback;
    }

    void SaveCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback)
    {
        captureReadyCallback_ = callback;
    }

    void SaveEstimatedCaptureDurationCallback(OH_PhotoOutput_EstimatedCaptureDuration callback)
    {
        estimatedCaptureDurationCallback_ = callback;
    }

    void RemoveCallback(PhotoOutput_Callbacks* callback)
    {
        if (callback->onFrameStart) {
            callback_.onFrameStart = nullptr;
        }
        if (callback->onFrameShutter) {
            callback_.onFrameShutter = nullptr;
        }
        if (callback->onFrameEnd) {
            callback_.onFrameEnd = nullptr;
        }
        if (callback->onError) {
            callback_.onError = nullptr;
        }
    }

    void RemoveCaptureStartWithInfoCallback(OH_PhotoOutput_CaptureStartWithInfo callback)
    {
        if (callback != nullptr) {
            captureStartWithInfoCallback_ = nullptr;
        }
    }

    void RemoveCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback)
    {
        if (callback != nullptr) {
            captureEndCallback_ = nullptr;
        }
    }

    void RemoveFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback)
    {
        if (callback != nullptr) {
            frameShutterEndCallback_ = nullptr;
        }
    }

    void RemoveCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback)
    {
        if (callback != nullptr) {
            captureReadyCallback_ = nullptr;
        }
    }

    void RemoveEstimatedCaptureDurationCallback(OH_PhotoOutput_EstimatedCaptureDuration callback)
    {
        if (callback != nullptr) {
            estimatedCaptureDurationCallback_ = nullptr;
        }
    }

    void OnCaptureStarted(const int32_t captureID) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureStarted is called!, captureID: %{public}d", captureID);
        Camera_CaptureStartInfo info;
        info.captureId = captureID;
        if (photoOutput_ != nullptr && captureStartWithInfoCallback_ != nullptr) {
            captureStartWithInfoCallback_(photoOutput_, &info);
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

    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override
    {
        MEDIA_DEBUG_LOG("OnFrameShutterEnd is called!, captureId: %{public}d", captureId);
        Camera_FrameShutterInfo info;
        info.captureId = captureId;
        info.timestamp = timestamp;
        if (photoOutput_ != nullptr && frameShutterEndCallback_ != nullptr) {
            frameShutterEndCallback_(photoOutput_, &info);
        }
    }

    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureReady is called!, captureId: %{public}d", captureId);
        if (photoOutput_ != nullptr && captureReadyCallback_ != nullptr) {
            captureReadyCallback_(photoOutput_);
        }
    }

    void OnEstimatedCaptureDuration(const int32_t duration) const override
    {
        MEDIA_DEBUG_LOG("OnEstimatedCaptureDuration is called!, duration: %{public}d", duration);
        if (photoOutput_ != nullptr && estimatedCaptureDurationCallback_ != nullptr) {
            estimatedCaptureDurationCallback_(photoOutput_, duration);
        }
    }

    void OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureEnded is called! captureID: %{public}d", captureID);
        MEDIA_DEBUG_LOG("OnCaptureEnded is called! framecount: %{public}d", frameCount);
        if (photoOutput_ != nullptr && callback_.onFrameEnd != nullptr) {
            callback_.onFrameEnd(photoOutput_, frameCount);
        }
        if (photoOutput_ != nullptr && captureEndCallback_ != nullptr) {
            captureEndCallback_(photoOutput_, frameCount);
        }
    }

    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnCaptureError is called!, errorCode: %{public}d", errorCode);
        if (photoOutput_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(photoOutput_, OHOS::CameraStandard::FrameworkToNdkCameraError(errorCode));
        }
    }

private:
    Camera_PhotoOutput* photoOutput_;
    PhotoOutput_Callbacks callback_;
    OH_PhotoOutput_CaptureStartWithInfo captureStartWithInfoCallback_ = nullptr;
    OH_PhotoOutput_CaptureEnd captureEndCallback_ = nullptr;
    OH_PhotoOutput_OnFrameShutterEnd frameShutterEndCallback_ = nullptr;
    OH_PhotoOutput_CaptureReady captureReadyCallback_ = nullptr;
    OH_PhotoOutput_EstimatedCaptureDuration estimatedCaptureDurationCallback_ = nullptr;
};

struct Camera_PhotoOutput {
public:
    explicit Camera_PhotoOutput(OHOS::sptr<OHOS::CameraStandard::PhotoOutput> &innerPhotoOutput);
    ~Camera_PhotoOutput();

    Camera_ErrorCode RegisterCallback(PhotoOutput_Callbacks* callback);

    Camera_ErrorCode UnregisterCallback(PhotoOutput_Callbacks* callback);

    Camera_ErrorCode RegisterCaptureStartWithInfoCallback(OH_PhotoOutput_CaptureStartWithInfo callback);

    Camera_ErrorCode UnregisterCaptureStartWithInfoCallback(OH_PhotoOutput_CaptureStartWithInfo callback);

    Camera_ErrorCode RegisterCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback);

    Camera_ErrorCode UnregisterCaptureEndCallback(OH_PhotoOutput_CaptureEnd callback);

    Camera_ErrorCode RegisterFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback);

    Camera_ErrorCode UnregisterFrameShutterEndCallback(OH_PhotoOutput_OnFrameShutterEnd callback);

    Camera_ErrorCode RegisterCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback);

    Camera_ErrorCode UnregisterCaptureReadyCallback(OH_PhotoOutput_CaptureReady callback);

    Camera_ErrorCode RegisterEstimatedCaptureDurationCallback(OH_PhotoOutput_EstimatedCaptureDuration callback);

    Camera_ErrorCode UnregisterEstimatedCaptureDurationCallback(OH_PhotoOutput_EstimatedCaptureDuration callback);
	
    Camera_ErrorCode RegisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback);

    Camera_ErrorCode UnregisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback);

    Camera_ErrorCode RegisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback);

    Camera_ErrorCode UnregisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback);

    Camera_ErrorCode Capture();

    Camera_ErrorCode Capture_WithCaptureSetting(Camera_PhotoCaptureSetting setting);

    Camera_ErrorCode Release();

    Camera_ErrorCode IsMirrorSupported(bool* isSupported);

    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> GetInnerPhotoOutput();

    void SetPhotoSurface(OHOS::sptr<OHOS::Surface> &photoSurface);

    OH_PhotoNative* CreateCameraPhotoNative(std::shared_ptr<OHOS::Media::NativeImage> &image, bool isMain);

    Camera_ErrorCode IsMovingPhotoSupported(bool* isSupported);

    Camera_ErrorCode EnableMovingPhoto(bool enableMovingPhoto);

    Camera_ErrorCode GetActiveProfile(Camera_Profile** profile);

private:
    Camera_ErrorCode RegisterRawPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback);

    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> innerPhotoOutput_ = nullptr;
    std::shared_ptr<InnerPhotoOutputCallback> innerCallback_ = nullptr;
    OHOS::sptr<OHOS::Surface> photoSurface_ = nullptr;
    OHOS::sptr<OHOS::CameraStandard::PhotoListener> photoListener_ = nullptr;
    OHOS::sptr<OHOS::CameraStandard::RawPhotoListener> rawPhotoListener_ = nullptr;
    uint8_t callbackFlag_ = 0;
    OH_PhotoNative *photoNative_ = nullptr;
};
#endif // OHOS_PHOTO_OUTPUT_IMPL_H