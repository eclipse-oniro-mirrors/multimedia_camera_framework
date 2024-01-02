/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PHOTO_OUTPUT_NAPI_H_
#define PHOTO_OUTPUT_NAPI_H_

#include "camera_napi_template_utils.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "listener_base.h"
#include "native_image.h"
#include "output/camera_output_capability.h"
#include "output/photo_output.h"

namespace OHOS {
namespace CameraStandard {
const std::string dataWidth = "dataWidth";
const std::string dataHeight = "dataHeight";
const std::string thumbnailRegisterName = "quickThumbnail";
const std::string captureRegisterName = "photoAvailable";
static const char CAMERA_PHOTO_OUTPUT_NAPI_CLASS_NAME[] = "PhotoOutput";

struct CallbackInfo {
    int32_t captureID;
    uint64_t timestamp = 0;
    int32_t frameCount = 0;
    int32_t errorCode;
};

enum PhotoOutputEventType {
    CAPTURE_START,
    CAPTURE_END,
    CAPTURE_FRAME_SHUTTER,
    CAPTURE_ERROR,
    CAPTURE_INVALID_TYPE
};

static EnumHelper<PhotoOutputEventType> PhotoOutputEventTypeHelper({
        {CAPTURE_START, "captureStart"},
        {CAPTURE_END, "captureEnd"},
        {CAPTURE_FRAME_SHUTTER, "frameShutter"},
        {CAPTURE_ERROR, "error"}
    },
    PhotoOutputEventType::CAPTURE_INVALID_TYPE
);

class PhotoBufferProcessor : public Media::IBufferProcessor {
public:
    explicit PhotoBufferProcessor(sptr<Surface> photoSurface) : photoSurface_(photoSurface) {}
    ~PhotoBufferProcessor()
    {
        photoSurface_ = nullptr;
    }
    void BufferRelease(sptr<SurfaceBuffer>& buffer) override
    {
        if (photoSurface_ != nullptr) {
            photoSurface_->ReleaseBuffer(buffer, -1);
        }
    }

private:
    sptr<Surface> photoSurface_ = nullptr;
};

class PhotoListener : public IBufferConsumerListener, public ListenerBase {
public:
    explicit PhotoListener(napi_env env, const sptr<Surface> photoSurface);
    ~PhotoListener() = default;
    void OnBufferAvailable() override;

private:
    sptr<Surface> photoSurface_;
    shared_ptr<PhotoBufferProcessor> bufferProcessor_;
    void UpdateJSCallback(sptr<Surface> photoSurface) const;
    void UpdateJSCallbackAsync(sptr<Surface> photoSurface) const;
};

class PhotoOutputCallback : public PhotoStateCallback, public std::enable_shared_from_this<PhotoOutputCallback> {
public:
    explicit PhotoOutputCallback(napi_env env);
    ~PhotoOutputCallback() = default;

    void OnCaptureStarted(const int32_t captureID) const override;
    void OnCaptureStarted(const int32_t captureID, uint32_t exposureTime) const override;
    void OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const override;
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override;
    void SaveCallbackReference(const std::string& eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback, const std::string& eventType);
    void RemoveAllCallbacks(const std::string& eventType);

private:
    void UpdateJSCallback(PhotoOutputEventType eventType, const CallbackInfo& info) const;
    void UpdateJSCallbackAsync(PhotoOutputEventType eventType, const CallbackInfo& info) const;
    void ExecuteCaptureStartCb(const CallbackInfo& info) const;
    void ExecuteCaptureEndCb(const CallbackInfo& info) const;
    void ExecuteFrameShutterCb(const CallbackInfo& info) const;
    void ExecuteCaptureErrorCb(const CallbackInfo& info) const;
    std::mutex mutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> captureStartCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> captureEndCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> frameShutterCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> errorCbList_;
};

class ThumbnailListener : public IBufferConsumerListener, public ListenerBase {
public:
    explicit ThumbnailListener(napi_env env, const sptr<PhotoOutput> photoOutput);
    ~ThumbnailListener() = default;
    void OnBufferAvailable() override;

private:
    sptr<PhotoOutput> photoOutput_;
    void UpdateJSCallback(sptr<PhotoOutput> photoOutput) const;
    void UpdateJSCallbackAsync(sptr<PhotoOutput> photoOutput) const;
};

struct PhotoOutputCallbackInfo {
    PhotoOutputEventType eventType_;
    CallbackInfo info_;
    weak_ptr<const PhotoOutputCallback> listener_;
    PhotoOutputCallbackInfo(
        PhotoOutputEventType eventType, CallbackInfo info, shared_ptr<const PhotoOutputCallback> listener)
        : eventType_(eventType), info_(info), listener_(listener)
    {}
};

struct ThumbnailListenerInfo {
    sptr<PhotoOutput> photoOutput_;
    const ThumbnailListener* listener_;
    ThumbnailListenerInfo(sptr<PhotoOutput> photoOutput, const ThumbnailListener* listener)
        : photoOutput_(photoOutput), listener_(listener)
    {}
};

struct PhotoListenerInfo {
    sptr<Surface> photoSurface_;
    const PhotoListener* listener_;
    PhotoListenerInfo(sptr<Surface> photoSurface, const PhotoListener* listener)
        : photoSurface_(photoSurface), listener_(listener)
    {}
};

class PhotoOutputNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePhotoOutput(napi_env env, Profile& profile, std::string surfaceId);
    static napi_value GetDefaultCaptureSetting(napi_env env, napi_callback_info info);

    static napi_value Capture(napi_env env, napi_callback_info info);
    static napi_value ConfirmCapture(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsMirrorSupported(napi_env env, napi_callback_info info);
    static napi_value SetMirror(napi_env env, napi_callback_info info);
    static napi_value EnableQuickThumbnail(napi_env env, napi_callback_info info);
    static napi_value IsQuickThumbnailSupported(napi_env env, napi_callback_info info);
    static bool IsPhotoOutput(napi_env env, napi_value obj);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value RegisterCallback(
        napi_env env, napi_value jsThis, const std::string& eventType, napi_value callback, bool isOnce);
    static napi_value UnregisterCallback(
        napi_env env, napi_value jsThis, const std::string& eventType, napi_value callback);
    static int32_t MapQualityLevelFromJs(int32_t jsQuality, PhotoCaptureSetting::QualityLevel& nativeQuality);
    static int32_t MapImageRotationFromJs(int32_t jsRotation, PhotoCaptureSetting::RotationConfig& nativeRotation);

    PhotoOutputNapi();
    ~PhotoOutputNapi();

    sptr<PhotoOutput> GetPhotoOutput();

private:
    static void PhotoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PhotoOutputNapiConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<PhotoOutput> sPhotoOutput_;
    static thread_local sptr<Surface> sPhotoSurface_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<PhotoOutput> photoOutput_;
    Profile profile_;
    bool isQuickThumbnailEnabled_ = false;
    sptr<ThumbnailListener> thumbnailListener_;
    sptr<PhotoListener> photoListener_;
    static thread_local uint32_t photoOutputTaskId;
};

struct PhotoOutputAsyncContext : public AsyncContext {
    int32_t quality = -1;
    int32_t rotation = -1;
    double latitude = -1.0;
    double longitude = -1.0;
    bool isMirror = false;
    bool hasPhotoSettings = false;
    bool bRetBool;
    bool isSupported = false;
    std::unique_ptr<Location> location;
    PhotoOutputNapi* objectInfo;
    std::string surfaceId;
    ~PhotoOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* PHOTO_OUTPUT_NAPI_H_ */
