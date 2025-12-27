/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PHOTO_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PHOTO_OUTPUT_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "camera_output_capability.h"
#include "photo_output.h"
#include "photo_output_callback.h"
#include "capture_output.h"
#include "camera_output_taihe.h"
#include "camera_template_utils_taihe.h"
#include "camera_worker_queue_keeper_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "camera_event_listener_taihe.h"
#include "native_image.h"
#include "pixel_map.h"

#include "refbase.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;
using namespace ohos::multimedia::camera;
const std::string dataWidth = "dataWidth";
const std::string dataHeight = "dataHeight";
static const std::string CONST_CAPTURE_ERROR = "error";
static const std::string CONST_CAPTURE_START_WITH_INFO = "captureStartWithInfo";
static const std::string CONST_CAPTURE_END = "captureEnd";
static const std::string CONST_CAPTURE_READY = "captureReady";
static const std::string CONST_CAPTURE_FRAME_SHUTTER = "frameShutter";
static const std::string CONST_CAPTURE_FRAME_SHUTTER_END = "frameShutterEnd";
static const std::string CONST_CAPTURE_ESTIMATED_CAPTURE_DURATION = "estimatedCaptureDuration";
static const std::string CONST_CAPTURE_PHOTO_AVAILABLE = "photoAvailable";
static const std::string CONST_CAPTURE_DEFERRED_PHOTO_AVAILABLE = "deferredPhotoProxyAvailable";
static const std::string CONST_CAPTURE_OFFLINE_DELIVERY_FINISHED = "offlineDeliveryFinished";
static const std::string CONST_CAPTURE_PHOTO_ASSET_AVAILABLE = "photoAssetAvailable";
static const std::string CONST_CAPTURE_QUICK_THUMBNAIL = "quickThumbnail";
static const std::string CONST_GAINMAP_SURFACE = "gainmap";
static const std::string CONST_DEEP_SURFACE = "deep";
static const std::string CONST_EXIF_SURFACE = "exif";
static const std::string CONST_DEBUG_SURFACE = "debug";

enum SurfaceType {
    GAINMAP_SURFACE = 0,
    DEEP_SURFACE = 1,
    EXIF_SURFACE = 2,
    DEBUG_SURFACE = 3,
    INVALID_SURFACE = -1,
};

static EnumHelper<SurfaceType> SurfaceTypeHelper({
    {GAINMAP_SURFACE, CONST_GAINMAP_SURFACE},
    {DEEP_SURFACE, CONST_DEEP_SURFACE},
    {EXIF_SURFACE, CONST_EXIF_SURFACE},
    {DEBUG_SURFACE, CONST_DEBUG_SURFACE},
},
SurfaceType::INVALID_SURFACE
);

class PhotoOutputCallbackAni : public OHOS::CameraStandard::PhotoStateCallback,
                               public OHOS::CameraStandard::PhotoAvailableCallback,
                               public OHOS::CameraStandard::PhotoAssetAvailableCallback,
                               public OHOS::CameraStandard::ThumbnailCallback,
                               public ListenerBase,
                               public std::enable_shared_from_this<PhotoOutputCallbackAni> {
public:
    explicit PhotoOutputCallbackAni(ani_env* env) : ListenerBase(env) {}
    ~PhotoOutputCallbackAni() = default;

    void OnCaptureStarted(const int32_t captureId) const override;
    void OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const override;
    void OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const override;
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override;
    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override;
    void OnEstimatedCaptureDuration(const int32_t duration) const override;
    void OnOfflineDeliveryFinished(const int32_t captureId) const override;
    void OnConstellationDrawingState(const int32_t state) const override;
    void OnPhotoAvailable(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const override;
    void OnPhotoAvailable(const std::shared_ptr<Media::Picture> picture) const override;
    void OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri,
        int32_t cameraShotType, const std::string &burstKey) const override;
    void OnThumbnailAvailable(int32_t captureId, int64_t timestamp,
        std::unique_ptr<Media::PixelMap> pixelMap) const override;

private:
    void OnCaptureStartedWithInfoCallback(const int32_t captureId, uint32_t exposureTime) const;
    void OnCaptureEndedCallback(const int32_t captureId, const int32_t frameCount) const;
    void OnFrameShutterCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnFrameShutterEndCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnCaptureReadyCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnCaptureErrorCallback(const int32_t captureId, const int32_t errorCode) const;
    void OnEstimatedCaptureDurationCallback(const int32_t duration) const;
    void OnOfflineDeliveryFinishedCallback(const int32_t captureId) const;
    void OnPhotoAvailableCallback(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const;
    void OnPhotoAvailableCallback(const std::shared_ptr<Media::Picture> picture) const;
    void OnPhotoAssetAvailableCallback(const int32_t captureId, const std::string &uri,
        int32_t cameraShotType, const std::string &burstKey) const;
    void OnThumbnailAvailableCallback(int32_t captureId, int64_t timestamp,
        std::unique_ptr<Media::PixelMap>& pixelMap) const;
};

class PhotoOutputImpl : public CameraOutputImpl,
                        public CameraAniEventEmitter<PhotoOutputImpl> {
public:
    PhotoOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output);
    ~PhotoOutputImpl() {};

    void ReleaseSync() override;

    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnCaptureStartWithInfo(callback_view<void(uintptr_t, CaptureStartInfo const&)> callback);
    void OffCaptureStartWithInfo(optional_view<callback<void(uintptr_t, CaptureStartInfo const&)>> callback);
    void OnCaptureEnd(callback_view<void(uintptr_t, CaptureEndInfo const&)> callback);
    void OffCaptureEnd(optional_view<callback<void(uintptr_t, CaptureEndInfo const&)>> callback);
    void OnCaptureReady(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffCaptureReady(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnFrameShutter(callback_view<void(uintptr_t, FrameShutterInfo const&)> callback);
    void OffFrameShutter(optional_view<callback<void(uintptr_t, FrameShutterInfo const&)>> callback);
    void OnFrameShutterEnd(callback_view<void(uintptr_t, FrameShutterEndInfo const&)> callback);
    void OffFrameShutterEnd(optional_view<callback<void(uintptr_t, FrameShutterEndInfo const&)>> callback);
    void OnEstimatedCaptureDuration(callback_view<void(uintptr_t, double)> callback);
    void OffEstimatedCaptureDuration(optional_view<callback<void(uintptr_t, double)>> callback);
    void OnPhotoAvailable(callback_view<void(uintptr_t, weak::Photo)> callback);
    void OffPhotoAvailable(optional_view<callback<void(uintptr_t, weak::Photo)>> callback);
    void OnDeferredPhotoProxyAvailable(callback_view<void(uintptr_t, weak::DeferredPhotoProxy)> callback);
    void OffDeferredPhotoProxyAvailable(optional_view<callback<void(uintptr_t, weak::DeferredPhotoProxy)>> callback);
    void OnOfflineDeliveryFinished(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffOfflineDeliveryFinished(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnPhotoAssetAvailable(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffPhotoAssetAvailable(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnQuickThumbnail(callback_view<void(uintptr_t, ohos::multimedia::image::image::weak::PixelMap)> callback);
    void OffQuickThumbnail(
        optional_view<callback<void(uintptr_t, ohos::multimedia::image::image::weak::PixelMap)>> callback);
    void CaptureSync();
    void CaptureSyncWithSetting(PhotoCaptureSetting const& setting);
    void BurstCaptureSync(PhotoCaptureSetting const& setting);
    bool GetEnableMirror();
    void EnableMirror(bool enabled);
    bool IsMirrorSupported();
    Profile GetActiveProfile();
    void EnableOffline();
    bool IsOfflineSupported();
    void EnableMovingPhoto(bool enabled);
    bool IsMovingPhotoSupported();
    ImageRotation GetPhotoRotation();
    ImageRotation GetPhotoRotation(int32_t deviceDegree);
    void EnableQuickThumbnail(bool enabled);
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> GetPhotoOutput();
    void EnableAutoCloudImageEnhancement(bool enabled);
    bool isAutoCloudImageEnhancementSupported();
    bool IsDepthDataDeliverySupported();
    void EnableDepthDataDelivery(bool enabled);
    bool IsAutoHighQualityPhotoSupported();
    void EnableAutoHighQualityPhoto(bool enabled);
    bool IsAutoCloudImageEnhancementSupported();
    void EnableRawDelivery(bool enabled);
    bool IsRawDeliverySupported();
    void SetMovingPhotoVideoCodecType(VideoCodecType codecType);
    array<VideoCodecType> GetSupportedMovingPhotoVideoCodecTypes();
    void ConfirmCapture();
    bool IsDeferredImageDeliverySupported(DeferredDeliveryImageType type);
    bool IsDeferredImageDeliveryEnabled(DeferredDeliveryImageType type);
    bool IsQuickThumbnailSupported();
    void DeferImageDelivery(DeferredDeliveryImageType type);

    static uint32_t photoOutputTaskId_;
private:
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterCaptureStartWithInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    void RegisterCaptureEndCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterCaptureEndCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterReadyCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterReadyCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFrameShutterCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFrameShutterCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFrameShutterEndCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFrameShutterEndCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterEstimatedCaptureDurationCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    void RegisterPhotoAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterPhotoAvailableCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterDeferredPhotoProxyAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    void RegisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterOfflineDeliveryFinishedCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    void RegisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterPhotoAssetAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    void RegisterQuickThumbnailCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterQuickThumbnailCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual const EmitterFunctions& GetEmitterFunctions() override;
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput_ = nullptr;
    std::shared_ptr<OHOS::CameraStandard::Profile> profile_;
    std::shared_ptr<PhotoOutputCallbackAni> photoOutputCallback_ = nullptr;
    bool isQuickThumbnailEnabled_ = false;
    bool isMirrorEnabled_ = false;
    bool isDeferredPhotoEnabled_ = false;
    uint8_t callbackFlag_ = 0;
};

struct PhotoOutputTaiheAsyncContext : public TaiheAsyncContext {
    PhotoOutputTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    PhotoOutputImpl* objectInfo = nullptr;
    int32_t quality = -1;
    int32_t rotation = -1;
    bool isMirror = false;
    bool isMirrorSettedByUser = false;
    bool hasPhotoSettings = false;
    bool isSupported = false;
    std::shared_ptr<OHOS::CameraStandard::Location> location;
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PHOTO_OUTPUT_TAIHE_H