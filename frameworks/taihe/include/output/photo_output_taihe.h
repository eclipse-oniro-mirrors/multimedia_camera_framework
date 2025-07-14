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

private:
    void OnCaptureStartedWithInfoCallback(const int32_t captureId, uint32_t exposureTime) const;
    void OnCaptureEndedCallback(const int32_t captureId, const int32_t frameCount) const;
    void OnFrameShutterCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnFrameShutterEndCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnCaptureReadyCallback(const int32_t captureId, const uint64_t timestamp) const;
    void OnCaptureErrorCallback(const int32_t captureId, const int32_t errorCode) const;
    void OnEstimatedCaptureDurationCallback(const int32_t duration) const;
    void OnOfflineDeliveryFinishedCallback(const int32_t captureId) const;
};

class PhotoBufferProcessorAni : public Media::IBufferProcessor {
public:
    explicit PhotoBufferProcessorAni(sptr<Surface> photoSurface) : photoSurface_(photoSurface) {}
    ~PhotoBufferProcessorAni()
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

class PhotoListenerAni : public IBufferConsumerListener,
                         public ListenerBase,
                         public std::enable_shared_from_this<PhotoListenerAni> {
public:
    explicit PhotoListenerAni(ani_env* env, const sptr<Surface> photoSurface,
        wptr<OHOS::CameraStandard::PhotoOutput> photoOutput);
    virtual ~PhotoListenerAni();
    void OnBufferAvailable() override;
    void SaveCallback(const std::string eventName, std::shared_ptr<uintptr_t> callback);
    void RemoveCallback(const std::string eventName, std::shared_ptr<uintptr_t> callback);
    void ExecuteDeepCopySurfaceBuffer();
    std::shared_ptr<OHOS::CameraStandard::DeferredProcessing::TaskManager> taskManager_ = nullptr;
private:
    void UpdateJSCallback(sptr<Surface> photoSurface) const;
    void UpdateMainPictureStageOneJSCallback(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) const;
    void UpdatePictureJSCallback(int32_t captureId, const string uri, int32_t cameraShotType,
        const std::string burstKey) const;
    void ExecutePhoto(sptr<SurfaceBuffer> surfaceBfuffer, int64_t timestamp) const;
    void ExecuteDeferredPhoto(sptr<SurfaceBuffer> surfaceBuffer) const;
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer,
        int32_t captureId) const;
    void ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, bool isHighQuality, int64_t timestamp) const;
    int32_t GetAuxiliaryPhotoCount(sptr<SurfaceBuffer> surfaceBuffer);
    void AssembleAuxiliaryPhoto(int64_t timestamp, int32_t captureId);
    sptr<Surface> photoSurface_ = nullptr;
    wptr<OHOS::CameraStandard::PhotoOutput> photoOutput_ = nullptr;
    std::shared_ptr<PhotoBufferProcessorAni> bufferProcessor_ = nullptr;
    uint8_t callbackFlag_ = 0;
};

class RawPhotoListenerAni : public IBufferConsumerListener,
                            public ListenerBase,
                            public std::enable_shared_from_this<RawPhotoListenerAni> {
public:
    explicit RawPhotoListenerAni(ani_env* env, const sptr<Surface> rawPhotoSurface);
    ~RawPhotoListenerAni() = default;
    void OnBufferAvailable() override;

private:
    sptr<Surface> rawPhotoSurface_;
    std::shared_ptr<PhotoBufferProcessorAni> bufferProcessor_;
    void UpdateJSCallback(sptr<Surface> rawPhotoSurface) const;
    void ExecuteRawPhoto(sptr<SurfaceBuffer> rawPhotoSurface) const;
};

struct RawPhotoListenerInfo {
    sptr<Surface> rawPhotoSurface_;
    std::weak_ptr<const RawPhotoListenerAni> listener_;
    RawPhotoListenerInfo(sptr<Surface> rawPhotoSurface, std::shared_ptr<const RawPhotoListenerAni> listener)
        : rawPhotoSurface_(rawPhotoSurface), listener_(listener)
    {}
};

class AuxiliaryPhotoListener : public IBufferConsumerListener {
public:
    explicit AuxiliaryPhotoListener(const std::string surfaceName, const sptr<Surface> surface,
        wptr<OHOS::CameraStandard::PhotoOutput> photoOutput);
    ~AuxiliaryPhotoListener() = default;
    void OnBufferAvailable() override;
    void ExecuteDeepCopySurfaceBuffer();
private:
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer, int32_t) const;
    std::string surfaceName_;
    sptr<Surface> surface_;
    wptr<OHOS::CameraStandard::PhotoOutput> photoOutput_;
    std::shared_ptr<PhotoBufferProcessorAni> bufferProcessor_;
};

class PictureListener : public RefBase {
public:
    explicit PictureListener() = default;
    ~PictureListener() = default;
    void InitPictureListeners(wptr<OHOS::CameraStandard::PhotoOutput> photoOutput);
    sptr<AuxiliaryPhotoListener> gainmapImageListener;
    sptr<AuxiliaryPhotoListener> deepImageListener;
    sptr<AuxiliaryPhotoListener> exifImageListener;
    sptr<AuxiliaryPhotoListener> debugImageListener;
};

class ThumbnailListener : public IBufferConsumerListener, public ListenerBase {
public:
    explicit ThumbnailListener(ani_env* env, const sptr<OHOS::CameraStandard::PhotoOutput> photoOutput);
    virtual ~ThumbnailListener();
    void OnBufferAvailable() override;
    std::shared_ptr<OHOS::CameraStandard::DeferredProcessing::TaskManager> taskManager_ = nullptr;
    void ClearTaskManager();
    std::mutex taskManagerMutex_;
private:
    wptr<OHOS::CameraStandard::PhotoOutput> photoOutput_;
    void UpdateJSCallback(int32_t captureId, int64_t timestamp, std::unique_ptr<Media::PixelMap>) const;
    void UpdateJSCallbackAsync(int32_t captureId, int64_t timestamp, std::unique_ptr<Media::PixelMap>);
    void ExecuteDeepCopySurfaceBuffer();

    std::unique_ptr<Media::PixelMap> CreatePixelMapFromSurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer,
        int32_t width, int32_t height, bool isHdr);
    std::unique_ptr<Media::PixelMap> SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer,
        std::unique_ptr<Media::PixelMap> pixelMap, bool isHdr);
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer,
        int32_t thumbnailWidth, int32_t thumbnailHeight, bool isHdr) const;

    static constexpr int32_t PLANE_Y = 0;
    static constexpr int32_t PLANE_U = 1;
    static constexpr uint8_t PIXEL_SIZE_HDR_YUV = 3;
    static constexpr uint8_t  HDR_PIXEL_SIZE = 2;
    static constexpr uint8_t SDR_PIXEL_SIZE = 1;
};

struct ThumbnailListenerInfo {
    wptr<ThumbnailListener> listener_;
    int32_t captureId_;
    int64_t timestamp_;
    std::unique_ptr<Media::PixelMap> pixelMap_;
    ThumbnailListenerInfo(sptr<ThumbnailListener> listener, int32_t captureId,
        int64_t timestamp, std::unique_ptr<Media::PixelMap> pixelMap)
        : listener_(listener), captureId_(captureId), timestamp_(timestamp), pixelMap_(std::move(pixelMap))
    {}
};

class PhotoOutputImpl : public CameraOutputImpl,
                        public CameraAniEventEmitter<PhotoOutputImpl> {
public:
    PhotoOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output);
    ~PhotoOutputImpl() = default;

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
    void OnQuickThumbnail(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffQuickThumbnail(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
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
    void CreateMultiChannelPictureLisenter(ani_env* env);
    void CreateSingleChannelPhotoLisenter(ani_env* env);
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> photoOutput_ = nullptr;
    std::shared_ptr<OHOS::CameraStandard::Profile> profile_;
    std::shared_ptr<PhotoOutputCallbackAni> photoOutputCallback_ = nullptr;
    sptr<PhotoListenerAni> photoListener_ = nullptr;
    sptr<PictureListener> pictureListener_;
    sptr<ThumbnailListener> thumbnailListener_;
    sptr<RawPhotoListenerAni> rawPhotoListener_;
    std::shared_ptr<uintptr_t> rawCallback_;
    bool isQuickThumbnailEnabled_ = false;
    bool isMirrorEnabled_ = false;
    bool isDeferredPhotoEnabled_ = false;
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