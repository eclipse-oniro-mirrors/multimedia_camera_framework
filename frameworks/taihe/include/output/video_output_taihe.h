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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_VIDEO_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_VIDEO_OUTPUT_TAIHE_H

#include "camera_worker_queue_keeper_taihe.h"
#include "camera_output_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "listener_base_taihe.h"
#include "surface_utils.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;

struct VideoCallbackInfoTaihe {
    int32_t frameCount = 0;
    int32_t errorCode = 0;
    bool isDeferredVideoEnhancementAvailable = false;
    std::string videoId = "";
};

class VideoCallbackListener : public OHOS::CameraStandard::VideoStateCallback,
                              public ListenerBase,
                              public std::enable_shared_from_this<VideoCallbackListener> {
public:
    VideoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~VideoCallbackListener() = default;
    void OnError(int32_t errorCode) const override;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnDeferredVideoEnhancementInfo(
        const OHOS::CameraStandard::CaptureEndedInfoExt captureEndedInfo) const override;

private:
    void OnErrorCallback(int32_t errorCode) const;
    void OnFrameStartedCallback() const;
    void OnFrameEndedCallback(const int32_t frameCount) const;
};

class VideoOutputImpl : public CameraOutputImpl, public CameraAniEventEmitter<VideoOutputImpl> {
public:
    VideoOutputImpl(sptr<OHOS::CameraStandard::CaptureOutput> output);
    ~VideoOutputImpl() = default;

    void StartSync();
    void StopSync();

    void ReleaseSync() override;
    void EnableAutoVideoFrameRate(bool enabled);
    bool IsAutoVideoFrameRateSupported();
    bool IsMirrorSupported();
    void EnableMirror(bool enabled);
    bool IsAutoDeferredVideoEnhancementSupported();
    bool IsAutoDeferredVideoEnhancementEnabled();
    array<FrameRateRange> GetSupportedFrameRates();
    FrameRateRange GetActiveFrameRate();
    VideoProfile GetActiveProfile();
    void SetFrameRate(int32_t minFps, int32_t maxFps);
    void SetRotation(ImageRotation rotation);
    bool IsRotationSupported();
    array<ImageRotation> GetSupportedRotations();
    ImageRotation GetVideoRotation(int32_t deviceDegree);
    void AttachMetaSurface(string_view surfaceId, VideoMetaType type);
    array<VideoMetaType> GetSupportedVideoMetaTypes();
    void EnableAutoDeferredVideoEnhancement(bool enabled);

    const EmitterFunctions& GetEmitterFunctions() override;
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnDeferredVideoEnhancementInfo(callback_view<void(uintptr_t, DeferredVideoEnhancementInfo const&)> callback);
    void OffDeferredVideoEnhancementInfo(
        optional_view<callback<void(uintptr_t, DeferredVideoEnhancementInfo const&)>> callback);
    void OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    static uint32_t videoOutputTaskId_;
    sptr<CameraStandard::VideoOutput> GetVideoOutput()
    {
        return videoOutput_;
    }
private:
    void RegisterVideoOutputErrorCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterVideoOutputErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterDeferredVideoCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterDeferredVideoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFrameStartCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFrameStartCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFrameEndCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFrameEndCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);

    static const EmitterFunctions fun_map_;
    sptr<CameraStandard::VideoOutput> videoOutput_ = nullptr;
    std::shared_ptr<VideoCallbackListener> videoCallback_ = nullptr;
};

struct VideoOutputTaiheAsyncContext : public TaiheAsyncContext {
    VideoOutputTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~VideoOutputTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
    VideoOutputImpl* objectInfo = nullptr;
    std::vector<int32_t> vecFrameRateRangeList;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_VIDEO_OUTPUT_TAIHE_H