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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PREVIEW_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PREVIEW_OUTPUT_TAIHE_H


#include "camera_output_taihe.h"
#include "camera_worker_queue_keeper_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "camera_event_listener_taihe.h"

#include "preview_output.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

class PreviewOutputCallbackAni : public OHOS::CameraStandard::PreviewStateCallback,
                                 public ListenerBase,
                                 public std::enable_shared_from_this<PreviewOutputCallbackAni> {
public:
    explicit PreviewOutputCallbackAni(ani_env* env);
    ~PreviewOutputCallbackAni() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnSketchStatusDataChanged(const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const override;
    void OnFramePaused() const override;
    void OnFrameResumed() const override;
private:
    void OnFrameStartedCallback() const;
    void OnFrameEndedCallback(const int32_t frameCount) const;
    void OnErrorCallback(const int32_t errorCode) const;
    void OnSketchStatusDataChangedCallback(const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const;
    void OnFramePauseCallback() const;
    void OnFrameResumedCallback() const;
};

class PreviewOutputImpl : public CameraOutputImpl,
                          public CameraAniEventEmitter<PreviewOutputImpl>,
                          public CameraAniEventListener<PreviewOutputCallbackAni> {
public:
    PreviewOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output);
    ~PreviewOutputImpl() = default;
    void AddDeferredSurface(string_view surfaceId);
    bool IsSketchSupported();
    void ReleaseSync() override;
    void EnableSketch(bool enabled);
    double GetSketchRatio();
    array<FrameRateRange> GetSupportedFrameRates();
    Profile GetActiveProfile();
    FrameRateRange GetActiveFrameRate();
    void SetFrameRate(int32_t minFps, int32_t maxFps);
    ImageRotation GetPreviewRotation();
    ImageRotation GetPreviewRotation(int32_t displayRotation);
    void SetPreviewRotation(ImageRotation previewRotation, optional_view<bool> isDisplayLocked);
    void AttachSketchSurface(string_view surfaceId);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnSketchStatusChanged(callback_view<void(uintptr_t, SketchStatusData const&)> callback);
    void OffSketchStatusChanged(optional_view<callback<void(uintptr_t, SketchStatusData const&)>> callback);
    void OnFramePause(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFramePause(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void OnFrameResumed(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffFrameResumed(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    bool IsBandwidthCompressionSupported();
    void EnableBandwidthCompression(bool enabled);
    
    OHOS::sptr<OHOS::CameraStandard::PreviewOutput> GetPreviewOutput()
    {
        return previewOutput_;
    }
    
    static uint32_t previewOutputTaskId_;
private:
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void RegisterFrameStartCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void RegisterFrameEndCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterCommonCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterSketchStatusChangedCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterSketchStatusChangedCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFramePauseCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFramePauseCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFrameResumeChangedCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFrameResumeChangedCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    virtual const EmitterFunctions& GetEmitterFunctions() override;
    OHOS::sptr<OHOS::CameraStandard::PreviewOutput> previewOutput_ = nullptr;
};

struct PreviewOutputTaiheAsyncContext : public TaiheAsyncContext {
    PreviewOutputTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~PreviewOutputTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
    PreviewOutputImpl* objectInfo = nullptr;
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_PREVIEW_OUTPUT_TAIHE_H