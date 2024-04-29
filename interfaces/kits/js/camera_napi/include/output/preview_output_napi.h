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

#ifndef PREVIEW_OUTPUT_NAPI_H_
#define PREVIEW_OUTPUT_NAPI_H_

#include "camera_napi_event_emitter.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_output_napi.h"
#include "hilog/log.h"
#include "image_receiver.h"
#include "input/camera_manager.h"
#include "listener_base.h"
#include "output/camera_output_capability.h"
#include "output/preview_output.h"
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {
struct PreviewOutputAsyncContext;
static const char CAMERA_PREVIEW_OUTPUT_NAPI_CLASS_NAME[] = "PreviewOutput";

enum PreviewOutputEventType {
    PREVIEW_FRAME_START,
    PREVIEW_FRAME_END,
    PREVIEW_FRAME_ERROR,
    SKETCH_STATUS_CHANGED,
    PREVIEW_INVALID_TYPE
};

static EnumHelper<PreviewOutputEventType> PreviewOutputEventTypeHelper({
        {PREVIEW_FRAME_START, CONST_PREVIEW_FRAME_START},
        {PREVIEW_FRAME_END, CONST_PREVIEW_FRAME_END},
        {PREVIEW_FRAME_ERROR, CONST_PREVIEW_FRAME_ERROR},
        {SKETCH_STATUS_CHANGED, CONST_SKETCH_STATUS_CHANGED}
    },
    PreviewOutputEventType::PREVIEW_INVALID_TYPE
);

class PreviewOutputCallback : public PreviewStateCallback, public std::enable_shared_from_this<PreviewOutputCallback> {
public:
    explicit PreviewOutputCallback(napi_env env);
    ~PreviewOutputCallback() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnSketchStatusDataChanged(const SketchStatusData& sketchStatusData) const override;
    void SaveCallbackReference(const std::string& eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback, const std::string& eventType);
    void RemoveAllCallbacks(const std::string& eventType);

private:
    void UpdateJSCallback(PreviewOutputEventType eventType, const int32_t value) const;
    void UpdateJSCallbackAsync(PreviewOutputEventType eventType, const int32_t value) const;
    void OnSketchStatusDataChangedAsync(SketchStatusData sketchStatusData) const;
    void OnSketchStatusDataChangedCall(SketchStatusData sketchStatusData) const;
    std::mutex previewOutputCbMutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> frameStartCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> frameEndCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> errorCbList_;
    mutable std::vector<std::shared_ptr<AutoRef>> sketchStatusChangedCbList_;
};

struct PreviewOutputCallbackInfo {
    PreviewOutputEventType eventType_;
    int32_t value_;
    weak_ptr<const PreviewOutputCallback> listener_;
    PreviewOutputCallbackInfo(PreviewOutputEventType eventType, int32_t value,
        shared_ptr<const PreviewOutputCallback> listener)
        : eventType_(eventType), value_(value), listener_(listener) {}
};

struct SketchStatusCallbackInfo {
    SketchStatusData sketchStatusData_;
    weak_ptr<const PreviewOutputCallback> listener_;
    napi_env env_;
    SketchStatusCallbackInfo(SketchStatusData sketchStatusData, shared_ptr<const PreviewOutputCallback>
        listener, napi_env env)
        : sketchStatusData_(sketchStatusData), listener_(listener), env_(env)
    {}
};

class PreviewOutputNapi : public CameraOutputNapi, public CameraNapiEventEmitter<PreviewOutputNapi> {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePreviewOutput(napi_env env, Profile& profile, std::string surfaceId);
    static napi_value CreateDeferredPreviewOutput(napi_env env, Profile& profile);
    static bool IsPreviewOutput(napi_env env, napi_value obj);
    static napi_value AddDeferredSurface(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsSketchSupported(napi_env env, napi_callback_info info);
    static napi_value GetSketchRatio(napi_env env, napi_callback_info info);
    static napi_value EnableSketch(napi_env env, napi_callback_info info);
    static napi_value AttachSketchSurface(napi_env env, napi_callback_info info);
    static napi_value SetFrameRate(napi_env env, napi_callback_info info);
    static napi_value GetActiveFrameRate(napi_env env, napi_callback_info info);
    static napi_value GetSupportedFrameRates(napi_env env, napi_callback_info info);
    sptr<PreviewOutput> GetPreviewOutput();
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    const EmitterFunctions& GetEmitterFunctions() override;

    PreviewOutputNapi();
    ~PreviewOutputNapi() override;

private:
    static void PreviewOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PreviewOutputNapiConstructor(napi_env env, napi_callback_info info);
    static napi_status CreateAsyncTask(napi_env env, napi_value resource,
        std::unique_ptr<OHOS::CameraStandard::PreviewOutputAsyncContext>& asyncContext);

    void RegisterFrameStartCallbackListener(
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFrameStartCallbackListener(napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterFrameEndCallbackListener(
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFrameEndCallbackListener(napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterErrorCallbackListener(
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    void UnregisterErrorCallbackListener(napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterSketchStatusChangedCallbackListener(
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    void UnregisterSketchStatusChangedCallbackListener(
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    napi_env env_;
    napi_ref wrapper_;
    sptr<PreviewOutput> previewOutput_;
    std::shared_ptr<PreviewOutputCallback> previewCallback_;

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<PreviewOutput> sPreviewOutput_;
    static thread_local uint32_t previewOutputTaskId;
};

struct PreviewOutputAsyncContext : public AsyncContext {
    PreviewOutputNapi* objectInfo;
    bool bRetBool;
    std::string surfaceId;
    ~PreviewOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* PREVIEW_OUTPUT_NAPI_H_ */
