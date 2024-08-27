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

#ifndef DEPTH_DATA_OUTPUT_NAPI_H_
#define DEPTH_DATA_OUTPUT_NAPI_H_

#include "camera_napi_event_emitter.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "depth_data_napi.h"
#include "listener_base.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"
#include "output/depth_data_output.h"
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {
static const std::string CONST_DEPTH_DATA_AVAILABLE = "depthDataAvailable";
static const std::string CONST_DEPTH_DATA_ERROR = "error";

static const char CAMERA_DEPTH_DATA_OUTPUT_NAPI_CLASS_NAME[] = "DepthDataOutput";

enum DepthDataOutputEventType {
    DEPTH_DATA_AVAILABLE,
    DEPTH_DATA_ERROR,
    DEPTH_DATA_INVALID_TYPE
};

static EnumHelper<DepthDataOutputEventType> DepthDataOutputEventTypeHelper({
        {DEPTH_DATA_AVAILABLE, CONST_DEPTH_DATA_AVAILABLE},
        {DEPTH_DATA_ERROR, CONST_DEPTH_DATA_ERROR}
    },
    DepthDataOutputEventType::DEPTH_DATA_INVALID_TYPE
);

class DepthDataBufferProcessor {
public:
    explicit DepthDataBufferProcessor(sptr<Surface> depthDataSurface) : depthDataSurface_(depthDataSurface) {}
    ~DepthDataBufferProcessor()
    {
        depthDataSurface_ = nullptr;
    }
    void Release(sptr<SurfaceBuffer>& buffer)
    {
        if (depthDataSurface_ != nullptr) {
            depthDataSurface_->ReleaseBuffer(buffer, -1);
        }
    }

private:
    sptr<Surface> depthDataSurface_ = nullptr;
};

class DepthDataListener : public IBufferConsumerListener, public ListenerBase {
public:
    explicit DepthDataListener(napi_env env, const sptr<Surface> depthSurface, sptr<DepthDataOutput> depthDataOutput);
    ~DepthDataListener() = default;
    void OnBufferAvailable() override;
    void SaveCallback(const std::string eventName, napi_value callback);
    void RemoveCallback(const std::string eventName, napi_value callback);
    void SetDepthProfile(std::shared_ptr<DepthProfile> depthProfile);

private:
    sptr<Surface> depthDataSurface_;
    sptr<DepthDataOutput> depthDataOutput_;
    std::shared_ptr<DepthDataBufferProcessor> bufferProcessor_;
    std::shared_ptr<DepthProfile> depthProfile_;
    void UpdateJSCallback(sptr<Surface> depthSurface) const;
    void UpdateJSCallbackAsync(sptr<Surface> depthSurface) const;
    void ExecuteDepthData(sptr<SurfaceBuffer> surfaceBfuffer) const;
};

struct DepthDataListenerInfo {
    sptr<Surface> depthDataSurface_;
    const DepthDataListener* listener_;
    DepthDataListenerInfo(sptr<Surface> depthDataSurface, const DepthDataListener* listener)
        : depthDataSurface_(depthDataSurface), listener_(listener)
    {}
};

class DepthDataOutputCallback : public DepthDataStateCallback,
                              public ListenerBase,
                              public std::enable_shared_from_this<DepthDataOutputCallback> {
public:
    explicit DepthDataOutputCallback(napi_env env);
    ~DepthDataOutputCallback() = default;

    void OnDepthDataError(const int32_t errorCode) const override;
 
private:
    void UpdateJSCallback(DepthDataOutputEventType eventType, const int32_t value) const;
    void UpdateJSCallbackAsync(DepthDataOutputEventType eventType, const int32_t value) const;
    void ExecuteDepthData(sptr<SurfaceBuffer> surfaceBuffer) const;
};

struct DepthDataOutputCallbackInfo {
    DepthDataOutputEventType eventType_;
    int32_t value_;
    weak_ptr<const DepthDataOutputCallback> listener_;
    DepthDataOutputCallbackInfo(DepthDataOutputEventType eventType, int32_t value,
        shared_ptr<const DepthDataOutputCallback> listener)
        : eventType_(eventType), value_(value), listener_(listener) {}
};

struct DepthDataOutputAsyncContext;
class DepthDataOutputNapi : public CameraNapiEventEmitter<DepthDataOutputNapi> {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateDepthDataOutput(napi_env env, DepthProfile& depthProfile);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    sptr<DepthDataOutput> GetDepthDataOutput();
    static bool IsDepthDataOutput(napi_env env, napi_value obj);

    const EmitterFunctions& GetEmitterFunctions() override;

    DepthDataOutputNapi();
    ~DepthDataOutputNapi() override;

private:
    static void DepthDataOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value DepthDataOutputNapiConstructor(napi_env env, napi_callback_info info);

    void RegisterDepthDataAvailableCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterDepthDataAvailableCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<DepthDataOutput> sDepthDataOutput_;
    static thread_local sptr<Surface> sDepthDataSurface_;
    static thread_local uint32_t depthDataOutputTaskId;

    napi_env env_;
    sptr<DepthDataOutput> depthDataOutput_;
    sptr<DepthDataListener> depthDataListener_;
    std::shared_ptr<DepthDataOutputCallback> depthDataCallback_;
    static thread_local std::shared_ptr<DepthProfile> depthProfile_;
};

struct DepthDataOutputAsyncContext : public AsyncContext {
    DepthDataOutputNapi* objectInfo;
    bool bRetBool;
    std::string surfaceId;
    ~DepthDataOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* DEPTH_DATA_OUTPUT_NAPI_H_ */