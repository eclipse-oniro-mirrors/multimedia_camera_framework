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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_OUTPUT_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "camera_event_emitter_taihe.h"
#include "camera_output_taihe.h"
#include "camera_worker_queue_keeper_taihe.h"
#include "listener_base_taihe.h"

#include "camera_output_capability.h"
#include "capture_output.h"
#include "output/depth_data_output.h"

#include "ibuffer_consumer_listener.h"
#include "refbase.h"
#include "surface_buffer.h"
#include "surface_utils.h"

namespace Ani {
namespace Camera {
class DepthDataTaiheBufferProcessor {
public:
    explicit DepthDataTaiheBufferProcessor(OHOS::sptr<OHOS::Surface> depthDataSurface) : depthDataSurface_(
        depthDataSurface) {}
    ~DepthDataTaiheBufferProcessor()
    {
        depthDataSurface_ = nullptr;
    }
    void Release(OHOS::sptr<OHOS::SurfaceBuffer>& buffer)
    {
        if (depthDataSurface_ != nullptr) {
            depthDataSurface_->ReleaseBuffer(buffer, -1);
        }
    }

private:
    OHOS::sptr<OHOS::Surface> depthDataSurface_ = nullptr;
};
class DepthDataTaiheListener : public OHOS::IBufferConsumerListener, public ListenerBase,
    public std::enable_shared_from_this<DepthDataTaiheListener> {
public:
    explicit DepthDataTaiheListener(ani_env* env, const OHOS::sptr<OHOS::Surface> depthDataSurface,
        OHOS::sptr<OHOS::CameraStandard::DepthDataOutput> depthDataOutput);
    ~DepthDataTaiheListener() = default;
    void OnBufferAvailable() override;
    void SetDepthProfile(std::shared_ptr<OHOS::CameraStandard::DepthProfile> depthProfile);

private:
    void OnBufferAvailableCallback() const;
    void ExecuteDepthData(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer) const;
    OHOS::sptr<OHOS::Surface> depthDataSurface_;
    OHOS::sptr<OHOS::CameraStandard::DepthDataOutput> depthDataOutput_;
    std::shared_ptr<DepthDataTaiheBufferProcessor> bufferProcessor_;
    std::shared_ptr<OHOS::CameraStandard::DepthProfile> depthProfile_;
    static std::mutex depthDataMutex_;
};

class DepthDataOutputErrorListener : public OHOS::CameraStandard::DepthDataStateCallback,
                                     public ListenerBase,
                                     public std::enable_shared_from_this<DepthDataOutputErrorListener> {
public:
    explicit DepthDataOutputErrorListener(ani_env* env) : ListenerBase(env) {}
    ~DepthDataOutputErrorListener() = default;

    void OnDepthDataError(const int32_t errorCode) const override;

private:
    void OnDepthDataErrorCallback(const int32_t errorCode) const;
};

class DepthDataOutputImpl : public CameraOutputImpl, public CameraAniEventEmitter<DepthDataOutputImpl>,
    public std::enable_shared_from_this<DepthDataOutputImpl> {
public:
    DepthDataOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output, OHOS::sptr<OHOS::Surface> surface);
    ~DepthDataOutputImpl() = default;

    void StartSync();
    void StopSync();
    void ReleaseSync() override;

    const EmitterFunctions& GetEmitterFunctions() override;

    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnDepthDataAvailable(callback_view<void(uintptr_t, weak::DepthData)> callback);
    void OffDepthDataAvailable(optional_view<callback<void(uintptr_t, weak::DepthData)>> callback);

    static uint32_t depthDataOutputTaskId_;
private:
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterDepthDataAvailableCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterDepthDataAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t>callback);

    OHOS::sptr<OHOS::CameraStandard::DepthDataOutput> depthDataOutput_ = nullptr;
    OHOS::sptr<DepthDataTaiheListener> depthDataListener_ = nullptr;
    std::shared_ptr<DepthDataOutputErrorListener> depthDataCallback_;
    static thread_local OHOS::sptr<OHOS::Surface> sDepthDataSurface_;
    static thread_local std::shared_ptr<OHOS::CameraStandard::DepthProfile> depthProfile_;

    static const EmitterFunctions fun_map_;
};

struct DepthDataOutputTaiheAsyncContext : public TaiheAsyncContext {
    DepthDataOutputTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~DepthDataOutputTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
    DepthDataOutputImpl* objectInfo = nullptr;
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_DEPTH_DATA_OUTPUT_TAIHE_H