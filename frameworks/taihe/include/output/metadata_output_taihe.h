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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_METADATA_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_METADATA_OUTPUT_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "camera_worker_queue_keeper_taihe.h"
#include "camera_output_taihe.h"
#include "input/camera_manager.h"
#include "metadata_output.h"
#include "camera_event_emitter_taihe.h"
#include "listener_base_taihe.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;
class MetadataOutputCallbackListener : public OHOS::CameraStandard::MetadataStateCallback, public ListenerBase,
    public std::enable_shared_from_this<MetadataOutputCallbackListener> {
public:
    MetadataOutputCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~MetadataOutputCallbackListener() = default;
    void OnError(int32_t errorCode) const override;
private:
    void OnMetadataOutputErrorCallback(int32_t errorCode) const;
};

class MetadataObjectsAvailableCallbackListener : public OHOS::CameraStandard::MetadataObjectCallback,
    public ListenerBase, public std::enable_shared_from_this<MetadataObjectsAvailableCallbackListener> {
public:
    MetadataObjectsAvailableCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~MetadataObjectsAvailableCallbackListener() = default;
    void OnMetadataObjectsAvailable(std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metaObjects) const override;
private:
    void OnMetadataObjectsAvailableCallback(
        const std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metadataObjList) const;
};

class MetadataOutputImpl : public CameraOutputImpl, public CameraAniEventEmitter<MetadataOutputImpl> {
public:
    MetadataOutputImpl(sptr<OHOS::CameraStandard::MetadataOutput> output);
    ~MetadataOutputImpl() = default;
    void StartSync();
    void StopSync();
    void ReleaseSync() override;
    static uint32_t metadataOutputTaskId_;
    const EmitterFunctions& GetEmitterFunctions() override;
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnMetadataObjectsAvailable(callback_view<void(uintptr_t, array_view<MetadataObject>)> callback);
    void OffMetadataObjectsAvailable(optional_view<callback<void(uintptr_t, array_view<MetadataObject>)>> callback);
    void RemoveMetadataObjectTypes(array_view<MetadataObjectType> types);
    void AddMetadataObjectTypes(array_view<MetadataObjectType> types);
    std::shared_ptr<MetadataOutputCallbackListener> metadataOutputCallback_;
    std::shared_ptr<MetadataObjectsAvailableCallbackListener> metadataObjectsAvailableCallback_;
private:
    sptr<CameraStandard::MetadataOutput> metadataOutput_ = nullptr;
    static const EmitterFunctions fun_map_;
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterMetadataObjectsAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterMetadataObjectsAvailableCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
};

struct MetadataOutputAsyncContext : public TaiheAsyncContext {
    MetadataOutputAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~MetadataOutputAsyncContext()
    {
        objectInfo = nullptr;
    }
    MetadataOutputImpl* objectInfo = nullptr;
    std::string errorMsg;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_METADATA_OUTPUT_TAIHE_H