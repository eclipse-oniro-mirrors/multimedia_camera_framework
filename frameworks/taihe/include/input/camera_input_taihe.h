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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_INPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_INPUT_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "input/camera_input.h"

#include "camera_worker_queue_keeper_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "camera_event_listener_taihe.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace taihe;
using namespace ohos::multimedia::camera;

class ErrorCallbackListenerAni : public OHOS::CameraStandard::ErrorCallback,
                                 public ListenerBase,
                                 public std::enable_shared_from_this<ErrorCallbackListenerAni> {
public:
    ErrorCallbackListenerAni(ani_env* env) : ListenerBase(env) {}
    ~ErrorCallbackListenerAni() = default;
    void OnError(const int32_t errorType, const int32_t errorMsg) const override;

private:
    void OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const;
};

class OcclusionDetectCallbackListenerAni : public OHOS::CameraStandard::CameraOcclusionDetectCallback,
                                           public ListenerBase,
                                           public std::enable_shared_from_this<OcclusionDetectCallbackListenerAni> {
public:
    OcclusionDetectCallbackListenerAni(ani_env* env) : ListenerBase(env) {}
    ~OcclusionDetectCallbackListenerAni() = default;
    void OnCameraOcclusionDetected(const uint8_t isCameraOcclusion,
                                   const uint8_t isCameraLensDirty) const override;
 
private:
    void OnCameraOcclusionDetectedCallback(const uint8_t isCameraOcclusion,
                                           const uint8_t isCameraLensDirty) const;
};

class CameraInputImpl : public CameraAniEventEmitter<CameraInputImpl> {
public:
    explicit CameraInputImpl(sptr<OHOS::CameraStandard::CameraInput> input);
    ~CameraInputImpl() = default;

    void OpenSync();
    array<uint64_t> OpenByIsSecureEnabledSync(bool isSecureEnabled);
    void OpenByCameraConcurrentTypeSync(ohos::multimedia::camera::CameraConcurrentType type);
    void CloseSync();
    void ControlAuxiliarySync(AuxiliaryType auxiliaryType, AuxiliaryStatus auxiliaryStatus);
    OHOS::sptr<OHOS::CameraStandard::CameraInput> GetCameraInput();
    void CloseDelayedSync(int32_t time);
    void UsedAsPosition(CameraPosition position);
    inline int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<uintptr_t>(this);
    }

    void OnError(CameraDevice const& parm, callback_view<void(uintptr_t)> callback);
    void OffError(CameraDevice const& parm, optional_view<callback<void(uintptr_t)>> callback);
    void OnCameraOcclusionDetection(callback_view<void(uintptr_t, CameraOcclusionDetectionResult const&)> callback);
    void OffCameraOcclusionDetection(
        optional_view<callback<void(uintptr_t, CameraOcclusionDetectionResult const&)>> callback);

    static uint32_t cameraInputTaskId_;
private:
    void RegisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterOcclusionDetectCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterOcclusionDetectCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    virtual const EmitterFunctions& GetEmitterFunctions() override;
    sptr<OHOS::CameraStandard::CameraInput> cameraInput_;
    std::shared_ptr<ErrorCallbackListenerAni> errorCallback_;
    std::shared_ptr<OcclusionDetectCallbackListenerAni> occlusionDetectCallback_;
};

struct CameraInputAsyncContext : public TaiheAsyncContext {
    CameraInputAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};
    ~CameraInputAsyncContext()
    {
        objectInfo = nullptr;
    }
    CameraInputImpl* objectInfo = nullptr;
    bool isEnableSecCam = false;
    int32_t delayTime  = 0 ;
    uint64_t secureCameraSeqId = 0L;
    int32_t cameraConcurrentType = -1;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_INPUT_TAIHE_H