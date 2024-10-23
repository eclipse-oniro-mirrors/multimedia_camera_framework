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

#ifndef CAMERA_INPUT_NAPI_H_
#define CAMERA_INPUT_NAPI_H_

#include <atomic>
#include <cstdint>
#include <mutex>

#include "camera_napi_event_emitter.h"
#include "camera_napi_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "listener_base.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_INPUT_NAPI_CLASS_NAME[] = "CameraInput";

struct CameraInputAsyncContext;

class ErrorCallbackListener : public ErrorCallback,
                              public ListenerBase,
                              public std::enable_shared_from_this<ErrorCallbackListener> {
public:
    ErrorCallbackListener(napi_env env) : ListenerBase(env) {}
    ~ErrorCallbackListener() = default;
    void OnError(const int32_t errorType, const int32_t errorMsg) const override;

private:
    void OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const;
    void OnErrorCallbackAsync(const int32_t errorType, const int32_t errorMsg) const;
};

struct ErrorCallbackInfo {
    int32_t errorType_;
    int32_t errorMsg_;
    weak_ptr<const ErrorCallbackListener> listener_;
    ErrorCallbackInfo(int32_t errorType, int32_t errorMsg, shared_ptr<const ErrorCallbackListener> listener)
        : errorType_(errorType), errorMsg_(errorMsg), listener_(listener) {}
};

class OcclusionDetectCallbackListener : public CameraOcclusionDetectCallback,
                              public ListenerBase,
                              public std::enable_shared_from_this<OcclusionDetectCallbackListener> {
public:
    OcclusionDetectCallbackListener(napi_env env) : ListenerBase(env) {}
    ~OcclusionDetectCallbackListener() = default;
    void OnCameraOcclusionDetected(const uint8_t isCameraOcclusion,
                                   const uint8_t isCameraLensDirty) const override;
 
private:
    void OnCameraOcclusionDetectedCallback(const uint8_t isCameraOcclusion,
                                           const uint8_t isCameraLensDirty) const;
    void OnCameraOcclusionDetectedCallbackAsync(const uint8_t isCameraOcclusion,
                                                const uint8_t isCameraLensDirty) const;
};
 
struct CameraOcclusionDetectResult {
    uint8_t isCameraOccluded_;
    uint8_t isCameraLensDirty_;
    weak_ptr<const OcclusionDetectCallbackListener> listener_;
    CameraOcclusionDetectResult(uint8_t isCameraOccluded, uint8_t isCameraLensDirty,
        shared_ptr<const OcclusionDetectCallbackListener> listener)
        : isCameraOccluded_(isCameraOccluded), isCameraLensDirty_(isCameraLensDirty), listener_(listener) {}
};

class CameraInputNapi : public CameraNapiEventEmitter<CameraInputNapi> {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraInput(napi_env env, sptr<CameraInput> cameraInput);
    CameraInputNapi();
    ~CameraInputNapi() override;

    static void NapiCreateInt32Logs(
        napi_env env, int32_t contextMode, std::unique_ptr<JSAsyncContextOutput>& jsContext);
    static void NapiCreateDoubleLogs(
        napi_env env, double contextMode, std::unique_ptr<JSAsyncContextOutput>& jsContext);

    static napi_value Open(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);

    const EmitterFunctions& GetEmitterFunctions() override;

    sptr<CameraInput> GetCameraInput();
    sptr<CameraInput> cameraInput_;

private:
    static void CameraInputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraInputNapiConstructor(napi_env env, napi_callback_info info);

    void RegisterErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterOcclusionDetectCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterOcclusionDetectCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);

    napi_env env_;
    std::string cameraId_;
    shared_ptr<ErrorCallbackListener> errorCallback_;
    shared_ptr<OcclusionDetectCallbackListener> occlusionDetectCallback_;

    static thread_local napi_ref sConstructor_;
    static thread_local std::string sCameraId_;
    static thread_local sptr<CameraInput> sCameraInput_;
    static thread_local uint32_t cameraInputTaskId;
};

struct CameraInputAsyncContext : public AsyncContext {
    CameraInputAsyncContext(std::string funcName, int32_t taskId) : AsyncContext(funcName, taskId) {};
    CameraInputNapi* objectInfo = nullptr;
    bool isEnableSecCam = false;
    uint64_t secureCameraSeqId = 0L;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_INPUT_NAPI_H_ */
