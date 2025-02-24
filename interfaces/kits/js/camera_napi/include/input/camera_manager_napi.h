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

#ifndef CAMERA_MANAGER_NAPI_H_
#define CAMERA_MANAGER_NAPI_H_

#include "camera_napi_utils.h"
#include "input/camera_device.h"
#include "input/camera_input_napi.h"
#include "input/camera_manager.h"
#include "listener_base.h"
#include "output/camera_output_capability.h"
#include "output/capture_output.h"
#include "output/depth_data_output_napi.h"
#include "output/photo_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "session/camera_session_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_MANAGER_NAPI_CLASS_NAME[] = "CameraManager";

enum CameraManagerAsyncCallbackModes {
    CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK,
};

class CameraManagerCallbackNapi : public CameraManagerCallback, public ListenerBase,
    public std::enable_shared_from_this<CameraManagerCallbackNapi> {
public:
    explicit CameraManagerCallbackNapi(napi_env env);
    virtual ~CameraManagerCallbackNapi();
    void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const override;
    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const override;

private:
    void OnCameraStatusCallback(const CameraStatusInfo &cameraStatusInfo) const;
    void OnCameraStatusCallbackAsync(const CameraStatusInfo &cameraStatusInfo) const;
};

struct CameraStatusCallbackInfo {
    CameraStatusInfo info_;
    weak_ptr<const CameraManagerCallbackNapi> listener_;
    CameraStatusCallbackInfo(CameraStatusInfo info, shared_ptr<const CameraManagerCallbackNapi> listener)
        : info_(info), listener_(listener) {}
    ~CameraStatusCallbackInfo()
    {
        listener_.reset();
    }
};

class CameraMuteListenerNapi : public CameraMuteListener, public ListenerBase,
    public std::enable_shared_from_this<CameraMuteListenerNapi> {
public:
    explicit CameraMuteListenerNapi(napi_env env);
    virtual ~CameraMuteListenerNapi();
    void OnCameraMute(bool muteMode) const override;
private:
    void OnCameraMuteCallback(bool muteMode) const;
    void OnCameraMuteCallbackAsync(bool muteMode) const;
};

struct CameraMuteCallbackInfo {
    bool muteMode_;
    weak_ptr<const CameraMuteListenerNapi> listener_;
    CameraMuteCallbackInfo(bool muteMode, shared_ptr<const CameraMuteListenerNapi> listener)
        : muteMode_(muteMode), listener_(listener) {}
    ~CameraMuteCallbackInfo()
    {
        listener_.reset();
    }
};

class TorchListenerNapi : public TorchListener, public ListenerBase,
    public std::enable_shared_from_this<TorchListenerNapi> {
public:
    explicit TorchListenerNapi(napi_env env);
    virtual ~TorchListenerNapi();
    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override;
private:
    void OnTorchStatusChangeCallback(const TorchStatusInfo &torchStatusInfo) const;
    void OnTorchStatusChangeCallbackAsync(const TorchStatusInfo &torchStatusInfo) const;
};

struct TorchStatusChangeCallbackInfo {
    TorchStatusInfo info_;
    weak_ptr<const TorchListenerNapi> listener_;
    TorchStatusChangeCallbackInfo(TorchStatusInfo info, shared_ptr<const TorchListenerNapi> listener)
        : info_(info), listener_(listener) {}
    ~TorchStatusChangeCallbackInfo()
    {
        listener_.reset();
    }
};

class FoldListenerNapi : public FoldListener, public ListenerBase,
    public std::enable_shared_from_this<FoldListenerNapi> {
public:
    explicit FoldListenerNapi(napi_env env);
    virtual ~FoldListenerNapi();
    void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const override;
private:
    void OnFoldStatusChangedCallback(const FoldStatusInfo &foldStatusInfo) const;
    void OnFoldStatusChangedCallbackAsync(const FoldStatusInfo &foldStatusInfo) const;
};

struct FoldStatusChangeCallbackInfo {
    FoldStatusInfo info_;
    weak_ptr<const FoldListenerNapi> listener_;
    FoldStatusChangeCallbackInfo(FoldStatusInfo info, shared_ptr<const FoldListenerNapi> listener)
        : info_(info), listener_(listener) {}
    ~FoldStatusChangeCallbackInfo()
    {
        listener_.reset();
    }
};

class CameraManagerNapi : public CameraNapiEventEmitter<CameraManagerNapi>,
                          public CameraNapiEventListener<TorchListenerNapi>,
                          public CameraNapiEventListener<CameraManagerCallbackNapi>,
                          public CameraNapiEventListener<CameraMuteListenerNapi>,
                          public CameraNapiEventListener<FoldListenerNapi> {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraManager(napi_env env);
    static napi_value GetSupportedCameras(napi_env env, napi_callback_info info);
    static napi_value GetSupportedModes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedOutputCapability(napi_env env, napi_callback_info info);
    static napi_value IsCameraMuted(napi_env env, napi_callback_info info);
    static napi_value IsCameraMuteSupported(napi_env env, napi_callback_info info);
    static napi_value MuteCamera(napi_env env, napi_callback_info info);
    static napi_value MuteCameraPersist(napi_env env, napi_callback_info info);
    static napi_value PrelaunchCamera(napi_env env, napi_callback_info info);
    static napi_value PreSwitchCamera(napi_env env, napi_callback_info info);
    static napi_value SetPrelaunchConfig(napi_env env, napi_callback_info info);
    static napi_value IsPrelaunchSupported(napi_env env, napi_callback_info info);
    static napi_value CreateCameraInputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateCameraSessionInstance(napi_env env, napi_callback_info info);
    static napi_value CreateSessionInstance(napi_env env, napi_callback_info info);
    static napi_value CreatePreviewOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateDeferredPreviewOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreatePhotoOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateVideoOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateMetadataOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateDepthDataOutputInstance(napi_env env, napi_callback_info info);
    static napi_value IsTorchSupported(napi_env env, napi_callback_info info);
    static napi_value IsTorchModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetTorchMode(napi_env env, napi_callback_info info);
    static napi_value SetTorchMode(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value GetCameraDevice(napi_env env, napi_callback_info info);
    static napi_value GetCameraConcurrentInfos(napi_env env, napi_callback_info info);

    CameraManagerNapi();
    ~CameraManagerNapi() override;

    virtual const EmitterFunctions& GetEmitterFunctions() override;

private:
    static void CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraManagerNapiConstructor(napi_env env, napi_callback_info info);
    static void ProcessCameraInfo(sptr<CameraManager>& cameraManager, const CameraPosition cameraPosition,
        const CameraType cameraType, sptr<CameraDevice>& cameraInfo);
    static void GetSupportedOutputCapabilityAdaptNormalMode(
        SceneMode fwkMode, sptr<CameraDevice>& cameraInfo, sptr<CameraOutputCapability>& outputCapability);
    static sptr<CameraDevice> GetSupportedOutputCapabilityGetCameraInfo(
        napi_env env, napi_callback_info info, CameraManagerNapi*& cameraManagerNapi, int32_t& jsSceneMode);

    static void RemoveDuplicatesProfile(sptr<CameraOutputCapability>& outputCapability);
    template<typename T>
    static void RemoveDuplicatesProfile(std::vector<T>& profiles);
    static napi_value CreateCameraConcurrentResult(napi_env env, vector<sptr<CameraDevice>> &cameraDeviceArrray,
        std::vector<bool> &cameraConcurrentType, std::vector<std::vector<SceneMode>> &modes,
        std::vector<std::vector<sptr<CameraOutputCapability>>> &outputCapabilities);
    void ParseGetCameraConcurrentInfos(napi_env env, napi_value arrayParam,
        std::vector<string> &cameraIdv);

    void RegisterCameraStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterCameraStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterCameraMuteCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterCameraMuteCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterTorchStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterTorchStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterFoldStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFoldStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);

    static thread_local napi_ref sConstructor_;

    napi_env env_;
    sptr<CameraManager> cameraManager_;
    static thread_local uint32_t cameraManagerTaskId;
};

struct CameraManagerContext : public AsyncContext {
    std::string surfaceId;
    CameraManagerNapi* managerInstance;
    Profile profile;
    VideoProfile videoProfile;
    DepthProfile depthProfile;
    CameraManagerAsyncCallbackModes modeForAsync;
    std::string errString;
    ~CameraManagerContext()
    {
        managerInstance = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_MANAGER_NAPI_H_ */
