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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_MANAGER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_MANAGER_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "input/camera_manager.h"
#include "listener_base_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "camera_event_listener_taihe.h"

#include "image_receiver.h"
#include "image_format.h"


namespace Ani {
namespace Camera {
using namespace ohos::multimedia::camera;
using namespace taihe;

class CameraMuteListenerAni : public OHOS::CameraStandard::CameraMuteListener, public ListenerBase,
    public std::enable_shared_from_this<CameraMuteListenerAni> {
public:
    explicit CameraMuteListenerAni(ani_env* env);
    virtual ~CameraMuteListenerAni();
    void OnCameraMute(bool muteMode) const override;
private:
    void OnCameraMuteCallback(bool muteMode) const;
};

class CameraManagerCallbackAni : public OHOS::CameraStandard::CameraManagerCallback, public ListenerBase,
    public std::enable_shared_from_this<CameraManagerCallbackAni> {
public:
    explicit CameraManagerCallbackAni(ani_env* env);
    virtual ~CameraManagerCallbackAni();
    void OnCameraStatusChanged(const OHOS::CameraStandard::CameraStatusInfo &cameraStatusInfo) const override;
    void OnFlashlightStatusChanged(
        const std::string &cameraID, const OHOS::CameraStandard::FlashStatus flashStatus) const override;
private:
    void OnCameraStatusCallback(const OHOS::CameraStandard::CameraStatusInfo &cameraStatusInfo) const;
};

class TorchListenerAni : public OHOS::CameraStandard::TorchListener, public ListenerBase,
    public std::enable_shared_from_this<TorchListenerAni> {
public:
    explicit TorchListenerAni(ani_env* env);
    virtual ~TorchListenerAni();
    void OnTorchStatusChange(const OHOS::CameraStandard::TorchStatusInfo &torchStatusInfo) const override;
private:
    void OnTorchStatusChangeCallback(const OHOS::CameraStandard::TorchStatusInfo &torchStatusInfo) const;
};

class FoldListenerAni : public OHOS::CameraStandard::FoldListener, public ListenerBase,
    public std::enable_shared_from_this<FoldListenerAni> {
public:
    explicit FoldListenerAni(ani_env* env);
    virtual ~FoldListenerAni();
    void OnFoldStatusChanged(const OHOS::CameraStandard::FoldStatusInfo &foldStatusInfo) const override;
private:
    void OnFoldStatusChangedCallback(const OHOS::CameraStandard::FoldStatusInfo &foldStatusInfo) const;
};

class CameraManagerImpl : public CameraAniEventEmitter<CameraManagerImpl>,
                          public CameraAniEventListener<TorchListenerAni>,
                          public CameraAniEventListener<CameraMuteListenerAni>,
                          public CameraAniEventListener<CameraManagerCallbackAni>,
                          public CameraAniEventListener<FoldListenerAni>  {
public:
    CameraManagerImpl();
    ~CameraManagerImpl() {}

    array<CameraDevice> GetSupportedCameras();
    array<SceneMode> GetSupportedSceneModes(CameraDevice const& camera);
    CameraOutputCapability GetSupportedOutputCapability(CameraDevice const& camera, SceneMode mode);
    void Prelaunch();
    void PreSwitchCamera(string_view cameraId);
    bool IsTorchSupported();
    bool IsCameraMuted();
    bool IsCameraMuteSupported();
    bool IsPrelaunchSupported(CameraDevice const& camera);
    TorchMode GetTorchMode();
    void SetTorchMode(TorchMode mode);
    SessionUnion CreateSession(SceneMode mode);
    void MuteCameraPersistent(bool mute, PolicyType type);
    void OnCameraMute(callback_view<void(uintptr_t, bool)> callback);
    void OffCameraMute(optional_view<callback<void(uintptr_t, bool)>> callback);
    void OnCameraStatus(callback_view<void(uintptr_t, CameraStatusInfo const&)> callback);
    void OffCameraStatus(optional_view<callback<void(uintptr_t, CameraStatusInfo const&)>> callback);
    void OnFoldStatusChange(callback_view<void(uintptr_t, FoldStatusInfo const&)> callback);
    void OffFoldStatusChange(optional_view<callback<void(uintptr_t, FoldStatusInfo const&)>> callback);
    void OnTorchStatusChange(callback_view<void(uintptr_t, TorchStatusInfo const&)> callback);
    void OffTorchStatusChange(optional_view<callback<void(uintptr_t, TorchStatusInfo const&)>> callback);
    PreviewOutput CreatePreviewOutput(Profile const& profile, string_view surfaceId) ;
    PreviewOutput CreatePreviewOutputWithoutProfile(string_view surfaceId);
    PreviewOutput CreateDeferredPreviewOutput(optional_view<Profile> profile);
    PhotoOutput CreatePhotoOutput(optional_view<Profile> profile);
    VideoOutput CreateVideoOutput(VideoProfile const& profile, string_view surfaceId);
    VideoOutput CreateVideoOutputWithoutProfile(string_view surfaceId);
    CameraInput CreateCameraInputWithCameraDevice(CameraDevice const& camera);
    CameraInput CreateCameraInputWithPosition(CameraPosition position, CameraType type);
    DepthDataOutput CreateDepthDataOutput(DepthProfile const& profile);
    MetadataOutput CreateMetadataOutput(array_view<MetadataObjectType> metadataObjectTypes);
    array<CameraConcurrentInfo> GetCameraConcurrentInfos(array_view<CameraDevice> cameras);
    void SetPrelaunchConfig(PrelaunchConfig const& prelaunchConfig);
    CameraDevice GetCameraDevice(CameraPosition position, CameraType type);
    void RegisterCameraMuteCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterCameraMuteCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterCameraStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterCameraStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterTorchStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterTorchStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFoldStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFoldStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    virtual const EmitterFunctions& GetEmitterFunctions() override;
    bool IsTorchModeSupported(TorchMode mode);
private:
    static void GetSupportedOutputCapabilityAdaptNormalMode(OHOS::CameraStandard::SceneMode fwkMode,
        OHOS::sptr<OHOS::CameraStandard::CameraDevice>& cameraInfo,
        OHOS::sptr<OHOS::CameraStandard::CameraOutputCapability>& outputCapability);
    static void ProcessCameraInfo(OHOS::sptr<OHOS::CameraStandard::CameraManager>& cameraManager,
        const OHOS::CameraStandard::CameraPosition cameraPosition,
        const OHOS::CameraStandard::CameraType cameraType, OHOS::sptr<OHOS::CameraStandard::CameraDevice>& cameraInfo);
    SessionUnion CreateSessionWithMode(OHOS::CameraStandard::SceneMode sceneModeInner);
    OHOS::sptr<OHOS::CameraStandard::CameraManager> cameraManager_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_MANAGER_TAIHE_H