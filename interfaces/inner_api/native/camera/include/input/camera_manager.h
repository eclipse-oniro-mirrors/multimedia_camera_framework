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

#ifndef OHOS_CAMERA_CAMERA_MANAGER_H
#define OHOS_CAMERA_CAMERA_MANAGER_H

#include <cstdint>
#include <iostream>
#include <mutex>
#include <refbase.h>
#include <thread>
#include <unordered_map>
#include <vector>

#include "camera_stream_info_parse.h"
#include "deferred_proc_session/deferred_photo_proc_session.h"
#include "deferred_proc_session/deferred_video_proc_session.h"
#include "hcamera_listener_stub.h"
#include "hcamera_service_callback_stub.h"
#include "hcamera_service_proxy.h"
#include "icamera_device_service.h"
#include "input/camera_death_recipient.h"
#include "input/camera_device.h"
#include "input/camera_info.h"
#include "input/camera_input.h"
#include "istream_common.h"
#include "istream_repeat.h"
#include "output/camera_output_capability.h"
#include "output/depth_data_output.h"
#include "output/metadata_output.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include "safe_map.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace CameraStandard {
enum CameraDeviceStatus {
    CAMERA_DEVICE_STATUS_UNAVAILABLE = 0,
    CAMERA_DEVICE_STATUS_AVAILABLE
};

enum FlashlightStatus {
    FLASHLIGHT_STATUS_OFF = 0,
    FLASHLIGHT_STATUS_ON,
    FLASHLIGHT_STATUS_UNAVAILABLE
};

enum TorchMode {
    TORCH_MODE_OFF = 0,
    TORCH_MODE_ON,
    TORCH_MODE_AUTO
};

struct CameraStatusInfo {
    sptr<CameraInfo> cameraInfo;
    sptr<CameraDevice> cameraDevice;
    CameraStatus cameraStatus;
    std::string bundleName;
    ~CameraStatusInfo()
    {
        cameraInfo = nullptr;
        cameraDevice = nullptr;
    }
};

struct TorchStatusInfo {
    bool isTorchAvailable;
    bool isTorchActive;
    float torchLevel;
};

struct FoldStatusInfo {
    FoldStatus foldStatus;
    std::vector<sptr<CameraDevice>> supportedCameras;
};

typedef enum OutputCapStreamType {
    PREVIEW = 0,
    VIDEO_STREAM = 1,
    STILL_CAPTURE = 2,
    POST_VIEW = 3,
    ANALYZE = 4,
    CUSTOM = 5,
    DEPTH = 6
} OutputCapStreamType;

class CameraManagerCallback {
public:
    CameraManagerCallback() = default;
    virtual ~CameraManagerCallback() = default;
    virtual void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const = 0;
    virtual void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const = 0;
};

class CameraMuteListener {
public:
    CameraMuteListener() = default;
    virtual ~CameraMuteListener() = default;
    virtual void OnCameraMute(bool muteMode) const = 0;
};

class TorchListener {
public:
    TorchListener() = default;
    virtual ~TorchListener() = default;
    virtual void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const = 0;
};

class FoldListener {
public:
    FoldListener() = default;
    virtual ~FoldListener() = default;
    virtual void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const = 0;
};

class CameraServiceSystemAbilityListener : public SystemAbilityStatusChangeStub {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
};
class CameraManager : public RefBase {
public:
    virtual ~CameraManager();
    /**
     * @brief Get camera manager instance.
     *
     * @return Returns pointer to camera manager instance.
     */
    static sptr<CameraManager>& GetInstance();

    /**
     * @brief Get all available cameras.
     *
     * @return Returns vector of cameraDevice of available camera.
     */
    std::vector<sptr<CameraDevice>> GetSupportedCameras();

    /**
    * @brief Get support modes.
    *
    * @return Returns array the mode of current CameraDevice.
    */
    std::vector<SceneMode> GetSupportedModes(sptr<CameraDevice>& camera);

    /**
     * @brief Get extend output capaility of the mode of the given camera.
     *
     * @param Camera device for which extend capability need to be fetched.
     * @return Returns vector the ability of the mode of cameraDevice of available camera.
     */
    sptr<CameraOutputCapability> GetSupportedOutputCapability(sptr<CameraDevice>& camera, int32_t modeName = 0);

    /**
     * @brief Create camera input instance with provided camera position and type.
     *
     * @param The cameraDevice for which input has to be created.
     * @return Returns pointer to camera input instance.
     */

    sptr<CameraInput> CreateCameraInput(CameraPosition position, CameraType cameraType);

    /**
     * @brief Create camera input instance with provided camera position and type.
     *
     * @param The cameraDevice for which input has to be created.
     * @param Returns pointer to camera input instance.
     * @return Returns error code.
     */
    int CreateCameraInput(CameraPosition position, CameraType cameraType, sptr<CameraInput>* pCameraInput);

    /**
     * @brief Create camera input instance.
     *
     * @param The cameraDevice for which input has to be created.
     * @return Returns pointer to camera input instance.
     */
    sptr<CameraInput> CreateCameraInput(sptr<CameraDevice>& camera);

    /**
     * @brief Create camera input instance.
     *
     * @param The cameraDevice for which input has to be created.
     * @param Returns pointer to camera input instance.
     * @return Returns error code.
     */
    int CreateCameraInput(sptr<CameraDevice>& camera, sptr<CameraInput>* pCameraInput);

    /**
     * @brief Get all available cameras.
     *
     * @return Returns vector of cameraInfo of available camera.
     */
    [[deprecated]] std::vector<sptr<CameraInfo>> GetCameras();

    /**
     * @brief Create camera input instance.
     *
     * @param The cameraInfo for which input has to be created.
     * @return Returns pointer to camera input instance.
     */
    [[deprecated]] sptr<CameraInput> CreateCameraInput(sptr<CameraInfo>& camera);

    /**
     * @brief Create capture session.
     *
     * @return Returns pointer to capture session.
     */
    sptr<CaptureSession> CreateCaptureSession();

    /**
    * @brief Create capture session.
    *
    * @return Returns pointer to capture session.
    */
    sptr<CaptureSession> CreateCaptureSession(SceneMode mode);

    /**
     * @brief Create capture session.
     *
     * @param Returns pointer to capture session.
     * @return Returns error code.
     */
    int CreateCaptureSession(sptr<CaptureSession>* pCaptureSession);

    /**
     * @brief Create photo output instance using surface.
     *
     * @param The surface to be used for photo output.
     * @return Returns pointer to photo output instance.
     */
    sptr<PhotoOutput> CreatePhotoOutput(Profile& profile, sptr<IBufferProducer>& surface);

    /**
    * @brief Create deferred photo processing session.
    *
    * @return Returns pointer to capture session.
    */
    static sptr<DeferredPhotoProcSession> CreateDeferredPhotoProcessingSession(int userId,
        std::shared_ptr<IDeferredPhotoProcSessionCallback> callback);

    /**
    * @brief Create deferred photo processing session.
    *
    * @param Returns pointer to capture session.
    * @return Returns error code.
    */
    static int CreateDeferredPhotoProcessingSession(int userId,
        std::shared_ptr<IDeferredPhotoProcSessionCallback> callback,
        sptr<DeferredPhotoProcSession> *pDeferredPhotoProcSession);
    
    /**
     * @brief Create deferred video processing session.
     *
     * @return Returns pointer to capture session.
     */
    static sptr<DeferredVideoProcSession> CreateDeferredVideoProcessingSession(int userId,
        std::shared_ptr<IDeferredVideoProcSessionCallback> callback);

    /**
     * @brief Create deferred video processing session.
     *
     * @param Returns pointer to capture session.
     * @return Returns error code.
     */
    static int CreateDeferredVideoProcessingSession(int userId,
        std::shared_ptr<IDeferredVideoProcSessionCallback> callback,
        sptr<DeferredVideoProcSession> *pDeferredVideoProcSession);

    /**
     * @brief Create photo output instance.
     *
     * @param profile photo profile.
     * @param surface photo buffer surface.
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutput(Profile& profile, sptr<IBufferProducer>& surface, sptr<PhotoOutput>* pPhotoOutput);

    /**
     * @brief Create photo output instance without profile.
     *
     * @param surface photo buffer surface.
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutputWithoutProfile(sptr<IBufferProducer> surface, sptr<PhotoOutput>* pPhotoOutput);

    /**
     * @brief Create photo output instance using surface.
     *
     * @param The surface to be used for photo output.
     * @return Returns pointer to photo output instance.
     */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(sptr<IBufferProducer>& surface);

    /**
     * @brief Create photo output instance using IBufferProducer.
     *
     * @param The IBufferProducer to be used for photo output.
     * @param The format to be used for photo capture.
     * @return Returns pointer to photo output instance.
     */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format);

    /**
     * @brief Create video output instance using surface.
     *
     * @param The surface to be used for video output.
     * @return Returns pointer to video output instance.
     */
    sptr<VideoOutput> CreateVideoOutput(VideoProfile& profile, sptr<Surface>& surface);

    /**
     * @brief Create video output instance using surface.
     *
     * @param The surface to be used for video output.
     * @param Returns pointer to video output instance.
     * @return Returns error code.
     */
    int CreateVideoOutput(VideoProfile& profile, sptr<Surface>& surface, sptr<VideoOutput>* pVideoOutput);

    /**
     * @brief Create video output instance without profile.
     *
     * @param surface video buffer surface.
     * @param pVideoOutput pointer to video output instance.
     * @return Returns error code.
     */
    int CreateVideoOutputWithoutProfile(sptr<Surface> surface, sptr<VideoOutput>* pVideoOutput);

    /**
     * @brief Create video output instance using surface.
     *
     * @param The surface to be used for video output.
     * @return Returns pointer to video output instance.
     */
    [[deprecated]] sptr<VideoOutput> CreateVideoOutput(sptr<Surface>& surface);

    /**
     * @brief Create video output instance using IBufferProducer.
     *
     * @param The IBufferProducer to be used for video output.
     * @param The format to be used for video capture.
     * @return Returns pointer to video output instance.
     */
    [[deprecated]] sptr<VideoOutput> CreateVideoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format);

    /**
     * @brief Create preview output instance using surface.
     *
     * @param The surface to be used for preview.
     * @return Returns pointer to preview output instance.
     */
    sptr<PreviewOutput> CreatePreviewOutput(Profile& profile, sptr<Surface> surface);

    /**
     * @brief Create preview output instance.
     *
     * @param profile preview profile.
     * @param surface preview buffer surface.
     * @param pPhotoOutput pointer to photo preview instance.
     * @return Returns error code.
     */
    int CreatePreviewOutput(Profile& profile, sptr<Surface> surface, sptr<PreviewOutput>* pPreviewOutput);

    /**
     * @brief Create preview output instance without profile.
     *
     * @param surface preview buffer surface.
     * @param pPhotoOutput pointer to photo preview instance.
     * @return Returns error code.
     */
    int CreatePreviewOutputWithoutProfile(sptr<Surface> surface, sptr<PreviewOutput>* pPreviewOutput);

    /**
     * @brief Create preview output instance using surface.
     *
     * @param The surface to be used for preview.
     * @return Returns pointer to preview output instance.
     */
    [[deprecated]] sptr<PreviewOutput> CreatePreviewOutput(sptr<Surface> surface);

    /**
     * @brief Create preview output instance using IBufferProducer.
     *
     * @param The IBufferProducer to be used for preview output.
     * @param The format to be used for preview.
     * @return Returns pointer to video preview instance.
     */
    [[deprecated]] sptr<PreviewOutput> CreatePreviewOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format);

    /**
     * @brief Create preview output instance using surface.
     *
     * @param The surface to be used for preview.
     * @return Returns pointer to preview output instance.
     */
    sptr<PreviewOutput> CreateDeferredPreviewOutput(Profile& profile);

    /**
     * @brief Create preview output instance using surface.
     *
     * @param The surface to be used for preview.
     * @param Returns pointer to preview output instance.
     * @return Returns error code.
     */
    int CreateDeferredPreviewOutput(Profile& profile, sptr<PreviewOutput>* pPreviewOutput);

    /**
     * @brief Create preview output instance using surface
     * with custom width and height.
     *
     * @param The surface to be used for preview.
     * @param preview width.
     * @param preview height.
     * @return Returns pointer to preview output instance.
     */
    [[deprecated]] sptr<PreviewOutput> CreateCustomPreviewOutput(sptr<Surface> surface, int32_t width, int32_t height);

    /**
     * @brief Create preview output instance using IBufferProducer
     * with custom width and height.
     *
     * @param The IBufferProducer to be used for preview output.
     * @param The format to be used for preview.
     * @param preview width.
     * @param preview height.
     * @return Returns pointer to preview output instance.
     */
    [[deprecated]] sptr<PreviewOutput> CreateCustomPreviewOutput(
        const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width, int32_t height);

    /**
     * @brief Create metadata output instance.
     *
     * @return Returns pointer to metadata output instance.
     */
    sptr<MetadataOutput> CreateMetadataOutput();

    /**
     * @brief Create metadata output instance.
     *
     * @param Returns pointer to metadata output instance.
     * @return Returns error code.
     */
    int CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput);

    /**
     * @brief Create depth output instance.
     *
     * @param depthProfile depth profile.
     * @param surface depth data buffer surface.
     * @return pointer to depth data output instance.
     */
    sptr<DepthDataOutput> CreateDepthDataOutput(DepthProfile& depthProfile, sptr<IBufferProducer> &surface);

    /**
     * @brief Create depth output instance.
     *
     * @param depthProfile depth profile.
     * @param surface depth data buffer surface.
     * @param pDepthDataOutput pointer to depth data output instance.
     * @return Returns error code.
     */
    int CreateDepthDataOutput(DepthProfile& depthProfile, sptr<IBufferProducer> &surface,
                              sptr<DepthDataOutput>* pDepthDataOutput);

    /**
     * @brief Create metadata output instance.
     *
     * @param Returns pointer to metadata output instance.
     * @return Returns error code.
     */
    int CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput,
        std::vector<MetadataObjectType> metadataObjectTypes);

    /**
     * @brief Set camera manager callback.
     *
     * @param CameraManagerCallback pointer.
     */
    void SetCallback(std::shared_ptr<CameraManagerCallback> callback);

    /**
     * @brief Get the application callback.
     *
     * @return CameraManagerCallback pointer is set by application.
     */
    std::shared_ptr<CameraManagerCallback> GetApplicationCallback();

    /**
     * @brief Get cameraDevice of specific camera id.
     *
     * @param std::string camera id.
     * @return Returns pointer to cameraDevice of given Id if found else return nullptr.
     */
    sptr<CameraDevice> GetCameraDeviceFromId(std::string cameraId);

    /**
     * @brief Get cameraInfo of specific camera id.
     *
     * @param std::string camera id.
     * @return Returns pointer to cameraInfo of given Id if found else return nullptr.
     */
    [[deprecated]] sptr<CameraInfo> GetCameraInfo(std::string cameraId);

    /**
     * @brief Get the support of camera mute mode.
     *
     * @return Returns true is supported, false is not supported.
     */
    bool IsCameraMuteSupported();

    /**
     * @brief Get camera mute mode.
     *
     * @return Returns true is in mute, else is not in mute.
     */
    bool IsCameraMuted();

    /**
     * @brief Mute the camera
     *
     * @return.
     */
    void MuteCamera(bool muteMode);

    /**
     * @brief Mute the camera, and the mute mode can be persisting;
     *
     * @param PolicyType policyType.
     * @param bool muteMode.
     * @return.
     */
    int32_t MuteCameraPersist(PolicyType policyType, bool muteMode);

    /**
     * @brief register camera mute listener
     *
     * @param CameraMuteListener listener object.
     * @return.
     */
    void RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener);

    /**
     * @brief get the camera mute listener
     *
     * @return CameraMuteListener point..
     */
    std::shared_ptr<CameraMuteListener> GetCameraMuteListener();

    /**
     * @brief prelaunch the camera
     *
     * @return Server error code.
     */
    int32_t PrelaunchCamera();

    /**
     * @brief Pre-switch camera
     *
     * @return Server error code.
     */
    int32_t PreSwitchCamera(const std::string cameraId);

    /**
     * @brief set prelaunch config
     *
     * @return.
     */
    int32_t SetPrelaunchConfig(std::string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam);

    /**
     * @brief Get the support of camera pre launch mode.
     *
     * @return Returns true is supported, false is not supported.
     */
    bool IsPrelaunchSupported(sptr<CameraDevice> camera);

    /**
     * @brief register torch listener
     *
     * @param TorchListener listener object.
     * @return.
     */
    void RegisterTorchListener(std::shared_ptr<TorchListener> listener);

    /**
     * @brief get the camera mute listener
     *
     * @return TorchListener point..
     */
    std::shared_ptr<TorchListener> GetTorchListener();

    /**
     * @brief register fold status listener
     *
     * @param FoldListener listener object.
     * @return.
     */
    void RegisterFoldListener(std::shared_ptr<FoldListener> listener);

    /**
     * @brief get the camera fold listener
     *
     * @return FoldListener point..
     */
    std::shared_ptr<FoldListener> GetFoldListener();

    SafeMap<std::thread::id, std::shared_ptr<CameraManagerCallback>> GetCameraMngrCallbackMap();
    SafeMap<std::thread::id, std::shared_ptr<CameraMuteListener>> GetCameraMuteListenerMap();
    SafeMap<std::thread::id, std::shared_ptr<TorchListener>> GetTorchListenerMap();

    SafeMap<std::thread::id, std::shared_ptr<FoldListener>> GetFoldListenerMap();

    /**
     * @brief check device if support torch
     *
     * @return Returns true is supported, false is not supported.
     */
    bool IsTorchSupported();

    /**
     * @brief check mode if device can support
     *
     * @return Returns true is supported, false is not supported.
     */
    bool IsTorchModeSupported(TorchMode mode);

    /**
     * @brief get current torchmode
     *
     * @return Returns current torchmode
     */
    TorchMode GetTorchMode();

    /**
     * @brief set torch mode
     *
     * @return.
     */
    int32_t SetTorchMode(TorchMode mode);

    /**
     * @brief update torch mode
     *
     */
    void UpdateTorchMode(TorchMode mode);

    /**
    * @brief set cameramanager null
    *
    */
    void SetCameraManagerNull();

    int32_t CreatePreviewOutputStream(
        sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);

    int32_t CreateVideoOutputStream(
        sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);

    int32_t CreatePhotoOutputStream(
        sptr<IStreamCapture>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);
    /**
    * @brief clear remote stub obj.
    *
    */
    int32_t DestroyStubObj();

    static const std::string surfaceFormat;

    void OnCameraServerAlive();

    virtual bool GetIsFoldable();

    virtual FoldStatus GetFoldStatus();

    inline void ClearCameraDeviceListCache()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        cameraDeviceList_.clear();
    }

    inline void ClearCameraDeviceAbilitySupportMap()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceAbilitySupportMapMutex_);
        cameraDeviceAbilitySupportMap_.clear();
    }

    inline void RemoveCameraDeviceFromCache(const std::string& cameraId)
    {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        cameraDeviceList_.erase(std::remove_if(cameraDeviceList_.begin(), cameraDeviceList_.end(),
            [&cameraId](const auto& cameraDevice) { return cameraDevice->GetID() == cameraId; }),
            cameraDeviceList_.end());
    }

    void GetCameraOutputStatus(int32_t pid, int32_t &status);
    int CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> *pICameraDeviceService);
    inline sptr<ICameraService> GetServiceProxy()
    {
        std::lock_guard<std::mutex> lock(serviceProxyMutex_);
        return serviceProxyPrivate_;
    }

protected:
    // Only for UT
    explicit CameraManager(sptr<ICameraService> serviceProxy) : serviceProxyPrivate_(serviceProxy)
    {
        // Construct method add mutex lock is not necessary. Ignore g_instanceMutex.
        CameraManager::g_cameraManager = this;
    }

private:
    struct ProfilesWrapper {
        std::vector<Profile> photoProfiles = {};
        std::vector<Profile> previewProfiles = {};
        std::vector<VideoProfile> vidProfiles = {};
    };

    enum CameraAbilitySupportCacheKey { CAMERA_ABILITY_SUPPORT_TORCH, CAMERA_ABILITY_SUPPORT_MUTE };

    explicit CameraManager();
    void InitCameraManager();
    void SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback);
    void SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback);
    void SetTorchServiceCallback(sptr<ITorchServiceCallback>& callback);
    void SetFoldServiceCallback(sptr<IFoldServiceCallback>& callback);
    void CreateAndSetCameraServiceCallback();
    void CreateAndSetCameraMuteServiceCallback();
    void CreateAndSetTorchServiceCallback();
    void CreateAndSetFoldServiceCallback();
    int32_t CreateMetadataOutputInternal(sptr<MetadataOutput>& pMetadataOutput,
        const std::vector<MetadataObjectType>& metadataObjectTypes = {});

    sptr<CaptureSession> CreateCaptureSessionImpl(SceneMode mode, sptr<ICaptureSession> session);
    int32_t CreateListenerObject();
    void CameraServerDied(pid_t pid);
    int32_t AddServiceProxyDeathRecipient();
    void RemoveServiceProxyDeathRecipient();

    void ParseProfileLevel(
        ProfilesWrapper& profilesWrapper, const int32_t modeName, const camera_metadata_item_t& item);
    void CreateProfileLevel4StreamType(ProfilesWrapper& profilesWrapper, int32_t specId, StreamInfo& streamInfo);
    void GetSupportedMetadataObjectType(
        common_metadata_header_t* metadata, std::vector<MetadataObjectType>& objectTypes);
    void CreateProfile4StreamType(ProfilesWrapper& profilesWrapper, OutputCapStreamType streamType, uint32_t modeIndex,
        uint32_t streamIndex, ExtendInfo extendInfo);
    static const std::unordered_map<camera_format_t, CameraFormat> metaToFwCameraFormat_;
    static const std::unordered_map<CameraFormat, camera_format_t> fwToMetaCameraFormat_;
    static const std::unordered_map<DepthDataAccuracyType, DepthDataAccuracy> metaToFwDepthDataAccuracy_;
    void ParseExtendCapability(
        ProfilesWrapper& profilesWrapper, const int32_t modeName, const camera_metadata_item_t& item);
    void ParseBasicCapability(ProfilesWrapper& profilesWrapper, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata,
        const camera_metadata_item_t& item);
    void CreateDepthProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
        uint32_t streamIndex, ExtendInfo extendInfo);
    void CreateProfile4StreamType(OutputCapStreamType streamType, uint32_t modeIndex,
        uint32_t streamIndex, ExtendInfo extendInfo);
    void ParseExtendCapability(const int32_t modeName, const camera_metadata_item_t& item);
    void ParseBasicCapability(
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, const camera_metadata_item_t& item);
    void ParseDepthCapability(const int32_t modeName, const camera_metadata_item_t& item);
    void AlignVideoFpsProfile(std::vector<sptr<CameraDevice>>& cameraObjList);
    void SetProfile(std::vector<sptr<CameraDevice>>& cameraObjList);
    SceneMode GetFallbackConfigMode(SceneMode profileMode, ProfilesWrapper& profilesWrapper);
    void ParseCapability(ProfilesWrapper& profilesWrapper, sptr<CameraDevice>& camera, const int32_t modeName,
        camera_metadata_item_t& item, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    camera_format_t GetCameraMetadataFormat(CameraFormat format);
    std::vector<dmDeviceInfo> GetDmDeviceInfo();
    dmDeviceInfo GetDmDeviceInfo(const std::string& cameraId, const std::vector<dmDeviceInfo>& dmDeviceInfoList);
    int32_t SetTorchLevel(float level);
    int32_t ValidCreateOutputStream(Profile& profile, const sptr<OHOS::IBufferProducer>& producer);
    int32_t SubscribeSystemAbility();
    int32_t UnSubscribeSystemAbility();
    void ReportEvent(const string& cameraId);
    int32_t RefreshServiceProxy();
    std::vector<sptr<CameraDevice>> GetCameraDeviceListFromServer();
    bool IsSystemApp();
    vector<CameraFormat> GetSupportPhotoFormat(const int32_t modeName,
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    void FillSupportPhotoFormats(std::vector<Profile>& profiles);

    inline void SetServiceProxy(sptr<ICameraService> proxy)
    {
        std::lock_guard<std::mutex> lock(serviceProxyMutex_);
        serviceProxyPrivate_ = proxy;
    }

    inline std::vector<sptr<CameraDevice>> GetCameraDeviceList()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        if (cameraDeviceList_.empty()) {
            cameraDeviceList_ = GetCameraDeviceListFromServer();
        }
        return cameraDeviceList_;
    }

    inline bool IsCameraDeviceListCached()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        return !cameraDeviceList_.empty();
    }

    inline void CacheCameraDeviceAbilitySupportValue(CameraAbilitySupportCacheKey key, bool value)
    {
        std::lock_guard<std::mutex> lock(cameraDeviceAbilitySupportMapMutex_);
        cameraDeviceAbilitySupportMap_[key] = value;
    }

    inline bool GetCameraDeviceAbilitySupportValue(CameraAbilitySupportCacheKey key, bool& value)
    {
        std::lock_guard<std::mutex> lock(cameraDeviceAbilitySupportMapMutex_);
        auto it = cameraDeviceAbilitySupportMap_.find(key);
        if (it == cameraDeviceAbilitySupportMap_.end()) {
            return false;
        }
        value = it->second;
        return true;
    }

    std::mutex cameraDeviceListMutex_;
    std::vector<sptr<CameraDevice>> cameraDeviceList_ = {};

    std::mutex cameraDeviceAbilitySupportMapMutex_;
    std::unordered_map<CameraAbilitySupportCacheKey, bool> cameraDeviceAbilitySupportMap_;

    std::mutex serviceProxyMutex_;
    sptr<ICameraService> serviceProxyPrivate_;
    std::mutex deathRecipientMutex_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;

    static sptr<CameraManager> g_cameraManager;
    static std::mutex g_instanceMutex;
    std::mutex cameraSvcCallbackMutex_;
    sptr<ICameraServiceCallback> cameraSvcCallback_;
    std::mutex cameraMuteSvcCallbackMutex_;
    sptr<ICameraMuteServiceCallback> cameraMuteSvcCallback_;
    std::mutex torchSvcCallbackMutex_;
    sptr<ITorchServiceCallback> torchSvcCallback_;
    std::mutex foldSvcCallbackMutex_;
    sptr<IFoldServiceCallback> foldSvcCallback_;

    SafeMap<std::thread::id, std::shared_ptr<CameraManagerCallback>> cameraMngrCallbackMap_;
    SafeMap<std::thread::id, std::shared_ptr<CameraMuteListener>> cameraMuteListenerMap_;
    SafeMap<std::thread::id, std::shared_ptr<TorchListener>> torchListenerMap_;
    SafeMap<std::thread::id, std::shared_ptr<FoldListener>> foldListenerMap_;

    std::map<std::string, dmDeviceInfo> distributedCamInfoAndId_;

    std::map<std::string, std::vector<Profile>> modePhotoProfiles_ = {};
    std::map<std::string, std::vector<Profile>> modePreviewProfiles_ = {};
    std::vector<DepthProfile> depthProfiles_ = {};

    std::vector<CameraFormat> photoFormats_ = {};
    sptr<CameraInput> cameraInput_;
    TorchMode torchMode_ = TorchMode::TORCH_MODE_OFF;
    std::mutex saListenerMuxtex_;
    sptr<CameraServiceSystemAbilityListener> saListener_ = nullptr;
    std::string foldScreenType_;
    bool isSystemApp_ = false;
};

class CameraMuteServiceCallback : public HCameraMuteServiceCallbackStub {
public:
    explicit CameraMuteServiceCallback(sptr<CameraManager> cameraManager) : cameraManager_(cameraManager) {}
    int32_t OnCameraMute(bool muteMode) override;

private:
    wptr<CameraManager> cameraManager_ = nullptr;
};

class CameraStatusServiceCallback : public HCameraServiceCallbackStub {
public:
    explicit CameraStatusServiceCallback(sptr<CameraManager> cameraManager) : cameraManager_(cameraManager) {}
    int32_t OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status,
        const std::string& bundleName) override;
    int32_t OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status) override;

private:
    wptr<CameraManager> cameraManager_ = nullptr;
};

class TorchServiceCallback : public HTorchServiceCallbackStub {
public:
    explicit TorchServiceCallback(sptr<CameraManager> cameraManager) : cameraManager_(cameraManager) {}
    int32_t OnTorchStatusChange(const TorchStatus status) override;

private:
    wptr<CameraManager> cameraManager_ = nullptr;
};

class FoldServiceCallback : public HFoldServiceCallbackStub {
public:
    explicit FoldServiceCallback(sptr<CameraManager> cameraManager) : cameraManager_(cameraManager) {}
    int32_t OnFoldStatusChanged(const FoldStatus status) override;

private:
    wptr<CameraManager> cameraManager_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_MANAGER_H
