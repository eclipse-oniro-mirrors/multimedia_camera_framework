/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <memory>
#include <mutex>
#include <refbase.h>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "camera_stream_info_parse.h"
#include "camera_timer.h"
#include "color_space_info_parse.h"
#include "control_center_session.h"
#include "deferred_proc_session/deferred_photo_proc_session.h"
#include "deferred_proc_session/deferred_video_proc_session.h"
#include "hcamera_listener_stub.h"
#include "camera_service_callback_stub.h"
#include "camera_shared_service_callback_stub.h"
#include "camera_mute_service_callback_stub.h"
#include "control_center_status_callback_stub.h"
#include "fold_service_callback_stub.h"
#include "icamera_shared_service_callback.h"
#include "icontrol_center_status_callback.h"
#include "torch_service_callback_stub.h"
#include "camera_service_proxy.h"
#include "icamera_device_service.h"
#include "icamera_service_callback.h"
#include "input/camera_death_recipient.h"
#include "input/camera_device.h"
#include "input/camera_info.h"
#include "input/camera_input.h"
#include "istream_common.h"
#include "istream_repeat.h"
#include "output/camera_output_capability.h"
#include "output/metadata_output.h"
#include "output/movie_file_output.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"
#include "safe_map.h"
#include "session/mech_session.h"
#include "session/cameraSwitch_session.h"
#include "unify_movie_file_output.h"

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

class ControlCenterStatusListener {
public:
    ControlCenterStatusListener() = default;
    virtual ~ControlCenterStatusListener() = default;
    virtual void OnControlCenterStatusChanged(bool status) const = 0;
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

class CameraSharedStatusListener {
public:
    CameraSharedStatusListener() = default;
    virtual ~CameraSharedStatusListener() = default;
    virtual void OnCameraSharedStatusChanged(const CameraSharedStatus status) const = 0;
};

class TorchServiceListenerManager;
class CameraStatusListenerManager;
class CameraMuteListenerManager;
class ControlCenterStatusListenerManager;
class FoldStatusListenerManager;
class CameraSharedStatusListenerManager;
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
     * @brief Get extend output capaility of the mode of the given camera from cameraDevice.
     *
     * @param Camera device for which extend capability need to be fetched.
     * @return Returns vector the ability of the mode of cameraDevice of available camera from cameraDevice.
     */
    sptr<CameraOutputCapability> GetSupportedOutputCapability(sptr<CameraDevice>& cameraDevice, int32_t modeName = 0);

    /**
     * @brief Get full output capaility of the mode of the given camera from cameraDevice.
     *
     * @param Camera device for which full capability need to be fetched.
     * @return Returns vector the ability of the mode of cameraDevice of available camera from cameraDevice.
     */
    sptr<CameraOutputCapability> GetSupportedFullOutputCapability(sptr<CameraDevice>& cameraDevice,
        int32_t modeName = 0);

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
    * @brief Create capture session from hcamera service.
    *
    * @return Returns error code.
    */
    int32_t CreateCaptureSessionFromService(sptr<ICaptureSession>& session, SceneMode mode);

    /**
     * @brief Create capture session.
     *
     * @param pCaptureSession pointer to capture session.
     * @param mode Target mode
     * @return Returns error code.
     */
    int32_t CreateCaptureSession(sptr<CaptureSession>& pCaptureSession, SceneMode mode);

    /**
     * @brief Create capture session.
     *
     * @param pCaptureSession pointer to capture session.
     * @return Returns error code.
     */
    int32_t CreateCaptureSession(sptr<CaptureSession>* pCaptureSession);

    /**
     * @brief Create photo output instance using surfaceProducer.
     *
     * @param The surfaceProducer to be used for photo output.
     * @return Returns pointer to photo output instance.
     */
    sptr<PhotoOutput> CreatePhotoOutput(Profile& profile, sptr<IBufferProducer>& surfaceProducer);

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
     * @brief Create mech session.
     *
     * @return Returns pointer to mech session.
     */
    sptr<MechSession> CreateMechSession(int userId);

    /**
     * @brief Create Create mech session.
     *
     * @param pMechSession pointer to mech session instance.
     * @return Returns error code.
     */
    int CreateMechSession(int userId, sptr<MechSession> *pMechSession);

    /**
     * @brief Get the support of mech.
     *
     * @return Returns true is supported, false is not supported.
     */
    bool IsMechSupported();

    /**
     * @brief Create cameraSwitch session.
     *
     * @return Returns pointer to cameraSwitch session.
     */
    sptr<CameraSwitchSession> CreateCameraSwitchSession();

    /**
     * @brief Create cameraSwitch session.
     *
     * @param pMechSession pointer to cameraSwitch session instance.
     * @return Returns error code.
     */
    int CreateCameraSwitchSession(sptr<CameraSwitchSession> *switchSession);

    /**
     * @brief Create photo output instance.
     *
     * @param profile photo profile.
     * @param surfaceProducer photo buffer surfaceProducer.
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutput(Profile& profile, sptr<IBufferProducer>& surfaceProducer, sptr<PhotoOutput>* pPhotoOutput);

    /**
     * @brief Create photo output instance.
     *
     * @param profile photo profile.
     * @param surfaceProducer photo buffer surfaceProducer.
     * @param pPhotoOutput pointer to photo output instance.
     * @param photoSurface photo buffer surface.
     * @return Returns error code.
     */
    int CreatePhotoOutput(Profile &profile, sptr<IBufferProducer> &surfaceProducer, sptr<PhotoOutput> *pPhotoOutput,
                          sptr<Surface> photoSurface);

    /**
     * @brief Create photo output instance.
     *
     * @param profile photo profile.
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutput(Profile &profile, sptr<PhotoOutput> *pPhotoOutput);

    /**
     * @brief Create photo output instance without profile.
     *
     * @param surfaceProducer photo buffer surfaceProducer.
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutputWithoutProfile(sptr<IBufferProducer> surfaceProducer, sptr<PhotoOutput>* pPhotoOutput);

    /**
     * @brief Create photo output instance without profile.
     *
     * @param surfaceProducer photo buffer surfaceProducer.
     * @param pPhotoOutput pointer to photo output instance.
     * @param photoSurface photo buffer surface.
     * @return Returns error code.
     */
    int CreatePhotoOutputWithoutProfile(sptr<IBufferProducer> surfaceProducer, sptr<PhotoOutput>* pPhotoOutput,
                                        sptr<Surface> photoSurface);

    /**
     * @brief Create photo output instance without profile.
     *
     * @param pPhotoOutput pointer to photo output instance.
     * @return Returns error code.
     */
    int CreatePhotoOutputWithoutProfile(sptr<PhotoOutput>* pPhotoOutput);

    /**
     * @brief Create photo output instance using surfaceProducer.
     *
     * @param The surfaceProducer to be used for photo output.
     * @return Returns pointer to photo output instance.
     */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(sptr<IBufferProducer>& surfaceProducer);

    /**
     * @brief Create photo output instance using IBufferProducer.
     *
     * @param The IBufferProducer to be used for photo output.
     * @param The format to be used for photo capture.
     * @return Returns pointer to photo output instance.
     */
    [[deprecated]] sptr<PhotoOutput> CreatePhotoOutput(
        const sptr<OHOS::IBufferProducer> &surfaceProducer, int32_t format);

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
     * @brief Get stream depth data from service.
     *
     * @param depthProfile depth profile.
     * @param surfaceProducer depth data buffer surfaceProducer.
     * @param streamDepthData pointer to depth data stream.
     * @return Returns error code.
     */
    int GetStreamDepthDataFromService(DepthProfile& depthProfile, sptr<IBufferProducer> &surfaceProducer,
        sptr<IStreamDepthData>& streamDepthData);

    /**
     * @brief Create metadata output instance.
     *
     * @param Returns pointer to metadata output instance.
     * @return Returns error code.
     */
    int CreateMetadataOutput(sptr<MetadataOutput>& pMetadataOutput,
        std::vector<MetadataObjectType> metadataObjectTypes);

    /**
     * @brief Create movie file output instance.
     *
     * @param Returns pointer to movie file output instance.
     * @return Returns error code.
     */
    int CreateMovieFileOutput(VideoProfile &profile, sptr<MovieFileOutput> *pMovieFileOutput);

    /**
     * @brief Create movie file output instance.
     *
     * @param Returns pointer to movie file output instance.
     * @return Returns error code.
     */
    int CreateMovieFileOutput(VideoProfile &profile, sptr<UnifyMovieFileOutput> *pMovieFileOutput);

    /**
     * @brief Register camera status listener.
     *
     * @param listener CameraManagerCallback pointer.
     */
    void SetCallback(std::shared_ptr<CameraManagerCallback> listener);

    /**
     * @brief Register camera status listener.
     *
     * @param listener CameraManagerCallback pointer.
     */
    void RegisterCameraStatusCallback(std::shared_ptr<CameraManagerCallback> listener);

    /**
     * @brief Unregister camera status listener.
     *
     * @param listener CameraManagerCallback pointer.
     */
    void UnregisterCameraStatusCallback(std::shared_ptr<CameraManagerCallback> listener);

    /**
     * @brief Get the camera status listener manager.
     *
     * @return CameraStatusListenerManager pointer is set by application.
     */
    sptr<CameraStatusListenerManager> GetCameraStatusListenerManager();

    /**
     * @brief Get cameraDevice of specific camera id.
     *
     * @param std::string camera id.
     * @return Returns pointer to cameraDevice of given Id if found else return nullptr.
     */
    sptr<CameraDevice> GetCameraDeviceFromId(std::string cameraId);

    /**
     * @brief check if control center active
     *
     * @return Returns true if active, false if not active.
     */
    bool IsControlCenterActive();

    /**
     * @brief create the ControlCenterSession instance.
     *
     * @return Returns the instance of ControlCenterSession.
     */
    int32_t CreateControlCenterSession(sptr<ControlCenterSession>& pControlCenterSession);

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
     * @brief Register camera mute listener
     *
     * @param listener The mute listener object.
     *
     */
    void RegisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener);

    /**
     * @brief Unregister camera mute listener
     *
     * @param listener The mute listener object.
     * @return.
     */
    void UnregisterCameraMuteListener(std::shared_ptr<CameraMuteListener> listener);

    /**
     * @brief Register control center status listener
     *
     * @param listener The control center status listener object.
     * @return.
     */
    void RegisterControlCenterStatusListener(std::shared_ptr<ControlCenterStatusListener> listener);

    /**
     * @brief Unregister control center status listener
     *
     * @param listener The control center status object.
     * @return.
     */
    void UnregisterControlCenterStatusListener(std::shared_ptr<ControlCenterStatusListener> listener);

    /**
     * @brief Get the ControlCenterStatusListenerManager.
     *
     * @return ControlCenterStatusListenerManager.
     */
    sptr<ControlCenterStatusListenerManager> GetControlCenterStatusListenerManager();

    /**
     * @brief Set control center frame condition.
     *
     * @param frameCondition The control center frame condition.
     * @return.
     */
    void SetControlCenterFrameCondition(bool frameCondition);

    /**
     * @brief Set control center resolution condition.
     *
     * @param resolutionCondition The control center resolution condition.
     * @return.
     */
    void SetControlCenterResolutionCondition(bool resolutionCondition);

    /**
     * @brief Set control center position condition.
     *
     * @param positionCondition The control center position condition.
     * @return.
     */
    void SetControlCenterPositionCondition(bool positionCondition);

    /**
     * @brief Update control center precondition.
     *
     * @return.
     */
    void UpdateControlCenterPrecondition();

    /**
     * @brief Get control center precondition.
     *
     * @return Returns control center precondition.
     */
    bool GetControlCenterPrecondition();

    /**
     * @brief Set if control center supported.
     *
     * @param isSupported The control center isSupported.
     * @return.
     */
    void SetIsControlCenterSupported(bool isSupported);

    /**
     * @brief Get if control center supported.
     *
     * @return Returns if control center supported.
     */
    bool GetIsControlCenterSupported();

    /**
     * @brief Get the camera mute listener manager.
     *
     * @return CameraMuteListenerManager point.
     */
    sptr<CameraMuteListenerManager> GetCameraMuteListenerManager();

    /**
     * @brief Register camera shared status listener
     *
     * @param listener The camera shared status listener object.
     * @return.
     */
    void RegisterCameraSharedStatusListener(std::shared_ptr<CameraSharedStatusListener> listener);

    /**
     * @brief Unregister camera shared status listener
     *
     * @param listener The camera shared status object.
     * @return.
     */
    void UnregisterCameraSharedStatusListener(std::shared_ptr<CameraSharedStatusListener> listener);

    /**
     * @brief Get the CameraSharedStatusListenerManager.
     *
     * @return CameraSharedStatusListenerManager.
     */
    sptr<CameraSharedStatusListenerManager> GetCameraSharedStatusListenerManager();

    /**
     * @brief prelaunch the camera
     *
     * @return Server error code.
     */
    int32_t PrelaunchCamera(int32_t flag = -1);

    /**
     * @brief prelaunch the camera for scan
     *
     * @return Server error code.
     */
    int32_t PrelaunchScanCamera(const std::string bundleName, const std::string pageName,
        PrelaunchScanModeOhos prelaunchScanMode);

    /**
     * @brief reset rss priority
     *
     * @return Server error code.
     */
    int32_t ResetRssPriority();

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
     * @brief Register torch listener
     *
     * @param TorchListener listener object.
     * @return.
     */
    void RegisterTorchListener(std::shared_ptr<TorchListener> listener);

    /**
     * @brief Unregister torch listener
     *
     * @param TorchListener listener object.
     * @return.
     */
    void UnregisterTorchListener(std::shared_ptr<TorchListener> listener);

    /**
     * @brief Get the TorchServiceListenerManager.
     *
     * @return TorchServiceListenerManager.
     */
    sptr<TorchServiceListenerManager> GetTorchServiceListenerManager();

    /**
     * @brief Register fold status listener
     *
     * @param listener The fold listener object.
     * @return.
     */
    void RegisterFoldListener(std::shared_ptr<FoldListener> listener);

    /**
     * @brief Unregister fold status listener
     *
     * @param listener The fold listener object.
     * @return.
     */
    void UnregisterFoldListener(std::shared_ptr<FoldListener> listener);

    /**
     * @brief Get the FoldStatusListenerManager.
     *
     * @return FoldStatusListenerManager.
     */
    sptr<FoldStatusListenerManager> GetFoldStatusListenerManager();

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

    /**
     * @brief Get storageSize.
     *
     * @return Returns camera storage.
     */
    int32_t GetCameraStorageSize(int64_t& storage);

    int32_t RequireMemorySize(int32_t memSize);

    int32_t CreatePreviewOutputStream(
        sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);

    int32_t CreateVideoOutputStream(
        sptr<IStreamRepeat>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);

    int32_t CreatePhotoOutputStream(
        sptr<IStreamCapture>& streamPtr, Profile& profile, const sptr<OHOS::IBufferProducer>& producer);

    int32_t CreatePhotoOutputStream(sptr<IStreamCapture>& streamPtr, Profile& profile);
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
    void SetCameraIdTransform(sptr<ICameraDeviceService> deviceObj, std::string originCameraId);
    inline sptr<ICameraService> GetServiceProxy()
    {
        std::lock_guard<std::mutex> lock(serviceProxyMutex_);
        return serviceProxyPrivate_;
    }
    std::vector<sptr<CameraDevice>> GetSupportedCamerasWithFoldStatus();

    struct ProfilesWrapper {
        std::vector<Profile> photoProfiles = {};
        std::vector<Profile> previewProfiles = {};
        std::vector<VideoProfile> vidProfiles = {};
    };

    void GetCameraConcurrentInfos(std::vector<sptr<CameraDevice>> cameraDeviceArrray,
        std::vector<bool> cameraConcurrentType, std::vector<std::vector<SceneMode>> &modes,
        std::vector<std::vector<sptr<CameraOutputCapability>>> &outputCapabilities);
    bool GetConcurrentType(std::vector<sptr<CameraDevice>> cameraDeviceArrray,
        std::vector<bool> &cameraConcurrentType);
    bool CheckConcurrentExecution(std::vector<sptr<CameraDevice>> cameraDeviceArrray);
    std::vector<dmDeviceInfo> GetDmDeviceInfo();
    CameraConcurrentLimtedCapability limtedCapabilitySave_;
    std::unordered_map<std::string, CameraConcurrentLimtedCapability> cameraConLimCapMap_;
    friend int CameraInput::Open(int32_t cameraConcurrentType);
    std::string GetFoldScreenType();
    bool GetIsInWhiteList();
    void RegisterTimeforDevice(const std::string& cameraId, const uint32_t& timestmp);
    void UnregisterTimeforDevice(const std::string& cameraId);
    bool IsNaturalDirectionCorrect();
    uint32_t DisplayModeToFoldStatus(uint32_t displayMode);
    void SaveOldCameraId(std::string realCameraId, std::string oldCameraId);
    std::string GetOldCameraIdfromReal(std::string realCameraId);
    void SaveOldMeta(std::string cameraId, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetOldMeta(std::string cameraId);
    void SetOldMetatoInput(sptr<CameraDevice>& cameraObj, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    inline std::vector<sptr<CameraDevice>> GetCameraDeviceList()
    {
        std::lock_guard<std::mutex> lock(cameraDeviceListMutex_);
        if (cameraDeviceList_.empty()) {
            cameraDeviceList_ = GetCameraDeviceListFromServer();
        }
        return cameraDeviceList_;
    }
    std::string GetBundleName();
    void GetCameraStatusData(std::vector<CameraStatusData> &cameraStatusDataList);
    std::vector<sptr<CameraDevice>> GetCameraDevices();
    bool ShouldClearCache();
protected:
    // Only for UT
    explicit CameraManager(sptr<ICameraService> serviceProxy) : serviceProxyPrivate_(serviceProxy)
    {
        // Construct method add mutex lock is not necessary. Ignore g_instanceMutex.
        CameraManager::g_cameraManager = this;
    }

private:

    enum CameraAbilitySupportCacheKey {
        CAMERA_ABILITY_SUPPORT_TORCH,
        CAMERA_ABILITY_SUPPORT_MUTE,
        CAMERA_ABILITY_SUPPORT_MECH,
    };

    explicit CameraManager();
    void InitCameraManager();
    int32_t SetCameraServiceCallback(sptr<ICameraServiceCallback>& callback, bool executeCallbackNow = true);
    int32_t UnSetCameraServiceCallback();

    int32_t SetCameraMuteServiceCallback(sptr<ICameraMuteServiceCallback>& callback);
    int32_t UnSetCameraMuteServiceCallback();

    int32_t SetTorchServiceCallback(sptr<ITorchServiceCallback>& callback);
    int32_t UnSetTorchServiceCallback();

    int32_t SetFoldServiceCallback(sptr<IFoldServiceCallback>& callback);
    int32_t UnSetFoldServiceCallback();

    int32_t SetControlCenterStatusCallback(sptr<IControlCenterStatusCallback>& callback);
    int32_t UnSetControlCenterStatusCallback();

    int32_t SetCameraSharedStatusCallback(sptr<ICameraSharedServiceCallback>& callback);
    int32_t UnSetCameraSharedStatusCallback();

    int32_t CreateMetadataOutputInternal(sptr<MetadataOutput>& pMetadataOutput,
        const std::vector<MetadataObjectType>& metadataObjectTypes = {});

    sptr<CaptureSession> CreateCaptureSessionImpl(SceneMode mode, sptr<ICaptureSession> session);
    int32_t CreateListenerObject();
    void CameraServerDied(pid_t pid);
    int32_t AddServiceProxyDeathRecipient();
    void RemoveServiceProxyDeathRecipient();
    sptr<CameraOutputCapability> ParseSupportedOutputCapability(sptr<CameraDevice>& camera, int32_t modeName = 0,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility = nullptr);
    void ParseProfileLevel(
        ProfilesWrapper& profilesWrapper, const int32_t modeName, const camera_metadata_item_t& item);
    void CreateProfileLevel4StreamType(ProfilesWrapper& profilesWrapper, int32_t specId, StreamInfo& streamInfo);
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
    void SetProfile(sptr<CameraDevice>& cameraObj, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    SceneMode GetFallbackConfigMode(SceneMode profileMode, ProfilesWrapper& profilesWrapper);
    void ParseCapability(ProfilesWrapper& profilesWrapper, sptr<CameraDevice>& camera, const int32_t modeName,
        camera_metadata_item_t& item, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
    camera_format_t GetCameraMetadataFormat(CameraFormat format);

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
    void FillVirtualSupportPreviewFormats(std::vector<Profile>& profiles);
#ifdef CAMERA_CAPTURE_YUV
    void FillExtendedSupportPhotoFormats(std::vector<Profile>& profiles);
    void RemoveExtendedSupportPhotoFormats(std::vector<Profile>& photoProfiles);
#endif
    void FillSupportPreviewFormats(std::vector<Profile>& previewProfiles);
    inline void SetServiceProxy(sptr<ICameraService> proxy)
    {
        std::lock_guard<std::mutex> lock(serviceProxyMutex_);
        serviceProxyPrivate_ = proxy;
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

    inline sptr<CameraDevice> GetInnerCamera()
    {
        std::lock_guard<std::mutex> lock(innerCameraMutex_);
        return innerCamera_;
    }

    inline void SetInnerCamera(sptr<CameraDevice> cameraDevice)
    {
        std::lock_guard<std::mutex> lock(innerCameraMutex_);
        innerCamera_ = cameraDevice;
    }

    void GetMetadataInfos(camera_metadata_item_t item,
        std::vector<SceneMode> &modeofThis, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
        shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility);
    void SetCameraOutputCapabilityofthis(sptr<CameraOutputCapability> &cameraOutputCapability,
        ProfilesWrapper &profilesWrapper, int32_t modeName,
        shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility);
    bool CheckCameraConcurrentId(std::unordered_map<std::string, int32_t> &idmap,
        std::vector<std::string> &cameraIdv);
    void ParsingCameraConcurrentLimted(camera_metadata_item_t &item,
        std::vector<SceneMode> &mode, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
        shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility, sptr<CameraDevice>cameraDevNow);
    void GetMetadataInfosfordouble(camera_metadata_item_t &item, double* originInfo, uint32_t i,
        std::vector<SceneMode> &modeofThis, std::vector<sptr<CameraOutputCapability>> &outputCapabilitiesofThis,
        shared_ptr<OHOS::Camera::CameraMetadata> &cameraAbility);
    void GetSpecInfofordouble(double* originInfo, uint32_t start, uint32_t end, ProfileLevelInfo &modeInfo);
    void GetStreamInfofordouble(double* originInfo, uint32_t start, uint32_t end, SpecInfo &specInfo);
    void GetDetailInfofordouble(double* originInfo, uint32_t start, uint32_t end, StreamInfo &streamInfo);
    void GetAbilityStructofConcurrentLimted(std::vector<int32_t> &vec, double* originInfo, int length);
    void GetAbilityStructofConcurrentLimtedfloat(std::vector<float> &vec, double* originInfo, int length);
    void FindConcurrentLimtedEnd(double* originInfo, int32_t i, int32_t count, int32_t &countl);

    void CheckWhiteList();
    std::vector<CameraFormat> GetPhotoFormats();
    void SetPhotoFormats(const std::vector<CameraFormat>& photoFormats);
    std::vector<sptr<CameraDevice>> GetSupportedCamerasList();
    std::mutex cameraDeviceListMutex_;
    std::mutex innerCameraMutex_;
    std::vector<sptr<CameraDevice>> cameraDeviceList_ = {};

    std::mutex cameraDeviceAbilitySupportMapMutex_;
    std::unordered_map<CameraAbilitySupportCacheKey, bool> cameraDeviceAbilitySupportMap_;

    std::mutex serviceProxyMutex_;
    sptr<ICameraService> serviceProxyPrivate_;
    std::mutex deathRecipientMutex_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;

    static sptr<CameraManager> g_cameraManager;
    static std::mutex g_instanceMutex;

    sptr<CameraMuteListenerManager> cameraMuteListenerManager_ = sptr<CameraMuteListenerManager>::MakeSptr();
    sptr<ControlCenterStatusListenerManager> controlCenterStatusListenerManager_ =
        sptr<ControlCenterStatusListenerManager>::MakeSptr();
    sptr<TorchServiceListenerManager> torchServiceListenerManager_ = sptr<TorchServiceListenerManager>::MakeSptr();
    sptr<CameraStatusListenerManager> cameraStatusListenerManager_ = sptr<CameraStatusListenerManager>::MakeSptr();
    sptr<FoldStatusListenerManager> foldStatusListenerManager_ = sptr<FoldStatusListenerManager>::MakeSptr();
    sptr<CameraSharedStatusListenerManager> cameraSharedStatusListenerManager_ =
        sptr<CameraSharedStatusListenerManager>::MakeSptr();

    std::map<std::string, dmDeviceInfo> distributedCamInfoAndId_;

    std::map<std::string, std::vector<Profile>> modePhotoProfiles_ = {};
    std::map<std::string, std::vector<Profile>> modePreviewProfiles_ = {};
    std::vector<DepthProfile> depthProfiles_ = {};

    std::mutex photoFormatsMutex_;
    std::vector<CameraFormat> photoFormats_ = {};
    sptr<CameraInput> cameraInput_;
    TorchMode torchMode_ = TorchMode::TORCH_MODE_OFF;
    std::mutex saListenerMuxtex_;
    sptr<IRemoteBroker> saListener_ = nullptr;
    std::string foldScreenType_;
    bool isSystemApp_ = false;
    bool isInWhiteList_ = false;
    std::string bundleName_ = "";
    std::string curBundleName_ = "";
    sptr<CameraDevice> innerCamera_ = nullptr;
    FoldStatus preFoldStatus = FoldStatus::UNKNOWN_FOLD;
    unordered_map<std::string, std::queue<uint32_t>> timeQueueforDevice_;
    std::mutex registerTime_;
    std::unordered_map<std::string, std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraOldCamera_;
    std::unordered_map<std::string, std::string>realtoVirtual_;
    bool controlCenterFrameCondition_ = true;
    bool controlCenterResolutionCondition_ = true;
    bool controlCenterPositionCondition_ = true;
    bool controlCenterPrecondition_ = true;
};

class CameraManagerGetter {
public:
    void SetCameraManager(wptr<CameraManager> cameraManager);
    sptr<CameraManager> GetCameraManager();

private:
    wptr<CameraManager> cameraManager_ = nullptr;
};

class CameraStatusListenerManager : public CameraManagerGetter,
                                    public CameraServiceCallbackStub,
                                    public CameraListenerManager<CameraManagerCallback> {
public:
    int32_t OnCameraStatusChanged(
        const std::string& cameraId, const int32_t status, const std::string& bundleName) override;
    int32_t OnFlashlightStatusChanged(const std::string& cameraId, const int32_t status) override;

    inline std::vector<std::shared_ptr<CameraStatusInfo>> GetCachedCameraStatus()
    {
        std::lock_guard<std::mutex> lock(cachedCameraStatusMutex_);
        std::vector<std::shared_ptr<CameraStatusInfo>> infoList = {};
        for (auto& it : cachedCameraStatus_) {
            if (it.second != nullptr) {
                infoList.emplace_back(it.second);
            }
        }
        return infoList;
    }
    inline std::vector<std::pair<std::string, FlashStatus>> GetCachedFlashStatus()
    {
        std::lock_guard<std::mutex> lock(cachedFlashStatusMutex_);
        std::vector<std::pair<std::string, FlashStatus>> statusList = {};
        for (auto& it : cachedFlashStatus_) {
            statusList.emplace_back(it);
        }
        return statusList;
    }

    bool CheckCameraStatusValid(sptr<CameraDevice> cameraInfo);

private:
    inline void CacheCameraStatus(const std::string& cameraId, std::shared_ptr<CameraStatusInfo> statusInfo)
    {
        std::lock_guard<std::mutex> lock(cachedCameraStatusMutex_);
        cachedCameraStatus_[cameraId] = statusInfo;
    }

    inline void CacheFlashStatus(const std::string& cameraId, const FlashStatus status)
    {
        std::lock_guard<std::mutex> lock(cachedFlashStatusMutex_);
        cachedFlashStatus_[cameraId] = status;
    }

    std::mutex cachedCameraStatusMutex_;
    unordered_map<string, std::shared_ptr<CameraStatusInfo>> cachedCameraStatus_;
    std::mutex cachedFlashStatusMutex_;
    unordered_map<string, FlashStatus> cachedFlashStatus_;
};

class TorchServiceListenerManager : public CameraManagerGetter,
                                    public TorchServiceCallbackStub,
                                    public CameraListenerManager<TorchListener> {
public:
    int32_t OnTorchStatusChange(const TorchStatus status, const float level) override;

    inline TorchStatusInfo GetCachedTorchStatus()
    {
        return cachedTorchStatus_;
    }

private:
    TorchStatusInfo cachedTorchStatus_ = {};
};

class CameraMuteListenerManager : public CameraManagerGetter,
                                  public CameraMuteServiceCallbackStub,
                                  public CameraListenerManager<CameraMuteListener> {
public:
    int32_t OnCameraMute(bool muteMode) override;
};

class ControlCenterStatusListenerManager : public CameraManagerGetter,
                                          public ControlCenterStatusCallbackStub,
                                          public CameraListenerManager<ControlCenterStatusListener> {
public:
    int32_t OnControlCenterStatusChanged(bool status) override;

};

class FoldStatusListenerManager : public CameraManagerGetter,
                                  public FoldServiceCallbackStub,
                                  public CameraListenerManager<FoldListener> {
public:
    int32_t OnFoldStatusChanged(const FoldStatus status) override;
};

class CameraSharedStatusListenerManager : public CameraManagerGetter,
                                       public CameraSharedServiceCallbackStub,
                                       public CameraListenerManager<CameraSharedStatusListener> {
public:
    int32_t OnCameraSharedStatusChanged(const int32_t status) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_MANAGER_H
