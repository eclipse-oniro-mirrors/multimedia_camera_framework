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

#ifndef OHOS_CAMERA_H_CAMERA_SERVICE_H
#define OHOS_CAMERA_H_CAMERA_SERVICE_H
#include <atomic>
#include <cstdint>
#include <mutex>
#include <stdint.h>
#include "camera_metadata_info.h"
#include "icontrol_center_status_callback.h"
#include "task_manager.h"
#define EXPORT_API __attribute__((visibility("default")))

#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <shared_mutex>
#include <vector>

#include "camera_datashare_helper.h"
#include "camera_rotate_strategy_parser.h"
#include "camera_util.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "display_manager.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "camera_service_stub.h"
#include "hcapture_session.h"
#include "hmech_session.h"
#include "hstream_capture.h"
#include "hstream_operator.h"
#include "hstream_depth_data.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "datashare_helper.h"
#include "icamera_service_callback.h"
#include "imech_session_callback.h"
#include "iremote_stub.h"
#include "privacy_kit.h"
#include "refbase.h"
#include "system_ability.h"
#include "ideferred_photo_processing_session_callback.h"
#include "ideferred_photo_processing_session.h"
#include "input/i_standard_camera_listener.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using namespace OHOS::HDI::Camera::V1_0;
using namespace DeferredProcessing;
struct CameraMetaInfo {
    string cameraId;
    uint8_t cameraType;
    uint8_t position;
    uint8_t connectionType;
    uint8_t foldStatus;
    std::vector<uint8_t> supportModes;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    CameraMetaInfo(string cameraId, uint8_t cameraType, uint8_t position, uint8_t connectionType, uint8_t foldStatus,
        std::vector<uint8_t> supportModes, shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
        : cameraId(cameraId), cameraType(cameraType), position(position), connectionType(connectionType),
        foldStatus(foldStatus), supportModes(supportModes), cameraAbility(cameraAbility) {}
};

struct CameraStatusCallbacksInfo {
    CameraStatus status;
    string bundleName;
};

enum class CameraServiceStatus : int32_t {
    SERVICE_READY = 0,
    SERVICE_NOT_READY,
};

enum TemperPressure {
    TEMPER_PRESSURE_COOL = 0,
    TEMPER_PRESSURE_NORMAL,
    TEMPER_PRESSURE_WARM,
    TEMPER_PRESSURE_HOT,
    TEMPER_PRESSURE_OVERHEATED,
    TEMPER_PRESSURE_WARNING,
    TEMPER_PRESSURE_EMERGENCY,
    TEMPER_PRESSURE_ESCAPE
};

class CameraInfoDumper;

class EXPORT_API HCameraService
    : public SystemAbility, public CameraServiceStub, public HCameraHostManager::StatusCallback,
    public OHOS::Rosen::DisplayManager::IFoldStatusListener {
    DECLARE_SYSTEM_ABILITY(HCameraService);

public:
    DISALLOW_COPY_AND_MOVE(HCameraService);

    explicit HCameraService(int32_t systemAbilityId, bool runOnCreate = true);
    ~HCameraService() override;
    void CreateAndSaveTask(const string& cameraId, CameraStatus status, uint32_t pid);
    int32_t GetCameras(vector<string>& cameraIds,
        vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList) override;
    int32_t GetCameraIds(std::vector<std::string>& cameraIds) override;
    int32_t GetCameraAbility(const std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) override;
    int32_t CreateCameraDevice(const string& cameraId, sptr<ICameraDeviceService>& device) override;
    int32_t CreateCaptureSession(sptr<ICaptureSession>& session, int32_t opMode) override;
    int32_t GetVideoSessionForControlCenter(sptr<ICaptureSession>& session) override;
    int32_t CreateDeferredPhotoProcessingSession(int32_t userId,
        const sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session) override;
    int32_t CreateDeferredVideoProcessingSession(int32_t userId,
        const sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session) override;
    int32_t CreateMechSession(int32_t userId, sptr<IMechSession>& session) override;
    int32_t IsMechSupported(bool &isMechSupported) override;
    int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamCapture>& photoOutput) override;
    int32_t CreatePhotoOutput(
        int32_t format, int32_t width, int32_t height, sptr<IStreamCapture> &photoOutput) override;
    int32_t CreateDeferredPreviewOutput(
        int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& previewOutput) override;
    int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamRepeat>& previewOutput) override;
    int32_t CreateDepthDataOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamDepthData>& depthDataOutput) override;
    int32_t CreateMetadataOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format,
        const std::vector<int32_t>& metadataTypes, sptr<IStreamMetadata>& metadataOutput) override;
    int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamRepeat>& videoOutput) override;
    int32_t UnSetAllCallback(pid_t pid);
    int32_t CloseCameraForDestory(pid_t pid);
    int32_t SetCameraCallback(const sptr<ICameraServiceCallback>& callback) override;
    int32_t UnSetCameraCallback() override;
    int32_t SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback) override;
    int32_t UnSetMuteCallback() override;
    int32_t SetTorchCallback(const sptr<ITorchServiceCallback>& callback) override;
    int32_t UnSetTorchCallback() override;
    int32_t SetFoldStatusCallback(const sptr<IFoldServiceCallback>& callback, bool isInnerCallback) override;
    int32_t UnSetFoldStatusCallback() override;
    int32_t MuteCamera(bool muteMode) override;
    int32_t SetControlCenterCallback(const sptr<IControlCenterStatusCallback>& callback) override;
    int32_t UnSetControlCenterStatusCallback() override;
    int32_t EnableControlCenter(bool status, bool needPersistEnable) override;
    int32_t SetControlCenterPrecondition(bool condition) override;
    int32_t SetDeviceControlCenterAbility(bool ability) override;
    int32_t GetControlCenterStatus(bool& status) override;
    int32_t CheckControlCenterPermission() override;
    int32_t MuteCameraPersist(PolicyType policyType, bool isMute) override;
    int32_t PrelaunchCamera(int32_t flag) override;
    int32_t ResetRssPriority() override;
    int32_t PreSwitchCamera(const std::string& cameraId) override;
    int32_t SetPrelaunchConfig(const string& cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        const EffectParam& effectParam) override;
    int32_t IsTorchSupported(bool &isTorchSupported) override;
    int32_t IsCameraMuteSupported(bool& isCameraMuteSupported) override;
    int32_t IsCameraMuted(bool& muteMode) override;
    int32_t GetTorchStatus(int32_t &status) override;
    int32_t SetTorchLevel(float level) override;
    int32_t AllowOpenByOHSide(const std::string& cameraId, int32_t state, bool &canOpenCamera) override;
    int32_t NotifyCameraState(const std::string& cameraId, int32_t state) override;
    int32_t SetPeerCallback(const sptr<ICameraBroker>& callback) override;
    int32_t UnsetPeerCallback() override;
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;
    int32_t Dump(int fd, const vector<u16string>& args) override;
    int DestroyStubObj() override;
    int SetListenerObject(const sptr<IRemoteObject>& object) override;

    CameraServiceStatus GetServiceStatus();
    void SetServiceStatus(CameraServiceStatus);
    // HCameraHostManager::StatusCallback
    void OnCameraStatus(const string& cameraId, CameraStatus status,
                        CallbackInvoker invoker) override;
    void OnFlashlightStatus(const string& cameraId, FlashStatus status) override;
    void OnTorchStatus(TorchStatus status) override;
    // for resource proxy
    int32_t ProxyForFreeze(const std::set<int32_t>& pidList, bool isProxy) override;
    int32_t ResetAllFreezeStatus() override;
    int32_t GetDmDeviceInfo(std::vector<std::string> &deviceInfos) override;
    int32_t GetCameraOutputStatus(int32_t pid, int32_t &status) override;
    bool ShouldSkipStatusUpdates(pid_t pid);
    void OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus) override;
    int32_t UnSetFoldStatusCallback(pid_t pid);
    int32_t UnSetControlCenterStatusCallback(pid_t pid);
    void RegisterFoldStatusListener();
    void UnregisterFoldStatusListener();
    int32_t RequireMemorySize(int32_t memSize) override;
    int32_t GetIdforCameraConcurrentType(int32_t cameraPosition, std::string &cameraId) override;
    int32_t GetConcurrentCameraAbility(const std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) override;
    int32_t CheckWhiteList(bool &isInWhiteList) override;
    int32_t GetCameraStorageSize(int64_t& size) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t SetUsePhysicalCameraOrientation(bool isUsed) override;
    bool GetUsePhysicalCameraOrientation();
protected:
    explicit HCameraService(sptr<HCameraHostManager> cameraHostManager);
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    int32_t GetMuteModeFromDataShareHelper(bool &muteMode);
    bool SetMuteModeFromDataShareHelper();
    void OnReceiveEvent(const EventFwk::CommonEventData &data);
    int32_t SetMuteModeByDataShareHelper(bool muteMode);
    int32_t MuteCameraFunc(bool muteMode);
    int32_t GetControlCenterStatusFromDataShareHelper(bool &status);
    void UpdateControlCenterStatus(bool isStart);
    int32_t UpdateDataShareAndTag(bool status, bool needPersistEnable);
    int32_t CreateControlCenterDataShare(std::map<std::string,
        std::array<float, CONTROL_CENTER_DATA_SIZE>> controlCenterMap, std::string bundleName, bool status);
    int8_t ChooseFisrtBootFoldCamIdx(
        FoldStatus curFoldStatus, std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList);
    PressureStatus TransferTemperToPressure(int32_t temperLevel);
    void ClearCameraListenerByPid(pid_t pid);
    int DestroyStubForPid(pid_t pid);
    void ClientDied(pid_t pid);
    sptr<HCaptureSession> videoSessionForControlCenter_;
#ifdef NOTIFICATION_ENABLE
    int32_t SetBeauty(int32_t beautyStatus);
#endif

#ifdef MEMMGR_OVERRID
    void PrelaunchRequireMemory(int32_t flag);
#endif

#ifdef DEVICE_MANAGER
    class DeviceInitCallBack;
#endif
private:
    class ServiceHostStatus : public StatusCallback {
    public:
        explicit ServiceHostStatus(wptr<HCameraService> cameraService) : cameraService_(cameraService) {};
        virtual ~ServiceHostStatus() = default;
        void OnCameraStatus(const std::string& cameraId, CameraStatus status, CallbackInvoker invoker) override
        {
            auto cameraService = cameraService_.promote();
            if (cameraService != nullptr) {
                cameraService->OnCameraStatus(cameraId, status, invoker);
            }
        }
        void OnFlashlightStatus(const std::string& cameraId, FlashStatus status) override
        {
            auto cameraService = cameraService_.promote();
            if (cameraService != nullptr) {
                cameraService->OnFlashlightStatus(cameraId, status);
            }
        }
        void OnTorchStatus(TorchStatus status) override
        {
            auto cameraService = cameraService_.promote();
            if (cameraService != nullptr) {
                cameraService->OnTorchStatus(status);
            }
        }

    private:
        wptr<HCameraService> cameraService_;
    };

    void FillCameras(vector<shared_ptr<CameraMetaInfo>>& cameraInfos,
        vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);
    shared_ptr<CameraMetaInfo>GetCameraMetaInfo(std::string &cameraId,
        shared_ptr<OHOS::Camera::CameraMetadata>cameraAbility);
    void OnMute(bool muteMode);
    void ExecutePidSetCallback(const sptr<ICameraServiceCallback>& callback, std::vector<std::string> &cameraIds);

    void DumpCameraSummary(vector<string> cameraIds, CameraInfoDumper& infoDumper);
    void DumpCameraInfo(CameraInfoDumper& infoDumper, std::vector<std::string>& cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);
    void DumpCameraAbility(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraStreamInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraZoom(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraFlash(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraCompensation(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraColorSpace(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraAF(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraQualityPrioritization(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraAE(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraSensorInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraVideoStabilization(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraVideoFrameRateRange(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraPrelaunch(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraThumbnail(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraConcurrency(
        CameraInfoDumper& infoDumper, std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);

    vector<shared_ptr<CameraMetaInfo>> ChooseDeFaultCameras(vector<shared_ptr<CameraMetaInfo>> cameraInfos);
    vector<shared_ptr<CameraMetaInfo>> ChoosePhysicalCameras(const vector<shared_ptr<CameraMetaInfo>>& cameraInfos,
        const vector<shared_ptr<CameraMetaInfo>>& choosedCameras);
    bool IsCameraMuteSupported(string cameraId);
    bool IsPrelaunchSupported(string cameraId);
    int32_t UpdateMuteSetting(sptr<HCameraDevice> cameraDevice, bool muteMode);
    std::shared_ptr<OHOS::Camera::CameraMetadata> CreateDefaultSettingForRestore(sptr<HCameraDevice> activeDevice);
    int32_t UpdateSkinSmoothSetting(shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata, int skinSmoothValue);
    int32_t UpdateFaceSlenderSetting(shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata,
        int faceSlenderValue);
    int32_t UpdateSkinToneSetting(shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata, int skinToneValue);
    int32_t UnSetCameraCallback(pid_t pid);
    int32_t UnSetMuteCallback(pid_t pid);
    int32_t UnSetTorchCallback(pid_t pid);
    int32_t SaveCurrentParamForRestore(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam, sptr<HCaptureSession> captureSession);

    mutex mutex_;
    mutex cameraCbMutex_;
    mutex muteCbMutex_;
    mutex serviceStatusMutex_;
    mutex controlCenterStatusMutex_;
    mutex usePhysicalCameraOrientationMutex_;
    recursive_mutex torchCbMutex_;
    recursive_mutex foldCbMutex_;
    TorchStatus torchStatus_ = TorchStatus::TORCH_STATUS_UNAVAILABLE;
    FoldStatus preFoldStatus_ = FoldStatus::UNKNOWN_FOLD;
    sptr<HCameraHostManager> cameraHostManager_;
    std::shared_ptr<StatusCallback> statusCallback_;
    map<uint32_t, sptr<ITorchServiceCallback>> torchServiceCallbacks_;
    map<uint32_t, sptr<IFoldServiceCallback>> foldServiceCallbacks_;
    map<uint32_t, sptr<ICameraMuteServiceCallback>> cameraMuteServiceCallbacks_;
    map<uint32_t, sptr<ICameraServiceCallback>> cameraServiceCallbacks_;
    map<uint32_t, sptr<IControlCenterStatusCallback>> controlcenterCallbacks_;
    SafeMap<pid_t, sptr<IStandardCameraListener>> cameraListenerMap_;

    void CacheCameraStatus(const string& cameraId, std::shared_ptr<CameraStatusCallbacksInfo> info);
    std::shared_ptr<CameraStatusCallbacksInfo> GetCachedCameraStatus(const string& cameraId);
    std::mutex cameraStatusCallbacksMutex_;
    map<string, std::shared_ptr<CameraStatusCallbacksInfo>> cameraStatusCallbacks_;

    void CacheFlashStatus(const string& cameraId, FlashStatus flashStatus);
    FlashStatus GetCachedFlashStatus(const string& cameraId);
    std::mutex flashStatusCallbacksMutex_;
    map<string, FlashStatus> flashStatusCallbacks_;

    bool muteModeStored_;
    bool isFoldable = false;
    bool isFoldableInit = false;
    bool isControlCenterEnabled_ = false;
    bool controlCenterPrecondition = true;
    bool deviceControlCenterAbility = false;
    bool usePhysicalCameraOrientation_ = false;
    string preCameraId_;
    string preCameraClient_;
    std::shared_ptr<CameraDataShareHelper> cameraDataShareHelper_;
    CameraServiceStatus serviceStatus_ = CameraServiceStatus::SERVICE_READY;

    std::mutex peerCallbackMutex_;
    sptr<ICameraBroker> peerCallback_;

    bool isFoldRegister = false;
    sptr<IFoldServiceCallback> innerFoldCallback_;
    std::vector<CameraRotateStrategyInfo> cameraRotateStrategyInfos_;
    pid_t pressurePid_;
    std::mutex freezedPidListMutex_;
    std::set<int32_t> freezedPidList_;
    std::map<uint32_t, std::map<string, std::function<void()>>> delayCbtaskMap_;
    std::map<uint32_t, std::function<void()>> delayFoldStatusCbTaskMap;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_SERVICE_H
