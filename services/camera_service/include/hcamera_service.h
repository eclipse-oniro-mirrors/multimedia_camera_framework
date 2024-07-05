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

#ifndef OHOS_CAMERA_H_CAMERA_SERVICE_H
#define OHOS_CAMERA_H_CAMERA_SERVICE_H
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <shared_mutex>
#include <vector>

#include "camera_util.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "display_manager.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "hcamera_service_stub.h"
#include "hcapture_session.h"
#include "hstream_capture.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "datashare_helper.h"
#include "icamera_service_callback.h"
#include "iremote_stub.h"
#include "privacy_kit.h"
#include "refbase.h"
#include "system_ability.h"
#ifdef CAMERA_USE_SENSOR
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#endif
#include "ideferred_photo_processing_session_callback.h"
#include "ideferred_photo_processing_session.h"

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
    std::vector<uint8_t> supportModes;
    shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    CameraMetaInfo(string cameraId, uint8_t cameraType, uint8_t position, uint8_t connectionType,
        std::vector<uint8_t> supportModes, shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
        : cameraId(cameraId), cameraType(cameraType), position(position), connectionType(connectionType),
        supportModes(supportModes), cameraAbility(cameraAbility) {}
};

enum class CameraServiceStatus : int32_t {
    SERVICE_READY = 0,
    SERVICE_NOT_READY,
};

class CameraInfoDumper;

class HCameraService : public SystemAbility, public HCameraServiceStub, public HCameraHostManager::StatusCallback,
    public OHOS::Rosen::DisplayManager::IFoldStatusListener {
    DECLARE_SYSTEM_ABILITY(HCameraService);

public:
    DISALLOW_COPY_AND_MOVE(HCameraService);

    explicit HCameraService(int32_t systemAbilityId, bool runOnCreate = true);
    ~HCameraService() override;
    int32_t GetCameras(vector<string>& cameraIds,
        vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList) override;
    int32_t GetCameraIds(std::vector<std::string>& cameraIds) override;
    int32_t GetCameraAbility(std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) override;
    int32_t CreateCameraDevice(string cameraId, sptr<ICameraDeviceService>& device) override;
    int32_t CreateCaptureSession(sptr<ICaptureSession>& session, int32_t opMode) override;
    int32_t CreateDeferredPhotoProcessingSession(int32_t userId,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session) override;
    int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamCapture>& photoOutput) override;
    int32_t CreateDeferredPreviewOutput(
        int32_t format, int32_t width, int32_t height, sptr<IStreamRepeat>& previewOutput) override;
    int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamRepeat>& previewOutput) override;
    int32_t CreateMetadataOutput(
        const sptr<OHOS::IBufferProducer>& producer, int32_t format, sptr<IStreamMetadata>& metadataOutput) override;
    int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer>& producer, int32_t format, int32_t width,
        int32_t height, sptr<IStreamRepeat>& videoOutput) override;
    int32_t UnSetAllCallback(pid_t pid) override;
    int32_t CloseCameraForDestory(pid_t pid) override;
    int32_t SetCameraCallback(sptr<ICameraServiceCallback>& callback) override;
    int32_t SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback) override;
    int32_t SetTorchCallback(sptr<ITorchServiceCallback>& callback) override;
    int32_t SetFoldStatusCallback(sptr<IFoldServiceCallback>& callback) override;
    int32_t MuteCamera(bool muteMode) override;
    int32_t MuteCameraPersist(PolicyType policyType, bool isMute) override;
    int32_t PrelaunchCamera() override;
    int32_t PreSwitchCamera(const std::string cameraId) override;
    int32_t SetPrelaunchConfig(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam) override;
//    std::string GetClientBundle(int uid);
    int32_t IsCameraMuted(bool& muteMode) override;
    int32_t SetTorchLevel(float level) override;
    int32_t AllowOpenByOHSide(std::string cameraId, int32_t state, bool &canOpenCamera) override;
    int32_t NotifyCameraState(std::string cameraId, int32_t state) override;
    int32_t SetPeerCallback(sptr<ICameraBroker>& callback) override;
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;
    int32_t Dump(int fd, const vector<u16string>& args) override;

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
    bool ShouldSkipStatusUpdates(pid_t pid);
    void CreateAndSaveTask(const string& cameraId, CameraStatus status, uint32_t pid, const string& bundleName);
    void CreateAndSaveTask(FoldStatus status, uint32_t pid);
    void OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus) override;
    int32_t UnSetFoldStatusCallback(pid_t pid);
    void RegisterFoldStatusListener();
    void UnRegisterFoldStatusListener();
protected:
    explicit HCameraService(sptr<HCameraHostManager> cameraHostManager);
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    int32_t GetMuteModeFromDataShareHelper(bool &muteMode);
    int32_t SetMuteModeByDataShareHelper(bool muteMode);
    int32_t MuteCameraFunc(bool muteMode);
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

    class CameraDataShareHelper {
    public:
        CameraDataShareHelper() = default;
        ~CameraDataShareHelper() = default;
        int32_t QueryOnce(const std::string key, std::string &value);
        int32_t UpdateOnce(const std::string key, std::string value);
    private:
        std::shared_ptr<DataShare::DataShareHelper> CreateCameraDataShareHelper();
    };

    void FillCameras(vector<shared_ptr<CameraMetaInfo>>& cameraInfos,
        vector<string>& cameraIds, vector<shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);
    shared_ptr<CameraMetaInfo>GetCameraMetaInfo(std::string &cameraId,
        shared_ptr<OHOS::Camera::CameraMetadata>cameraAbility);
    void OnMute(bool muteMode);

    void DumpCameraSummary(vector<string> cameraIds, CameraInfoDumper& infoDumper);
    void DumpCameraInfo(CameraInfoDumper& infoDumper, std::vector<std::string>& cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);
    void DumpCameraAbility(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraStreamInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraZoom(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraFlash(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraAF(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraAE(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraSensorInfo(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraVideoStabilization(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraVideoFrameRateRange(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraPrelaunch(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpCameraThumbnail(common_metadata_header_t* metadataEntry, CameraInfoDumper& infoDumper);
    void DumpPreconfigInfo(CameraInfoDumper& infoDumper);
    void DumpPreconfig720P(CameraInfoDumper& infoDumper);
    void DumpPreconfig1080P(CameraInfoDumper& infoDumper);
    void DumpPreconfig4k(CameraInfoDumper& infoDumper);
    void DumpPreconfigHighQuality(CameraInfoDumper& infoDumper);

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
#ifdef CAMERA_USE_SENSOR
    void RegisterSensorCallback();
    void UnRegisterSensorCallback();
    static void DropDetectionDataCallbackImpl(SensorEvent *event);
#endif
    int32_t SaveCurrentParamForRestore(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam, sptr<HCaptureSession> captureSession);
    mutex mutex_;
    mutex cameraCbMutex_;
    mutex muteCbMutex_;
    mutex serviceStatusMutex_;
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
    bool muteModeStored_;
    bool isFoldable = false;
    bool isFoldableInit = false;
    string preCameraId_;
    string preCameraClient_;
    bool isRegisterSensorSuccess;
    std::shared_ptr<CameraDataShareHelper> cameraDataShareHelper_;
    CameraServiceStatus serviceStatus_;
#ifdef CAMERA_USE_SENSOR
    SensorUser user;
#endif
    SafeMap<uint32_t, sptr<HCaptureSession>> captureSessionsManager_;
    std::mutex freezedPidListMutex_;
    std::set<int32_t> freezedPidList_;
    std::map<uint32_t, std::function<void()>> delayCbtaskMap;
    std::map<uint32_t, std::function<void()>> delayFoldStatusCbTaskMap;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_SERVICE_H
