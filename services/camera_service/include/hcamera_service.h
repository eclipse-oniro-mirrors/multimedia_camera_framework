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
#include <set>
#include <shared_mutex>
#include <vector>

#include "camera_util.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "hcamera_service_stub.h"
#include "hcapture_session.h"
#include "hstream_capture.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
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
        : cameraId(cameraId), cameraType(cameraType), position(position),
          connectionType(connectionType), supportModes(supportModes), cameraAbility(cameraAbility) {}
};
class HCameraService : public SystemAbility, public HCameraServiceStub, public HCameraHostManager::StatusCallback {
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
    int32_t SetCallback(sptr<ICameraServiceCallback>& callback) override;
    int32_t UnSetCallback(pid_t pid) override;
    int32_t CloseCameraForDestory(pid_t pid) override;
    int32_t SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback) override;
    int32_t SetTorchCallback(sptr<ITorchServiceCallback>& callback) override;
    int32_t MuteCamera(bool muteMode) override;
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

    // HCameraHostManager::StatusCallback
    void OnCameraStatus(const string& cameraId, CameraStatus status) override;
    void OnFlashlightStatus(const string& cameraId, FlashStatus status) override;
    void OnTorchStatus(TorchStatus status) override;

protected:
    explicit HCameraService(sptr<HCameraHostManager> cameraHostManager);

private:
    class ServiceHostStatus : public StatusCallback {
    public:
        explicit ServiceHostStatus(wptr<HCameraService> cameraService) : cameraService_(cameraService) {};
        virtual ~ServiceHostStatus() = default;
        void OnCameraStatus(const std::string& cameraId, CameraStatus status) override
        {
            auto cameraService = cameraService_.promote();
            if (cameraService != nullptr) {
                cameraService->OnCameraStatus(cameraId, status);
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
    void CheckCameraMute(bool muteMode);

    void CameraSummary(vector<string> cameraIds, string& dumpString);
    void CameraDumpCameraInfo(std::string& dumpString, std::vector<std::string>& cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList);
    void CameraDumpAbility(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpStreaminfo(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpZoom(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpFlash(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpAF(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpAE(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpSensorInfo(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpVideoStabilization(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpVideoFrameRateRange(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpPrelaunch(common_metadata_header_t* metadataEntry, string& dumpString);
    void CameraDumpThumbnail(common_metadata_header_t* metadataEntry, string& dumpString);
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
    int32_t UnSetMuteCallback(pid_t pid);
    int32_t UnSetTorchCallback(pid_t pid);
    bool IsDeviceAlreadyOpen(pid_t& tempPid, string& tempCameraId, sptr<HCameraDevice>& tempDevice);
    int32_t DeviceClose(sptr<HCameraDevice> cameraDevice);
#ifdef CAMERA_USE_SENSOR
    void RegisterSensorCallback();
    void UnRegisterSensorCallback();
    static void DropDetectionDataCallbackImpl(SensorEvent *event);
#endif
    int32_t SaveCurrentParamForRestore(string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam, sptr<HCaptureSession> captureSession);
    mutex mutex_;
    mutex cbMutex_;
    mutex muteCbMutex_;
    recursive_mutex torchCbMutex_;
    TorchStatus torchStatus_ = TorchStatus::TORCH_STATUS_UNAVAILABLE;
    sptr<HCameraHostManager> cameraHostManager_;
    std::shared_ptr<StatusCallback> statusCallback_;
    map<uint32_t, sptr<ITorchServiceCallback>> torchServiceCallbacks_;
    map<uint32_t, sptr<ICameraMuteServiceCallback>> cameraMuteServiceCallbacks_;
    map<uint32_t, sptr<ICameraServiceCallback>> cameraServiceCallbacks_;
    bool muteMode_;
    bool isFoldable = false;
    bool isFoldableInit = false;
    mutex mapOperatorsLock_;
    string preCameraId_;
    string preCameraClient_;
    bool isRegisterSensorSuccess;
#ifdef CAMERA_USE_SENSOR
    SensorUser user;
#endif
    SafeMap<uint32_t, sptr<HCaptureSession>> captureSessionsManager_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_SERVICE_H
