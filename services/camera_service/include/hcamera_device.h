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

#ifndef OHOS_CAMERA_H_CAMERA_DEVICE_H
#define OHOS_CAMERA_H_CAMERA_DEVICE_H
#include <vector>
#include "refbase.h"
#define EXPORT_API __attribute__((visibility("default")))

#include <cstdint>
#include <functional>
#include <iostream>
#include <atomic>
#include <mutex>
#include <set>
#include <shared_mutex>

#include "camera_privacy.h"
#include "camera_sensor_plugin.h"
#include "v1_0/icamera_device_callback.h"
#include "camera_metadata_info.h"
#include "camera_util.h"
#include "camera_device_service_stub.h"
#include "hcamera_host_manager.h"
#include "v1_0/icamera_device.h"
#include "v1_1/icamera_device.h"
#include "v1_2/icamera_device.h"
#include "v1_3/icamera_device.h"
#include "v1_5/icamera_device.h"
#include "v1_0/icamera_host.h"
#include "camera_rotate_strategy_parser.h"
#include "icamera_ipc_checker.h"
#include "applist_manager/camera_applist_manager.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t HDI_STREAM_ID_INIT = 1;
using OHOS::HDI::Camera::V1_0::ICameraDeviceCallback;
using OHOS::HDI::Camera::V1_5::IStreamOperatorCallback;
class IHCameraCloseListener : public virtual RefBase {
public:
    virtual void BeforeDeviceClose() = 0;
};

class EXPORT_API HCameraDevice
    : public CameraDeviceServiceStub, public ICameraDeviceCallback, public ICameraIpcChecker {
public:
    explicit HCameraDevice(
        sptr<HCameraHostManager>& cameraHostManager, std::string cameraID, const uint32_t callingTokenId);
    ~HCameraDevice();

    int32_t Open() override;
    int32_t OpenSecureCamera(uint64_t& secureSeqId) override;
    int32_t Open(int32_t concurrentType) override;
    int32_t Close() override;
    int32_t closeDelayed() override;
    int32_t Release() override;
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) override;
    int32_t SetUsedAsPosition(uint8_t value) override;
    int32_t UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
            std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut) override;
    int32_t GetEnabledResults(std::vector<int32_t>& results) override;
    int32_t EnableResult(const std::vector<int32_t>& results) override;
    int32_t DisableResult(const std::vector<int32_t>& results) override;
    int32_t SetDeviceRetryTime() override;
    int32_t ReleaseStreams(std::vector<int32_t>& releaseStreamIds);
    int32_t SetCallback(const sptr<ICameraDeviceServiceCallback>& callback) override;
    int32_t UnSetCallback() override;
    int32_t OnError(OHOS::HDI::Camera::V1_0::ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetDeviceAbility();
    std::shared_ptr<OHOS::Camera::CameraMetadata> CloneCachedSettings();
    std::string GetCameraId();
    int32_t GetCameraType();
    int32_t GetCameraPosition();
    bool IsOpenedCameraDevice();
    int32_t GetCallerToken();

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t SetMdmCheck(bool mdmCheck) override;
    int32_t SetCameraIdTransform(const std::string& originCameraId) override;
    std::string GetCameraIdTransform();

    int32_t ResetDeviceSettings();
    int32_t DispatchDefaultSettingToHdi();
    void SetDeviceMuteMode(bool muteMode);
    uint8_t GetUsedAsPosition();
    bool GetDeviceMuteMode();
    float GetZoomRatio();
    int32_t GetFocusMode();
    int32_t GetVideoStabilizationMode();
#ifdef CAMERA_MOVING_PHOTO
    void EnableMovingPhoto(bool isMovingPhotoEnabled);
    bool CheckMovingPhotoSupported(int32_t mode);
    void SetMovingPhotoStartTimeCallback(std::function<void(int64_t, int64_t)> callback);
    void SetMovingPhotoEndTimeCallback(std::function<void(int64_t, int64_t)> callback);
#endif
    static void DeviceEjectCallBack();
    static void DeviceFaultCallBack();

    inline void SetStreamOperatorCallback(wptr<IStreamOperatorCallback> operatorCallback)
    {
        std::lock_guard<std::mutex> lock(proxyStreamOperatorCallbackMutex_);
        proxyStreamOperatorCallback_ = operatorCallback;
    }

    inline sptr<IStreamOperatorCallback> GetStreamOperatorCallback()
    {
        std::lock_guard<std::mutex> lock(proxyStreamOperatorCallbackMutex_);
        return proxyStreamOperatorCallback_.promote();
    }

    inline void SetCameraPrivacy(sptr<CameraPrivacy> cameraPrivacy)
    {
        std::lock_guard<std::mutex> lock(cameraPrivacyMutex_);
        cameraPrivacy_ = cameraPrivacy;
    }

    inline sptr<CameraPrivacy> GetCameraPrivacy()
    {
        std::lock_guard<std::mutex> lock(cameraPrivacyMutex_);
        return cameraPrivacy_;
    }

    void RemoveResourceWhenHostDied();

    int64_t GetSecureCameraSeq(uint64_t* secureSeqId);

    void NotifyCameraStatus(int32_t state, int32_t msg = 0);

    int32_t CloseDevice();

    bool GetCameraResourceCost(int32_t &cost, std::set<std::string> &conflicting);

    int32_t closeDelayedDevice();

    void SetZoomInfoCallback(std::function<void(ZoomInfo)> callback);

    void SetMechMetadataCallback(std::function<void(std::shared_ptr<OHOS::Camera::CameraMetadata>)> callback);

    inline void SetCameraConcurrentType(int32_t cameraConcurrentTypenum)
    {
        cameraConcurrentType_ = cameraConcurrentTypenum;
    }

    std::vector<std::vector<std::int32_t>> GetConcurrentDevicesTable();

    inline int32_t GetTargetConcurrencyType()
    {
        return cameraConcurrentType_;
    }
    int32_t GetStreamOperator(const sptr<IStreamOperatorCallback> &callbackObj,
        sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> &streamOperator);

    inline void SetCameraCloseListener(wptr<IHCameraCloseListener> listener)
    {
        std::lock_guard<std::mutex> lock(cameraCloseListenerMutex_);
        cameraCloseListener_ = listener;
    }

    std::string GetClientName();

    int32_t GetCameraConnectType();

    int32_t GetSensorOrientation();

    inline bool IsDeviceOpenedByConcurrent()
    {
        return isDeviceOpenedByConcurrent_;
    }

    inline void EnableDeviceOpenedByConcurrent(bool enable)
    {
        isDeviceOpenedByConcurrent_ = enable;
    }

    int32_t UpdateCameraRotateAngleAndZoom(std::vector<int32_t> &frameRateRange, bool isResetDegree = false);
    int32_t GetCameraOrientation();
    int32_t GetOriginalCameraOrientation();
    bool IsPhysicalCameraOrientationVariable();
    void UpdateCameraRotateAngle();
    void SetCameraRotateStrategyInfos(std::vector<CameraRotateStrategyInfo> infos);
    bool GetSigleStrategyInfo(CameraRotateStrategyInfo &strategyInfo);
    void EnableKeyFrameReport(bool isKeyFrameReportEnabled);
    std::vector<uint8_t> GetKeyFrameInfoBuffer(int64_t firstFrameTimestamp);
    int32_t SetUsePhysicalCameraOrientation(bool isUsed) override;
    int32_t GetNaturalDirectionCorrect(bool& isNaturalDirectionCorrect) override;
    bool GetUsePhysicalCameraOrientation();
    bool ShowDialogFlag();
    void UpdateCameraSwitchCameraId(std::string cameraId);
    void SetLastDisplayMode(int32_t lastDisplayMode);
    void SetFrameRateRange(const std::vector<int32_t>& frameRateRange);
    void SetIsHasFitedRotation(bool isHasFitedRotation);
    bool GetIsHasFitedRotation();
    std::vector<int32_t> GetFrameRateRange();
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
    void UpdateLiveStreamSceneMetadata(uint32_t mode);
#endif
    void HandleScanScene(std::string clientName);

private:
    class FoldScreenListener;
    class DisplayModeListener;
    sptr<FoldScreenListener> listener_;
    static const std::vector<std::tuple<uint32_t, std::string, std::string>> reportTagInfos_;
    sptr<DisplayModeListener> displayModeListener_;

    std::mutex opMutex_; // Lock the operations updateSettings_, streamOperator_, and hdiCameraDevice_.
    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings_;
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> hdiCameraDevice_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cachedSettings_;
    int32_t cameraConcurrentType_ = 0;
    std::atomic<bool> isDeviceOpenedByConcurrent_ = false;

    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraID_;
    std::atomic<bool> isOpenedCameraDevice_;
    std::mutex deviceSvcCbMutex_;
    std::mutex cachedSettingsMutex_;
    static std::mutex g_deviceOpenCloseMutex_;
    sptr<ICameraDeviceServiceCallback> deviceSvcCallback_;
    std::map<int32_t, wptr<ICameraServiceCallback>> statusSvcCallbacks_;

    uint32_t callerToken_;
    std::mutex cameraPrivacyMutex_;
    int32_t cameraPid_;

    sptr<CameraPrivacy> cameraPrivacy_;
    std::mutex proxyStreamOperatorCallbackMutex_;
    wptr<IStreamOperatorCallback> proxyStreamOperatorCallback_;

    std::mutex deviceAbilityMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceAbility_;

    std::mutex deviceOpenLifeCycleMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceOpenLifeCycleSettings_;

    std::mutex isHasFitedRotationMutex_;
    bool isHasFitedRotation_ = false;

    bool isLogicCamera_  = false;
    std::string foldScreenType_;
    std::string clientName_ = "";
    uint64_t openCamTime_ = 0;
    int clientUserId_;
    uint8_t usedAsPosition_ = OHOS_CAMERA_POSITION_OTHER;
    std::mutex unPrepareZoomMutex_;
    uint32_t zoomTimerId_;
    std::atomic<bool> inPrepareZoom_ {false};
    std::atomic<bool> deviceMuteMode_ {false};
    bool isHasOpenSecure = false;
    uint64_t mSecureCameraSeqId = 0L;
    int32_t lastDeviceProtectionStatus_ = -1;
    std::mutex deviceProtectionStatusMutex_;
    int64_t lastDeviceEjectTime_ = 0;
    std::atomic<uint32_t> deviceEjectTimes_ = 0;
    std::atomic<bool> isKeyFrameReportEnabled_ { false };

    void UpdateDeviceOpenLifeCycleSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> changedSettings);
    void ResetDeviceOpenLifeCycleSettings();
    int32_t UpdateRotateAngleForSpecialBundle(bool isResetDegree);
    bool GetUseLogicCamera(int32_t displayMode);

    sptr<ICameraDeviceServiceCallback> GetDeviceServiceCallback();
    inline void SetDeviceServiceCallback(sptr<ICameraDeviceServiceCallback> callback)
    {
        std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
        deviceSvcCallback_ = callback;
    };

    void ResetCachedSettings();
    void ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void RegisterFoldStatusListener();
    void UnregisterFoldStatusListener();
    void RegisterDisplayModeListener();
    void UnregisterDisplayModeListener();
    void CheckOnResultData(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
    bool CanOpenCamera();
    void ResetZoomTimer();
    void CheckZoomChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void CheckFocusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void CheckVideoStabilizationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void UnPrepareZoom();
    int32_t OpenDevice(bool isEnableSecCam = false);
    void HandleFoldableDevice();
    int32_t CheckPermissionBeforeOpenDevice();
    bool HandlePrivacyBeforeOpenDevice();
    void HandlePrivacyWhenOpenDeviceFail();
    void HandlePrivacyAfterCloseDevice();
    void DebugLogForSmoothZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAfRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAeRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogTag(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                     uint32_t tag, std::string tagName, std::string dfxUbStr);
    void CreateMuteSetting(std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t UpdateDeviceSetting();
    void ReleaseSessionBeforeCloseDevice();
#ifdef MEMMGR_OVERRID
    int32_t RequireMemory(const std::string& reason);
#endif
#ifdef CAMERA_MOVING_PHOTO
    void GetMovingPhotoStartAndEndTime(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
    bool isMovingPhotoEnabled_ = false;
    std::mutex movingPhotoStartTimeCallbackLock_;
    std::mutex movingPhotoEndTimeCallbackLock_;
    std::function<void(int32_t, int64_t)> movingPhotoStartTimeCallback_;
    std::function<void(int32_t, int64_t)> movingPhotoEndTimeCallback_;
#endif
    std::vector<CameraRotateStrategyInfo> GetCameraRotateStrategyInfos();
    void ReportDeviceProtectionStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata> &metadata);
    bool CanReportDeviceProtectionStatus(int32_t status);
    bool ShowDeviceProtectionDialog(DeviceProtectionStatus status);
    std::string BuildDeviceProtectionDialogCommand(DeviceProtectionStatus status);
    void RegisterSensorCallback();
    void UnRegisterSensorCallback();
    static void DropDetectionDataCallbackImpl(const OHOS::Rosen::MotionSensorEvent &motionData);
    void ReportZoomInfos(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
    void ReportMechMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    void SaveKeyFrameInfo(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
#endif
    bool GetScanScene();
    void UpdateScanSceneMetadata(uint32_t previewQuality);
    std::vector<int32_t> frameRateRange_ = {0, 0};
    std::mutex clientNameMutex_;
    std::mutex lastDisplayModeLock_;
    std::mutex fpsRangeLock_;
    std::mutex originCameraIdLock_;
    std::mutex usePhysicalCameraOrientationMutex_;
    std::mutex sensorLock_;
    std::mutex cameraCloseListenerMutex_;
    std::mutex foldStateListenerMutex_;
    wptr<IHCameraCloseListener> cameraCloseListener_;
    std::mutex displayModeListenerMutex_;
    std::mutex cameraRotateStrategyInfosLock_;
    std::vector<CameraRotateStrategyInfo> cameraRotateStrategyInfos_;
    std::string bundleName_ = "";
    std::shared_mutex zoomInfoCallbackLock_;
    std::function<void(ZoomInfo)> zoomInfoCallback_;
    float zoomRatio_ = 1.0f;
    int32_t focusMode_ = -1;
    bool focusStatus_ = false;
    std::map<int64_t, uint8_t> keyFrameInfoMap_;
    int64_t firstFrameTimestamp_ {0};
    int32_t videoStabilizationMode_ = 0;
    int32_t lastDisplayMode_ = -1;
    bool usePhysicalCameraOrientation_ = false;
    std::vector<std::string> keyFrameInfoVec_;
    std::string pidForLiveScene_;
    std::string uidForLiveScene_;
    std::string bundleNameForLiveScene_;
    bool mdmCheck_ = true;
    std::string originCameraId_;
    std::shared_mutex mechMetadataCallbackLock_;
    std::function<void(std::shared_ptr<OHOS::Camera::CameraMetadata>)> mechMetadataCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_H
