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

#ifndef OHOS_CAMERA_H_CAMERA_HOST_MANAGER_H
#define OHOS_CAMERA_H_CAMERA_HOST_MANAGER_H

#include <refbase.h>
#include <iostream>
#include <map>
#include <utility>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "camera_log.h"
#include "camera_metadata_info.h"
#include "v1_0/icamera_device.h"
#include "v1_1/icamera_device.h"
#include "v1_2/icamera_device.h"
#include "v1_3/icamera_device.h"
#include "v1_0/icamera_host.h"
#include "v1_1/icamera_host.h"
#include "v1_2/icamera_host.h"
#include "v1_3/icamera_host.h"
#include "icamera_device_service.h"
#include "icamera_service_callback.h"
#include "iservmgr_hdi.h"
#include "iservstat_listener_hdi.h"
#include "hcamera_restore_param.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::ICameraDeviceCallback;
class HCameraHostManager : public RefBase {
public:
    class StatusCallback {
    public:
        virtual ~StatusCallback() = default;
        virtual void OnCameraStatus(const std::string& cameraId, CameraStatus status) = 0;
        virtual void OnFlashlightStatus(const std::string& cameraId, FlashStatus status) = 0;
        virtual void OnTorchStatus(TorchStatus status) = 0;
    };
    class CameraHostDeadCallback {
    public:
        explicit CameraHostDeadCallback(wptr<HCameraHostManager> hostManager) : hostManager_(hostManager) {};
        virtual ~CameraHostDeadCallback() = default;
        virtual void OnCameraHostDied(const std::string& hostName)
        {
            auto hostManager = hostManager_.promote();
            if (hostManager == nullptr) {
                MEDIA_ERR_LOG("HCameraHostManager OnCameraHostDied, but manager is nullptr");
                return;
            }
            hostManager->RemoveCameraHost(hostName);
        };

    private:
        wptr<HCameraHostManager> hostManager_;
    };

    explicit HCameraHostManager(std::shared_ptr<StatusCallback> statusCallback);
    ~HCameraHostManager() override;

    int32_t Init(void);
    void DeInit(void);
    void AddCameraDevice(const std::string& cameraId, sptr<ICameraDeviceService> cameraDevice);
    virtual int32_t GetVersionByCamera(const std::string& cameraId);
    void RemoveCameraDevice(const std::string& cameraId);
    void CloseCameraDevice(const std::string& cameraId);

    virtual int32_t GetCameras(std::vector<std::string> &cameraIds);
    virtual int32_t GetCameraAbility(std::string &cameraId, std::shared_ptr<OHOS::Camera::CameraMetadata> &ability);
    virtual int32_t OpenCameraDevice(std::string &cameraId,
                                     const sptr<ICameraDeviceCallback> &callback,
                                     sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> &pDevice,
                                     bool isEnableSecCam = false);
    virtual int32_t SetFlashlight(const std::string& cameraId, bool isEnable);
    virtual int32_t Prelaunch(const std::string& cameraId, std::string clientName);
    virtual int32_t PreSwitchCamera(const std::string& cameraId);
    virtual int32_t SetTorchLevel(float level);
    void NotifyDeviceStateChangeInfo(int notifyType, int deviceState);

    void SaveRestoreParam(sptr<HCameraRestoreParam> cameraRestoreParam);

    void UpdateRestoreParamCloseTime(const std::string& clientName, const std::string& cameraId);

    sptr<HCameraRestoreParam> GetRestoreParam(const std::string& clientName, const std::string& cameraId);

    sptr<HCameraRestoreParam> GetTransitentParam(const std::string& clientName, const std::string& cameraId);

    void UpdateRestoreParam(sptr<HCameraRestoreParam> &cameraRestoreParam);

    void DeleteRestoreParam(const std::string& clientName, const std::string& cameraId);

    bool CheckCameraId(sptr<HCameraRestoreParam> cameraRestoreParam, const std::string& cameraId);

    void AddCameraHost(const std::string& svcName);

    void RemoveCameraHost(const std::string& svcName);

    ::OHOS::sptr<HDI::ServiceManager::V1_0::IServStatListener> GetRegisterServStatListener();

    static const std::string LOCAL_SERVICE_NAME;
    static const std::string DISTRIBUTED_SERVICE_NAME;

    void SetMuteMode(bool muteMode);

private:
    struct CameraDeviceInfo;
    class CameraHostInfo;

    sptr<CameraHostInfo> FindCameraHostInfo(const std::string& cameraId);
    sptr<CameraHostInfo> FindLocalCameraHostInfo();
    bool IsCameraHostInfoAdded(const std::string& svcName);

    std::mutex mutex_;
    std::mutex deviceMutex_;
    std::mutex saveRestoreMutex_;
    std::weak_ptr<StatusCallback> statusCallback_;
    std::shared_ptr<CameraHostDeadCallback> cameraHostDeadCallback_;
    std::vector<sptr<CameraHostInfo>> cameraHostInfos_;
    std::map<std::string, sptr<ICameraDeviceService>> cameraDevices_;
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> persistentParamMap_;
    std::map<std::string, sptr<HCameraRestoreParam>> transitentParamMap_;
    ::OHOS::sptr<HDI::ServiceManager::V1_0::IServStatListener> registerServStatListener_;
    bool muteMode_;
};

class RegisterServStatListener : public HDI::ServiceManager::V1_0::ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const HDI::ServiceManager::V1_0::ServiceStatus&)>;
    
    explicit RegisterServStatListener(StatusCallback callback) : callback_(std::move(callback)) {
    }
    
    ~RegisterServStatListener() override = default;
    
    void OnReceive(const HDI::ServiceManager::V1_0::ServiceStatus& status) override;

private:
    StatusCallback callback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_HOST_MANAGER_H
