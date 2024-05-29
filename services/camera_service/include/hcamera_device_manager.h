/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_CAMERA_DEVICE_MANAGER_H
#define OHOS_CAMERA_H_CAMERA_DEVICE_MANAGER_H

#include <refbase.h>
#include "hcamera_device.h"
#include "camera_util.h"
#include "mem_mgr_client.h"
#include "safe_map.h"

namespace OHOS {
namespace CameraStandard {
class HCameraDeviceManager : public RefBase {
public:
    ~HCameraDeviceManager();
    /**
    * @brief Get camera device manager instance.
    *
    * @return Returns pointer to camera device manager instance.
    */
    static sptr<HCameraDeviceManager> &GetInstance();

    /**
    * @brief Add opened device in camera device manager.
    *
    * @param device Device that have been turned on.
    * @param pid Pid for opening the device.
    */
    void AddDevice(pid_t pid, sptr<HCameraDevice> device);

    /**
    * @brief remove camera in camera device manager.
    *
    * @param device Device that have been turned off.
    */
    void RemoveDevice();

    /**
    * @brief Get cameras by active process pid.
    *
    * @param pid Pid of active process.
    */
    sptr<HCameraDevice> GetCameraByPid(pid_t pid);

    /**
    * @brief Get process pid device manager instance.
    *
    * @return Returns pointer to camera device manager instance.
    */
    pid_t GetActiveClient();

    void SetStateOfACamera(std::string cameraId, int32_t state);

    void SetPeerCallback(sptr<ICameraBroker>& callback);

    SafeMap<std::string, int32_t> &GetCameraStateOfASide();

    /**
    * @brief remove camera in camera device manager.
    *
    * @param camerasNeedEvict Devices that need to be shut down.
    * @param cameraIdRequestOpen device is requested to turn on.
    */
    bool GetConflictDevices(sptr<HCameraDevice> &camerasNeedEvict, sptr<HCameraDevice> cameraIdRequestOpen);
private:
    HCameraDeviceManager();
    static sptr<HCameraDeviceManager> cameraDeviceManager_;
    static std::mutex instanceMutex_;
    SafeMap<pid_t, sptr<HCameraDevice>> pidToCameras_;
    SafeMap<std::string, int32_t> stateOfACamera_;
    std::mutex mapMutex_;
    sptr<ICameraBroker> PeerCallback_;
    std::string GetACameraId();
    int32_t GetAdjForCameraState(std::string cameraId);
    bool isAllowOpen(pid_t activeClient);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_MANAGER_H