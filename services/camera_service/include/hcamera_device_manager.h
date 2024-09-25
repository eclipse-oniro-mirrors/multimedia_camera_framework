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


class CameraProcessPriority : public RefBase {
public:
    CameraProcessPriority(int32_t uid, int32_t state, int32_t focusState) : processUid_(uid),
        processState_(state), focusState_(focusState) {}

    inline bool operator == (const CameraProcessPriority& rhs) const
    {
        return (this->processState_ == rhs.processState_) && (this->focusState_ == rhs.focusState_);
    }

    inline bool operator < (const CameraProcessPriority& rhs) const
    {
        if (this->processUid_ < maxSysUid_) {
            MEDIA_DEBUG_LOG("this->processUid_ :%{public}d", this->processUid_);
            return true;
        } else if (this->processUid_ >= maxSysUid_ && rhs.processUid_ < maxSysUid_) {
            MEDIA_DEBUG_LOG("this->processUid_ :%{public}d, rhs.processUid_ :%{public}d",
                this->processUid_, rhs.processUid_);
            return false;
        }
        if (this->processState_ == rhs.processState_) {
            MEDIA_DEBUG_LOG("this->processState_ :%{public}d == rhs.processState_: %{public}d",
                this->processState_, rhs.processState_);
            return this->focusState_ < rhs.focusState_;
        } else {
            MEDIA_DEBUG_LOG("this->processState:%{public}d, rhs.processState_:%{public}d",
                this->processState_, rhs.processState_);
            return this->processState_ > rhs.processState_;
        }
    }

    inline bool operator > (const CameraProcessPriority& rhs) const
    {
        return rhs < *this;
    }

    inline bool operator <= (const CameraProcessPriority& rhs) const
    {
        if (this->processUid_ < maxSysUid_ && rhs.processUid_ < maxSysUid_) {
            return true;
        }
        return !(*this > rhs);
    }

    inline bool operator >= (const CameraProcessPriority& rhs) const
    {
        if (this->processUid_ < maxSysUid_ && rhs.processUid_ < maxSysUid_) {
            return false;
        }
        return !(*this < rhs);
    }

    inline void SetProcessState(int32_t state)
    {
        processState_ = state;
    }

    inline void SetProcessFocusState(int32_t focusState)
    {
        focusState_ = focusState;
    }

    inline int32_t GetUid() const{ return processUid_; }

    inline int32_t GetState() const { return processState_; }

    inline int32_t GetFocusState() const { return focusState_; }

private:
    const int32_t maxSysUid_ = 10000;
    int32_t processUid_;
    int32_t processState_;
    int32_t focusState_;
};

class HCameraDeviceHolder : public RefBase {
public:
    HCameraDeviceHolder(int32_t pid, int32_t uid, int32_t state, int32_t focusState,
        sptr<HCameraDevice> device, uint32_t accessTokenId)
        :pid_(pid), uid_(uid), state_(state), focusState_(focusState), accessTokenId_(accessTokenId), device_(device)
    {
        processPriority_ = new CameraProcessPriority(uid, state, focusState);
    }
    inline void SetPid(int32_t pid) { pid_ = pid; }
    inline void SetUid(int32_t uid) { uid_ = uid; }
    inline void SetState(int32_t state)
    {
        processPriority_->SetProcessState(state);
        state_ = state;
    }
    inline void SetFocusState(int32_t focusState)
    {
        processPriority_->SetProcessFocusState(focusState);
        focusState_ = focusState;
    }

    inline int32_t GetPid() const {return pid_;}

    inline int32_t GetUid() const{ return uid_; }

    inline int32_t GetState() const { return state_; }

    inline int32_t GetFocusState() const { return focusState_; }

    inline uint32_t GetAccessTokenId() const { return accessTokenId_; }

    inline sptr<HCameraDevice> GetDevice() const { return device_; }

    inline sptr<CameraProcessPriority> GetPriority() const {return processPriority_;}

private:
    int32_t pid_;
    int32_t uid_;
    int32_t state_;
    int32_t focusState_;
    uint32_t accessTokenId_;
    sptr<CameraProcessPriority> processPriority_;
    sptr<HCameraDevice> device_;
};

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
    * @brief Get cameraHolder by active process pid.
    *
    * @param pid Pid of active process.
    */
    sptr<HCameraDeviceHolder> GetCameraHolderByPid(pid_t pid);

    /**
    * @brief Get cameras by active process pid.
    *
    * @param pid Pid of active process.
    */
    sptr<HCameraDevice> GetCameraByPid(pid_t pidRequest);

    /**
    * @brief Get process pid device manager instance.
    *
    * @return Returns pointer to camera device manager instance.
    */
    pid_t GetActiveClient();

    void SetStateOfACamera(std::string cameraId, int32_t state);

    void SetPeerCallback(sptr<ICameraBroker>& callback);

    void UnsetPeerCallback();

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
    SafeMap<pid_t, sptr<HCameraDeviceHolder>> pidToCameras_;
    SafeMap<std::string, int32_t> stateOfACamera_;
    std::mutex mapMutex_;
    sptr<ICameraBroker> peerCallback_;
    std::mutex peerCbMutex_;
    std::string GetACameraId();
    bool IsAllowOpen(pid_t activeClient);
    void UpdateProcessState(int32_t& activeState, int32_t& requestState,
        uint32_t activeAccessTokenId, uint32_t requestAccessTokenId);
    void PrintClientInfo(sptr<HCameraDeviceHolder> activeCameraHolder, sptr<HCameraDeviceHolder> requestCameraHolder);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_MANAGER_H