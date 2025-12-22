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
#include <set>
#include "hcamera_device.h"
#include "camera_util.h"
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

    inline void SetProcessUid(int32_t uid)
    {
        processUid_ = uid;
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
        sptr<HCameraDevice> device, uint32_t accessTokenId, int32_t cost, const std::set<std::string> &conflicting,
        int32_t firstTokenId)
        :pid_(pid), uid_(uid), accessTokenId_(accessTokenId), device_(device), cost_(cost), conflicting_(conflicting),
        firstTokenId_(firstTokenId)
    {
        processPriority_ = new CameraProcessPriority(uid, state, focusState);
    }
    inline void SetPid(int32_t pid) { pid_ = pid; }
    inline void SetUid(int32_t uid) { uid_ = uid; }
    inline void SetState(int32_t state)
    {
        processPriority_->SetProcessState(state);
    }
    inline void SetFocusState(int32_t focusState)
    {
        processPriority_->SetProcessFocusState(focusState);
    }

    inline void SetPriorityUid(int32_t uid)
    {
        processPriority_->SetProcessUid(uid);
    }

    inline int32_t GetPid() const {return pid_;}

    inline int32_t GetUid() const{ return uid_; }

    inline int32_t GetState() const { return processPriority_->GetState(); }

    inline int32_t GetFocusState() const { return processPriority_->GetFocusState(); }

    inline uint32_t GetAccessTokenId() const { return accessTokenId_; }

    inline sptr<HCameraDevice> GetDevice() const { return device_; }
    
    inline sptr<CameraProcessPriority> GetPriority() const {return processPriority_;}

    inline int32_t GetCost() const{ return cost_; }

    inline bool IsConflicting(const std::string &cameraId) const
    {
        std::string curCameraId = device_->GetCameraId();
        if (cameraId == curCameraId) {
            return true;
        }
        for (const auto &x : conflicting_) {
            if (cameraId == x) {
                return true;
            }
        }
        return false;
    }

    inline uint32_t GetFirstTokenID() const { return firstTokenId_; }

    inline std::set<std::string> GetConflicting() const { return conflicting_; }

private:
    int32_t pid_;
    int32_t uid_;
    uint32_t accessTokenId_;
    sptr<CameraProcessPriority> processPriority_;
    sptr<HCameraDevice> device_;
    int32_t cost_;
    std::set<std::string> conflicting_;
    int32_t firstTokenId_;
};

class CameraConcurrentSelector : public RefBase {
public:
    CameraConcurrentSelector() = default;
    ~CameraConcurrentSelector() = default;

    /**
    * @brief Setting up a baseline camera and producing a table of concurrent cameras
    */
    void SetRequestCameraId(sptr<HCameraDeviceHolder> requestCameraHolder);

    /**
    * @brief Check and save whether the camera can be retained.
    */
    bool SaveConcurrentCameras(std::vector<sptr<HCameraDeviceHolder>> holdersSortedByProprity,
                                          sptr<HCameraDeviceHolder> holderWaitToConfirm);

    /**
    * @brief Return to cameras that must be retained.
    *
    * @return Return to cameras that must be retained.
    */
    inline std::vector<sptr<HCameraDeviceHolder>> GetCamerasRetainable()
    {
        return listOfCameraRetainable_;
    }

    /**
    * @brief Return the Concurrent List.
    *
    * @return Return the Concurrent List.
    */
    inline std::vector<std::vector<std::int32_t>> GetConcurrentCameraTable()
    {
        return concurrentCameraTable_;
    }

    bool CanOpenCameraconcurrently(std::vector<sptr<HCameraDeviceHolder>> reservedCameras,
                                   std::vector<std::vector<std::int32_t>> concurrentCameraTable);

private:
    sptr<HCameraDeviceHolder> requestCameraHolder_;
    std::vector<sptr<HCameraDeviceHolder>> listOfCameraRetainable_ = {};
    std::vector<std::vector<std::int32_t>> concurrentCameraTable_ = {};
    int32_t GetCameraIdNumber(std::string);
    bool ConcurrentWithRetainedDevicesOrNot(sptr<HCameraDeviceHolder> cameraIdNeedConfirm);
};

class HCameraDeviceManager : public RefBase {
public:
    /**
    * @brief the default maxinum "cost" allowed before evicting.
    *
    */
    static constexpr int32_t DEFAULT_MAX_COST = 100;

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
    void RemoveDevice(const std::string &cameraId);

    /**
    * @brief Get cameraHolder by active process pid.
    *
    * @param pid Pid of active process.
    */
    std::vector<sptr<HCameraDeviceHolder>> GetCameraHolderByPid(pid_t pid);

    /**
    * @brief Get cameras by active process pid.
    *
    * @param pid Pid of active process.
    */
    std::vector<sptr<HCameraDevice>> GetCamerasByPid(pid_t pidRequest);

    /**
    * @brief Get process pid device manager instance.
    *
    * @return Returns pointer to camera device manager instance.
    */
    std::vector<pid_t> GetActiveClient();
 
    /**
    * @brief Get the existing holder object.
    *
    * @return Returns the list of existing holders.
    */

    std::vector<sptr<HCameraDeviceHolder>> GetActiveCameraHolders();

    void SetStateOfACamera(std::string cameraId, int32_t state);

    bool IsMultiCameraActive(int32_t pid);

    void SetPeerCallback(const sptr<ICameraBroker>& callback);

    void UnsetPeerCallback();

    size_t GetActiveCamerasCount();

    SafeMap<std::string, int32_t> &GetCameraStateOfASide();

    /**
    * @brief remove camera in camera device manager.
    *
    * @param camerasNeedEvict Devices that need to be shut down.
    * @param cameraIdRequestOpen device is requested to turn on.
    */
    bool GetConflictDevices(std::vector<sptr<HCameraDevice>> &cameraNeedEvict, sptr<HCameraDevice> cameraIdRequestOpen,
                            int32_t concurrentTypeOfRequest);
    void UpdateCameraHolders(const std::vector<pid_t>& pidOfActiveClients,
                            sptr<HCameraDeviceHolder> requestHolder);
    /**
    * @brief handle active camera evictions in camera device manager.
    *
    * @param evictedClients Devices that need to be shut down.
    * @param cameraRequestOpen device is requested to turn on.
    */
    bool HandleCameraEvictions(std::vector<sptr<HCameraDeviceHolder>> &evictedClients,
                               sptr<HCameraDeviceHolder> &cameraRequestOpen);

    bool IsProcessHasConcurrentDevice(pid_t pid);

    std::mutex mapMutex_;
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
    void SetLiveScene(bool isLiveScene);
    bool IsLiveScene();
#endif
private:
    HCameraDeviceManager();
    static sptr<HCameraDeviceManager> cameraDeviceManager_;
    static std::mutex instanceMutex_;
    std::map<pid_t, std::vector<sptr<HCameraDeviceHolder>>> pidToCameras_;
    SafeMap<std::string, int32_t> stateOfRgmCamera_;
    // LRU ordered, most recent at end
    std::vector<sptr<HCameraDeviceHolder>> activeCameras_;
    std::vector<sptr<HCameraDeviceHolder>> holderSortedByProprity_;
    sptr<ICameraBroker> peerCallback_;
    std::mutex peerCbMutex_;
    sptr<CameraConcurrentSelector> concurrentSelector_;
    std::string GetACameraId();
    bool IsAllowOpen(pid_t activeClient);
    int32_t GetCurrentCost() const;
    void DetermineHighestPriorityOwner(int32_t &highestPriorityOwner, int32_t &owner,
        sptr<CameraProcessPriority> requestPriority);
    std::vector<sptr<HCameraDeviceHolder>> WouldEvict(sptr<HCameraDeviceHolder> &cameraRequestOpen);
    void GenerateEachProcessCameraState(int32_t& processState, uint32_t processTokenId);
    void PrintClientInfo(sptr<HCameraDeviceHolder> activeCameraHolder, sptr<HCameraDeviceHolder> requestCameraHolder);
    sptr<HCameraDeviceHolder> GenerateCameraHolder(sptr<HCameraDevice> device, pid_t pid, int32_t uid,
        uint32_t accessTokenId, uint32_t firstTokenId);
    std::vector<sptr<HCameraDeviceHolder>> SortDeviceByPriority();
    void RefreshCameraDeviceHolderState(sptr<HCameraDeviceHolder> requestCameraHolder);
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
    std::atomic<bool> isLiveScene_ = false;
#endif
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_MANAGER_H