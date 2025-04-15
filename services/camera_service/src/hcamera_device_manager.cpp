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

#include "camera_app_manager_client.h"
#include "camera_log.h"
#include "camera_window_manager_agent.h"
#include "camera_window_manager_client.h"
#include "camera_app_manager_utils.h"
#include "ipc_skeleton.h"
#include "hcamera_device_manager.h"
#include <mutex>
#include <regex>

namespace OHOS {
namespace CameraStandard {
static const int32_t FOREGROUND_STATE_OF_PROCESS = 0;
static const int32_t PIP_STATE_OF_PROCESS = 1;
static const int32_t BCAKGROUND_STATE_OF_PROCESS = 2;
static const int32_t UNKNOW_STATE_OF_PROCESS = 3;
static const std::unordered_map<int32_t, int32_t> APP_MGR_STATE_TO_CAMERA_STATE = {
    {2,  FOREGROUND_STATE_OF_PROCESS},
    {4,  BCAKGROUND_STATE_OF_PROCESS}
};
static const int32_t FOCUSED_STATE_OF_PROCESS = 1;
static const int32_t UNFOCUSED_STATE_OF_PROCESS = 0;
sptr<HCameraDeviceManager> HCameraDeviceManager::cameraDeviceManager_;
std::mutex HCameraDeviceManager::instanceMutex_;

HCameraDeviceManager::HCameraDeviceManager()
{
    concurrentSelector_ = new CameraConcurrentSelector();
}

HCameraDeviceManager::~HCameraDeviceManager()
{
    HCameraDeviceManager::cameraDeviceManager_ = nullptr;
}

sptr<HCameraDeviceManager> &HCameraDeviceManager::GetInstance()
{
    if (cameraDeviceManager_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraDeviceManager_ == nullptr) {
            MEDIA_INFO_LOG("Initializing camera device manager instance");
            cameraDeviceManager_ = new HCameraDeviceManager();
            CameraWindowManagerClient::GetInstance();
        }
    }
    return cameraDeviceManager_;
}

size_t HCameraDeviceManager::GetActiveCamerasCount()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveCamerasCount: %{public}zu", activeCameras_.size());
    return activeCameras_.size();
}

void HCameraDeviceManager::AddDevice(pid_t pid, sptr<HCameraDevice> device)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::AddDevice start, cameraID: %{public}s", device->GetCameraId().c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);
    int32_t cost = 0;
    std::set<std::string> conflicting;
    device->GetCameraResourceCost(cost, conflicting);
    int32_t uidOfRequestProcess = IPCSkeleton::GetCallingUid();
    int32_t pidOfRequestProcess = IPCSkeleton::GetCallingPid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    int32_t firstTokenIdOfRequestProc = IPCSkeleton::GetFirstTokenID();
    sptr<HCameraDeviceHolder> cameraHolder = new HCameraDeviceHolder(
        pidOfRequestProcess, uidOfRequestProcess, FOREGROUND_STATE_OF_PROCESS,
        FOCUSED_STATE_OF_PROCESS, device, accessTokenIdOfRequestProc, cost, conflicting, firstTokenIdOfRequestProc);
    pidToCameras_[pid].push_back(cameraHolder);
    MEDIA_DEBUG_LOG("HCameraDeviceManager::AddDevice pidToCameras_ size: %{public}zu", pidToCameras_.size());
    activeCameras_.push_back(cameraHolder);
    MEDIA_INFO_LOG("HCameraDeviceManager::AddDevice end, cameraID: %{public}s", device->GetCameraId().c_str());
}

void HCameraDeviceManager::RemoveDevice(const std::string &cameraId)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::RemoveDevice cameraId=%{public}s start", cameraId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);
    CHECK_ERROR_RETURN(activeCameras_.empty());
    auto it = std::find_if(activeCameras_.begin(), activeCameras_.end(), [&](const sptr<HCameraDeviceHolder> &x) {
        const std::string &curCameraId = x->GetDevice()->GetCameraId();
        return cameraId == curCameraId;
    });
    CHECK_ERROR_RETURN_LOG(it == activeCameras_.end(), "HCameraDeviceManager::RemoveDevice error");
    int32_t pidNumber = (*it)->GetPid();
    auto itPid = pidToCameras_.find(pidNumber);
    if (itPid != pidToCameras_.end()) {
        auto &camerasOfPid = itPid->second;
        camerasOfPid.erase(std::remove_if(camerasOfPid.begin(), camerasOfPid.end(),
                                          [cameraId](const sptr<HCameraDeviceHolder> &holder) {
                                              return holder->GetDevice()->GetCameraId() == cameraId;
                                          }),
                           camerasOfPid.end());
        if (camerasOfPid.empty()) {
            MEDIA_INFO_LOG("HCameraDeviceManager::RemoveDevice %{public}d "
                "no active client exists. Clear table records", pidNumber);
            pidToCameras_.erase(pidNumber);
        }
    }
    activeCameras_.erase(it);
    MEDIA_DEBUG_LOG("HCameraDeviceManager::RemoveDevice end");
}

std::vector<sptr<HCameraDeviceHolder>> HCameraDeviceManager::GetCameraHolderByPid(pid_t pidRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraHolderByPid start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto it = pidToCameras_.find(pidRequest);
    if (it == pidToCameras_.end()) {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraHolderByPid end, pid: %{public}d not found", pidRequest);
        return {};
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraHolderByPid end, pid: %{public}d found", pidRequest);
    return it->second;
}

std::vector<sptr<HCameraDevice>> HCameraDeviceManager::GetCamerasByPid(pid_t pidRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraByPid start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto it = pidToCameras_.find(pidRequest);
    if (it == pidToCameras_.end()) {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetCamerasByPid end, pid: %{public}d not found", pidRequest);
        return {};
    }
    std::vector<sptr<HCameraDevice>> cameras = {};
    if (!it->second.empty()) {
        for (auto cameraHolder : it->second) {
            cameras.push_back(cameraHolder->GetDevice());
        }
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraByPid end");
    return cameras;
}

std::vector<pid_t> HCameraDeviceManager::GetActiveClient()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    std::vector<pid_t> activeClientPids;
    if (!pidToCameras_.empty()) {
        for (auto pair : pidToCameras_) {
            activeClientPids.emplace_back(pair.first);
        }
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient end");
    return activeClientPids;
}

std::vector<sptr<HCameraDeviceHolder>> HCameraDeviceManager::GetActiveCameraHolders()
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    return activeCameras_;
}

void HCameraDeviceManager::SetStateOfACamera(std::string cameraId, int32_t state)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::SetStateOfACamera start %{public}s, state: %{public}d",
                   cameraId.c_str(), state);\
    if (state == 0) {
        stateOfRgmCamera_.EnsureInsert(cameraId, state);
    } else {
        stateOfRgmCamera_.Clear();
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::SetStateOfACamera end");
}

SafeMap<std::string, int32_t> &HCameraDeviceManager::GetCameraStateOfASide()
{
    return stateOfRgmCamera_;
}

void HCameraDeviceManager::SetPeerCallback(sptr<ICameraBroker>& callback)
{
    CHECK_ERROR_RETURN_LOG(callback == nullptr, "HCameraDeviceManager::SetPeerCallback failed to set peer callback");
    std::lock_guard<std::mutex> lock(peerCbMutex_);
    peerCallback_ = callback;
}

void HCameraDeviceManager::UnsetPeerCallback()
{
    std::lock_guard<std::mutex> lock(peerCbMutex_);
    peerCallback_ = nullptr;
}

static void GetInfoFromCameraDeviceHolder(sptr<HCameraDeviceHolder> requestCameraHolder, int32_t &retPid,
    int32_t &retUid, int32_t &retTokenId)
{
    using namespace Security::AccessToken;
    retPid = requestCameraHolder->GetPid();
    retUid = requestCameraHolder->GetUid();
    retTokenId = requestCameraHolder->GetAccessTokenId();

    if (AccessTokenKit::GetTokenTypeFlag(requestCameraHolder->GetAccessTokenId()) != ATokenTypeEnum::TOKEN_NATIVE) {
        MEDIA_DEBUG_LOG("token is not sa");
        return;
    }

    uint32_t firstTokenId = requestCameraHolder->GetFirstTokenID();
    if (firstTokenId == 0) {
        return;
    }

    if (AccessTokenKit::GetTokenTypeFlag(firstTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        MEDIA_INFO_LOG("first token is not hap");
        return;
    }

    HapTokenInfoExt hapTokenInfo = {};
    int32_t getHapInfoRet = AccessTokenKit::GetHapTokenInfoExtension(firstTokenId, hapTokenInfo);
    if (getHapInfoRet != 0) {
        MEDIA_ERR_LOG("get hap info fail");
        return;
    }

    std::vector<AppExecFwk::AppStateData> appDataList;
    CameraAppManagerUtils::GetForegroundApplications(appDataList);

    std::optional<AppExecFwk::AppStateData> callerAppData;
    for (const auto& appData : appDataList) {
    std::string callerBundleName;
        if (appData.accessTokenId == firstTokenId) {
            callerAppData = appData;
            break;
        }
    }

    if (!callerAppData.has_value()) {
        MEDIA_INFO_LOG("app not found");
        return;
    }

    MEDIA_INFO_LOG("get camera device holder info by first token id, origin pid: %{public}d, uid %{public}d, "
        "after pid: %{public}d, uid %{public}d", retPid, retUid, callerAppData->pid, callerAppData->uid);
    retPid = callerAppData->pid;
    retUid = callerAppData->uid;
    retTokenId = firstTokenId;
}

void HCameraDeviceManager::RefreshCameraDeviceHolderState(sptr<HCameraDeviceHolder> requestCameraHolder)
{
    if (requestCameraHolder == nullptr) {
        return;
    }

    int32_t uid = 0;
    int32_t pid = 0;
    int32_t tokenId = 0;
    GetInfoFromCameraDeviceHolder(requestCameraHolder, pid, uid, tokenId);
    int32_t processState = CameraAppManagerClient::GetInstance()->GetProcessState(pid);
    GenerateEachProcessCameraState(processState, tokenId);

    pid_t focusWindowPid = -1;
    CameraWindowManagerClient::GetInstance()->GetFocusWindowInfo(focusWindowPid);
    if (focusWindowPid == -1) {
        MEDIA_INFO_LOG("GetFocusWindowInfo faild");
    }
    int32_t focusState = focusWindowPid == pid ? FOCUSED_STATE_OF_PROCESS : UNFOCUSED_STATE_OF_PROCESS;
    requestCameraHolder->SetState(processState);
    requestCameraHolder->SetFocusState(focusState);
    requestCameraHolder->SetPriorityUid(uid);
}

bool HCameraDeviceManager::GetConflictDevices(std::vector<sptr<HCameraDevice>>& cameraNeedEvict,
                                              sptr<HCameraDevice> cameraRequestOpen, int32_t concurrentTypeOfRequest)
{
    std::vector<pid_t> pidOfActiveClients = GetActiveClient();
    pid_t pidOfOpenRequest = IPCSkeleton::GetCallingPid();
    pid_t uidOfOpenRequest = IPCSkeleton::GetCallingUid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    int32_t firstTokenIdOfOpenRequest = IPCSkeleton::GetFirstTokenID();
    for (auto pidItem : pidOfActiveClients) {
        MEDIA_INFO_LOG("GetConflictDevices get active: %{public}d, openRequestPid: %{public}d "
            "openRequestUid: %{public}d",
            pidItem, pidOfOpenRequest, uidOfOpenRequest);
    }
    // Protecting for mysterious call
    if (stateOfRgmCamera_.Size() != 0) {
        CHECK_ERROR_RETURN_RET_LOG(pidOfActiveClients.size() != 0, false,
            "HCameraDeviceManager::GetConflictDevices Exceptional error occurred before");
        return IsAllowOpen(pidOfOpenRequest);
    } else {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices no rgm camera active");
    }
    CHECK_ERROR_RETURN_RET(pidOfActiveClients.size() == 0, true);
    // Protecting for mysterious call end.

    sptr<HCameraDeviceHolder> requestHolder =
        GenerateCameraHolder(cameraRequestOpen, pidOfOpenRequest, uidOfOpenRequest, accessTokenIdOfRequestProc,
            firstTokenIdOfOpenRequest);

    // Update each cameraHolder.
    for (auto pidOfEachClient : pidOfActiveClients) {
        std::vector<sptr<HCameraDeviceHolder>> activeCameraHolders = GetCameraHolderByPid(pidOfEachClient);
        if (activeCameraHolders.empty()) {
            MEDIA_WARNING_LOG("HCameraDeviceManager::GetConflictDevices the current PID has an unknown behavior.");
            continue;
        }
        for (auto holder : activeCameraHolders) {
            // Device startup requests from different processes.
            RefreshCameraDeviceHolderState(holder);
            PrintClientInfo(holder, requestHolder);
        }
    }
    concurrentSelector_->SetRequestCameraId(requestHolder);
    // Active clients that have been sorted by priority. The same priority complies with the LRU rule.
    holderSortedByProprity_ = SortDeviceByPriority();
    for (auto it = holderSortedByProprity_.rbegin(); it != holderSortedByProprity_.rend(); ++it) {
        if (concurrentSelector_->SaveConcurrentCameras(holderSortedByProprity_, *it)) {
            MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices id: %{public}s can open concurrently",
                (*it)->GetDevice()->GetCameraId().c_str());
            continue;
        } else {
            MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices id: %{public}s can not open concurrently",
                (*it)->GetDevice()->GetCameraId().c_str());
            cameraNeedEvict.emplace_back((*it)->GetDevice());
        }
    }

    // Return Can the cameras that must be left be concurrent.
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices reservedCameras size: %{public}zu",
        concurrentSelector_->GetCamerasRetainable().size());
    return concurrentSelector_->CanOpenCameraconcurrently(concurrentSelector_->GetCamerasRetainable(),
        concurrentSelector_->GetConcurrentCameraTable());
}

bool HCameraDeviceManager::HandleCameraEvictions(std::vector<sptr<HCameraDeviceHolder>> &evictedClients,
    sptr<HCameraDeviceHolder> &cameraRequestOpen)
{
    std::vector<pid_t> pidOfActiveClients = GetActiveClient();
    pid_t pidOfOpenRequest = IPCSkeleton::GetCallingPid();
    sptr<CameraAppManagerClient> amsClientInstance = CameraAppManagerClient::GetInstance();
    const std::string &cameraId = cameraRequestOpen->GetDevice()->GetCameraId();
    int32_t requestState = amsClientInstance->GetProcessState(pidOfOpenRequest);
    for (auto eachClientPid : pidOfActiveClients) {
        int32_t activeState = amsClientInstance->GetProcessState(eachClientPid);
        MEDIA_INFO_LOG("Request Open camera ID %{public}s active pid: %{public}d, state: %{public}d,"
            "request pid: %{public}d, state: %{public}d", cameraId.c_str(), eachClientPid,
            activeState, pidOfOpenRequest, requestState);
    }

    RefreshCameraDeviceHolderState(cameraRequestOpen);
    MEDIA_INFO_LOG("focusStateOfRequestProcess = %{public}d", cameraRequestOpen->GetFocusState());
    for (const auto &deviceHolder : activeCameras_) {
        RefreshCameraDeviceHolderState(deviceHolder);
    }

    // Find Camera Device that would be evicted
    std::vector<sptr<HCameraDeviceHolder>> evicted = WouldEvict(cameraRequestOpen);

    // If the incoming client was 'evicted,' higher priority clients have the camera in the
    // background, so we cannot do evictions
    if (std::find(evicted.begin(), evicted.end(), cameraRequestOpen) != evicted.end()) {
        MEDIA_INFO_LOG("PID %{public}d) rejected with higher priority", pidOfOpenRequest);
        return false;
    }
    for (auto &x : evicted) {
        if (x == nullptr) {
            MEDIA_ERR_LOG("Invalid state: Null client in active client list.");
            continue;
        }
        MEDIA_INFO_LOG("evicting conflicting client for camera ID %s",
                       x->GetDevice()->GetCameraId().c_str());
        evictedClients.push_back(x);
    }
    MEDIA_INFO_LOG("Camera: %{public}s could be opened", cameraId.c_str());
    return true;
}

std::vector<sptr<HCameraDeviceHolder>> HCameraDeviceManager::WouldEvict(sptr<HCameraDeviceHolder> &cameraRequestOpen)
{
    std::vector<sptr<HCameraDeviceHolder>> evictList;
    // Disallow null clients, return input
    if (cameraRequestOpen == nullptr) {
        evictList.push_back(cameraRequestOpen);
        return evictList;
    }
    const std::string &cameraId = cameraRequestOpen->GetDevice()->GetCameraId();
    sptr<CameraProcessPriority> requestPriority = cameraRequestOpen->GetPriority();
    int32_t owner = cameraRequestOpen->GetPid();
    int32_t totalCost = GetCurrentCost() + cameraRequestOpen->GetCost();

    // Determine the MRU of the owners tied for having the highest priority
    int32_t highestPriorityOwner = owner;
    sptr<CameraProcessPriority> highestPriority = requestPriority;
    for (const auto &x : activeCameras_) {
        sptr<CameraProcessPriority> curPriority = x->GetPriority();
        if (*curPriority > *highestPriority) {
            highestPriority = curPriority;
            highestPriorityOwner = x->GetPid();
        }
    }
    // Switch back owner if the incoming client has the highest priority, as it is MRU
    highestPriorityOwner = (*highestPriority == *requestPriority) ? owner : highestPriorityOwner;

    // Build eviction list of clients to remove
    for (const auto &x : activeCameras_) {
        const std::string &curCameraId = x->GetDevice()->GetCameraId();
        int32_t curCost = x->GetCost();
        sptr<CameraProcessPriority> curPriority = x->GetPriority();
        int32_t curOwner = x->GetPid();
        MEDIA_INFO_LOG("CameraId:[%{public}s, %{public}s], totalCost: %{public}d", curCameraId.c_str(),
                       cameraId.c_str(), totalCost);
        MEDIA_INFO_LOG("ControlConflict:[%{public}d, %{public}d]", x->IsConflicting(cameraId),
                       cameraRequestOpen->IsConflicting(curCameraId));
        bool deviceConflict = (curCameraId == cameraId);
        bool controlConflict = x->IsConflicting(cameraId) || cameraRequestOpen->IsConflicting(curCameraId);
        if ((deviceConflict || controlConflict) && (*curPriority <= *requestPriority)) {
            evictList.clear();
            evictList.push_back(x);
            MEDIA_INFO_LOG("deviceConflict: requestProcess has higher priority, Evict current CameraClient");
            return evictList;
        } else if ((deviceConflict || controlConflict) && (*curPriority > *requestPriority)) {
            evictList.clear();
            evictList.push_back(cameraRequestOpen);
            MEDIA_INFO_LOG(
                "DeviceConflict or controlConflict, current client has higher priority, Evict request client");
            return evictList;
        }
        if ((totalCost > DEFAULT_MAX_COST && curCost > 0) && (*curPriority <= *requestPriority) &&
            !(highestPriorityOwner == owner && owner == curOwner)) {
            MEDIA_INFO_LOG("Evict current camera client");
            evictList.push_back(x);
            totalCost -= curCost;
        }
    }
    MEDIA_INFO_LOG("non-conflicting:  totalCost:%{public}d", totalCost);
    // If the total cost is too high, return the input unless the input has the highest priority
    if (totalCost > DEFAULT_MAX_COST) {
        MEDIA_INFO_LOG("totalCost > DEFAULT_MAX_COST, Evict ReqCamera");
        evictList.clear();
        evictList.push_back(cameraRequestOpen);
    }
    return evictList;
}

int32_t HCameraDeviceManager::GetCurrentCost() const
{
    int32_t totalCost = 0;
    for (const auto &x : activeCameras_) {
        totalCost += x->GetCost();
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCurrentCost:%{public}d", totalCost);
    return totalCost;
}

std::string HCameraDeviceManager::GetACameraId()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient start");
    std::string cameraId;
    if (!stateOfRgmCamera_.IsEmpty()) {
        stateOfRgmCamera_.Iterate([&](const std::string pid, int32_t state) {
            cameraId = pid;
        });
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient end");
    return cameraId;
}

bool HCameraDeviceManager::IsAllowOpen(pid_t pidOfOpenRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::isAllowOpen has a client open in A proxy");
    CHECK_ERROR_RETURN_RET_LOG(pidOfOpenRequest == -1, false,
        "HCameraDeviceManager::GetConflictDevices wrong pid of the process whitch is goning to turn on");
        std::string cameraId = GetACameraId();
    CHECK_ERROR_RETURN_RET_LOG(peerCallback_ == nullptr, false,
        "HCameraDeviceManager::isAllowOpen falied to close peer device");
            peerCallback_->NotifyCloseCamera(cameraId);
            MEDIA_ERR_LOG("HCameraDeviceManager::isAllowOpen success to close peer device");
        return true;
}

void HCameraDeviceManager::GenerateEachProcessCameraState(int32_t& processState, uint32_t processTokenId)
{
    sptr<IWindowManagerAgent> winMgrAgent = CameraWindowManagerClient::GetInstance()->GetWindowManagerAgent();
    uint32_t accessTokenIdInPip = 0;
    if (winMgrAgent != nullptr) {
        accessTokenIdInPip =
            static_cast<CameraWindowManagerAgent*>(winMgrAgent.GetRefPtr())->GetAccessTokenId();
        MEDIA_DEBUG_LOG("update current pip window accessTokenId");
    }

    auto updateState = [accessTokenIdInPip](int32_t& state, uint32_t accessTokenId) {
        auto it = APP_MGR_STATE_TO_CAMERA_STATE.find(state);
        state = (it != APP_MGR_STATE_TO_CAMERA_STATE.end()) ? it->second : UNKNOW_STATE_OF_PROCESS;
        if (accessTokenId == accessTokenIdInPip) {
            state = PIP_STATE_OF_PROCESS;
        }
    };
    updateState(processState, processTokenId);
}

void HCameraDeviceManager::PrintClientInfo(sptr<HCameraDeviceHolder> activeCameraHolder,
    sptr<HCameraDeviceHolder> requestCameraHolder)
{
    MEDIA_INFO_LOG("activeInfo: uid: %{public}d, pid: %{public}d, processState: %{public}d, "
                   "focusState: %{public}d, cameraId: %{public}s "
                   "requestInfo: uid: %{public}d, pid: %{public}d, processState: %{public}d, "
                   "focusState: %{public}d, cameraId: %{public}s",
                   activeCameraHolder->GetPriority()->GetUid(), activeCameraHolder->GetPid(),
                   activeCameraHolder->GetPriority()->GetState(), activeCameraHolder->GetPriority()->GetFocusState(),
                   activeCameraHolder->GetDevice()->GetCameraId().c_str(), requestCameraHolder->GetPriority()->GetUid(),
                   requestCameraHolder->GetPid(), requestCameraHolder->GetPriority()->GetState(),
                   requestCameraHolder->GetPriority()->GetFocusState(),
                   requestCameraHolder->GetDevice()->GetCameraId().c_str());
}

bool HCameraDeviceManager::IsMultiCameraActive(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    uint8_t count = 0;
    for (const auto &x : activeCameras_) {
        if (pid == x->GetPid()) {
            count++;
        }
    }

    MEDIA_INFO_LOG("pid(%{public}d) has activated %{public}d camera.", pid, count);
    return count > 0;
}


sptr<HCameraDeviceHolder> HCameraDeviceManager::GenerateCameraHolder(sptr<HCameraDevice> device, pid_t pid, int32_t uid,
    uint32_t accessTokenId, uint32_t firstTokenId)
{
    int32_t cost = 0;
    std::set<std::string> conflicting;
    sptr<HCameraDeviceHolder> requestCameraHolder = new HCameraDeviceHolder(
        pid, uid, 0, 0, device, accessTokenId, cost, conflicting, firstTokenId);
    RefreshCameraDeviceHolderState(requestCameraHolder);
    return requestCameraHolder;
}

bool HCameraDeviceManager::IsProcessHasConcurrentDevice(pid_t pid)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto mapIt = pidToCameras_.find(pid);
    if (mapIt == pidToCameras_.end()) {
        return false;
    }
    for (auto& holder : mapIt->second) {
        auto device = holder->GetDevice();
        if (device == nullptr) {
            continue;
        }
        if (device->IsDeviceOpenedByConcurrent()) {
            return true;
        }
    }
    return false;
}

void CameraConcurrentSelector::SetRequestCameraId(sptr<HCameraDeviceHolder> requestCameraHolder)
{
    CHECK_ERROR_RETURN_LOG(
        requestCameraHolder == nullptr, "requestCameraHolder is null");
    requestCameraHolder_ = requestCameraHolder;
    concurrentCameraTable_ = requestCameraHolder->GetDevice()->GetConcurrentDevicesTable();
    listOfCameraRetainable_ = {};
}

std::vector<sptr<HCameraDeviceHolder>> HCameraDeviceManager::SortDeviceByPriority()
{
    std::vector<sptr<HCameraDeviceHolder>> sortedList = activeCameras_;
    std::sort(sortedList.begin(), sortedList.end(),
              [](const sptr<HCameraDeviceHolder> &a, const sptr<HCameraDeviceHolder> &b) {
                  return a->GetPriority() < b->GetPriority();
              });
    return sortedList;
}

bool CameraConcurrentSelector::CanOpenCameraconcurrently(std::vector<sptr<HCameraDeviceHolder>> reservedCameras,
                                                         std::vector<std::vector<std::int32_t>> concurrentCameraTable)
{
    for (const auto& row : concurrentCameraTable) {
        std::stringstream ss;
        for (size_t i = 0; i < row.size(); ++i) {
            ss << row[i];
            if (i < row.size() - 1) {
                ss << ", "; // 使用逗号分隔元素
            }
        }
        MEDIA_DEBUG_LOG("CameraConcurrentSelector::canOpenCameraconcurrently "
            "concurrentCameraTable_ current group: %{public}s", ss.str().c_str());
    }
    if (reservedCameras.size() == 0) {
        return true;
    }
    std::vector<int32_t> cameraIds;
    for (const auto& camera : reservedCameras) {
        cameraIds.push_back(GetCameraIdNumber(camera->GetDevice()->GetCameraId()));
    }
    for (const auto& group : concurrentCameraTable) {
        bool allCamerasInGroup = true;
        for (int32_t cameraId : cameraIds) {
            if (std::find(group.begin(), group.end(), cameraId) == group.end()) {
                allCamerasInGroup = false;
                break;
            }
        }
        if (allCamerasInGroup) return true;
    }
    return false;
}

bool CameraConcurrentSelector::SaveConcurrentCameras(std::vector<sptr<HCameraDeviceHolder>> holdersSortedByProprity,
                                                     sptr<HCameraDeviceHolder> holderWaitToConfirm)
{
    // Same pid
    if (holderWaitToConfirm->GetPid() == requestCameraHolder_->GetPid()) {
        if (!holderWaitToConfirm->GetDevice()->GetCameraId().compare(
            requestCameraHolder_->GetDevice()->GetCameraId())) {
            // The current device can never be concurrent with itself, the latter one always turns on
            return false;
        } else {
            listOfCameraRetainable_.emplace_back(holderWaitToConfirm);
            return true;
        }
    }

    for (const auto& row : concurrentCameraTable_) {
        std::stringstream ss;
        for (size_t i = 0; i < row.size(); ++i) {
            ss << row[i];
            if (i < row.size() - 1) {
                ss << ", "; // 使用逗号分隔元素
            }
        }
        MEDIA_DEBUG_LOG("CameraConcurrentSelector::SaveConcurrentCameras"
            "concurrentCameraTable_ current group: %{public}s", ss.str().c_str());
    }

    // This device cannot be opened concurrently. Pure priority is preferred.
    if (concurrentCameraTable_.size() == 0) {
        if ((*holderWaitToConfirm->GetPriority()) <= (*requestCameraHolder_->GetPriority())) {
            return false;
        } else {
            // A higher priority, which needs to be reserved
            listOfCameraRetainable_.emplace_back(holderWaitToConfirm);
            return true;
        }
    }

    // Devices can be opened concurrently.
    bool canConcurrentOpen = ConcurrentWithRetainedDevicesOrNot(holderWaitToConfirm);
    if (canConcurrentOpen) {
        listOfCameraRetainable_.emplace_back(holderWaitToConfirm);
        return true;
    } else {
        if ((*holderWaitToConfirm->GetPriority()) <= (*requestCameraHolder_->GetPriority())) {
            return false;
        } else {
            // A higher priority, which needs to be reserved
            listOfCameraRetainable_.emplace_back(holderWaitToConfirm);
            return true;
        }
    }
    MEDIA_WARNING_LOG("CameraConcurrentSelector::ConfirmAndInsertRetainableCamera Unknown concurrency type");
    return false;
}

int32_t CameraConcurrentSelector::GetCameraIdNumber(std::string cameraId)
{
    const int32_t ILLEGAL_ID = -1;
    std::regex regex("\\d+$");
    std::smatch match;
    if (std::regex_search(cameraId, match, regex)) {
        std::string numberStr  = match[0];
        std::stringstream ss(numberStr);
        int number;
        ss >> number;
        return number;
    } else {
        return ILLEGAL_ID;
    }
}

bool CameraConcurrentSelector::ConcurrentWithRetainedDevicesOrNot(sptr<HCameraDeviceHolder> cameraIdNeedConfirm)
{
    std::vector<int32_t> tempListToCheck;
    for (auto each : listOfCameraRetainable_) {
        tempListToCheck.emplace_back(GetCameraIdNumber(each->GetDevice()->GetCameraId()));
    }
    tempListToCheck.emplace_back(GetCameraIdNumber(cameraIdNeedConfirm->GetDevice()->GetCameraId()));
    bool canOpenConcurrent = std::any_of(
        concurrentCameraTable_.begin(), concurrentCameraTable_.end(), [&](const std::vector<int32_t> &innerVec) {
            return std::all_of(tempListToCheck.begin(), tempListToCheck.end(), [&](int32_t element) {
                return std::find(innerVec.begin(), innerVec.end(), element) != innerVec.end();
            });
        });
    int32_t targetConcurrencyType = cameraIdNeedConfirm->GetDevice()->GetTargetConcurrencyType();
    MEDIA_DEBUG_LOG("CameraConcurrentSelector::ConcurrentWithRetainedDevicesOrNot canOpenConcurrent:%{public}d,"
        "targetType:%{public}d, confirmType:%{public}d, requestType: %{public}d",
        canOpenConcurrent, targetConcurrencyType, cameraIdNeedConfirm->GetDevice()->GetTargetConcurrencyType(),
        requestCameraHolder_->GetDevice()->GetTargetConcurrencyType());
    return canOpenConcurrent &&
           (targetConcurrencyType == cameraIdNeedConfirm->GetDevice()->GetTargetConcurrencyType() &&
            targetConcurrencyType == requestCameraHolder_->GetDevice()->GetTargetConcurrencyType());
}
} // namespace CameraStandard
} // namespace OHOS