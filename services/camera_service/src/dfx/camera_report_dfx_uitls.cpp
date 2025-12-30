/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#include <mutex>
#include <cinttypes>
#include <unordered_map>
#include "camera_report_dfx_uitls.h"
 
#include "camera_util.h"
#include "camera_log.h"
#include "bms_adapter.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "steady_clock.h"
 
namespace OHOS {
namespace CameraStandard {
using namespace std;
static const std::string SYSTEM_CAMERA_BUNDLE_NAME = "com.huawei.hmos.camera";
sptr<CameraReportDfxUtils> CameraReportDfxUtils::cameraReportDfx_;
std::mutex CameraReportDfxUtils::instanceMutex_;

sptr<CameraReportDfxUtils> &CameraReportDfxUtils::GetInstance()
{
    if (CameraReportDfxUtils::cameraReportDfx_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (CameraReportDfxUtils::cameraReportDfx_ == nullptr) {
            MEDIA_INFO_LOG("Initializing camera report dfx instance");
            CameraReportDfxUtils::cameraReportDfx_ = new CameraReportDfxUtils();
        }
    }
    return CameraReportDfxUtils::cameraReportDfx_;
}

void CameraReportDfxUtils::SetPictureId(int32_t captureId, std::string pictureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPictureId set pictureId: %{public}s for captureID: %{public}d",
                    pictureId.c_str(), captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            auto& captureInfo = iter->second;
            captureInfo.pictureId = pictureId;
        }
    }
}
 
void CameraReportDfxUtils::SetFirstBufferStartInfo(CaptureDfxInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.firstBufferStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, CaptureDfxInfo>(captureInfo.captureId, captureInfo));
}
 
void CameraReportDfxUtils::SetFirstBufferEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.firstBufferEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyStartInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyStartInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyStartInfo");
            auto& captureInfo = iter->second;
            captureInfo.prepareProxyStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.prepareProxyEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetAddProxyStartInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyStartInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyStartInfo");
            auto& captureInfo = iter->second;
            captureInfo.addProxyStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetAddProxyEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.addProxyEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            ReportPerformanceDeferredPhoto(captureInfo);
            captureList_.erase(captureId);
        }
    }
}
 
void CameraReportDfxUtils::ReportPerformanceDeferredPhoto(CaptureDfxInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::ReportPerformanceDeferredPhoto start");
    if (captureInfo.firstBufferEndTime < captureInfo.firstBufferStartTime ||
        captureInfo.prepareProxyEndTime < captureInfo.prepareProxyStartTime ||
        captureInfo.addProxyEndTime < captureInfo.addProxyStartTime) {
        MEDIA_ERR_LOG("CameraReportDfxUtils::ReportPerformanceDeferredPhoto overflow detected");
        return;
    }
    uint64_t firstBufferCostTime = captureInfo.firstBufferEndTime - captureInfo.firstBufferStartTime;
    uint64_t prepareProxyCostTime = captureInfo.prepareProxyEndTime - captureInfo.prepareProxyStartTime;
    uint64_t addProxyCostTime = captureInfo.addProxyEndTime - captureInfo.addProxyStartTime;
 
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_DEFERRED_PHOTO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "MSG", captureInfo.isSystemApp ? "System Camera" : "Non-system camera",
        "BUNDLE_NAME", captureInfo.bundleName,
        "CAPTURE_ID", captureInfo.captureId,
        "PICTURE_ID", captureInfo.pictureId,
        "FIRST_BUFFER_COST_TIME", firstBufferCostTime,
        "PREPARE_PROXY_COST_TIME", prepareProxyCostTime,
        "ADD_PROXY_COSTTIME", addProxyCostTime);
}

void CameraReportDfxUtils::UpdateAliveClient(const pid_t pid, const ClientState state)
{
    unique_lock<mutex> lock(mutex_);
    if (state == ClientState::DIED && aliveClientSet_.find(pid) != aliveClientSet_.end()) {
        aliveClientSet_.erase(pid);
    } else if (state == ClientState::ALIVE) {
        aliveClientSet_.insert(pid);
    }
}

bool CameraReportDfxUtils::IsClientDied(const int32_t captureId)
{
    map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
    if (iter != captureList_.end()) {
        pid_t pid = (iter->second).pid;
        return aliveClientSet_.find(pid) == aliveClientSet_.end();
    }
    return false;
}

std::string CameraReportDfxUtils::GetBundleName(const int32_t captureId)
{
    std::string bundleName = BmsAdapter::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
    CHECK_RETURN_RET(captureId == 0, bundleName);
    map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
    if (iter != captureList_.end()) {
        return (iter->second).bundleName;
    }
    return bundleName;
}

bool CameraReportDfxUtils::IsCaptureStateNeedReport()
{
    if (isReporting_) {
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::IsCaptureStateNeedReport is reporting.");
        return false;
    }

    uint64_t currentTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
    if ((currentTime_ - lastCaptureStateReportTime_) < REPORT_TIME_INTERVAL) {
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::IsCaptureStateNeedReport time interval is not satisfied.");
        return false;
    }

    isReporting_ = true;
    lastSatisfiedTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
    return true;
}

bool CameraReportDfxUtils::SatisfiedReportCondition(CaptureState state, int32_t captureId)
{
    if (state != CaptureState::PHOTO_AVAILABLE) {
        return false;
    }
    if (!isReporting_) {
        return false;
    }
    uint64_t currentTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
    if (currentTime_ - lastSatisfiedTime_ >= WAIT_CALLBACK_TIME_INTERVAL) {
        return true;
    }
    return captureId == waitForCallbackEndId_;
}

bool CameraReportDfxUtils::IsMatchedCallback(CaptureState state, int32_t captureId)
{
    if (state != CaptureState::PHOTO_AVAILABLE) {
        return false;
    }
    bool ret = false;
    ret = ((waitForCallbackEndId_ < waitForCallbackStartId_) ?
        captureId > waitForCallbackStartId_ || captureId <= waitForCallbackEndId_ :
        captureId > waitForCallbackStartId_ && captureId <= waitForCallbackEndId_);
    return ret;
}

void CameraReportDfxUtils::ReportCaptureState()
{
    vector<std::string> bundleNames = {};
    vector<int32_t> captureFwks;
    vector<int32_t> halErrors;
    vector<int32_t> captureFwkErrors;
    vector<int32_t> appNoSaves;
    vector<int32_t> mediaLibraryErrors;

    reportCaptureStateMap_.Iterate([&bundleNames, &captureFwks, &halErrors, &captureFwkErrors, &appNoSaves,
        &mediaLibraryErrors](std::string key, CaptureStateCount &val) {
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::ReportCaptureState report: bundleName[%{public}s], "
            "captureFwk[%{public}d], halError[%{public}d], appNoSave[%{public}d], mediaLibraryError[%{public}d], "
            "callback[%{public}d], captureStart[%{public}d]", key.c_str(), val.captureFwk, val.halError,
            val.appNoSave, val.mediaLibraryError, val.callback, val.captureStart);
        bundleNames.push_back(key);
        captureFwks.push_back(val.captureFwk);
        // 下发拍照指令阶段 error + （回调 onerror && 不回调）
        halErrors.push_back(val.halError + abs(val.captureStart - val.callback));
        captureFwkErrors.push_back(abs(val.captureFwk - val.captureStart));
        appNoSaves.push_back(val.appNoSave);
        mediaLibraryErrors.push_back(val.mediaLibraryError);
    });

    if (!reportCaptureStateMap_.IsEmpty()) {
        HiSysEventWrite(
            HiviewDFX::HiSysEvent::Domain::CAMERA,
            "REPORT_CAMERA_CLIENT_STATISTICS",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "BUNDLE_NAME", bundleNames,
            "CAPTURE_FWK", captureFwks,
            "HAL_ERROR", halErrors,
            "CAMERA_FWK_ERROR", captureFwkErrors,
            "APP_NO_SAVE", appNoSaves,
            "MEDIALIBRARY_ERROR", mediaLibraryErrors);
    }

    reportCaptureStateMap_.Clear();
    reportCaptureStateMap_ = reportCaptureStateTempMap_;
    reportCaptureStateTempMap_.Clear();

    waitForCallbackStartId_ = 0;
    waitForCallbackEndId_ = 0;
    lastCaptureStateReportTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
    isReporting_ = false;
}

void CameraReportDfxUtils::InsertIntoMap(SafeMap<std::string, CaptureStateCount> &map,
    CaptureState state, int32_t captureId)
{
    std::string bundleName = GetBundleName(captureId);
    // 暂时只打点系统相机
    CHECK_RETURN(bundleName.empty() || bundleName != SYSTEM_CAMERA_BUNDLE_NAME);
    CaptureStateCount captureStateCount{
        .captureFwk = 0,
        .halError = 0,
        .callback = 0,
        .appNoSave = 0,
        .mediaLibraryError = 0,
        .captureStart = 0
    };
    map.Find(bundleName, captureStateCount);
    switch (state) {
        case CaptureState::CAPTURE_FWK:
            captureStateCount.captureFwk++;
            break;
        case CaptureState::HAL_ERROR:
            captureStateCount.halError++;
            break;
        case CaptureState::CAPTURE_START:
            captureStateCount.captureStart++;
            break;
        case CaptureState::HAL_ON_ERROR:
            captureStateCount.halError++;
            captureStateCount.callback++;
            lastReportCallbackId_ = captureId;
            break;
        case CaptureState::PHOTO_AVAILABLE:
            captureStateCount.callback++;
            lastReportCallbackId_ = captureId;
            if (IsClientDied(captureId)) {
                captureStateCount.appNoSave++;
            }
            break;
        case CaptureState::MEDIALIBRARY_ERROR:
            captureStateCount.mediaLibraryError++;
            break;
        default:
            MEDIA_ERR_LOG("CameraReportDfxUtils::InsertIntoMap unknown capture state!");
            return;
    }
    map.EnsureInsert(bundleName, captureStateCount);
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::InsertIntoMap bundleName[%{public}s], captureFwk[%{public}d], "
        "halError[%{public}d], appNoSave[%{public}d], mediaLibraryError[%{public}d], callback[%{public}d], "
        "captureStart[%{public}d]", bundleName.c_str(), captureStateCount.captureFwk, captureStateCount.halError,
        captureStateCount.appNoSave, captureStateCount.mediaLibraryError, captureStateCount.callback,
        captureStateCount.captureStart);
}

void CameraReportDfxUtils::SetCaptureState(const CaptureState state, const int32_t captureId)
{
    unique_lock<mutex> lock(mutex_);
    bool shouldUseTempMap = isReporting_ && !IsMatchedCallback(state, captureId);
    if (shouldUseTempMap) {
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetCaptureState insert into temp map: "
            "state[%{public}d], captureId[%{public}d]", state, captureId);
        InsertIntoMap(reportCaptureStateTempMap_, state, captureId);
    } else {
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetCaptureState insert into normal map: "
            "state[%{public}d], captureId[%{public}d]", state, captureId);
        InsertIntoMap(reportCaptureStateMap_, state, captureId);
    }

    if (SatisfiedReportCondition(state, captureId)) {
        ReportCaptureState();
    }

    if (state == CaptureState::CAPTURE_START && IsCaptureStateNeedReport()) {
        waitForCallbackEndId_ = captureId;
        waitForCallbackStartId_ = lastReportCallbackId_;
        MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetCaptureState wait for Id from %{public}d to %{public}d",
            waitForCallbackStartId_, waitForCallbackEndId_);
    }
}
} // namespace CameraStandard
} // namespace OHOS