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
#include "camera_report_uitls.h"

#include "camera_util.h"
#include "camera_log.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

void CameraReportUtils::SetOpenCamPerfPreInfo(const string& cameraId, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfPreInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (IsCallerChanged(caller_, caller)) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfPreInfo caller changed");
            isModeChanging_ = false;
        }
        openCamPerfStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isPrelaunching_ = true;
        cameraId_ = cameraId;
        caller_ = caller;
    }
}

void CameraReportUtils::SetOpenCamPerfStartInfo(const string& cameraId, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (IsCallerChanged(caller_, caller)) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfStartInfo caller changed");
            isModeChanging_ = false;
        }
        if (!isPrelaunching_) {
            openCamPerfStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
            isOpening_ = true;
            MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfStartInfo update start time");
        }
        preCameraId_ = cameraId_;
        cameraId_ = cameraId;
        caller_ = caller;
    }
}

void CameraReportUtils::SetOpenCamPerfEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isPrelaunching_ && !isOpening_) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfEndInfo not ready");
            return;
        }
        if (isSwitching_) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetOpenCamPerfEndInfo cancel report");
            isOpening_ = false;
            isPrelaunching_ = false;
            return;
        }
        openCamPerfEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        string startType = isPrelaunching_ ? "preLaunch" : "open";
        isOpening_ = false;
        isPrelaunching_ = false;
        ReportOpenCameraPerf(openCamPerfEndTime_ - openCamPerfStartTime_, startType);
    }
}

void CameraReportUtils::ReportOpenCameraPerf(uint64_t costTime, const string& startType)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::ReportOpenCameraPerf costTime: %{public}" PRIu64 "", costTime);
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_START",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "CALLER_PID", caller_.pid,
        "CALLER_UID", caller_.uid,
        "CALLER_TOKENID", caller_.tokenID,
        "CALLER_BUNDLE_NAME", caller_.bundleName,
        "COST_TIME", costTime,
        "CUR_CAMERA_ID", cameraId_,
        "START_TYPE", startType,
        "CUR_MODE", curMode_);
}

void CameraReportUtils::SetModeChangePerfStartInfo(int32_t preMode, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetModeChangePerfStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        modeChangeStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isModeChanging_ = true;
        preMode_ = preMode;
        caller_ = caller;
        ResetImagingValue();
    }
}

void CameraReportUtils::updateModeChangePerfInfo(int32_t curMode, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::updateModeChangePerfInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (IsCallerChanged(caller_, caller)) {
            MEDIA_DEBUG_LOG("updateModeChangePerfInfo caller changed, cancle mode change report");
            isModeChanging_ = false;
        }
        caller_ = caller;
        curMode_ = curMode;
    }
}

void CameraReportUtils::SetModeChangePerfEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetModeChangePerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isModeChanging_) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetModeChangePerfEndInfo cancel report");
            return;
        }
        if (curMode_ == preMode_ || isSwitching_) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetModeChangePerfEndInfo mode not changed");
            isModeChanging_ = false;
            return;
        }

        modeChangeEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isModeChanging_ = false;
        ReportModeChangePerf(modeChangeEndTime_ - modeChangeStartTime_);
    }
}

void CameraReportUtils::ReportModeChangePerf(uint64_t costTime)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::ReportModeChangePerf costTime:  %{public}" PRIu64 "", costTime);
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_MODE_CHANGE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "CALLER_PID", caller_.pid,
        "CALLER_UID", caller_.uid,
        "CALLER_TOKENID", caller_.tokenID,
        "CALLER_BUNDLE_NAME", caller_.bundleName,
        "COST_TIME", costTime,
        "PRE_MODE", preMode_,
        "CUR_MODE", curMode_,
        "PRE_CAMERA_ID", preCameraId_,
        "CUR_CAMERA_ID", cameraId_);
}

void CameraReportUtils::SetCapturePerfStartInfo(DfxCaptureInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetCapturePerfStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.captureStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, DfxCaptureInfo>(captureInfo.captureId, captureInfo));
}

void CameraReportUtils::SetCapturePerfEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetCapturePerfEndInfo start");
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, DfxCaptureInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetCapturePerfEndInfo");
            auto dfxCaptureInfo = iter->second;
            dfxCaptureInfo.captureEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            ReportCapturePerf(dfxCaptureInfo);
            ReportImagingInfo(dfxCaptureInfo);
            captureList_.erase(captureId);
        }
    }
}

void CameraReportUtils::ReportCapturePerf(DfxCaptureInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::ReportCapturePerf captureInfo");
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_CAPTURE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "CALLER_PID", captureInfo.caller.pid,
        "CALLER_UID", captureInfo.caller.uid,
        "CALLER_TOKENID", captureInfo.caller.tokenID,
        "CALLER_BUNDLE_NAME", captureInfo.caller.bundleName,
        "COST_TIME", captureInfo.captureEndTime - captureInfo.captureStartTime,
        "CAPTURE_ID", captureInfo.captureId,
        "CUR_MODE", curMode_,
        "CUR_CAMERA_ID", cameraId_);
}

void CameraReportUtils::SetSwitchCamPerfStartInfo(CallerInfo caller)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetSwitchCamPerfStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        switchCamPerfStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isSwitching_ = true;
        caller_ = caller;
    }
}

void CameraReportUtils::SetSwitchCamPerfEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetSwitchCamPerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isSwitching_) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetSwitchCamPerfEndInfo cancel report");
            return;
        }

        switchCamPerfEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isSwitching_ = false;
        ReportSwitchCameraPerf(switchCamPerfEndTime_ - switchCamPerfStartTime_);
    }
}

void CameraReportUtils::ReportSwitchCameraPerf(uint64_t costTime)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::ReportSwitchCameraPerf costTime:  %{public}" PRIu64 "", costTime);
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_SWITCH_CAMERA",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "CALLER_PID", caller_.pid,
        "CALLER_UID", caller_.uid,
        "CALLER_TOKENID", caller_.tokenID,
        "CALLER_BUNDLE_NAME", caller_.bundleName,
        "COST_TIME", costTime,
        "PRE_MODE", preMode_,
        "CUR_MODE", curMode_,
        "PRE_CAMERA_ID", preCameraId_,
        "CUR_CAMERA_ID", cameraId_);
}

CallerInfo CameraReportUtils::GetCallerInfo()
{
    CallerInfo callerInfo;
    callerInfo.pid = IPCSkeleton::GetCallingPid();
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.tokenID = IPCSkeleton::GetCallingTokenID();
    callerInfo.bundleName = GetClientBundle(callerInfo.uid);
    MEDIA_DEBUG_LOG("CameraReportUtils::GetCallerInfo pid:%{public}d uid:%{public}d tokenID:%{public}d",
        callerInfo.pid, callerInfo.uid, callerInfo.tokenID);
    return callerInfo;
}

bool CameraReportUtils::IsCallerChanged(CallerInfo preCaller, CallerInfo curCaller)
{
    if (preCaller.pid != curCaller.pid ||
        preCaller.uid != curCaller.uid ||
        preCaller.tokenID != curCaller.tokenID
    ) {
        return true;
    }
    return false;
}

void CameraReportUtils::ReportCameraError(string funcName,
                                          int32_t errCode,
                                          bool isHdiErr,
                                          CallerInfo callerInfo)
{
    string str = funcName;
    if (isHdiErr) {
        str += " faild, hdi errCode:" + to_string(errCode);
    } else {
        str += " faild, errCode:" + to_string(errCode);
    }
    str += " caller pid:" + to_string(callerInfo.pid)
        + " uid:" + to_string(callerInfo.uid)
        + " tokenID:" + to_string(callerInfo.tokenID)
        + " bundleName:" + callerInfo.bundleName;
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}

void CameraReportUtils::ReportUserBehavior(string behaviorName,
                                           string value,
                                           CallerInfo callerInfo)
{
    unique_lock<mutex> lock(mutex_);
    {
        if (!IsBehaviorNeedReport(behaviorName, value)) {
            MEDIA_DEBUG_LOG("CameraReportUtils::ReportUserBehavior cancle");
            return;
        }
        MEDIA_DEBUG_LOG("CameraReportUtils::ReportUserBehavior");
        stringstream ss;
        ss << S_BEHAVIORNAME << behaviorName
        << S_VALUE << value
        << S_CUR_MODE << curMode_
        << S_CUR_CAMERAID << cameraId_
        << S_CPID << callerInfo.pid
        << S_CUID << callerInfo.uid
        << S_CTOKENID << callerInfo.tokenID
        << S_CBUNDLENAME << callerInfo.bundleName;
        
        HiSysEventWrite(
            HiviewDFX::HiSysEvent::Domain::CAMERA,
            "USER_BEHAVIOR",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "MSG", ss.str());
    }
}

void CameraReportUtils::ReportImagingInfo(DfxCaptureInfo dfxCaptureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::ReportImagingInfo");
    stringstream ss;
    ss << "CurMode:" << curMode_ << ",CameraId:" << cameraId_ << ",Profile:" << profile_;
    for (auto it = imagingValueList_.begin(); it != imagingValueList_.end(); it++) {
        ss << "," << it->first << ":" << it->second;
    }

    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "IMAGING_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "MSG", ss.str());
}

void CameraReportUtils::UpdateProfileInfo(const string& profileStr)
{
    profile_ = profileStr;
}

void CameraReportUtils::UpdateImagingInfo(const string& imagingKey, const string& value)
{
    auto it = imagingValueList_.find(imagingKey);
    if (it != imagingValueList_.end()) {
        it->second = value;
    } else {
        imagingValueList_.emplace(imagingKey, value);
    }
}

bool CameraReportUtils::IsBehaviorNeedReport(const string& behaviorName, const string& value)
{
    auto it = mapBehaviorImagingKey.find(behaviorName);
    if (it == mapBehaviorImagingKey.end()) {
        MEDIA_ERR_LOG("IsBehaviorNeedReport error imagingKey not found.");
        return true;
    }
    const string& imagingKey = it->second;
    auto valueIt = imagingValueList_.find(imagingKey);
    if (valueIt != imagingValueList_.end()) {
        if (valueIt->second == value) {
            return false;
        } else {
            valueIt->second = value;
            return true;
        }
    } else {
        imagingValueList_.emplace(imagingKey, value);
        return true;
    }
}

void CameraReportUtils::ResetImagingValue()
{
    imagingValueList_.clear();
}

void CameraReportUtils::SetVideoStartInfo(DfxCaptureInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetVideoStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.captureStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, DfxCaptureInfo>(captureInfo.captureId, captureInfo));
}

void CameraReportUtils::SetVideoEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportUtils::SetVideoEndInfo start");
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, DfxCaptureInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportUtils::SetVideoEndInfo");
            auto dfxCaptureInfo = iter->second;
            dfxCaptureInfo.captureEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            imagingValueList_.emplace("VideoDuration",
                to_string(dfxCaptureInfo.captureEndTime - dfxCaptureInfo.captureStartTime));
            ReportImagingInfo(dfxCaptureInfo);
            captureList_.erase(captureId);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS
