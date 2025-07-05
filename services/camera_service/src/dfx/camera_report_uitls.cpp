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
#include "bms_adapter.h"
#include "camera_report_uitls.h"

#include "camera_log.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "base/timer/steady_clock.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

constexpr const char* DFX_BEHAVIOR_MAP[] = {
    "ZoomRatio",                // DFX_UB_SET_ZOOMRATIO
    "ZoomRatio",                // DFX_UB_SET_SMOOTHZOOM
    "VideoStabilizationMode",   // DFX_UB_SET_VIDEOSTABILIZATIONMODE
    "FilterType",               // DFX_UB_SET_FILTER
    "PortraitEffect",           // DFX_UB_SET_PORTRAITEFFECT
    "BeautyValue",              // DFX_UB_SET_BEAUTY_AUTOVALUE
    "SkinSmooth",               // DFX_UB_SET_BEAUTY_SKINSMOOTH
    "FaceSlender",              // DFX_UB_SET_BEAUTY_FACESLENDER
    "SkinTone",                 // DFX_UB_SET_BEAUTY_SKINTONE
    "FocusMode",                // DFX_UB_SET_FOCUSMODE
    "FocusPoint",               // DFX_UB_SET_FOCUSPOINT
    "ExposureMode",             // DFX_UB_SET_EXPOSUREMODE
    "ExposureBias",             // DFX_UB_SET_EXPOSUREBIAS
    "MeteringPoint",            // DFX_UB_SET_METERINGPOINT
    "FlashMode",                // DFX_UB_SET_FLASHMODE
    "FrameRateRange",           // DFX_UB_SET_FRAMERATERANGE
    "MuteCamera",               // DFX_UB_MUTE_CAMERA
    "SetQualityPrioritization"  // DFX_UB_SET_QUALITY_PRIORITIZATION
};

const char* GetBehaviorImagingKey(DFX_UB_NAME behavior)
{
    if (behavior < 0 || behavior >= sizeof(DFX_BEHAVIOR_MAP) / sizeof(DFX_BEHAVIOR_MAP[0])) {
        return nullptr;
    }
    return DFX_BEHAVIOR_MAP[behavior];
};

void CameraReportUtils::SetOpenCamPerfPreInfo(const string& cameraId, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("SetOpenCamPerfPreInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (IsCallerChanged(caller_, caller)) {
            MEDIA_DEBUG_LOG("SetOpenCamPerfPreInfo caller changed");
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
    MEDIA_DEBUG_LOG("SetOpenCamPerfStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (IsCallerChanged(caller_, caller)) {
            MEDIA_DEBUG_LOG("SetOpenCamPerfStartInfo caller changed");
            isModeChanging_ = false;
        }
        if (!isPrelaunching_) {
            openCamPerfStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
            isOpening_ = true;
            MEDIA_DEBUG_LOG("SetOpenCamPerfStartInfo update start time");
        }
        preCameraId_ = cameraId_;
        cameraId_ = cameraId;
        caller_ = caller;
    }
}

void CameraReportUtils::SetStreamInfo(const std::list<sptr<HStreamCommon>>& allStreams)
{
    unique_lock<mutex> lock(mutex_);
    stringstream ss;
    bool isFirst = true;
    for (auto& curStream : allStreams) {
        CHECK_EXECUTE(!isFirst, ss << ",");
        isFirst = false;
        if (curStream->GetStreamType() == StreamType::REPEAT) {
            ss << "\'RepeatStreamType:" <<
                static_cast<int32_t>(CastStream<HStreamRepeat>(curStream)->GetRepeatStreamType()) <<
                ",format:" << curStream->format_ << ",width:" << curStream->width_ << ",height:" <<
                curStream->height_ << "\'";
        } else if (curStream->GetStreamType() == StreamType::METADATA) {
            ss << "\'MetadataStream, format:" << curStream->format_ << ",width:" << curStream->width_ <<
                ",height:" << curStream->height_ << "\'";
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            ss << "\'CaptureStream, format:" << curStream->format_ << ",width:" << curStream->width_ <<
                ",height:" << curStream->height_ << "\'";
        } else if (curStream->GetStreamType() == StreamType::DEPTH) {
            ss << "\'DepthStream, format:" << curStream->format_ << ",width:" << curStream->width_ <<
                ",height:" << curStream->height_ << "\'";
        }
    }
    streamInfo_ = ss.str();
}

void CameraReportUtils::SetOpenCamPerfEndInfo()
{
    MEDIA_DEBUG_LOG("SetOpenCamPerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isPrelaunching_ && !isOpening_) {
            MEDIA_DEBUG_LOG("SetOpenCamPerfEndInfo not ready");
            return;
        }
        if (isSwitching_) {
            MEDIA_DEBUG_LOG("SetOpenCamPerfEndInfo cancel report");
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
    MEDIA_DEBUG_LOG("ReportOpenCameraPerf costTime: %{public}" PRIu64 "", costTime);
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
        "CUR_MODE", curMode_,
        "MSG", streamInfo_);
}

void CameraReportUtils::SetModeChangePerfStartInfo(int32_t preMode, CallerInfo caller)
{
    MEDIA_DEBUG_LOG("SetModeChangePerfStartInfo");
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
    MEDIA_DEBUG_LOG("updateModeChangePerfInfo");
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
    MEDIA_DEBUG_LOG("SetModeChangePerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isModeChanging_) {
            MEDIA_DEBUG_LOG("SetModeChangePerfEndInfo cancel report");
            return;
        }
        if (curMode_ == preMode_ || isSwitching_) {
            MEDIA_DEBUG_LOG("SetModeChangePerfEndInfo mode not changed");
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
    MEDIA_DEBUG_LOG("ReportModeChangePerf costTime:  %{public}" PRIu64 "", costTime);
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
    MEDIA_DEBUG_LOG("SetCapturePerfStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.captureStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, DfxCaptureInfo>(captureInfo.captureId, captureInfo));
}

void CameraReportUtils::SetCapturePerfEndInfo(int32_t captureId, bool isOfflinCapture, int32_t offlineOutputCnt)
{
    MEDIA_DEBUG_LOG("SetCapturePerfEndInfo start");
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, DfxCaptureInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("SetCapturePerfEndInfo");
            auto dfxCaptureInfo = iter->second;
            dfxCaptureInfo.captureEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            dfxCaptureInfo.isOfflinCapture = isOfflinCapture;
            dfxCaptureInfo.offlineOutputCnt = static_cast<uint32_t>(offlineOutputCnt);
            ReportCapturePerf(dfxCaptureInfo);
            ReportImagingInfo(dfxCaptureInfo);
            captureList_.erase(captureId);
        }
    }
}

void CameraReportUtils::ReportCapturePerf(DfxCaptureInfo captureInfo)
{
    MEDIA_DEBUG_LOG("ReportCapturePerf captureInfo");
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
        "CUR_CAMERA_ID", cameraId_,
        "IS_OFFLINE_CAPTURE", captureInfo.isOfflinCapture,
        "CUR_OFFLINE_COUNT", captureInfo.offlineOutputCnt);
}

void CameraReportUtils::SetSwitchCamPerfStartInfo(CallerInfo caller)
{
    MEDIA_DEBUG_LOG("SetSwitchCamPerfStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        switchCamPerfStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isSwitching_ = true;
        caller_ = caller;
    }
}

void CameraReportUtils::SetSwitchCamPerfEndInfo()
{
    MEDIA_DEBUG_LOG("SetSwitchCamPerfEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        if (!isSwitching_) {
            MEDIA_DEBUG_LOG("SetSwitchCamPerfEndInfo cancel report");
            return;
        }

        switchCamPerfEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isSwitching_ = false;
        ReportSwitchCameraPerf(switchCamPerfEndTime_ - switchCamPerfStartTime_);
    }
}

void CameraReportUtils::ReportSwitchCameraPerf(uint64_t costTime)
{
    MEDIA_DEBUG_LOG("ReportSwitchCameraPerf costTime:  %{public}" PRIu64 "", costTime);
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
    callerInfo.bundleName = BmsAdapter::GetInstance()->GetBundleName(callerInfo.uid);
    MEDIA_DEBUG_LOG("GetCallerInfo pid:%{public}d uid:%{public}d", callerInfo.pid, callerInfo.uid);
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

void CameraReportUtils::ReportUserBehavior(DFX_UB_NAME behaviorName,
                                           string value,
                                           CallerInfo callerInfo)
{
    unique_lock<mutex> lock(mutex_);
    {
        if (!IsBehaviorNeedReport(behaviorName, value)) {
            MEDIA_DEBUG_LOG("ReportUserBehavior cancle");
            return;
        }
        MEDIA_DEBUG_LOG("ReportUserBehavior");
        const char* behaviorString = GetBehaviorImagingKey(behaviorName);
        if (behaviorString == nullptr) {
            MEDIA_ERR_LOG("ReportUserBehavior error imagingKey not found.");
            return;
        }
        std::string str = "behaviorName:" + std::string(behaviorString)
            + ",value:" + value
            + ",curMode:" + to_string(curMode_)
            + ",curCameraId:" + cameraId_
            + ",cPid:" + to_string(callerInfo.pid)
            + ",cUid:" + to_string(callerInfo.uid)
            + ",cTokenID:" + to_string(callerInfo.tokenID)
            + ",cBundleName:" + callerInfo.bundleName;
        
        HiSysEventWrite(
            HiviewDFX::HiSysEvent::Domain::CAMERA,
            "USER_BEHAVIOR",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "MSG", str);
    }
}

void CameraReportUtils::ReportImagingInfo(DfxCaptureInfo dfxCaptureInfo)
{
    MEDIA_DEBUG_LOG("ReportImagingInfo");
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

bool CameraReportUtils::IsBehaviorNeedReport(DFX_UB_NAME behaviorName, const string& value)
{
    const char* imagingKey = GetBehaviorImagingKey(behaviorName);
    if (imagingKey == nullptr) {
        MEDIA_ERR_LOG("IsBehaviorNeedReport error imagingKey not found.");
        return true;
    }
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
    MEDIA_DEBUG_LOG("SetVideoStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.captureStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, DfxCaptureInfo>(captureInfo.captureId, captureInfo));
}

void CameraReportUtils::SetVideoEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoEndInfo start");
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, DfxCaptureInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("SetVideoEndInfo");
            auto dfxCaptureInfo = iter->second;
            dfxCaptureInfo.captureEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            imagingValueList_.emplace("VideoDuration",
                to_string(dfxCaptureInfo.captureEndTime - dfxCaptureInfo.captureStartTime));
            ReportImagingInfo(dfxCaptureInfo);
            captureList_.erase(captureId);
        }
    }
}

void CameraReportUtils::ReportUserBehaviorAddDevice(string behaviorName, string value, CallerInfo callerInfo)
{
    unique_lock<mutex> lock(mutex_);
    {
        MEDIA_DEBUG_LOG("CameraReportUtils::ReportUserBehaviorAddDevice");
        stringstream ss;
        ss << "BEHAVIORNAME" << behaviorName
        << ",MODE" << curMode_
        << ",CAMERAID" << value
        << ",PID" << callerInfo.pid
        << ",UID" << callerInfo.uid
        << ",TOKENID" << callerInfo.tokenID
        << ",BUNDLENAME" << callerInfo.bundleName;

        HiSysEventWrite(
            HiviewDFX::HiSysEvent::Domain::CAMERA,
            "USER_BEHAVIOR",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "MSG", ss.str());
    }
}

void CameraReportUtils::ReportCameraErrorForUsb(string funcName,
                                                int32_t errCode,
                                                bool isHdiErr,
                                                string connectionType,
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
        + " connectionType:" + connectionType;
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
} // namespace CameraStandard
} // namespace OHOS
