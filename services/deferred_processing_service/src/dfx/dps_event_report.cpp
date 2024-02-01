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

#include "dps_event_report.h"
#include "hisysevent.h"
#include "dp_log.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
static constexpr char CAMERA_FWK_UE[] = "CAMERA_FWK_UE";
void DPSEventReport::ReportOperateImage(const std::string& imageId, int32_t userId, DPSEventInfo& dpsEventInfo)
{
    DP_DEBUG_LOG("ReportOperateImage enter.");
    UpdateEventInfo(dpsEventInfo);
    HiSysEventWrite(
        CAMERA_FWK_UE,
        "DPS_IMAGE_OPERATE",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_IMAGEID, imageId,
        EVENT_KEY_USERID, userId,
        EVENT_KEY_DEFEVENTTYPE, dpsEventInfo.operatorStage,
        EVENT_KEY_DISCARDABLE, dpsEventInfo.discardable,
        EVENT_KEY_TRIGGERMODE, dpsEventInfo.triggerMode,
        EVENT_KEY_HIGHJOBNUM, dpsEventInfo.highJobNum,
        EVENT_KEY_NORMALJOBNUM, dpsEventInfo.normalJobNum,
        EVENT_KEY_LOWJOBNUM, dpsEventInfo.lowJobNum,
        EVENT_KEY_TEMPERATURELEVEL, temperatureLevel_);
}

void DPSEventReport::ReportImageProcessResult(const std::string& imageId, int32_t userId, uint64_t endTime)
{
    DP_DEBUG_LOG("ReportImageProcessResult enter.");
    DPSEventInfo dpsEventInfo = GetEventInfo(imageId, userId);
    if (endTime > 0) {
        dpsEventInfo.imageDoneTimeEndTime = endTime;
    }
    HiSysEventWrite(
        CAMERA_FWK_UE,
        "DPS_IMAGE_PROCESS_RESULT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_IMAGEID, dpsEventInfo.imageId,
        EVENT_KEY_USERID, dpsEventInfo.userId,
        EVENT_KEY_SYNCHRONIZETIME, GetTotalTime(dpsEventInfo.synchronizeTimeBeginTime,
            dpsEventInfo.synchronizeTimeEndTime),
        EVENT_KEY_DISPATCHTIME, GetTotalTime(dpsEventInfo.dispatchTimeBeginTime, dpsEventInfo.dispatchTimeEndTime),
        EVENT_KEY_PROCESSTIME, GetTotalTime(dpsEventInfo.processTimeBeginTime, dpsEventInfo.processTimeEndTime),
        EVENT_KEY_IMAGEDONETIME, GetTotalTime(dpsEventInfo.imageDoneTimeBeginTime, dpsEventInfo.imageDoneTimeEndTime),
        EVENT_KEY_RESTORETIME, GetTotalTime(dpsEventInfo.restoreTimeBeginTime, dpsEventInfo.restoreTimeEndTime),
        EVENT_KEY_REMOVETIME, GetTotalTime(dpsEventInfo.removeTimeBeginTime, dpsEventInfo.removeTimeEndTime),
        EVENT_KEY_TRAILINGTIME, GetTotalTime(dpsEventInfo.trailingTimeBeginTime, dpsEventInfo.trailingTimeEndTime),
        EVENT_KEY_PHOTOJOBTYPE, static_cast<int32_t>(dpsEventInfo.photoJobType),
        EVENT_KEY_HIGHJOBNUM, dpsEventInfo.highJobNum,
        EVENT_KEY_NORMALJOBNUM, dpsEventInfo.normalJobNum,
        EVENT_KEY_LOWJOBNUM, dpsEventInfo.lowJobNum,
        EVENT_KEY_TEMPERATURELEVEL, temperatureLevel_);
    RemoveEventInfo(imageId, userId);
}

int DPSEventReport::GetTotalTime (uint64_t beginTime, uint64_t endTime)
{
    if (beginTime < endTime) {
        return endTime - beginTime;
    }
    return 0;
}

void DPSEventReport::ReportImageModeChange(ExecutionMode executionMode)
{
    DP_INFO_LOG("ReportImageModeChange enter.");
    HiSysEventWrite(
        CAMERA_FWK_UE,
        "DPS_IMAGE_MODE_CHANGE",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_EXCUTIONMODE, static_cast<int32_t>(executionMode),
        EVENT_KEY_CHANGEREASON, static_cast<int32_t>(eventType_),
        EVENT_KEY_TEMPERATURELEVEL, temperatureLevel_);
}

void DPSEventReport::ReportImageException(const std::string& imageId, int32_t userId)
{
    DPSEventInfo dpsEventInfo = GetEventInfo(imageId, userId);
    HiSysEventWrite(
        CAMERA_FWK_UE,
        "DPS_IMAGE_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_IMAGEID, dpsEventInfo.imageId,
        EVENT_KEY_USERID, dpsEventInfo.userId,
        EVENT_KEY_EXCEPTIONSOURCE, static_cast<int32_t>(dpsEventInfo.exceptionSource),
        EVENT_KEY_EXCEPTIONCAUSE, static_cast<int32_t>(dpsEventInfo.exceptionCause),
        EVENT_KEY_TEMPERATURELEVEL, temperatureLevel_);
}

void DPSEventReport::SetEventInfo(const std::string& imageId, int32_t userId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.imageId = imageId;
    dpsEventInfo.userId = userId;
    dpsEventInfo.triggerMode = TrigerMode::TRIGER_ACTIVE;
    dpsEventInfo.operatorStage = static_cast<uint32_t>(DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
    dpsEventInfo.synchronizeTimeBeginTime = 0;
    dpsEventInfo.synchronizeTimeEndTime = 0;
    dpsEventInfo.dispatchTimeBeginTime = 0;
    dpsEventInfo.dispatchTimeEndTime = 0;
    dpsEventInfo.processTimeBeginTime = 0;
    dpsEventInfo.processTimeEndTime = 0;
    dpsEventInfo.imageDoneTimeBeginTime = 0;
    dpsEventInfo.imageDoneTimeEndTime = 0;
    dpsEventInfo.restoreTimeBeginTime = 0;
    dpsEventInfo.restoreTimeEndTime = 0;
    dpsEventInfo.removeTimeBeginTime = 0;
    dpsEventInfo.removeTimeEndTime = 0;
    dpsEventInfo.trailingTimeBeginTime = 0;
    dpsEventInfo.trailingTimeEndTime = 0;
    dpsEventInfo.highJobNum = 0;
    dpsEventInfo.normalJobNum = 0;
    dpsEventInfo.lowJobNum = 0;
    dpsEventInfo.temperatureLevel = 0;
    dpsEventInfo.executionMode = ExecutionMode::DUMMY;
    dpsEventInfo.photoJobType = PhotoJobType::BACKGROUND;
    dpsEventInfo.changeReason = EventType::USER_INITIATED_EVENT;
    dpsEventInfo.exceptionSource = ExceptionSource::HDI_EXCEPTION;
    dpsEventInfo.exceptionCause = ExceptionCause::HDI_TIMEOUT;

    auto imageIdToEventInfoTemp = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfoTemp != userIdToImageIdEventInfo.end()) {
        (imageIdToEventInfoTemp->second)[imageId] = dpsEventInfo;
    } else {
        std::map<std::string, DPSEventInfo> imageIdToEventInfo;
        imageIdToEventInfo[imageId] = dpsEventInfo;
        userIdToImageIdEventInfo[userId] = imageIdToEventInfo;
    }
}

void DPSEventReport::SetEventInfo(DPSEventInfo& dpsEventInfo)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto imageIdToEventInfoTemp = userIdToImageIdEventInfo.find(dpsEventInfo.userId);
    if (imageIdToEventInfoTemp != userIdToImageIdEventInfo.end()) {
        (imageIdToEventInfoTemp->second)[dpsEventInfo.imageId] = dpsEventInfo;
    } else {
        std::map<std::string, DPSEventInfo> imageIdToEventInfo;
        imageIdToEventInfo[dpsEventInfo.imageId] = dpsEventInfo;
        userIdToImageIdEventInfo[dpsEventInfo.userId] = imageIdToEventInfo;
    }
}

void DPSEventReport::UpdateEventInfo(DPSEventInfo& dpsEventInfo)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto imageIdToEventInfoTemp = userIdToImageIdEventInfo.find(dpsEventInfo.userId);
    if (imageIdToEventInfoTemp == userIdToImageIdEventInfo.end()) {
        std::map<std::string, DPSEventInfo> imageIdToEventInfo;
        imageIdToEventInfo[dpsEventInfo.imageId] = dpsEventInfo;
        userIdToImageIdEventInfo[dpsEventInfo.userId] = imageIdToEventInfo;
        return;
    }
    DPSEventInfo dpsEventInfoTemp = (imageIdToEventInfoTemp->second)[dpsEventInfo.imageId];
    UpdateDispatchTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateProcessTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateRestoreTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateImageDoneTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateRemoveTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateTrailingTime(dpsEventInfo, dpsEventInfoTemp);
    UpdateSynchronizeTime(dpsEventInfo, dpsEventInfoTemp);

    (imageIdToEventInfoTemp->second)[dpsEventInfo.imageId] = dpsEventInfo;
}

void DPSEventReport::SetTemperatureLevel(int temperatureLevel)
{
    temperatureLevel_ = temperatureLevel;
}

void DPSEventReport::SetExecutionMode(ExecutionMode executionMode)
{
    executionMode_ = executionMode;
}

void DPSEventReport::SetEventType(EventType eventType)
{
    eventType_ = eventType;
}

DPSEventInfo DPSEventReport::GetEventInfo(const std::string& imageId, int32_t userId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    DPSEventInfo dpsEventInfo;
    auto imageIdToEventInfo = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfo != userIdToImageIdEventInfo.end()) {
        std::map<std::string, DPSEventInfo>::iterator iter = (userIdToImageIdEventInfo[userId]).begin();
        while (iter != (userIdToImageIdEventInfo[userId]).end()) {
            auto eventInfo = iter->second;
            if (eventInfo.imageId == imageId) {
                return eventInfo;
            }
            ++iter;
        }
    }
    return dpsEventInfo;
}

void DPSEventReport::RemoveEventInfo(const std::string& imageId, int32_t userId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    DPSEventInfo dpsEventInfo;
    auto imageIdToEventInfo = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfo != userIdToImageIdEventInfo.end()) {
        std::map<std::string, DPSEventInfo>::iterator iter = (userIdToImageIdEventInfo[userId]).begin();
        while (iter != (userIdToImageIdEventInfo[userId]).end()) {
            if ((iter->second).imageId == imageId) {
                (imageIdToEventInfo->second).erase(imageId);
                return;
            }
            ++iter;
        }
    }
    return;
}

void DPSEventReport::UpdateProcessDoneTime(const std::string& imageId, int32_t userId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto imageIdToEventInfoTemp = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfoTemp != userIdToImageIdEventInfo.end()) {
        uint64_t currentTime = SteadyClock::GetTimestampMilli();
        (imageIdToEventInfoTemp->second)[imageId].imageDoneTimeBeginTime = currentTime;
        (imageIdToEventInfoTemp->second)[imageId].processTimeEndTime = currentTime;
    }
}

void DPSEventReport::UpdateSynchronizeTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.synchronizeTimeEndTime > 0) {
        dpsEventInfo.synchronizeTimeEndTime = dpsEventInfoSrc.synchronizeTimeEndTime;
    }
    if (dpsEventInfoSrc.synchronizeTimeBeginTime > 0) {
        dpsEventInfo.synchronizeTimeBeginTime = dpsEventInfoSrc.synchronizeTimeBeginTime;
    }
}

void DPSEventReport::UpdateDispatchTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.dispatchTimeBeginTime > 0) {
        dpsEventInfo.dispatchTimeBeginTime = dpsEventInfoSrc.dispatchTimeBeginTime;
    }
    if (dpsEventInfoSrc.dispatchTimeEndTime > 0) {
        dpsEventInfo.dispatchTimeEndTime = dpsEventInfoSrc.dispatchTimeEndTime;
    }
}

void DPSEventReport::UpdateProcessTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.processTimeBeginTime > 0) {
        dpsEventInfo.processTimeBeginTime = dpsEventInfoSrc.processTimeBeginTime;
    }
    if (dpsEventInfoSrc.processTimeEndTime > 0) {
        dpsEventInfo.processTimeEndTime = dpsEventInfoSrc.processTimeEndTime;
    }
}

void DPSEventReport::UpdateImageDoneTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.imageDoneTimeBeginTime > 0) {
        dpsEventInfo.imageDoneTimeBeginTime = dpsEventInfoSrc.imageDoneTimeBeginTime;
    }
    if (dpsEventInfoSrc.imageDoneTimeEndTime > 0) {
        dpsEventInfo.imageDoneTimeEndTime = dpsEventInfoSrc.imageDoneTimeEndTime;
    }
}

void DPSEventReport::UpdateRestoreTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.restoreTimeBeginTime > 0) {
        dpsEventInfo.restoreTimeBeginTime = dpsEventInfoSrc.restoreTimeBeginTime;
    }
    if (dpsEventInfoSrc.restoreTimeEndTime > 0) {
        dpsEventInfo.restoreTimeEndTime = dpsEventInfoSrc.restoreTimeEndTime;
    }
}

void DPSEventReport::UpdateRemoveTime(const std::string& imageId, int32_t userId)
{
    auto imageIdToEventInfoTemp = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfoTemp != userIdToImageIdEventInfo.end()) {
        uint64_t currentTime = SteadyClock::GetTimestampMilli();
        (imageIdToEventInfoTemp->second)[imageId].removeTimeEndTime = currentTime;
        ReportImageProcessResult(imageId, userId);
    }
}

void DPSEventReport::UpdateRemoveTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.removeTimeBeginTime > 0) {
        dpsEventInfo.removeTimeBeginTime = dpsEventInfoSrc.removeTimeBeginTime;
    }
    if (dpsEventInfoSrc.removeTimeEndTime > 0) {
        dpsEventInfo.removeTimeEndTime = dpsEventInfoSrc.removeTimeEndTime;
    }
}

void DPSEventReport::UpdateTrailingTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc)
{
    if (dpsEventInfoSrc.trailingTimeBeginTime > 0) {
        dpsEventInfo.trailingTimeBeginTime = dpsEventInfoSrc.trailingTimeBeginTime;
    }
    if (dpsEventInfoSrc.trailingTimeEndTime > 0) {
        dpsEventInfo.trailingTimeEndTime = dpsEventInfoSrc.trailingTimeEndTime;
    }
}
} // namsespace DeferredProcessingService
} // namespace CameraStandard
} // namespace OHOS