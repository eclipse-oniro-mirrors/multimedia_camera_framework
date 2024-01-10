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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
static constexpr char CAMERA_FWK_UE[] = "CAMERA_FWK_UE";
void DPSEventReport::ReportOperateImage(const std::string& imageId, int32_t userId, DPSEventInfo& dpsEventInfo)
{
    DP_DEBUG_LOG("ReportOperateImage enter.");
    SetEventInfo(dpsEventInfo);
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
    if (endTime != 0) {
        dpsEventInfo.imageDoneTimeEndTime = endTime;
    }
    HiSysEventWrite(
        CAMERA_FWK_UE,
        "DPS_IMAGE_PROCESS_RESULT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_IMAGEID, dpsEventInfo.imageId,
        EVENT_KEY_USERID, dpsEventInfo.userId,
        EVENT_KEY_SYNCHRONIZETIME, (dpsEventInfo.synchronizeTimeEndTime - dpsEventInfo.synchronizeTimeBeginTime),
        EVENT_KEY_DISPATCHTIME, (dpsEventInfo.dispatchTimeEndTime - dpsEventInfo.dispatchTimeBeginTime),
        EVENT_KEY_PROCESSTIME, (dpsEventInfo.processTimeEndTime - dpsEventInfo.processTimeBeginTime),
        EVENT_KEY_IMAGEDONETIME, (dpsEventInfo.imageDoneTimeEndTime - dpsEventInfo.imageDoneTimeBeginTime),
        EVENT_KEY_RESTORETIME, (dpsEventInfo.restoreTimeEndTime - dpsEventInfo.restoreTimeBeginTime),
        EVENT_KEY_REMOVETIME, (dpsEventInfo.removeTimeEndTime - dpsEventInfo.removeTimeBeginTime),
        EVENT_KEY_TRAILINGTIME, (dpsEventInfo.trailingTimeEndTime - dpsEventInfo.trailingTimeBeginTime),
        EVENT_KEY_PHOTOJOBTYPE, static_cast<int32_t>(dpsEventInfo.photoJobType),
        EVENT_KEY_HIGHJOBNUM, dpsEventInfo.highJobNum,
        EVENT_KEY_NORMALJOBNUM, dpsEventInfo.normalJobNum,
        EVENT_KEY_LOWJOBNUM, dpsEventInfo.lowJobNum,
        EVENT_KEY_TEMPERATURELEVEL, temperatureLevel_);
    RemoveEventInfo(imageId, userId);
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

void DPSEventReport::UpdateJobProperty(const std::string& imageId, int32_t userId, bool discardable,
    PhotoJobType photoJobType, TrigerMode triggermode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto imageIdToEventInfo = userIdToImageIdEventInfo.find(userId);
    if (imageIdToEventInfo != userIdToImageIdEventInfo.end()) {
        std::map<std::string, DPSEventInfo>::iterator iter = (userIdToImageIdEventInfo[userId]).begin();
        while (iter != (userIdToImageIdEventInfo[userId]).end()) {
            if ((iter->second).imageId == imageId) {
                UpdateDiscardable(iter->second, discardable);
                UpdatePhotoJobType(iter->second, discardable);
                UpdateTriggerMode(iter->second, discardable);
                break;
            }
            iter++;
        }
    }
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
            iter++;
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
            iter++;
        }
    }
    return;
}

void DPSEventReport::UpdateOperatorStage(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.operatorStage = std::any_cast<DeferredProcessingServiceInterfaceCode>(value);
}

void DPSEventReport::UpdateDiscardable(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.discardable = std::any_cast<bool>(value);
}

void DPSEventReport::UpdateTriggerMode(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.triggerMode = std::any_cast<TrigerMode>(value);
}

void DPSEventReport::UpdateHighJobNum(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.highJobNum = std::any_cast<int>(value);
}

void DPSEventReport::UpdateNormalJobNum(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.normalJobNum = std::any_cast<int>(value);
}

void DPSEventReport::UpdateLowJobNum(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.lowJobNum = std::any_cast<int>(value);
}

void DPSEventReport::UpdateTemperatureLevel(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.temperatureLevel = std::any_cast<int>(value);
}

void DPSEventReport::UpdateSynchronizeTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.synchronizeTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateDispatchTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.dispatchTimeEndTime  = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateProcessTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.processTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateImageDoneTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.imageDoneTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateRestoreTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.restoreTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateRemoveTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.removeTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdateTrailingTime(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.trailingTimeEndTime = std::any_cast<int64_t>(value);
}

void DPSEventReport::UpdatePhotoJobType(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.photoJobType = std::any_cast<PhotoJobType>(value);
}

void DPSEventReport::UpdateExcutionMode(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.executionMode = std::any_cast<ExecutionMode>(value);
}

void DPSEventReport::UpdateChangeReason(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.changeReason = std::any_cast<EventType>(value);
}

void DPSEventReport::UpdateExceptionSource(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.exceptionSource = std::any_cast<ExceptionSource>(value);
}

void DPSEventReport::UpdateExceptionCause(DPSEventInfo& dpsEventInfo, std::any value)
{
    dpsEventInfo.exceptionCause = std::any_cast<ExceptionCause>(value);
}
} // namsespace DeferredProcessingService
} // namespace CameraStandard
} // namespace OHOS