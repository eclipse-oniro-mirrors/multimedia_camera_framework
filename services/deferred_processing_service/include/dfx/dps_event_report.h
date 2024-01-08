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

#ifndef OHOS_CAMERA_DPS_DEFERRED_EVENT_REPORT_H
#define OHOS_CAMERA_DPS_DEFERRED_EVENT_REPORT_H

#include <cstdint>
#include <string>
#include <string>
#include <schedule/photo_processor/photo_job_repository/deferred_photo_job.h>
#include "deferred_processing_service_ipc_interface_code.h"
#include <shared_mutex>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string EVENT_KEY_IMAGEID = "IMAGEID";
const std::string EVENT_KEY_USERID = "USERID";
const std::string EVENT_KEY_DEFEVENTTYPE = "DEFEVENTTYPE";
const std::string EVENT_KEY_DISCARDABLE = "DISCARDABLE";
const std::string EVENT_KEY_TRIGGERMODE = "TRIGGERMODE";
const std::string EVENT_KEY_HIGHJOBNUM = "HIGHJOBNUM";
const std::string EVENT_KEY_NORMALJOBNUM = "NORMALJOBNUM";
const std::string EVENT_KEY_LOWJOBNUM = "LOWJOBNUM";
const std::string EVENT_KEY_TEMPERATURELEVEL = "TEMPERATURELEVEL";
const std::string EVENT_KEY_SYNCHRONIZETIME = "SYNCHRONIZETIME";
const std::string EVENT_KEY_DISPATCHTIME = "DISPATCHTIME";
const std::string EVENT_KEY_PROCESSTIME = "PROCESSTIME";
const std::string EVENT_KEY_IMAGEDONETIME = "IMAGEDONETIME";
const std::string EVENT_KEY_RESTORETIME = "RESTORETIME";
const std::string EVENT_KEY_REMOVETIME = "CANCELTIME";
const std::string EVENT_KEY_TRAILINGTIME = "TRAILINGTIME";
const std::string EVENT_KEY_PHOTOJOBTYPE = "PHOTOJOBTYPE";
const std::string EVENT_KEY_EXCUTIONMODE = "EXCUTIONMODE";
const std::string EVENT_KEY_CHANGEREASON = "CHANGEREASON";
const std::string EVENT_KEY_EXCEPTIONSOURCE = "EXCEPTIONSOURCE";
const std::string EVENT_KEY_EXCEPTIONCAUSE = "EXCEPTIONCAUSE";

struct DPSEventInfo {
    std::string imageId;
    int32_t userId;
    TrigerMode triggerMode;
    uint32_t operatorStage;
    bool discardable;
    uint64_t synchronizeTimeBeginTime;
    uint64_t synchronizeTimeEndTime;
    uint64_t dispatchTimeBeginTime;
    uint64_t dispatchTimeEndTime;
    uint64_t processTimeBeginTime;
    uint64_t processTimeEndTime;
    uint64_t imageDoneTimeBeginTime;
    uint64_t imageDoneTimeEndTime;
    uint64_t restoreTimeBeginTime;
    uint64_t restoreTimeEndTime;
    uint64_t removeTimeBeginTime;
    uint64_t removeTimeEndTime;
    uint64_t trailingTimeBeginTime;
    uint64_t trailingTimeEndTime;
    int highJobNum;
    int normalJobNum;
    int lowJobNum;
    int temperatureLevel;
    ExecutionMode executionMode;
    PhotoJobType photoJobType;
    EventType changeReason;
    ExceptionSource exceptionSource;
    ExceptionCause exceptionCause;
};

class DPSEventReport {
public:
    static DPSEventReport &GetInstance()
    {
        static DPSEventReport instance;
        return instance;
    }
    void ReportOperateImage(const std::string& imageId, int32_t userId, DPSEventInfo& dpsEventInfo);
    void ReportImageProcessResult(const std::string& imageId, int32_t userId, DPSEventInfo& dpsEventInfo);
    void ReportImageModeChange(ExecutionMode executionMode);
    void ReportImageException(const std::string& imageId, int32_t userId);
    void SetEventInfo(const std::string& imageId, int32_t userId);
    void SetEventInfo(DPSEventInfo& dpsEventInfo);
    void RemoveEventInfo(const std::string& imageId, int32_t userId);
    void UpdateEventInfo(const std::string& imageId, int32_t userId, const std::string& keyName, std::any value);
    void UpdateJobNum(const std::string& imageId, int32_t userId, int lowJobNum,
        int normalJobNum, int highJobNum);
    void UpdateJobProperty(const std::string& imageId, int32_t userId, bool discardable,
        PhotoJobType photoJobType, TrigerMode triggermode);

    void SetTemperatureLevel(int temperatureLevel);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetEventType(EventType eventType_);

private:
    DPSEventInfo GetEventInfo(const std::string& imageId, int32_t userId);
    static void UpdateOperatorStage(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateDiscardable(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateTriggerMode(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateHighJobNum(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateNormalJobNum(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateLowJobNum(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateTemperatureLevel(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateSynchronizeTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateDispatchTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateProcessTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateImageDoneTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateRestoreTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateRemoveTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateTrailingTime(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdatePhotoJobType(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateExcutionMode(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateChangeReason(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateExceptionSource(DPSEventInfo& dpsEventInfo, std::any value);
    static void UpdateExceptionCause(DPSEventInfo& dpsEventInfo, std::any value);
    std::unordered_map<std::string,
    void (*)(DPSEventInfo& dpsEventInfo, std::any value)> sysEventFuncMap_ = {
        {EVENT_KEY_DEFEVENTTYPE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateOperatorStage(dpsEventInfo, value);
        }},
        {EVENT_KEY_DISCARDABLE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateDiscardable(dpsEventInfo, value);
        }},
        {EVENT_KEY_TRIGGERMODE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateTriggerMode(dpsEventInfo, value);
        }},
        {EVENT_KEY_NORMALJOBNUM, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateNormalJobNum(dpsEventInfo, value);
        }},
        {EVENT_KEY_LOWJOBNUM, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateLowJobNum(dpsEventInfo, value);
        }},
        {EVENT_KEY_TEMPERATURELEVEL, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateTemperatureLevel(dpsEventInfo, value);
        }},
        {EVENT_KEY_SYNCHRONIZETIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateSynchronizeTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_DISPATCHTIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateDispatchTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_PROCESSTIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateProcessTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_IMAGEDONETIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateImageDoneTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_RESTORETIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateRestoreTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_REMOVETIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateRemoveTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_TRAILINGTIME, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateTrailingTime(dpsEventInfo, value);
        }},
        {EVENT_KEY_PHOTOJOBTYPE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdatePhotoJobType(dpsEventInfo, value);
        }},
        {EVENT_KEY_EXCUTIONMODE,  [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateExcutionMode(dpsEventInfo, value);
        }},
        {EVENT_KEY_CHANGEREASON, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateChangeReason(dpsEventInfo, value);
        }},
        {EVENT_KEY_EXCEPTIONSOURCE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateExceptionSource(dpsEventInfo, value);
        }},
        {EVENT_KEY_EXCEPTIONCAUSE, [](DPSEventInfo& dpsEventInfo, std::any value) {
            UpdateExceptionCause(dpsEventInfo, value);
        }},
    };
    std::mutex mutex_;
    std::map<int32_t, std::map<std::string, DPSEventInfo>> userIdToImageIdEventInfo; //userid--imageid--eventinfo
    ExecutionMode executionMode_;
    int temperatureLevel_;
    EventType eventType_;
};
} // namespace DeferredProcessingService
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PROCESSING_SERVICE_H