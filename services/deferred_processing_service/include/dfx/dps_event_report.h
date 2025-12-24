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

#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
inline constexpr char EVENT_KEY_IMAGEID[] = "IMAGEID";
inline constexpr char EVENT_KEY_USERID[] = "USERID";
inline constexpr char EVENT_KEY_DEFEVENTTYPE[] = "DEFEVENTTYPE";
inline constexpr char EVENT_KEY_DISCARDABLE[] = "DISCARDABLE";
inline constexpr char EVENT_KEY_TRIGGERMODE[] = "TRIGGERMODE";
inline constexpr char EVENT_KEY_HIGHJOBNUM[] = "HIGHJOBNUM";
inline constexpr char EVENT_KEY_NORMALJOBNUM[] = "NORMALJOBNUM";
inline constexpr char EVENT_KEY_LOWJOBNUM[] = "LOWJOBNUM";
inline constexpr char EVENT_KEY_TEMPERATURELEVEL[] = "TEMPERATURELEVEL";
inline constexpr char EVENT_KEY_SYNCHRONIZETIME[] = "SYNCHRONIZETIME";
inline constexpr char EVENT_KEY_DISPATCHTIME[] = "DISPATCHTIME";
inline constexpr char EVENT_KEY_PROCESSTIME[] = "PROCESSTIME";
inline constexpr char EVENT_KEY_IMAGEDONETIME[] = "IMAGEDONETIME";
inline constexpr char EVENT_KEY_RESTORETIME[] = "RESTORETIME";
inline constexpr char EVENT_KEY_REMOVETIME[] = "CANCELTIME";
inline constexpr char EVENT_KEY_TRAILINGTIME[] = "TRAILINGTIME";
inline constexpr char EVENT_KEY_PHOTOJOBTYPE[] = "PHOTOJOBTYPE";
inline constexpr char EVENT_KEY_EXCUTIONMODE[] = "EXCUTIONMODE";
inline constexpr char EVENT_KEY_CHANGEREASON[] = "CHANGEREASON";
inline constexpr char EVENT_KEY_EXCEPTIONSOURCE[] = "EXCEPTIONSOURCE";
inline constexpr char EVENT_KEY_EXCEPTIONCAUSE[] = "EXCEPTIONCAUSE";
inline constexpr char EVENT_KEY_EXECUTIONMODE[] = "EXECUTIONMODE";
inline constexpr char EVENT_KEY_COMPONENT_NAME[] = "COMPONENT_NAME";
inline constexpr char EVENT_KEY_PARTITION_NAME[] = "PARTITION_NAME";
inline constexpr char EVENT_KEY_REMAIN_PARTITION_SIZE[] = "REMAIN_PARTITION_SIZE";
inline constexpr char EVENT_KEY_FILE_OR_FOLDER_PATH[] = "FILE_OR_FOLDER_PATH";
inline constexpr char EVENT_KEY_FILE_OR_FOLDER_SIZE[] = "FILE_OR_FOLDER_SIZE";
inline constexpr char EVENT_KEY_MEMORY_SIZE[] = "AVAILABLEMEMORYSIZE";
inline constexpr char COMPONENT_NAME[] = "camera_framework";
inline constexpr char PARTITION_NAME[] = "/data";
inline constexpr char EVENT_KEY_CAPTUREFLAG[] = "CAPTUREFLAG";

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
    int32_t highJobNum;
    int32_t normalJobNum;
    int32_t lowJobNum;
    int temperatureLevel;
    PhotoJobType photoJobType;
    EventType changeReason;
    ExceptionSource exceptionSource;
    ExceptionCause exceptionCause;
    ExecutionMode executionMode = ExecutionMode::DUMMY;
};

class DPSEventReport {
public:
    static DPSEventReport &GetInstance()
    {
        static DPSEventReport instance;
        return instance;
    }
    void ReportOperateImage(const std::string& imageId, int32_t userId, DPSEventInfo& dpsEventInfo);
    void ReportImageProcessResult(const std::string& imageId, int32_t userId, uint64_t endTime = 0);
    void ReportImageModeChange(ExecutionMode executionMode, int32_t memorySize);
    void ReportImageException(const std::string& imageId, int32_t userId);
    void ReportPartitionUsage();
    void SetEventInfo(const std::string& imageId, int32_t userId);
    void SetEventInfo(DPSEventInfo& dpsEventInfo);
    void RemoveEventInfo(const std::string& imageId, int32_t userId);

    void SetTemperatureLevel(int temperatureLevel);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetEventType(EventType eventType_);
    void UpdateEventInfo(DPSEventInfo& dpsEventInfo);
    void UpdateProcessDoneTime(const std::string& imageId, int32_t userId);
    void UpdateRemoveTime(const std::string& imageId, int32_t userId);
    void UpdateExecutionMode(const std::string& imageId, int32_t userId, ExecutionMode executionMode);
    void ReportImageProcessCaptureFlag(uint32_t captureFlag);

private:
    DPSEventInfo GetEventInfo(const std::string& imageId, int32_t userId);
    void UpdateSynchronizeTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateDispatchTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateProcessTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateImageDoneTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateRestoreTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateRemoveTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateTrailingTime(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    void UpdateExecutionMode(DPSEventInfo& dpsEventInfo, DPSEventInfo& dpsEventInfoSrc);
    int GetTotalTime (uint64_t beginTime, uint64_t endTime);
    bool GetDeviceValidSize(const std::string& path, double& size);
    uint64_t GetFolderSize(const std::string& path);
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