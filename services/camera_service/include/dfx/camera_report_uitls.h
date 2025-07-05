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

#ifndef OHOS_CAMERA_REPORT_UITLS_H
#define OHOS_CAMERA_REPORT_UITLS_H

#include <map>
#include <mutex>
#include <string>
#include "hstream_repeat.h"

namespace OHOS {
namespace CameraStandard {
    constexpr const char* DFX_PHOTO_SETTING_QUALITY = "Quality";
    constexpr const char* DFX_PHOTO_SETTING_MIRROR = "Mirror";
    constexpr const char* DFX_PHOTO_SETTING_ROTATION = "Rotation";
enum DFX_UB_NAME {
    DFX_UB_NOT_REPORT = 0,
    DFX_UB_SET_ZOOMRATIO,
    DFX_UB_SET_SMOOTHZOOM,
    DFX_UB_SET_VIDEOSTABILIZATIONMODE,
    DFX_UB_SET_FILTER,
    DFX_UB_SET_PORTRAITEFFECT,
    DFX_UB_SET_BEAUTY_AUTOVALUE,
    DFX_UB_SET_BEAUTY_SKINSMOOTH,
    DFX_UB_SET_BEAUTY_FACESLENDER,
    DFX_UB_SET_BEAUTY_SKINTONE,
    DFX_UB_SET_FOCUSMODE,
    DFX_UB_SET_FOCUSPOINT,
    DFX_UB_SET_EXPOSUREMODE,
    DFX_UB_SET_EXPOSUREBIAS,
    DFX_UB_SET_METERINGPOINT,
    DFX_UB_SET_FLASHMODE,
    DFX_UB_SET_FRAMERATERANGE,
    DFX_UB_MUTE_CAMERA,
    DFX_UB_SET_QUALITY_PRIORITIZATION,
    DFX_UB_ADD_USB_CAMERA
};

struct CallerInfo {
    int32_t pid;
    int32_t uid;
    uint32_t tokenID;
    std::string bundleName;
};

struct DfxCaptureInfo {
    int32_t captureId;
    CallerInfo caller;
    uint64_t captureStartTime;
    uint64_t captureEndTime;
    bool isOfflinCapture = false;
    uint32_t offlineOutputCnt = 0;
};

class CameraReportUtils {
public:
    static CameraReportUtils &GetInstance()
    {
        static CameraReportUtils instance;
        return instance;
    }
    static CallerInfo GetCallerInfo();
    static void ReportCameraError(
        std::string funcName, int32_t errCode, bool isHdiErr, CallerInfo callerInfo);
    static void ReportCameraErrorForUsb(
            std::string funcName, int32_t errCode, bool isHdiErr, std::string connectionType, CallerInfo callerInfo);
    void ReportUserBehavior(DFX_UB_NAME behaviorName,
                                   std::string value,
                                   CallerInfo callerInfo);
    void ReportUserBehaviorAddDevice(std::string behaviorName, std::string value, CallerInfo callerInfo);

    void SetStreamInfo(const std::list<sptr<HStreamCommon>>& allStreams);
    void SetOpenCamPerfPreInfo(const std::string& cameraId, CallerInfo caller);
    void SetOpenCamPerfStartInfo(const std::string& cameraId, CallerInfo caller);
    void SetOpenCamPerfEndInfo();

    void SetModeChangePerfStartInfo(int32_t preMode, CallerInfo caller);
    void updateModeChangePerfInfo(int32_t curMode, CallerInfo caller);
    void SetModeChangePerfEndInfo();

    void SetCapturePerfStartInfo(DfxCaptureInfo captureInfo);
    void SetCapturePerfEndInfo(int32_t captureId, bool isOfflinCapture = false, int32_t offlineOutputCnt = 0);

    void SetSwitchCamPerfStartInfo(CallerInfo caller);
    void SetSwitchCamPerfEndInfo();

    void UpdateProfileInfo(const std::string& profileStr);
    void UpdateImagingInfo(const std::string& imagingKey, const std::string& value);
    void SetVideoStartInfo(DfxCaptureInfo captureInfo);
    void SetVideoEndInfo(int32_t captureId);

private:
    std::mutex mutex_;
    CallerInfo caller_;
    std::string preCameraId_;
    std::string cameraId_;
    int32_t preMode_;
    int32_t curMode_;

    std::string profile_;
    std::string streamInfo_{""};

    uint64_t openCamPerfStartTime_;
    uint64_t openCamPerfEndTime_;
    bool isPrelaunching_;
    bool isOpening_;

    uint64_t modeChangeStartTime_;
    uint64_t modeChangeEndTime_;
    bool isModeChanging_;

    uint64_t switchCamPerfStartTime_;
    uint64_t switchCamPerfEndTime_;
    bool isSwitching_;

    std::map<int32_t, DfxCaptureInfo> captureList_;
    std::unordered_map<std::string, std::string> imagingValueList_;

    bool IsCallerChanged(CallerInfo preCaller, CallerInfo curCaller);
    bool IsBehaviorNeedReport(DFX_UB_NAME behaviorName, const std::string& value);

    void ReportOpenCameraPerf(uint64_t costTime, const std::string& startType);
    void ReportModeChangePerf(uint64_t costTime);
    void ReportCapturePerf(DfxCaptureInfo captureInfo);
    void ReportSwitchCameraPerf(uint64_t costTime);
    void ReportImagingInfo(DfxCaptureInfo captureInfo);
    void ResetImagingValue();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_REPORT_UITLS_H
