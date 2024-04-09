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

namespace OHOS {
namespace CameraStandard {

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
    
    void SetOpenCamPerfPreInfo(const std::string& cameraId, CallerInfo caller);
    void SetOpenCamPerfStartInfo(const std::string& cameraId, CallerInfo caller);
    void SetOpenCamPerfEndInfo();

    void SetModeChangePerfStartInfo(int32_t preMode, CallerInfo caller);
    void updateModeChangePerfInfo(int32_t curMode, CallerInfo caller);
    void SetModeChangePerfEndInfo();

    void SetCapturePerfStartInfo(DfxCaptureInfo captureInfo);
    void SetCapturePerfEndInfo(int32_t captureId);

    void SetSwitchCamPerfStartInfo(CallerInfo caller);
    void SetSwitchCamPerfEndInfo();

private:
    std::mutex mutex_;
    CallerInfo caller_;
    std::string preCameraId_;
    std::string cameraId_;
    int32_t preMode_;
    int32_t curMode_;

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

    bool IsCallerChanged(CallerInfo preCaller, CallerInfo curCaller);
    void ReportOpenCameraPerf(uint64_t costTime, const std::string& startType);
    void ReportModeChangePerf(uint64_t costTime);
    void ReportCapturePerf(DfxCaptureInfo captureInfo);
    void ReportSwitchCameraPerf(uint64_t costTime);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_REPORT_UITLS_H
