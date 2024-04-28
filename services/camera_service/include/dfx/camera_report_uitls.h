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
static const std::string S_BEHAVIORNAME = "behaviorName:";
static const std::string S_VALUE = ",value:";
static const std::string S_CUR_MODE = ",curMode:";
static const std::string S_CUR_CAMERAID = ",curCameraId:";
static const std::string S_CPID = ",cPid:";
static const std::string S_CUID = ",cUid:";
static const std::string S_CTOKENID = ",cTokenID:";
static const std::string S_CBUNDLENAME = ",cBundleName:";

static const std::string DFX_PROFILE = "Profile";
static const std::string DFX_PHOTO_SETTING_QUALITY = "Quality";
static const std::string DFX_PHOTO_SETTING_MIRROR = "Mirror";
static const std::string DFX_PHOTO_SETTING_ROTATION = "Rotation";

static const std::string DFX_ZOOMRATIO = "ZoomRatio";
static const std::string DFX_VIDEOSTABILIZATIONMODE = "VideoStabilizationMode";
static const std::string DFX_FILTERTYPE = "FilterType";
static const std::string DFX_PORTRAITEFFECT = "PortraitEffect";
static const std::string DFX_BEAUTY_AUTOVALUE = "BeautyValue";
static const std::string DFX_BEAUTY_SKINSMOOTH = "SkinSmooth";
static const std::string DFX_BEAUTY_FACESLENDER = "FaceSlender";
static const std::string DFX_BEAUTY_SKINTONE = "SkinTone";
static const std::string DFX_FOCUSMODE = "FocusMode";
static const std::string DFX_FOCUSPOINT = "FocusPoint";
static const std::string DFX_EXPOSUREMODE = "ExposureMode";
static const std::string DFX_EXPOSUREBIAS = "ExposureBias";
static const std::string DFX_METERINGPOINT = "MeteringPoint";
static const std::string DFX_FLASHMODE = "FlashMode";
static const std::string DFX_FRAMERATERANGE = "FrameRateRange";
static const std::string DFX_MUTE_CAMERA = "MuteCamera";

static const std::string DFX_UB_SET_ZOOMRATIO = "SetZoomRatio";
static const std::string DFX_UB_SET_SMOOTHZOOM = "SetSmoothZoom";
static const std::string DFX_UB_SET_VIDEOSTABILIZATIONMODE = "SetVideoStabilizationMode";
static const std::string DFX_UB_SET_FILTER = "SetFilter";
static const std::string DFX_UB_SET_PORTRAITEFFECT = "SetPortraitEffect";
static const std::string DFX_UB_SET_BEAUTY_AUTOVALUE = "SetBeautyaAutoValue";
static const std::string DFX_UB_SET_BEAUTY_SKINSMOOTH = "SetBeautySkinSmooth";
static const std::string DFX_UB_SET_BEAUTY_FACESLENDER = "SetBeautyFaceSlender";
static const std::string DFX_UB_SET_BEAUTY_SKINTONE = "SetBeautySkinTone";
static const std::string DFX_UB_SET_FOCUSMODE = "SetFocusMode";
static const std::string DFX_UB_SET_FOCUSPOINT = "SetFocusPoint";
static const std::string DFX_UB_SET_EXPOSUREMODE = "SetExposureMode";
static const std::string DFX_UB_SET_EXPOSUREBIAS = "SetExposureBias";
static const std::string DFX_UB_SET_METERINGPOINT = "SetMeteringPoint";
static const std::string DFX_UB_SET_FLASHMODE = "setFlashMode";
static const std::string DFX_UB_SET_FRAMERATERANGE = "SetFrameRateRange";
static const std::string DFX_UB_MUTE_CAMERA = "MuteCamera";

static const std::unordered_map<std::string, std::string> mapBehaviorImagingKey = {
    {DFX_UB_SET_ZOOMRATIO, DFX_ZOOMRATIO},
    {DFX_UB_SET_SMOOTHZOOM, DFX_ZOOMRATIO},
    {DFX_UB_SET_VIDEOSTABILIZATIONMODE, DFX_VIDEOSTABILIZATIONMODE},
    {DFX_UB_SET_FILTER, DFX_FILTERTYPE},
    {DFX_UB_SET_PORTRAITEFFECT, DFX_PORTRAITEFFECT},
    {DFX_UB_SET_BEAUTY_AUTOVALUE, DFX_BEAUTY_AUTOVALUE},
    {DFX_UB_SET_BEAUTY_SKINSMOOTH, DFX_BEAUTY_SKINSMOOTH},
    {DFX_UB_SET_BEAUTY_FACESLENDER, DFX_BEAUTY_FACESLENDER},
    {DFX_UB_SET_BEAUTY_SKINTONE, DFX_BEAUTY_SKINTONE},
    {DFX_UB_SET_FOCUSMODE, DFX_FOCUSMODE},
    {DFX_UB_SET_FOCUSPOINT, DFX_FOCUSPOINT},
    {DFX_UB_SET_EXPOSUREMODE, DFX_EXPOSUREMODE},
    {DFX_UB_SET_EXPOSUREBIAS, DFX_EXPOSUREBIAS},
    {DFX_UB_SET_METERINGPOINT, DFX_METERINGPOINT},
    {DFX_UB_SET_FLASHMODE, DFX_FLASHMODE},
    {DFX_UB_SET_FRAMERATERANGE, DFX_FRAMERATERANGE},
    {DFX_UB_MUTE_CAMERA, DFX_MUTE_CAMERA}
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
    void ReportUserBehavior(std::string behaviorName,
                                   std::string value,
                                   CallerInfo callerInfo);

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
    bool IsBehaviorNeedReport(const std::string& behaviorName, const std::string& value);

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
