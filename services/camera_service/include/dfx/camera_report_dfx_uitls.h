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
 
#ifndef OHOS_CAMERA_REPORT_DFX_UITLS_H
#define OHOS_CAMERA_REPORT_DFX_UITLS_H
 
#include <map>
#include <safe_map.h>
#include <unordered_set>
#include <mutex>
#include <refbase.h>
 
namespace OHOS {
namespace CameraStandard {
static const uint64_t REPORT_TIME_INTERVAL = 24 * 60 * 60 * 1000L; // 24 hour in milliseconds
static const uint64_t WAIT_CALLBACK_TIME_INTERVAL = 2 * 1000L;

enum ClientState {
    ALIVE = 0,
    DIED
};

enum CaptureState {
    CAPTURE_FWK = 0,
    HAL_ERROR,
    HAL_ON_ERROR,
    PHOTO_AVAILABLE,
    MEDIALIBRARY_ERROR,
    CAPTURE_START
};

struct CaptureDfxInfo {
    int32_t captureId;
    int32_t pid;
    std::string bundleName;
    std::string pictureId;
    bool isSystemApp;
    uint64_t firstBufferStartTime;
    uint64_t firstBufferEndTime;
    uint64_t prepareProxyStartTime;
    uint64_t prepareProxyEndTime;
    uint64_t addProxyStartTime;
    uint64_t addProxyEndTime;
};

struct CaptureStateCount {
    int32_t captureFwk = 0;
    int32_t halError = 0;
    int32_t callback = 0;
    int32_t appNoSave = 0;
    int32_t mediaLibraryError = 0;
    int32_t captureStart = 0;
};

class CameraReportDfxUtils : public RefBase {
public:
    static sptr<CameraReportDfxUtils> &GetInstance();

    void SetPictureId(int32_t captureId, std::string pictureId);
 
    void SetFirstBufferStartInfo(CaptureDfxInfo captureInfo);
    void SetFirstBufferEndInfo(int32_t captureId);
 
    void SetPrepareProxyStartInfo(int32_t captureId);
    void SetPrepareProxyEndInfo(int32_t captureId);
 
    void SetAddProxyStartInfo(int32_t captureId);
    void SetAddProxyEndInfo(int32_t captureId);

    void SetCaptureState(const CaptureState state, const int32_t captureId);
    void UpdateAliveClient(const pid_t pid, const ClientState state);

private:
    std::mutex mutex_;

    static sptr<CameraReportDfxUtils> cameraReportDfx_;
    static std::mutex instanceMutex_;

    std::map<int32_t, CaptureDfxInfo> captureList_;
    SafeMap<std::string, CaptureStateCount> reportCaptureStateMap_;
    SafeMap<std::string, CaptureStateCount> reportCaptureStateTempMap_;
    std::unordered_set<pid_t> aliveClientSet_;
    uint64_t lastCaptureStateReportTime_ = 0;
    uint64_t lastSatisfiedTime_ = 0;
    int32_t waitForCallbackStartId_ = 0;
    int32_t waitForCallbackEndId_ = 0;
    int32_t lastReportCallbackId_ = 0;
    bool isReporting_ = false;
 
    void ReportPerformanceDeferredPhoto(CaptureDfxInfo captureInfo);
    void ReportCaptureState();
    std::string GetBundleName(const int32_t captureId);
    bool IsCaptureStateNeedReport();
    bool SatisfiedReportCondition(CaptureState state, int32_t captureId);
    bool IsClientDied(const int32_t captureId);
    bool IsMatchedCallback(CaptureState state, int32_t captureId);
    void InsertIntoMap(SafeMap<std::string, CaptureStateCount> &map, CaptureState state, int32_t captureId);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_REPORT_DFX_UITLS_H