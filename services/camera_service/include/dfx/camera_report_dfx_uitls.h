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
#include <refbase.h>
 
namespace OHOS {
namespace CameraStandard {

struct CaptureDfxInfo {
    int32_t captureId;
    bool isSystemApp;
    uint64_t firstBufferStartTime;
    uint64_t firstBufferEndTime;
    uint64_t prepareProxyStartTime;
    uint64_t prepareProxyEndTime;
    uint64_t addProxyStartTime;
    uint64_t addProxyEndTime;
};

class CameraReportDfxUtils : public RefBase {
public:
    static sptr<CameraReportDfxUtils> &GetInstance();
 
    void SetFirstBufferStartInfo(CaptureDfxInfo captureInfo);
    void SetFirstBufferEndInfo(int32_t captureId);
 
    void SetPrepareProxyStartInfo(int32_t captureId);
    void SetPrepareProxyEndInfo(int32_t captureId);
 
    void SetAddProxyStartInfo(int32_t captureId);
    void SetAddProxyEndInfo(int32_t captureId);
    
private:
    std::mutex mutex_;

    static sptr<CameraReportDfxUtils> cameraReportDfx_;
    static std::mutex instanceMutex_;

    std::map<int32_t, CaptureDfxInfo> captureList_;
 
    void ReportPerformanceDeferredPhoto(CaptureDfxInfo captureInfo);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_REPORT_DFX_UITLS_H