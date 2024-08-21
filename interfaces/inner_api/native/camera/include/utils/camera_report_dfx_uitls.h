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
namespace CameraStandard : public RefBase {
class CameraReportDfxUtils {
public:
    static sptr<CameraReportDfxUtils> &GetInstance();
 
    void SetFirstBufferStartInfo();
    void SetFirstBufferEndInfo();
 
    void SetPrepareProxyStartInfo();
    void SetPrepareProxyEndInfo();
 
    void SetAddProxyStartInfo();
    void SetAddProxyEndInfo();
    
private:
    std::mutex mutex_;
 
    uint64_t setFirstBufferStartTime_;
    uint64_t setFirstBufferEndTime_;
    bool isBufferSetting_;
 
    uint64_t setPrepareProxyStartTime_;
    uint64_t setPrepareProxyEndTime_;
    bool isPrepareProxySetting_;
 
    uint64_t setAddProxyStartTime_;
    uint64_t setAddProxyEndTime_;
    bool isAddProxySetting_;

    static sptr<CameraReportDfxUtils> cameraReportDfx_;
    static std::mutex instanceMutex_;
 
    void ReportPerformanceDeferredPhoto();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_REPORT_DFX_UITLS_H