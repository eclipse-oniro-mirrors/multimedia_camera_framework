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
 
#include <mutex>
#include <cinttypes>
#include <unordered_map>
#include "camera_report_dfx_uitls.h"
 
#include "camera_util.h"
#include "camera_log.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "steady_clock.h"
 
namespace OHOS {
namespace CameraStandard {
using namespace std;
sptr<CameraReportDfxUtils> CameraReportDfxUtils::cameraReportDfx_;
std::mutex CameraReportDfxUtils::instanceMutex_;

sptr<CameraReportDfxUtils> &CameraReportDfxUtils::GetInstance()
{
    if (CameraReportDfxUtils::cameraReportDfx_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (CameraReportDfxUtils::cameraReportDfx_ == nullptr) {
            MEDIA_INFO_LOG("Initializing camera report dfx instance");
            CameraReportDfxUtils::cameraReportDfx_ = new CameraReportDfxUtils();
        }
    }
    return CameraReportDfxUtils::cameraReportDfx_;
}
 
void CameraReportDfxUtils::SetFirstBufferStartInfo(CaptureDfxInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferStartInfo captureID: %{public}d", captureInfo.captureId);
    captureInfo.firstBufferStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
    unique_lock<mutex> lock(mutex_);
    captureList_.insert(pair<int32_t, CaptureDfxInfo>(captureInfo.captureId, captureInfo));
}
 
void CameraReportDfxUtils::SetFirstBufferEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.firstBufferEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyStartInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyStartInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyStartInfo");
            auto& captureInfo = iter->second;
            captureInfo.prepareProxyStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.prepareProxyEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetAddProxyStartInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyStartInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyStartInfo");
            auto& captureInfo = iter->second;
            captureInfo.addProxyStartTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
        }
    }
}
 
void CameraReportDfxUtils::SetAddProxyEndInfo(int32_t captureId)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyEndInfo captureID: %{public}d", captureId);
    unique_lock<mutex> lock(mutex_);
    {
        map<int32_t, CaptureDfxInfo>::iterator iter = captureList_.find(captureId);
        if (iter != captureList_.end()) {
            MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyEndInfo");
            auto& captureInfo = iter->second;
            captureInfo.addProxyEndTime = DeferredProcessing::SteadyClock::GetTimestampMilli();
            ReportPerformanceDeferredPhoto(captureInfo);
            captureList_.erase(captureId);
        }
    }
}
 
void CameraReportDfxUtils::ReportPerformanceDeferredPhoto(CaptureDfxInfo captureInfo)
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::ReportPerformanceDeferredPhoto start");
    uint64_t firstBufferCostTime = captureInfo.firstBufferEndTime - captureInfo.firstBufferStartTime;
    uint64_t prepareProxyCostTime = captureInfo.prepareProxyEndTime - captureInfo.prepareProxyStartTime;
    uint64_t addProxyCostTime = captureInfo.addProxyEndTime - captureInfo.addProxyStartTime;
 
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_DEFERRED_PHOTO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "MSG", captureInfo.isSystemApp ? "System Camera" : "Non-system camera",
        "CAPTURE_ID", captureInfo.captureId,
        "FIRST_BUFFER_COST_TIME", firstBufferCostTime,
        "PREPARE_PROXY_COST_TIME", prepareProxyCostTime,
        "ADD_PROXY_COSTTIME", addProxyCostTime);
}
} // namespace CameraStandard
} // namespace OHOS