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
 
void CameraReportDfxUtils::SetFirstBufferStartInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        setFirstBufferStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isBufferSetting_ = true;
    }
}
 
void CameraReportDfxUtils::SetFirstBufferEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetFirstBufferEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        CHECK_ERROR_RETURN_LOG(!isBufferSetting_, "CameraReportDfxUtils::SetFirstBufferEndInfo cancel report");
        setFirstBufferEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isBufferSetting_ = false;
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyStartInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        setPrepareProxyStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isPrepareProxySetting_ = true;
    }
}
 
void CameraReportDfxUtils::SetPrepareProxyEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetPrepareProxyEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        CHECK_ERROR_RETURN_LOG(!isPrepareProxySetting_, "CameraReportDfxUtils::SetPrepareProxyEndInfo cancel report");
        setPrepareProxyEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isPrepareProxySetting_ = false;
    }
}
 
void CameraReportDfxUtils::SetAddProxyStartInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyStartInfo");
    unique_lock<mutex> lock(mutex_);
    {
        setAddProxyStartTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isAddProxySetting_ = true;
    }
}
 
void CameraReportDfxUtils::SetAddProxyEndInfo()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::SetAddProxyEndInfo");
    unique_lock<mutex> lock(mutex_);
    {
        CHECK_ERROR_RETURN_LOG(!isAddProxySetting_, "CameraReportDfxUtils::SetAddProxyEndInfo cancel report");
        setAddProxyEndTime_ = DeferredProcessing::SteadyClock::GetTimestampMilli();
        isAddProxySetting_ = false;
        ReportPerformanceDeferredPhoto();
    }
}
 
void CameraReportDfxUtils::ReportPerformanceDeferredPhoto()
{
    MEDIA_DEBUG_LOG("CameraReportDfxUtils::ReportPerformanceDeferredPhoto");
    stringstream ss;
    uint64_t firstBufferCostTime = setFirstBufferEndTime_ - setFirstBufferStartTime_;
    uint64_t prepareProxyCostTime = setPrepareProxyEndTime_ - setPrepareProxyStartTime_;
    uint64_t addProxyCostTime = setAddProxyEndTime_ - setAddProxyStartTime_;
    ss << "firstBufferCostTime:" << firstBufferCostTime
    << ",prepareProxyCostTime:" << prepareProxyCostTime
    << ",addProxyCostTime:" << addProxyCostTime;
 
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "PERFORMANCE_DEFERRED_PHOTO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "MSG", ss.str());
}
} // namespace CameraStandard
} // namespace OHOS