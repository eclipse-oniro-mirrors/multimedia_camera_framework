/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include "dps_video_report.h"

#include "dp_log.h"
#include "hisysevent.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
static constexpr char CAMERA_FWK_UE[] = "CAMERA_FWK_UE";

DfxVideoReport::DfxVideoReport()
{
    DP_DEBUG_LOG("entered.");
}

DfxVideoReport::~DfxVideoReport()
{
    DP_DEBUG_LOG("entered.");
}

void DfxVideoReport::ReportAddVideoEvent(const std::string &videoId, DpsCallerInfo callerInfo)
{
    DP_DEBUG_LOG("ReportAddVideoEvent enter.");
    VideoRecord videoRecord{
        .videoId = videoId,
        .calleBundle = callerInfo.bundleName,
        .calleVersion = callerInfo.version,
        .addTime = SteadyClock::GetTimestampMilli(),
    };
    auto iter = processVideoInfo_.find(videoId);
    if (iter == processVideoInfo_.end()) {
        processVideoInfo_.emplace(videoId, videoRecord);
    } else {
        DP_ERR_LOG("ReportAddVideoEvent video has been added.");
    }

    HiSysEventWrite(CAMERA_FWK_UE,
        "DPS_ADD_VIDEO",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_PNAMEID, callerInfo.bundleName,
        EVENT_KEY_PVERSIONID, callerInfo.pid,
        EVENT_KEY_VIDEOID, videoId);
}

void DfxVideoReport::ReportRemoveVideoEvent(const std::string &videoId, DpsCallerInfo callerInfo)
{
    DP_DEBUG_LOG("ReportRemoveVideoEvent enter.");
    auto iter = processVideoInfo_.find(videoId);
    if (iter != processVideoInfo_.end()) {
        processVideoInfo_.erase(videoId);
    }

    HiSysEventWrite(CAMERA_FWK_UE,
        "DPS_REMOVE_VIDEO",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_PNAMEID, callerInfo.bundleName,
        EVENT_KEY_PVERSIONID, callerInfo.pid,
        EVENT_KEY_VIDEOID, videoId);
}

void DfxVideoReport::ReportPauseVideoEvent(const std::string& videoId, int32_t pauseReason)
{
    DP_DEBUG_LOG("ReportPauseVideoEvent enter.");
    uint64_t processToPauseCost = 0;
    std::string bundleName;
    std::string version;
    auto iter = processVideoInfo_.find(videoId);
    if (iter != processVideoInfo_.end()) {
        DP_DEBUG_LOG("ReportPauseVideoEvent videoId found.");
        VideoRecord vr = iter->second;
        vr.pauseStartTime = SteadyClock::GetTimestampMilli();
        processToPauseCost = vr.pauseStartTime - vr.processTime;
        bundleName = vr.calleBundle;
        version = vr.calleVersion;
    } else {
        DP_DEBUG_LOG("ReportPauseVideoEvent videoId not found.");
    }

    HiSysEventWrite(CAMERA_FWK_UE,
        "DPS_PAUSE_VIDEO",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_PNAMEID, bundleName,
        EVENT_KEY_PVERSIONID, version,
        EVENT_KEY_VIDEOID, videoId,
        EVENT_KEY_ABORTTYPE, pauseReason,
        EVENT_KEY_ABORTTIME, processToPauseCost);
}

void DfxVideoReport::ReportResumeVideoEvent(const std::string &videoId)
{
    DP_DEBUG_LOG("ReportResumeVideoEvent enter.");
    uint64_t pauseToResumeCost = 0;
    std::string bundleName;
    std::string version;
    auto iter = processVideoInfo_.find(videoId);
    if (iter != processVideoInfo_.end()) {
        DP_DEBUG_LOG("ReportResumeVideoEvent videoId found.");
        VideoRecord vr = iter->second;
        if (vr.processTime == 0) {
            // 首次开始分段式任务
            DP_DEBUG_LOG("ReportResumeVideoEvent first process videoId:%{public}s", videoId.c_str());
            vr.processTime = SteadyClock::GetTimestampMilli();
        } else {
            // 中断后再次开始分段式任务
            vr.pauseEndTime = SteadyClock::GetTimestampMilli();
            pauseToResumeCost = vr.pauseEndTime - vr.pauseStartTime;
            vr.totlePauseTime += pauseToResumeCost;
            bundleName = vr.calleBundle;
            version = vr.calleVersion;
            HiSysEventWrite(
                CAMERA_FWK_UE,
                "DPS_RESUME_VIDEO",
                HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                EVENT_KEY_PNAMEID, bundleName,
                EVENT_KEY_PVERSIONID, version,
                EVENT_KEY_VIDEOID, videoId,
                EVENT_KEY_RECOVERTIME, pauseToResumeCost);
        }
    } else {
        DP_DEBUG_LOG("ReportPauseVideoEvent videoId not found.");
    }
}

void DfxVideoReport::ReportCompleteVideoEvent(const std::string &videoId)
{
    DP_DEBUG_LOG("ReportCompleteVideoEvent enter.");
    uint64_t completeTime = 0;
    uint64_t realCompleteTime = 0;
    std::string bundleName;
    std::string version;
    auto iter = processVideoInfo_.find(videoId);
    if (iter != processVideoInfo_.end()) {
        DP_DEBUG_LOG("ReportCompleteVideoEvent videoId found.");
        VideoRecord vr = iter->second;
        completeTime = SteadyClock::GetTimestampMilli() - vr.processTime;
        realCompleteTime = completeTime - vr.totlePauseTime;
        bundleName = vr.calleBundle;
        version = vr.calleVersion;
    } else {
        DP_DEBUG_LOG("ReportCompleteVideoEvent videoId not found.");
    }

    HiSysEventWrite(CAMERA_FWK_UE,
        "DPS_COMPLETE_VIDEO",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_KEY_PNAMEID, bundleName,
        EVENT_KEY_PVERSIONID, version,
        EVENT_KEY_VIDEOID, videoId,
        EVENT_KEY_COMPLETETIME, completeTime,
        EVENT_KEY_REALCOMPLETETIME, realCompleteTime);
}
}  // namespace DeferredProcessing
}  // namespace CameraStandard
}  // namespace OHOS