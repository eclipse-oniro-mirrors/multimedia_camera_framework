/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_VIDEO_REPORT_H
#define OHOS_CAMERA_DPS_VIDEO_REPORT_H

#include "dp_utils.h"
#include "deferred_video_job.h"
#include "singleton.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string EVENT_KEY_PNAMEID = "PNAMEID";
const std::string EVENT_KEY_PVERSIONID = "PVERSIONID";
const std::string EVENT_KEY_VIDEOID = "VIDEOID";
const std::string EVENT_KEY_ABORTTYPE = "ABORTTYPE";
const std::string EVENT_KEY_ABORTTIME = "ABORTTIME";
const std::string EVENT_KEY_RECOVERTIME = "RECOVERTIME";
const std::string EVENT_KEY_COMPLETETIME = "COMPLETETIME";
const std::string EVENT_KEY_REALCOMPLETETIME = "REALCOMPLETETIME";

struct VideoRecord {
    std::string videoId;
    std::string calleBundle;
    std::string calleVersion;
    uint64_t addTime = 0;
    uint64_t processTime = 0;
    uint64_t pauseStartTime = 0;
    uint64_t pauseEndTime = 0;
    uint64_t totlePauseTime = 0;
    ~VideoRecord()
    {}
};

class DfxVideoReport : public Singleton<DfxVideoReport> {
    DECLARE_SINGLETON(DfxVideoReport)

public:
    void ReportAddVideoEvent(const std::string& videoId, DpsCallerInfo callerInfo);
    void ReportRemoveVideoEvent(const std::string& videoId, DpsCallerInfo callerInfo);
    void ReportPauseVideoEvent(const std::string& videoId, int32_t pauseReason);
    void ReportResumeVideoEvent(const std::string& videoId);
    void ReportCompleteVideoEvent(const std::string &videoId);

private:
    std::map<std::string, VideoRecord> processVideoInfo_;
};
} // namespace DeferredProcessingService
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_REPORT_H