/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_DEFERRED_VIDEO_RESULT_H
#define OHOS_CAMERA_DPS_DEFERRED_VIDEO_RESULT_H

#include <unordered_map>
#include <unordered_set>

#include "basic_definitions.h"
#include "enable_shared_create.h"
#include "ipc_types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoResult : public EnableSharedCreateInit<DeferredVideoResult> {
public:
    ~DeferredVideoResult();

    int32_t Initialize() override;
    void RecordResult(const std::string& videoId, DpsError error = DPS_NO_ERROR);
    void DeRecordResult(const std::string& videoId);
    bool IsFatalError(DpsError error) const;
    DpsError GetCacheResult(const std::string& videoId);
    JobErrorType OnError(const std::string& videoId, DpsError& error, bool isHighJob);

    inline void ResetCrashCount(const std::string& videoId)
    {
        videoId2CrashCount_.erase(videoId);
    }

protected:
    DeferredVideoResult();

private:
    void CheckCrashCount(const std::string& videoId, DpsError& error);

    std::mutex mutex_;
    std::unordered_set<DpsError> fatalStatusCodes_ {};
    std::unordered_map<std::string, DpsError> cacheMap_ {};
    std::unordered_map<std::string, uint32_t> videoId2CrashCount_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_RESULT_H