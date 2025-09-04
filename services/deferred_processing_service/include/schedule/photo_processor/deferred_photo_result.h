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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_RESULT_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_RESULT_H

#include <atomic>
#include <set>

#include "basic_definitions.h"
#include "enable_shared_create.h"
#include "image_info.h"
#include "ipc_file_descriptor.h"
#include "istate_change_listener.h"
#include "picture_interface.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum class ErrorType {
    RETRY = 0,
    NORMAL_FAILED,
    HIGH_FAILED,
    FATAL_NOTIFY,
    FAILED_NOTIFY
};

class DeferredPhotoResult : public EnableSharedCreateInit<DeferredPhotoResult> {
public:
    ~DeferredPhotoResult();

    int32_t Initialize() override;
    void RecordHigh(const std::string& imageId);
    void DeRecordHigh(const std::string& imageId);
    bool IsFatalError(DpsError error) const;
    bool IsNeedReset();
    void OnSuccess(const std::string& imageId);
    ErrorType OnError(const std::string& imageId, DpsError& error, bool isHighJob);

    inline void ResetTimeoutCount()
    {
        processTimeoutCount_.store(DEFAULT_COUNT);
    }

    inline void ResetCrashCount(const std::string& imageId)
    {
        imageId2CrashCount_.erase(imageId);
    }

protected:
    DeferredPhotoResult();

private:
    friend class DeferredPhotoProcessor;
    void RecordResult(const std::string& imageId, const std::shared_ptr<ImageInfo>& result);
    void DeRecordResult(const std::string& imageId);
    std::shared_ptr<ImageInfo> GetCacheResult(const std::string& imageId);
    void CheckCrashCount(const std::string& imageId, DpsError& error);
    
    std::atomic_int32_t processTimeoutCount_ {DEFAULT_COUNT};
    std::set<DpsError> fatalStatusCodes_ {};
    std::set<std::string> highImages_ {};
    std::unordered_map<std::string, std::shared_ptr<ImageInfo>> cacheMap_ {};
    std::unordered_map<std::string, uint32_t> imageId2CrashCount_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_RESULT_H