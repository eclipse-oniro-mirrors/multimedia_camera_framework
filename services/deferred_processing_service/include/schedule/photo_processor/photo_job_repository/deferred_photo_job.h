/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H

#include <map>
#include <memory>
#include <string>

#include "basic_definitions.h"
#include "foundation/multimedia/camera_framework/interfaces/inner_api/native/camera/include/utils/dps_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum class PhotoJobStatus {
    NONE = 0,
    PENDING,
    RUNNING,
    FAILED,
    COMPLETED,
    DELETED
};

enum class PhotoJobPriority {
    NONE = 0,
    LOW,
    NORMAL,
    HIGH,
    DELETED
};

enum class PhotoJobType {
    OFFLINE = 0,
    BACKGROUND
};

enum ExecutionMode {
    HIGH_PERFORMANCE = 0,
    LOAD_BALANCE,
    LOW_POWER,
    DUMMY
};

class DeferredPhotoJob {
public:
    DeferredPhotoJob(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    ~DeferredPhotoJob();

    PhotoJobPriority GetCurPriority();
    PhotoJobPriority GetPrePriority();
    PhotoJobPriority GetRunningPriority();
    PhotoJobStatus GetCurStatus();
    PhotoJobStatus GetPreStatus();
    std::string& GetImageId();
    int GetDeferredProcType();

private:
    friend class PhotoJobRepository;

    bool SetJobStatus(PhotoJobStatus curStatus);
    bool SetJobPriority(PhotoJobPriority priority);
    void RecordJobRunningPriority();
    void SetJobType(PhotoJobType photoJobType);
    bool GetDiscardable();
    int GetPhotoJobType();
    void SetPhotoJobType(int photoJobType);

    std::string imageId_;
    bool discardable_;
    DpsMetadata metadata_;
    PhotoJobPriority prePriority_;
    PhotoJobPriority curPriority_;
    PhotoJobPriority runningPriority_;
    PhotoJobStatus preStatus_;
    PhotoJobStatus curStatus_;
    int photoJobType_;
};
using DeferredPhotoJobPtr = std::shared_ptr<DeferredPhotoJob>;

class DeferredPhotoWork {
public:
    DeferredPhotoWork(DeferredPhotoJobPtr jobPtr, ExecutionMode mode);
    ~DeferredPhotoWork();
    DeferredPhotoJobPtr GetDeferredPhotoJob();
    ExecutionMode GetExecutionMode();

private:
    DeferredPhotoJobPtr jobPtr_;
    ExecutionMode executionMode_;
};
using DeferredPhotoWorkPtr = std::shared_ptr<DeferredPhotoWork>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H