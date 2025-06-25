/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "depth_data_taihe.h"
#include "camera_utils_taihe.h"

#include "camera_log.h"


namespace Ani {
namespace Camera {
uint32_t DepthDataImpl::depthDataTaskId_ = CAMERA_PREVIEW_OUTPUT_TASKID;

void DepthDataImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<DepthDataTaiheAsyncContext> asyncContext = std::make_unique<DepthDataTaiheAsyncContext>(
        "DepthDataImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(depthDataTaskId_));
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("DepthDataImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

CameraFormat DepthDataImpl::GetFormat()
{
    return CameraUtilsTaihe::ToTaiheCameraFormat(format_);
}
DepthDataQualityLevel DepthDataImpl::GetQualityLevel()
{
    return CameraUtilsTaihe::ToTaiheDepthDataQualityLevel(qualityLevel_);
}
DepthDataAccuracy DepthDataImpl::GetDataAccuracy()
{
    return CameraUtilsTaihe::ToTaiheDepthDataAccuracy(dataAccuracy_);
}
} // namespace Camera
} // namespace Ani