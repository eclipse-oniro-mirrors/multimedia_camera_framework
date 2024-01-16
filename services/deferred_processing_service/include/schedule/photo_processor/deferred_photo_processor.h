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

#ifndef OHOS_CAMERA_DPS_SCHEDULE_CONTROLLER_H
#define OHOS_CAMERA_DPS_SCHEDULE_CONTROLLER_H

#include <memory>

#include "iimage_process_callbacks.h"
#include "photo_job_repository.h"
#include "photo_post_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessor : public IImageProcessCallbacks {
public:
    DeferredPhotoProcessor(int userId, TaskManager* taskManager, std::shared_ptr<PhotoJobRepository> repository,
        std::shared_ptr<IImageProcessCallbacks> callbacks);
    ~DeferredPhotoProcessor();
    void Initialize();

    void AddImage(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    void RemoveImage(const std::string& imageId, bool restorable);
    void RestoreImage(const std::string& imageId);
    void ProcessImage(const std::string& appName, const std::string& imageId);
    void CancelProcessImage(const std::string& imageId);

    void SetCallback(IImageProcessCallbacks callbacks);

    void OnProcessDone(int userId, const std::string& imageId, std::shared_ptr<BufferInfo> bufferInfo) override;
    void OnError(int userId, const std::string& imageId, DpsError errorCode) override;
    void OnStateChanged(int userId, DpsStatus statusCode) override;
    void NotifyScheduleState(DpsStatus status);

    void PostProcess(DeferredPhotoWorkPtr work);
    void Interrupt();
    int GetConcurrency(ExecutionMode mode);
    bool GetPendingImages(std::vector<std::string>& pendingImages);

private:
    bool IsFatalError(DpsError errorCode);

    int userId_;
    TaskManager* taskManager_;
    std::shared_ptr<PhotoJobRepository> repository_;
    std::shared_ptr<PhotoPostProcessor> postProcessor_;
    std::shared_ptr<IImageProcessCallbacks> callbacks_;
    std::set<std::string> requestedImages_;
    std::string postedImageId_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SCHEDULE_CONTROLLER_H