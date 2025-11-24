/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSOR_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSOR_H

#include "deferred_photo_result.h"
#include "enable_shared_create.h"
#include "ideferred_photo_processing_session_callback.h"
#include "image_info.h"
#include "photo_job_repository.h"
#include "photo_post_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessor : public EnableSharedCreateInit<DeferredPhotoProcessor> {
public:
    ~DeferredPhotoProcessor();

    int32_t Initialize() override;
    void AddImage(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    void RemoveImage(const std::string& imageId, bool restorable);
    void RestoreImage(const std::string& imageId);
    void ProcessImage(const std::string& appName, const std::string& imageId);
    void CancelProcessImage(const std::string& imageId);
    bool ProcessBPCache();
    void DoProcess(const DeferredPhotoJobPtr& job);

    void OnProcessSuccess(const int32_t userId, const std::string& imageId, std::unique_ptr<ImageInfo> imageInfo);
    void OnProcessError(const int32_t userId, const std::string& imageId, DpsError error);
    void NotifyScheduleState(DpsStatus status);

    void Interrupt();
    void SetDefaultExecutionMode();
    bool GetPendingImages(std::vector<std::string>& pendingImages);
    bool HasRunningJob();
    bool IsIdleState();
    std::shared_ptr<PhotoJobRepository> GetRepository();
    std::shared_ptr<PhotoPostProcessor> GetPhotoPostProcessor();

protected:
    DeferredPhotoProcessor(const int32_t userId, const std::shared_ptr<PhotoJobRepository>& repository,
        const std::shared_ptr<PhotoPostProcessor>& postProcessor);

private:
    void HandleSuccess(const int32_t userId, const std::string& imageId, std::unique_ptr<ImageInfo> imageInfo);
    void HandleError(const int32_t userId, const std::string& imageId, DpsError error, bool isHighJob);
    uint32_t StartTimer(const std::string& imageId);
    void StopTimer(const std::string& imageId);
    void ProcessPhotoTimeout(const std::string& imageId);
    bool ProcessCatchResults(const std::string& imageId);
    sptr<IDeferredPhotoProcessingSessionCallback> GetCallback();

    const int32_t userId_;
    bool initialized_ {false};
    std::shared_ptr<DeferredPhotoResult> result_ {nullptr};
    std::shared_ptr<PhotoJobRepository> repository_;
    std::shared_ptr<PhotoPostProcessor> postProcessor_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSOR_H