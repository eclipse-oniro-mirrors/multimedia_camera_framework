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

#include "set"

#include "photo_job_repository.h"
#include "photo_post_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoProcessor : public IImageProcessCallbacks,
    public std::enable_shared_from_this<IImageProcessCallbacks> {
public:
    ~DeferredPhotoProcessor();
    void Initialize();

    void AddImage(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    void RemoveImage(const std::string& imageId, bool restorable);
    void RestoreImage(const std::string& imageId);
    void ProcessImage(const std::string& appName, const std::string& imageId);
    void CancelProcessImage(const std::string& imageId);
    void OnProcessDone(const int32_t userId, const std::string& imageId,
        const std::shared_ptr<BufferInfo>& bufferInfo) override;
    void OnProcessDoneExt(int userId, const std::string& imageId,
        const std::shared_ptr<BufferInfoExt>& bufferInfo) override;
    void OnError(const int32_t userId, const std::string& imageId, DpsError errorCode) override;
    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override;
    void PostProcess(const DeferredPhotoWorkPtr& work);
    void SetDefaultExecutionMode();
    void Interrupt();
    int32_t GetConcurrency(ExecutionMode mode);
    bool GetPendingImages(std::vector<std::string>& pendingImages);

protected:
    DeferredPhotoProcessor(const int32_t userId, const std::shared_ptr<PhotoJobRepository>& repository,
        const std::shared_ptr<PhotoPostProcessor>& postProcessor,
        const std::weak_ptr<IImageProcessCallbacks>& callback);

private:
    bool IsFatalError(DpsError errorCode);

    const int32_t userId_;
    std::shared_ptr<PhotoJobRepository> repository_;
    std::shared_ptr<PhotoPostProcessor> postProcessor_;
    std::weak_ptr<IImageProcessCallbacks> callback_;
    std::set<std::string> requestedImages_ {};
    std::string postedImageId_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SCHEDULE_CONTROLLER_H