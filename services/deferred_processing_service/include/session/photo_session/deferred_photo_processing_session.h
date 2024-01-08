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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSING_SESSION_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSING_SESSION_H
#include <vector>
#include <shared_mutex>
#include <iostream>
#include <unordered_map>
#include "deferred_photo_processing_session_stub.h"
#include "ideferred_photo_processing_session_callback.h"
#include "task_manager.h"
#include "deferred_photo_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class DeferredPhotoProcessingSession : public DeferredPhotoProcessingSessionStub {
public:
    class PhotoInfo {
    public:
        PhotoInfo(bool discardable, DpsMetadata metadata)
            : discardable_(discardable), metadata_(metadata)
        {}
        ~PhotoInfo() = default;

        bool discardable_;
        DpsMetadata metadata_;
    };
    DeferredPhotoProcessingSession(int userId, std::shared_ptr<DeferredPhotoProcessor> deferredPhotoProcessor,
        TaskManager* taskManager, sptr<IDeferredPhotoProcessingSessionCallback> callback);

    ~DeferredPhotoProcessingSession();
    int32_t BeginSynchronize() override;
    int32_t EndSynchronize() override;
    int32_t AddImage(const std::string imageId, DpsMetadata& metadata, bool discardable) override;
    int32_t RemoveImage(const std::string imageId, bool restorable) override;
    int32_t RestoreImage(const std::string imageId) override;
    int32_t ProcessImage(const std::string appName, const std::string imageId) override;
    int32_t CancelProcessImage(const std::string imageId) override;

private:
    void ReportEvent(const std::string& imageId, int32_t event);
    int userId_;
    std::atomic<bool> inSync_;
    std::shared_ptr<DeferredPhotoProcessor> processor_;
    TaskManager* taskManager_;
    sptr<IDeferredPhotoProcessingSessionCallback> callback_;
    std::unordered_map<std::string, std::shared_ptr<PhotoInfo>> imageIds_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_PROCESSING_SESSION_H