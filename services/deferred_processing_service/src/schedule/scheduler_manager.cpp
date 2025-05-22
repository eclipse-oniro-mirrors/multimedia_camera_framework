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

#include "scheduler_manager.h"

#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
SchedulerManager::SchedulerManager()
{
    DP_DEBUG_LOG("entered.");
}

SchedulerManager::~SchedulerManager()
{
    DP_INFO_LOG("entered.");
    photoController_.clear();
    videoPosts_.clear();
    videoController_.clear();
    videoProcessors_.clear();
}

int32_t SchedulerManager::Initialize()
{
    DP_DEBUG_LOG("entered.");
    return DP_OK;
}

std::shared_ptr<PhotoPostProcessor> SchedulerManager::GetPhotoPostProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto controller = GetPhotoController(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller == nullptr, nullptr,
        "PhotoPostProcessor not found for userId: %{public}d.", userId);
    auto process = controller->GetPhotoProcessor();
    DP_CHECK_ERROR_RETURN_RET_LOG(process == nullptr, nullptr,
        "PhotoPostProcessor not found for userId: %{public}d.", userId);
    return process->GetPhotoPostProcessor();
}

std::shared_ptr<DeferredPhotoProcessor> SchedulerManager::GetPhotoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto controller = GetPhotoController(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller == nullptr, nullptr,
        "PhotoProcessors not found for userId: %{public}d.", userId);
    return controller->GetPhotoProcessor();
}

std::shared_ptr<DeferredPhotoController> SchedulerManager::GetPhotoController(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = photoController_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == photoController_.end(), nullptr,
        "PhotoController not found for userId: %{public}d", userId);
    return it->second;
}

void SchedulerManager::CreatePhotoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered");
    auto photoRepository = PhotoJobRepository::Create(userId);
    auto photoPost = PhotoPostProcessor::Create(userId);
    auto photoProcessor = DeferredPhotoProcessor::Create(userId, photoRepository, photoPost);
    auto photoController = DeferredPhotoController::Create(userId, photoProcessor);
    photoController_[userId] = photoController;
}

std::shared_ptr<VideoPostProcessor> SchedulerManager::GetVideoPostProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoPosts_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoPosts_.end(), nullptr,
        "VideoPostProcessor not found for userId: %{public}d", userId);
    return it->second;
}

std::shared_ptr<DeferredVideoProcessor> SchedulerManager::GetVideoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoProcessors_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoProcessors_.end(), nullptr,
        "VideoProcessor not found for userId: %{public}d", userId);
    return it->second;
}

std::shared_ptr<DeferredVideoController> SchedulerManager::GetVideoController(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoController_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoController_.end(), nullptr,
        "VideoController not found for userId: %{public}d", userId);
    return it->second;
}

void SchedulerManager::CreateVideoProcessor(const int32_t userId,
    const std::shared_ptr<IVideoProcessCallbacks>& callbacks)
{
    DP_DEBUG_LOG("entered.");
    auto videoRepository = std::make_shared<VideoJobRepository>(userId);
    auto videoPost = CreateShared<VideoPostProcessor>(userId);
    auto videoProcessor = CreateShared<DeferredVideoProcessor>(videoRepository, videoPost, callbacks);
    auto videoController = CreateShared<DeferredVideoController>(userId, videoRepository, videoProcessor);
    videoController->Initialize();
    videoPosts_[userId] = videoPost;
    videoProcessors_[userId] = videoProcessor;
    videoController_[userId] = videoController;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS