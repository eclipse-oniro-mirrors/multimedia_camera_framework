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
#ifdef CAMERA_DEFERRED
    videoController_.clear();
#endif
}

int32_t SchedulerManager::Initialize()
{
    DP_DEBUG_LOG("entered.");
    return DP_OK;
}

std::shared_ptr<PhotoPostProcessor> SchedulerManager::GetPhotoPostProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto process = GetPhotoProcessor(userId);
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
    DP_CHECK_RETURN(photoController_.find(userId) != photoController_.end());
    auto photoRepository = PhotoJobRepository::Create(userId);
    auto photoPost = PhotoPostProcessor::Create(userId);
    auto photoProcessor = DeferredPhotoProcessor::Create(userId, photoRepository, photoPost);
    auto photoController = DeferredPhotoController::Create(userId, photoProcessor);
    photoController_[userId] = photoController;
}

#ifdef CAMERA_DEFERRED
std::shared_ptr<VideoPostProcessor> SchedulerManager::GetVideoPostProcessor(const int32_t userId)
{
    auto process = GetVideoProcessor(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(process == nullptr, nullptr,
        "PhotoPostProcessor not found for userId: %{public}d.", userId);
    return process->GetVideoPostProcessor();
}

std::shared_ptr<DeferredVideoProcessor> SchedulerManager::GetVideoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto controller = GetVideoController(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller == nullptr, nullptr,
        "VideoProcessor not found for userId: %{public}d.", userId);
    return controller->GetVideoProcessor();
}

std::shared_ptr<DeferredVideoController> SchedulerManager::GetVideoController(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoController_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoController_.end(), nullptr,
        "VideoController not found for userId: %{public}d", userId);
    return it->second;
}

void SchedulerManager::CreateVideoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN(videoController_.find(userId) != videoController_.end());
    auto videoRepository = VideoJobRepository::Create(userId);
    auto videoPost = VideoPostProcessor::Create(userId);
    auto videoProcessor = DeferredVideoProcessor::Create(userId, videoRepository, videoPost);
    auto videoController = DeferredVideoController::Create(userId, videoProcessor);
    videoController_[userId] = videoController;
}
#endif
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS