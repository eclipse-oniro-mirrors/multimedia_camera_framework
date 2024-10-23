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

#include "mpeg_manager_factory.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
MpegManagerFactory::MpegManagerFactory()
{
    DP_DEBUG_LOG("entered.");
}

MpegManagerFactory::~MpegManagerFactory()
{
    DP_DEBUG_LOG("entered.");
    mpegManager_ = nullptr;
}

std::shared_ptr<MpegManager> MpegManagerFactory::Acquire(const std::string& requestId,
    const sptr<IPCFileDescriptor>& inputFd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mpegManager_ != nullptr) {
        if (requestId == requestId_) {
            refCount_++;
            return mpegManager_;
        }
        DP_DEBUG_LOG("requestId changed, reinitializing MpegManager.");
        mpegManager_.reset();
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(inputFd == nullptr, nullptr, "inputFd is nullptr.");

    mpegManager_ = std::make_shared<MpegManager>();
    if (mpegManager_->Init(requestId, inputFd) != OK) {
        DP_ERR_LOG("Failed to initialize MpegManager.");
        mpegManager_.reset();
        return nullptr;
    }

    DP_INFO_LOG("Initialized MpegManager successfully.");
    requestId_ = requestId;
    refCount_ = 1;
    return mpegManager_;
}

void MpegManagerFactory::Release(std::shared_ptr<MpegManager>& mpegManager)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_ERROR_RETURN_LOG(mpegManager == nullptr, "MpegManager is nullptr, release failed.");
    DP_CHECK_ERROR_RETURN_LOG(mpegManager != mpegManager_, "MpegManager does not match, release failed.");

    if (--refCount_ == 0) {
        DP_INFO_LOG("Destroying mpegManager.");
        if (mpegManager_ != nullptr) {
            mpegManager_->UnInit(MediaResult::FAIL);
        }
        mpegManager_.reset();
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS