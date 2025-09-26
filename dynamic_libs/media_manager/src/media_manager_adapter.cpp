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

#include "media_manager_adapter.h"
#include "dp_log.h"
#include "dp_utils.h"
#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
MediaManagerAdapter::MediaManagerAdapter()
{
    DP_DEBUG_LOG("MediaManagerAdapter constructor");
}

MediaManagerAdapter::~MediaManagerAdapter()
{
    DP_DEBUG_LOG("MediaManagerAdapter destructor");
}

int32_t MediaManagerAdapter::MpegAcquire(const std::string& requestId, const sptr<IPCFileDescriptor>& inputFd)
{
    DP_DEBUG_LOG("MpegAcquire called with requestId: %{public}s", requestId.c_str());
    mpegManager_ = MpegManagerFactory::GetInstance().Acquire(requestId, inputFd);
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, DP_ERR, "mpeg manager is nullptr.");
    DP_DEBUG_LOG("DPS_VIDEO: Acquire MpegManager.");
    return DP_OK;
}

int32_t MediaManagerAdapter::MpegUnInit(const int32_t result)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, DP_ERR, "mpeg manager is nullptr.");
    auto ret = mpegManager_->UnInit(static_cast<MediaResult>(result));
    DP_INFO_LOG("MpegUnInit result: %{public}d, ret: %{public}d", result, ret);
    return ret == OK ? DP_OK : DP_ERR;
}

sptr<IPCFileDescriptor> MediaManagerAdapter::MpegGetResultFd()
{
    DP_DEBUG_LOG("MpegGetResultFd called");
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, nullptr, "mpeg manager is nullptr.");
    return mpegManager_->GetResultFd();
}

void MediaManagerAdapter::MpegAddUserMeta(std::unique_ptr<MediaUserInfo> userInfo)
{
    DP_DEBUG_LOG("MpegAddUserMeta called");
    DP_CHECK_ERROR_RETURN_LOG(mpegManager_ == nullptr, "mpeg manager is nullptr.");
    DP_CHECK_ERROR_RETURN_LOG(userInfo == nullptr, "userProxyInfo is nullptr.");
    mpegManager_->AddUserMeta(std::move(userInfo));
}

uint64_t MediaManagerAdapter::MpegGetProcessTimeStamp()
{
    DP_DEBUG_LOG("MpegGetProcessTimeStamp called");
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, 0, "mpeg manager is nullptr.");
    return mpegManager_->GetProcessTimeStamp();
}

sptr<Surface> MediaManagerAdapter::MpegGetSurface()
{
    DP_DEBUG_LOG("MpegGetSurface called");
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, nullptr, "mpeg manager is nullptr.");
    return mpegManager_->GetSurface();
}

sptr<Surface> MediaManagerAdapter::MpegGetMakerSurface()
{
    DP_DEBUG_LOG("MpegGetMakerSurface called");
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, nullptr, "mpeg manager is nullptr.");
    return mpegManager_->GetMakerSurface();
}

void MediaManagerAdapter::MpegSetMarkSize(int32_t size)
{
    DP_DEBUG_LOG("MpegSetMarkSize called with size: %{public}d", size);
    DP_CHECK_ERROR_RETURN_LOG(mpegManager_ == nullptr, "mpeg manager is nullptr.");
    mpegManager_->SetMarkSize(size);
}

int32_t MediaManagerAdapter::MpegRelease()
{
    DP_DEBUG_LOG("MpegRelease called");
    MpegManagerFactory::GetInstance().Release(mpegManager_);
    mpegManager_.reset();
    DP_INFO_LOG("DPS_VIDEO: Release MpegManager.");
    return DP_OK; // Success
}

extern "C" MediaManagerIntf *createMediaManagerIntf()
{
    return new MediaManagerAdapter();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS