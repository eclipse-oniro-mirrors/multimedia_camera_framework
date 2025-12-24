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

#include "media_manager_proxy.h"
#include "ipc_file_descriptor.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
typedef MediaManagerIntf* (*CreateMediaManagerIntf)();

MediaManagerProxy::MediaManagerProxy(
    std::shared_ptr<Dynamiclib> mediaManagerLib, std::shared_ptr<MediaManagerIntf> mediaManagerIntf)
    : mediaManagerLib_(mediaManagerLib), mediaManagerIntf_(mediaManagerIntf)
{
    DP_DEBUG_LOG("MediaManagerProxy constructor");
}

std::shared_ptr<MediaManagerProxy> MediaManagerProxy::CreateMediaManagerProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_MANAGER_SO);
    DP_CHECK_ERROR_RETURN_RET_LOG(dynamiclib == nullptr, nullptr, "Failed to load media library");
    CreateMediaManagerIntf createMediaManagerIntf =
        (CreateMediaManagerIntf)dynamiclib->GetFunction("createMediaManagerIntf");
    DP_CHECK_ERROR_RETURN_RET_LOG(
        createMediaManagerIntf == nullptr, nullptr, "Failed to get createMediaManagerIntf function");
    MediaManagerIntf* mediaManagerIntf = createMediaManagerIntf();
    DP_CHECK_ERROR_RETURN_RET_LOG(
        mediaManagerIntf == nullptr, nullptr, "Failed to create MediaManagerIntf instance");
    std::shared_ptr<MediaManagerProxy> mediaManagerProxy =
        std::make_shared<MediaManagerProxy>(dynamiclib, std::shared_ptr<MediaManagerIntf>(mediaManagerIntf));
    return mediaManagerProxy;
}

MediaManagerProxy::~MediaManagerProxy()
{
    DP_INFO_LOG("MediaManagerProxy destructor");
}

int32_t MediaManagerProxy::MpegAcquire(const std::string& requestId, const DpsFdPtr& inputFd,
    int32_t width, int32_t height)
{
    DP_DEBUG_LOG("MpegAcquire requestId: %{public}s", requestId.c_str());
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, DP_ERR, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegAcquire(requestId, inputFd, width, height);
}

int32_t MediaManagerProxy::MpegUnInit(const int32_t result)
{
    DP_DEBUG_LOG("MpegUnInit result: %{public}d", result);
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, DP_ERR, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegUnInit(result);
}

DpsFdPtr MediaManagerProxy::MpegGetResultFd()
{
    DP_DEBUG_LOG("MpegGetResultFd");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, nullptr, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegGetResultFd();
}

void MediaManagerProxy::MpegAddUserMeta(std::unique_ptr<MediaUserInfo> userInfo)
{
    DP_DEBUG_LOG("MpegAddUserMeta");
    DP_CHECK_ERROR_RETURN_LOG(mediaManagerIntf_ == nullptr, "MediaManagerIntf is null");
    mediaManagerIntf_->MpegAddUserMeta(std::move(userInfo));
}

uint64_t MediaManagerProxy::MpegGetProcessTimeStamp()
{
    DP_DEBUG_LOG("MpegGetProcessTimeStamp");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, 0, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegGetProcessTimeStamp();
}

sptr<Surface> MediaManagerProxy::MpegGetSurface()
{
    DP_DEBUG_LOG("MpegGetSurface");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, nullptr, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegGetSurface();
}

sptr<Surface> MediaManagerProxy::MpegGetMakerSurface()
{
    DP_DEBUG_LOG("MpegGetMakerSurface");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, nullptr, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegGetMakerSurface();
}

int32_t MediaManagerProxy::MpegRelease()
{
    DP_DEBUG_LOG("MpegRelease");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, DP_ERR, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegRelease();
}

uint32_t MediaManagerProxy::MpegGetDuration()
{
    DP_DEBUG_LOG("MpegGetDuration");
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, 0, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegGetDuration();
}

int32_t MediaManagerProxy::MpegSetProgressNotifer(std::unique_ptr<MediaProgressNotifier> processNotifer)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf_ == nullptr, DP_ERR, "MediaManagerIntf is null");
    return mediaManagerIntf_->MpegSetProgressNotifer(std::move(processNotifer));
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS