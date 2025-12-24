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
#include "av_codec_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
typedef AVCodecIntf* (*CreateAVCodecIntf)();

AVCodecProxy::AVCodecProxy(std::shared_ptr<Dynamiclib> avcodecLib, std::shared_ptr<AVCodecIntf> avcodecIntf)
    : avcodecLib_(avcodecLib), avcodecIntf_(avcodecIntf)
{
    MEDIA_DEBUG_LOG("AVCodecProxy constructor");
    CHECK_RETURN_ELOG(avcodecLib_ == nullptr, "avcodecLib is nullptr");
    CHECK_RETURN_ELOG(avcodecIntf_ == nullptr, "avcodecIntf is nullptr");
}

AVCodecProxy::~AVCodecProxy()
{
    MEDIA_DEBUG_LOG("AVCodecProxy destructor");
}

std::shared_ptr<AVCodecProxy> AVCodecProxy::CreateAVCodecProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(AV_CODEC_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load media library");
    CreateAVCodecIntf createAVCodecIntf = (CreateAVCodecIntf)dynamiclib->GetFunction("createAVCodecIntf");
    CHECK_RETURN_RET_ELOG(createAVCodecIntf == nullptr, nullptr, "Failed to get createAVCodecInf function");
    AVCodecIntf* avcodecIntf = createAVCodecIntf();
    CHECK_RETURN_RET_ELOG(avcodecIntf == nullptr, nullptr, "Failed to create AVCodecIntf instance");
    return std::make_shared<AVCodecProxy>(dynamiclib, std::shared_ptr<AVCodecIntf>(avcodecIntf));
}

bool AVCodecProxy::IsBframeSupported(int32_t videoCodecType)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("IsBframeSupported is called");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, false, "avcodecIntf_ is nullptr");
    return avcodecIntf_->IsBframeSupported(videoCodecType);
}

int32_t AVCodecProxy::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("GetSupportedVideoCodecTypes is called");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, MEDIA_ERR, "avcodecIntf_ is nullptr");
    return avcodecIntf_->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
}
} // namespace CameraStandard
} // namespace OHOS