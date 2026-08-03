/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <mutex>
#include "av_codec_interface.h"
#include "codec_info_util.h"
#include "av_codec_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
namespace CodecInfoUtil {
const std::vector<CodecCapabilityInfo>& GetCodecInfo()
{
    static std::vector<CodecCapabilityInfo> codecCapabilityInfos = []() noexcept {
        auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
        CHECK_RETURN_RET_ELOG(avCodecProxy == nullptr, std::vector<CodecCapabilityInfo>{}, "avCodecProxy is null");
        std::vector<CodecCapabilityInfo> infos;
        int32_t ret = avCodecProxy->GetCodecCapabilityInfo(infos);
        AVCodecProxy::FreeAVCodecDynamiclibDelayed();
        return (ret == MEDIA_OK) ? std::move(infos) : std::vector<CodecCapabilityInfo>{};
    }();
    return codecCapabilityInfos;
}

bool IsValidCodecType(ProxyVideoCodecType codecType)
{
    return codecType >= ProxyVideoCodecType::AVC && codecType <= ProxyVideoCodecType::HEVC;
}

bool IsBframeSupported(ProxyVideoCodecType codecType)
{
    std::vector<CodecCapabilityInfo> capabilityInfo = GetCodecInfo();
    return std::any_of(capabilityInfo.begin(), capabilityInfo.end(), [codecType](const CodecCapabilityInfo& info) {
        return info.codecType == codecType &&
               info.isBframeSupported == true &&
               info.category == CodeCategory::HARDWARE;
    });
}

bool IsWatermarkSupported(ProxyVideoCodecType codecType)
{
    std::vector<CodecCapabilityInfo> capabilityInfo = GetCodecInfo();
    return std::any_of(capabilityInfo.begin(), capabilityInfo.end(), [codecType](const CodecCapabilityInfo& info) {
        return info.codecType == codecType &&
               info.isWaterMarkSupported == true &&
               info.category == CodeCategory::HARDWARE;
    });
}

int32_t GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    supportedVideoCodecTypes.clear();
    std::vector<CodecCapabilityInfo> infos = GetCodecInfo();
    for (const auto& info : infos) {
        if (IsValidCodecType(info.codecType)) {
            supportedVideoCodecTypes.emplace_back(static_cast<int32_t>(info.codecType));
        }
    }
    return MEDIA_OK;
}

int32_t GetSupportedVideoCodecTypes(std::vector<ProxyVideoCodecType>& supportedVideoCodecTypes)
{
    supportedVideoCodecTypes.clear();
    std::vector<CodecCapabilityInfo> infos = GetCodecInfo();
    for (const auto& info : infos) {
        if (IsValidCodecType(info.codecType)) {
            supportedVideoCodecTypes.emplace_back(info.codecType);
        }
    }
    return MEDIA_OK;
}
}  // namespace CodecInfoUtil
}  // namespace CameraStandard
}  // namespace OHOS