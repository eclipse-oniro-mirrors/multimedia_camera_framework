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
#include "av_codec_adapter.h"
#include "camera_log.h"
#include "avcodec_list.h"
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::MediaAVCodec;
constexpr int32_t AVC = 0;
constexpr int32_t HEVC = 1;
AVCodecAdapter::AVCodecAdapter()
{
    MEDIA_DEBUG_LOG("AVCodecAdapter constructor");
}

AVCodecAdapter::~AVCodecAdapter()
{
    MEDIA_DEBUG_LOG("AVCodecAdapter destructor");
}

bool AVCodecAdapter::IsBframeSupported(int32_t videoCodecType)
{
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    CHECK_RETURN_RET_ELOG(codecList == nullptr, false, "CodecList is nullptr.");
    MediaAVCodec::CapabilityData* capabilityData =
        codecList->GetCapability(MapCodecName(videoCodecType), true, MediaAVCodec::AVCodecCategory::AVCODEC_HARDWARE);
    CHECK_RETURN_RET_ELOG(capabilityData == nullptr, false, "CapabilityData is nullptr.");
    auto codecInfo = std::make_shared<MediaAVCodec::AVCodecInfo>(capabilityData);
    bool isBFrame = codecInfo->IsFeatureSupported(MediaAVCodec::AVCapabilityFeature::VIDEO_ENCODER_B_FRAME);
    return isBFrame;
}

int32_t AVCodecAdapter::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    using namespace OHOS::MediaAVCodec;
    std::shared_ptr<AVCodecList> avCodecList = AVCodecListFactory::CreateAVCodecList();
    CHECK_RETURN_RET_ELOG(avCodecList == nullptr, MEDIA_ERR, "get codec list failed");
    CapabilityData *capabilityDataHw = nullptr;
    CapabilityData *capabilityDataSw = nullptr;
    capabilityDataHw = avCodecList->GetCapability(MapCodecName(AVC), true, AVCodecCategory::AVCODEC_HARDWARE);
    capabilityDataSw = avCodecList->GetCapability(MapCodecName(AVC), true, AVCodecCategory::AVCODEC_SOFTWARE);
    CHECK_EXECUTE(capabilityDataHw || capabilityDataSw, supportedVideoCodecTypes.push_back(AVC));
    capabilityDataHw = avCodecList->GetCapability(MapCodecName(HEVC), true, AVCodecCategory::AVCODEC_HARDWARE);
    capabilityDataSw = avCodecList->GetCapability(MapCodecName(HEVC), true, AVCodecCategory::AVCODEC_SOFTWARE);
    CHECK_EXECUTE(capabilityDataHw || capabilityDataSw, supportedVideoCodecTypes.push_back(HEVC));
    return MEDIA_OK;
}

std::string AVCodecAdapter::MapCodecName(int32_t codecType) const
{
    if (codecType == HEVC) {
        return std::string(CodecMimeType::VIDEO_HEVC);
    } else if (codecType == AVC) {
        return std::string(CodecMimeType::VIDEO_AVC);
    }
    return std::string(CodecMimeType::VIDEO_AVC);
}

extern "C" AVCodecIntf *createAVCodecIntf()
{
    return new AVCodecAdapter();
}
} // namespace CameraStandard
} // namespace OHOS