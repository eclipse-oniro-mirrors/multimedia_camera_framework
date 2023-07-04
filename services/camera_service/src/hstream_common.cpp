/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hstream_common.h"

#include "camera_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
HStreamCommon::HStreamCommon(StreamType streamType, sptr<OHOS::IBufferProducer> producer,
                             int32_t format, int32_t width, int32_t height)
{
    MEDIA_DEBUG_LOG("Enter Into HStreamCommon::HStreamCommon");
    streamId_ = 0;
    curCaptureID_ = 0;
    isReleaseStream_ = false;
    streamOperator_ = nullptr;
    cameraAbility_ = nullptr;
    producer_ = producer;
    width_ = width;
    height_ = height;
    format_ = format;
    streamType_ = streamType;
}

HStreamCommon::~HStreamCommon()
{}

int32_t HStreamCommon::SetReleaseStream(bool isReleaseStream)
{
    isReleaseStream_ = isReleaseStream;
    return CAMERA_OK;
}

bool HStreamCommon::IsReleaseStream()
{
    return isReleaseStream_;
}

int32_t HStreamCommon::GetStreamId()
{
    return streamId_;
}

StreamType HStreamCommon::GetStreamType()
{
    return streamType_;
}

int32_t HStreamCommon::LinkInput(sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator,
                                 std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility, int32_t streamId)
{
    if (streamOperator == nullptr || cameraAbility == nullptr) {
        MEDIA_ERR_LOG("HStreamCommon::LinkInput streamOperator is null");
        return CAMERA_INVALID_ARG;
    }
    if (!IsValidSize(cameraAbility, format_, width_, height_)) {
        return CAMERA_INVALID_SESSION_CFG;
    }
    streamId_ = streamId;
    MEDIA_DEBUG_LOG("HStreamCommon::LinkInput streamId_ is %{public}d", streamId_);
    streamOperator_ = streamOperator;
    cameraAbility_ = cameraAbility;
    return CAMERA_OK;
}

void HStreamCommon::SetStreamInfo(StreamInfo_V1_1 &streamInfo)
{
    int32_t pixelFormat = PIXEL_FMT_YCRCB_420_SP;
    auto it = g_cameraToPixelFormat.find(format_);
    if (it != g_cameraToPixelFormat.end()) {
        pixelFormat = it->second;
    } else {
        MEDIA_ERR_LOG("HStreamCommon::SetStreamInfo find format error, pixelFormat use default format");
    }
    MEDIA_INFO_LOG("HStreamCommon::SetStreamInfo pixelFormat is %{public}d", pixelFormat);
    streamInfo.v1_0.streamId_ = streamId_;
    streamInfo.v1_0.width_ = width_;
    streamInfo.v1_0.height_ = height_;
    streamInfo.v1_0.format_ = pixelFormat;
    streamInfo.v1_0.minFrameDuration_ = 0;
    streamInfo.v1_0.tunneledMode_ = true;
    if (producer_ != nullptr) {
        MEDIA_INFO_LOG("HStreamCommon:producer is not null");
        streamInfo.v1_0.bufferQueue_ = new BufferProducerSequenceable(producer_);
    } else {
        streamInfo.v1_0.bufferQueue_ = nullptr;
    }
    streamInfo.v1_0.dataspace_ = CAMERA_COLOR_SPACE;
    streamInfo.extendedStreamInfos = {};
}

int32_t HStreamCommon::Release()
{
    std::lock_guard<std::mutex> lock(producerLock_);
    MEDIA_DEBUG_LOG("Enter Into HStreamCommon::Release");
    streamId_ = 0;
    curCaptureID_ = 0;
    streamOperator_ = nullptr;
    cameraAbility_ = nullptr;
    producer_ = nullptr;
    return CAMERA_OK;
}

void HStreamCommon::DumpStreamInfo(std::string& dumpString)
{
    StreamInfo_V1_1 curStreamInfo;
    SetStreamInfo(curStreamInfo);
    dumpString += "release status:[" + std::to_string(isReleaseStream_) + "]:\n";
    dumpString += "stream info: \n";
    std::string bufferProducerId = "    Buffer producer Id:[";
    if (curStreamInfo.v1_0.bufferQueue_ && curStreamInfo.v1_0.bufferQueue_->producer_) {
        bufferProducerId += std::to_string(curStreamInfo.v1_0.bufferQueue_->producer_->GetUniqueId());
    } else {
        bufferProducerId += "empty";
    }
    dumpString += bufferProducerId;
    dumpString += "]    stream Id:[" + std::to_string(curStreamInfo.v1_0.streamId_);
    std::map<int, std::string>::const_iterator iter =
        g_cameraFormat.find(format_);
    if (iter != g_cameraFormat.end()) {
        dumpString += "]    format:[" + iter->second;
    }
    dumpString += "]    width:[" + std::to_string(curStreamInfo.v1_0.width_);
    dumpString += "]    height:[" + std::to_string(curStreamInfo.v1_0.height_);
    dumpString += "]    dataspace:[" + std::to_string(curStreamInfo.v1_0.dataspace_);
    dumpString += "]    StreamType:[" + std::to_string(curStreamInfo.v1_0.intent_);
    dumpString += "]    TunnelMode:[" + std::to_string(curStreamInfo.v1_0.tunneledMode_);
    dumpString += "]    Encoding Type:[" + std::to_string(curStreamInfo.v1_0.encodeType_) + "]:\n";
    if (curStreamInfo.v1_0.bufferQueue_) {
        delete curStreamInfo.v1_0.bufferQueue_;
    }
}
} // namespace CameraStandard
} // namespace OHOS
