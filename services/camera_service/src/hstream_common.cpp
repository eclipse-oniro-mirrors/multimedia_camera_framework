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

#include <atomic>
#include <cstdint>
#include <mutex>
#include <set>

#include "camera_log.h"
#include "camera_util.h"
#include "display/graphic/common/v1_0/cm_color_space.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "ipc_skeleton.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_1;
static const std::map<ColorSpace, CM_ColorSpaceType> g_fwkToMetaColorSpaceMap_ = {
    {COLOR_SPACE_UNKNOWN, CM_COLORSPACE_NONE},
    {DISPLAY_P3, CM_P3_FULL},
    {SRGB, CM_SRGB_FULL},
    {BT709, CM_BT709_FULL},
    {BT2020_HLG, CM_BT2020_HLG_FULL},
    {BT2020_PQ, CM_BT2020_PQ_FULL},
    {P3_HLG, CM_P3_HLG_FULL},
    {P3_PQ, CM_P3_PQ_FULL},
    {DISPLAY_P3_LIMIT, CM_P3_LIMIT},
    {SRGB_LIMIT, CM_SRGB_LIMIT},
    {BT709_LIMIT, CM_BT709_LIMIT},
    {BT2020_HLG_LIMIT, CM_BT2020_HLG_LIMIT},
    {BT2020_PQ_LIMIT, CM_BT2020_PQ_LIMIT},
    {P3_HLG_LIMIT, CM_P3_HLG_LIMIT},
    {P3_PQ_LIMIT, CM_P3_PQ_LIMIT}
};
namespace {
static const int32_t STREAMID_BEGIN = 1;
static const int32_t CAPTUREID_BEGIN = 1;
static int32_t g_currentStreamId = STREAMID_BEGIN;

static std::atomic_int32_t g_currentCaptureId = CAPTUREID_BEGIN;

static int32_t GenerateStreamId()
{
    int newId = g_currentStreamId++;
    if (newId == INT32_MAX) {
        g_currentStreamId = STREAMID_BEGIN;
    }
    return newId;
}

static int32_t GenerateCaptureId()
{
    int32_t newId = g_currentCaptureId++;
    if (newId == INT32_MAX) {
        g_currentCaptureId = CAPTUREID_BEGIN;
    }
    return newId;
}
} // namespace

HStreamCommon::HStreamCommon(
    StreamType streamType, sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height)
    : format_(format), width_(width), height_(height), producer_(producer), streamType_(streamType)
{
    MEDIA_DEBUG_LOG("Enter Into HStreamCommon::HStreamCommon");
    callerToken_ = IPCSkeleton::GetCallingTokenID();
    fwkStreamId_ = streamType == StreamType::METADATA ? STREAM_ID_UNSET : GenerateStreamId();
    MEDIA_DEBUG_LOG(
        "HStreamCommon Create streamId_ is %{public}d, streamType is:%{public}d", fwkStreamId_, streamType_);
}

HStreamCommon::~HStreamCommon()
{
    MEDIA_DEBUG_LOG("Enter Into HStreamCommon::~HStreamCommon streamId is:%{public}d, streamType is:%{public}d",
        fwkStreamId_, streamType_);
}

void HStreamCommon::SetColorSpace(ColorSpace colorSpace)
{
    auto itr = g_fwkToMetaColorSpaceMap_.find(colorSpace);
    if (itr != g_fwkToMetaColorSpaceMap_.end()) {
        dataSpace_ = itr->second;
    } else {
        MEDIA_ERR_LOG("HStreamCommon::SetColorSpace, %{public}d failed", static_cast<int32_t>(colorSpace));
    }
}

int32_t HStreamCommon::LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    if (streamOperator == nullptr || cameraAbility == nullptr) {
        MEDIA_ERR_LOG("HStreamCommon::LinkInput streamOperator is null");
        return CAMERA_INVALID_ARG;
    }
    if (!IsValidSize(cameraAbility, format_, width_, height_)) {
        return CAMERA_INVALID_SESSION_CFG;
    }
    SetStreamOperator(streamOperator);
    std::lock_guard<std::mutex> lock(cameraAbilityLock_);
    cameraAbility_ = cameraAbility;
    return CAMERA_OK;
}

int32_t HStreamCommon::UnlinkInput()
{
    MEDIA_INFO_LOG("HStreamCommon::UnlinkInput streamType:%{public}d, streamId:%{public}d, hidStreamId:%{public}d",
        streamType_, fwkStreamId_, hdiStreamId_);
    StopStream();
    SetStreamOperator(nullptr);
    hdiStreamId_ = STREAM_ID_UNSET;
    return CAMERA_OK;
}

int32_t HStreamCommon::StopStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCommon::StopStream streamType:%{public}d, streamId:%{public}d, hdiStreamId:%{public}d, "
        "captureId:%{public}d", streamType_, fwkStreamId_, hdiStreamId_, curCaptureID_);
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        MEDIA_DEBUG_LOG("HStreamCommon::StopStream streamOperator is nullptr");
        return CAMERA_OK;
    }

    if (curCaptureID_ != CAPTURE_ID_UNSET) {
        CamRetCode rc = (CamRetCode)(streamOperator->CancelCapture(curCaptureID_));
        if (rc != CamRetCode::NO_ERROR) {
            MEDIA_ERR_LOG("HStreamCommon::StopStream streamOperator->CancelCapture get error code:%{public}d", rc);
        }
        ResetCaptureId();
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HStreamCommon::PrepareCaptureId()
{
    curCaptureID_ = GenerateCaptureId();
    return CAMERA_OK;
}

void HStreamCommon::ResetCaptureId()
{
    curCaptureID_ = CAPTURE_ID_UNSET;
}

int32_t HStreamCommon::GetPreparedCaptureId()
{
    return curCaptureID_;
}

void HStreamCommon::SetStreamInfo(StreamInfo_V1_1 &streamInfo)
{
    int32_t pixelFormat = OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_420_SP;
    auto it = g_cameraToPixelFormat.find(format_);
    if (it != g_cameraToPixelFormat.end()) {
        pixelFormat = it->second;
    } else {
        MEDIA_ERR_LOG("HStreamCommon::SetStreamInfo find format error, pixelFormat use default format");
    }
    MEDIA_INFO_LOG("HStreamCommon::SetStreamInfo pixelFormat is %{public}d", pixelFormat);
    streamInfo.v1_0.streamId_ = hdiStreamId_;
    streamInfo.v1_0.width_ = width_;
    streamInfo.v1_0.height_ = height_;
    streamInfo.v1_0.format_ = pixelFormat;
    streamInfo.v1_0.minFrameDuration_ = 0;
    streamInfo.v1_0.tunneledMode_ = true;
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        if (producer_ != nullptr) {
            MEDIA_INFO_LOG("HStreamCommon:producer is not null");
            streamInfo.v1_0.bufferQueue_ = new BufferProducerSequenceable(producer_);
        } else {
            streamInfo.v1_0.bufferQueue_ = nullptr;
        }
    }
    MEDIA_DEBUG_LOG("HStreamCommon::SetStreamInfo type %{public}d, dataSpace %{public}d", streamType_, dataSpace_);
    streamInfo.v1_0.dataspace_ = dataSpace_;
    streamInfo.extendedStreamInfos = {};
}

int32_t HStreamCommon::ReleaseStream(bool isDelay)
{
    MEDIA_INFO_LOG("Enter Into HStreamCommon::Release streamId is:%{public}d, hdiStreamId is:%{public}d, streamType "
        "is:%{public}d, isDelay:%{public}d",
        fwkStreamId_, hdiStreamId_, streamType_, isDelay);
    StopStream();
    if (!isDelay && hdiStreamId_ != STREAM_ID_UNSET) {
        auto streamOperator = GetStreamOperator();
        if (streamOperator != nullptr) {
            streamOperator->ReleaseStreams({ hdiStreamId_ });
        }
    }
    fwkStreamId_ = STREAM_ID_UNSET;
    hdiStreamId_ = STREAM_ID_UNSET;
    SetStreamOperator(nullptr);
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        cameraAbility_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        producer_ = nullptr;
    }
    return CAMERA_OK;
}

void HStreamCommon::DumpStreamInfo(std::string& dumpString)
{
    StreamInfo_V1_1 curStreamInfo;
    SetStreamInfo(curStreamInfo);
    dumpString += "stream info: \n";
    std::string bufferProducerId = "    Buffer producer Id:[";
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        if (curStreamInfo.v1_0.bufferQueue_ && curStreamInfo.v1_0.bufferQueue_->producer_) {
            bufferProducerId += std::to_string(curStreamInfo.v1_0.bufferQueue_->producer_->GetUniqueId());
        } else {
            bufferProducerId += "empty";
        }
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

void HStreamCommon::PrintCaptureDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_)
{
    camera_metadata_item_t item;
    int result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_QUALITY, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Failed to find OHOS_JPEG_QUALITY tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::find OHOS_JPEG_QUALITY value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().UpdateImagingInfo(DFX_PHOTO_SETTING_QUALITY, std::to_string(item.data.u8[0]));
    }

    // debug log for capture mirror
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Failed to find OHOS_CONTROL_CAPTURE_MIRROR tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::find OHOS_CONTROL_CAPTURE_MIRROR value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().UpdateImagingInfo(DFX_PHOTO_SETTING_MIRROR, std::to_string(item.data.u8[0]));
    }

    // debug log for image rotation
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Failed to find OHOS_JPEG_ORIENTATION tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::find OHOS_JPEG_ORIENTATION value = %{public}d", item.data.i32[0]);
        CameraReportUtils::GetInstance().UpdateImagingInfo(DFX_PHOTO_SETTING_ROTATION,
            std::to_string(item.data.i32[0]));
    }
}
} // namespace CameraStandard
} // namespace OHOS
