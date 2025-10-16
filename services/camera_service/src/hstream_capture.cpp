/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hstream_capture.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <uuid.h>
#include <iomanip>

#include "camera_log.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "camera/v1_4/types.h"
#include "datetime_ex.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"
#include "photo_asset_interface.h"
#include "photo_asset_proxy.h"
#include "camera_report_dfx_uitls.h"
#include "bms_adapter.h"
#include "picture_interface.h"
#include "hstream_operator_manager.h"
#include "hstream_operator.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "picture_proxy.h"
#include "task_manager.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif
#include "camera_buffer_manager/photo_buffer_consumer.h"
#include "camera_buffer_manager/photo_asset_buffer_consumer.h"
#include "camera_buffer_manager/photo_asset_auxiliary_consumer.h"
#include "camera_buffer_manager/thumbnail_buffer_consumer.h"
#include "camera_buffer_manager/picture_assembler.h"
#include "image_receiver.h"
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#include "mem_mgr_constant.h"
#endif

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::HDI::Display::Graphic::Common::V2_1;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
static const int32_t CAPTURE_ROTATE_360 = 360;
static const std::string BURST_UUID_BEGIN = "";
static std::string g_currentBurstUuid = BURST_UUID_BEGIN;
static const uint32_t TASKMANAGER_ONE = 1;
static const uint32_t TASKMANAGER_FOUR = 4;

static std::string GenerateBurstUuid()
{
    MEDIA_INFO_LOG("HStreamCapture::GenerateBurstUuid");
    uuid_t uuid;
    char str[37] = {}; // UUIDs are 36 characters plus the null terminator
    uuid_generate(uuid);
    uuid_unparse(uuid, str); // Convert the UUID to a string
    std::string burstUuid(str);
    g_currentBurstUuid = burstUuid;
    return burstUuid;
}

HStreamCapture::HStreamCapture(sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::CAPTURE, producer, format, width, height)
{
    MEDIA_INFO_LOG(
        "HStreamCapture::HStreamCapture construct, format:%{public}d size:%{public}dx%{public}d streamId:%{public}d",
        format, width, height, GetFwkStreamId());
    thumbnailSwitch_ = 0;
    rawDeliverySwitch_ = 0;
    modeName_ = 0;
    deferredPhotoSwitch_ = 0;
    deferredVideoSwitch_ = 0;
    burstNum_ = 0;
    movingPhotoSwitch_ = 0;
}

HStreamCapture::HStreamCapture(int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::CAPTURE, format, width, height)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG(
        "HStreamCapture::HStreamCapture new E, format:%{public}d size:%{public}dx%{public}d streamId:%{public}d",
        format, width, height, GetFwkStreamId());
    thumbnailSwitch_ = 0;
    rawDeliverySwitch_ = 0;
    modeName_ = 0;
    deferredPhotoSwitch_ = 0;
    deferredVideoSwitch_ = 0;
    burstNum_ = 0;
    movingPhotoSwitch_ = 0;
    isYuvCapture_ = format == OHOS_CAMERA_FORMAT_YCRCB_420_SP;
    CreateCaptureSurface();
}

void HStreamCapture::CreateCaptureSurface()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CreateCaptureSurface E");
    if (surfaceId_ == "") {
        surface_ = Surface::CreateSurfaceAsConsumer("photoOutput");
        MEDIA_DEBUG_LOG("create photoOutput surface");
    } else {
        surface_ = OHOS::Media::ImageReceiver::getSurfaceById(surfaceId_);
        MEDIA_DEBUG_LOG("get photoOutput surface by surfaceId:%{public}s", surfaceId_.c_str());
    }
    CHECK_RETURN_ELOG(surface_ == nullptr, "surface is null");
    // expand yuv auxiliary surfaces
    CHECK_EXECUTE(isYuvCapture_, CreateAuxiliarySurfaces());
}

void HStreamCapture::CreateAuxiliarySurfaces()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CreateAuxiliarySurfaces E");
    CHECK_RETURN_ELOG(pictureAssembler_ != nullptr, "pictureAssembler has been set");
    pictureAssembler_ = new (std::nothrow) PictureAssembler(this);
    CHECK_RETURN_ELOG(pictureAssembler_ == nullptr, "create pictureAssembler faild");

    std::string retStr = "";
    int32_t ret = 0;
    if (gainmapSurface_ == nullptr) {
        std::string bufferName = "gainmapImage";
        gainmapSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        MEDIA_INFO_LOG("CreateAuxiliarySurfaces 1 surfaceId: %{public}" PRIu64, gainmapSurface_->GetUniqueId());
        ret = SetBufferProducerInfo(bufferName, gainmapSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (deepSurface_ == nullptr) {
        std::string bufferName = "deepImage";
        deepSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        MEDIA_INFO_LOG("CreateAuxiliarySurfaces 2 surfaceId: %{public}" PRIu64, deepSurface_->GetUniqueId());
        ret = SetBufferProducerInfo(bufferName, deepSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (exifSurface_ == nullptr) {
        std::string bufferName = "exifImage";
        exifSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        MEDIA_INFO_LOG("CreateAuxiliarySurfaces 3 surfaceId: %{public}" PRIu64, exifSurface_->GetUniqueId());
        ret = SetBufferProducerInfo(bufferName, exifSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (debugSurface_ == nullptr) {
        std::string bufferName = "debugImage";
        debugSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        MEDIA_INFO_LOG("CreateAuxiliarySurfaces 4 surfaceId: %{public}" PRIu64, debugSurface_->GetUniqueId());
        ret = SetBufferProducerInfo(bufferName, debugSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    MEDIA_INFO_LOG("CreateAuxiliarySurfaces X, res:%{public}s", retStr.c_str());
}

HStreamCapture::~HStreamCapture()
{
    auto photoTask = photoTask_.Get();
    if (photoTask != nullptr) {
        photoTask->CancelAllTasks();
        photoTask_.Set(nullptr);
    }
    if (photoSubTask_ != nullptr) {
        photoSubTask_->CancelAllTasks();
        photoSubTask_ = nullptr;
    }
    if (thumbnailTask_ != nullptr) {
        thumbnailTask_->CancelAllTasks();
        thumbnailTask_ = nullptr;
    }
    photoAssetProxy_.Release();
    rotationMap_.Clear();
    MEDIA_INFO_LOG(
        "HStreamCapture::~HStreamCapture deconstruct, format:%{public}d size:%{public}dx%{public}d streamId:%{public}d",
        format_, width_, height_, GetFwkStreamId());
}

int32_t HStreamCapture::LinkInput(wptr<HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG("HStreamCapture::LinkInput streamId:%{public}d", GetFwkStreamId());
    return HStreamCommon::LinkInput(streamOperator, cameraAbility);
}

void HStreamCapture::FillingPictureExtendStreamInfos(StreamInfo_V1_1 &streamInfo, int32_t format)
{
    HDI::Camera::V1_1::ExtendedStreamInfo gainmapExtendedStreamInfo = {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_GAINMAP),
        .width = width_,
        .height = height_,
        .format = format, // HDR:NV21 P3:NV21
        .dataspace = dataSpace_, // HDR:BT2020_HLG_FULL P3:P3_FULL
        .bufferQueue = gainmapBufferQueue_.Get(),
    };
    HDI::Camera::V1_1::ExtendedStreamInfo deepExtendedStreamInfo = {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_DEPTH),
        .width = width_,
        .height = height_,
        .format = format,
        .bufferQueue = deepBufferQueue_.Get(),
    };
    HDI::Camera::V1_1::ExtendedStreamInfo exifExtendedStreamInfo = {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_EXIF),
        .width = width_,
        .height = height_,
        .format = format,
        .bufferQueue = exifBufferQueue_.Get(),
    };
    HDI::Camera::V1_1::ExtendedStreamInfo debugExtendedStreamInfo = {
        .type =
            static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_MAKER_INFO),
        .width = width_,
        .height = height_,
        .format = format,
        .bufferQueue = debugBufferQueue_.Get(),
    };
    std::vector<HDI::Camera::V1_1::ExtendedStreamInfo> extendedStreams = { gainmapExtendedStreamInfo,
        deepExtendedStreamInfo, exifExtendedStreamInfo, debugExtendedStreamInfo };
    streamInfo.extendedStreamInfos.insert(streamInfo.extendedStreamInfos.end(),
        extendedStreams.begin(), extendedStreams.end());
}

void HStreamCapture::FillingRawAndThumbnailStreamInfo(StreamInfo_V1_1 &streamInfo)
{
    if (rawDeliverySwitch_ && format_ != OHOS_CAMERA_FORMAT_DNG_XDRAW) {
        MEDIA_INFO_LOG("HStreamCapture::SetStreamInfo Set DNG info, streamId:%{public}d", GetFwkStreamId());
        HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo = {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_RAW),
            .width = width_,
            .height = height_,
            .format = streamInfo.v1_0.format_,
            .dataspace = 0,
            .bufferQueue = rawBufferQueue_.Get(),
        };
        streamInfo.extendedStreamInfos.push_back(extendedStreamInfo);
    }
    if (thumbnailSwitch_) {
        MEDIA_DEBUG_LOG("HStreamCapture::SetStreamInfo Set thumbnail info, dataspace:%{public}d", dataSpace_);
        int32_t pixelFormat = GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
        pixelFormat = dataSpace_ == CM_BT2020_HLG_FULL ? GRAPHIC_PIXEL_FMT_YCRCB_P010 : pixelFormat;
        HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo = {
            .type = HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL,
            .width = 0,
            .height = 0,
            .format = pixelFormat, // HDR: YCRCB_P010 P3: nv21
            .dataspace = dataSpace_, // HDR: BT2020_HLG_FULL P3: P3
            .bufferQueue = thumbnailBufferQueue_,
        };
        streamInfo.extendedStreamInfos.push_back(extendedStreamInfo);
    }
}

void HStreamCapture::SetDataSpaceForCapture(StreamInfo_V1_1 &streamInfo)
{
    // LCOV_EXCL_START
    switch (streamInfo.v1_0.dataspace_) {
        case CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL:
            //  HDR Video Session need P3 for captureStream
            streamInfo.v1_0.dataspace_ =  CM_ColorSpaceType_V2_1::CM_P3_FULL;
            break;
        case CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT:
            // HDR Video Session need P3 for captureStream
            streamInfo.v1_0.dataspace_ =  CM_ColorSpaceType_V2_1::CM_P3_FULL;
            break;
        case CM_ColorSpaceType_V2_1::CM_BT709_LIMIT:
            // SDR Video Session need SRGB for captureStream
            streamInfo.v1_0.dataspace_ = CM_ColorSpaceType_V2_1::CM_SRGB_FULL;
            break;
        default:
            streamInfo.v1_0.dataspace_ = CM_ColorSpaceType_V2_1::CM_SRGB_FULL;
            break;
    }
    // LCOV_EXCL_STOP
    MEDIA_DEBUG_LOG("HStreamCapture::SetDataSpaceForCapture current HDI dataSpace: %{public}d",
        streamInfo.v1_0.dataspace_);
}

void HStreamCapture::SetStreamInfo(StreamInfo_V1_1 &streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    MEDIA_INFO_LOG("HStreamCapture::SetStreamInfo streamId:%{public}d format:%{public}d", GetFwkStreamId(), format_);
    streamInfo.v1_0.intent_ = STILL_CAPTURE;

    // 录像抓拍场景下添加拍照流的色域信息转换
    SetDataSpaceForCapture(streamInfo);

    if (format_ == OHOS_CAMERA_FORMAT_HEIC) {
        streamInfo.v1_0.encodeType_ =
            static_cast<HDI::Camera::V1_0::EncodeType>(HDI::Camera::V1_3::ENCODE_TYPE_HEIC);
        streamInfo.v1_0.format_ = GRAPHIC_PIXEL_FMT_BLOB;
    } else if (format_ == OHOS_CAMERA_FORMAT_YCRCB_420_SP) { // NV21
        streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
        streamInfo.v1_0.format_ = GRAPHIC_PIXEL_FMT_YCRCB_420_SP; // NV21
        if (GetMode() != static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::TIMELAPSE_PHOTO)) {
            FillingPictureExtendStreamInfos(streamInfo, GRAPHIC_PIXEL_FMT_YCRCB_420_SP);
        }
    } else if (format_ == OHOS_CAMERA_FORMAT_DNG_XDRAW) {
        streamInfo.v1_0.encodeType_ =
            static_cast<HDI::Camera::V1_0::EncodeType>(HDI::Camera::V1_4::ENCODE_TYPE_DNG_XDRAW);
    } else {
        streamInfo.v1_0.encodeType_ = ENCODE_TYPE_JPEG;
    }
    FillingRawAndThumbnailStreamInfo(streamInfo);
}

int32_t HStreamCapture::SetThumbnail(bool isEnabled)
{
    if (isEnabled) {
        thumbnailSwitch_ = 1;
        thumbnailSurface_ = nullptr;
        thumbnailSurface_ = Surface::CreateSurfaceAsConsumer("quickThumbnail");
        CHECK_RETURN_RET_ELOG(thumbnailSurface_ == nullptr, CAMERA_OK, "thumbnail surface create faild");
        thumbnailBufferQueue_ = new BufferProducerSequenceable(thumbnailSurface_->GetProducer());
    } else {
        thumbnailSwitch_ = 0;
        thumbnailSurface_ = nullptr;
        thumbnailBufferQueue_ = nullptr;
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::EnableRawDelivery(bool enabled)
{
    MEDIA_INFO_LOG("EnableRawDelivery E,enabled:%{public}d", enabled);
    int32_t ret = CAMERA_OK;
    if (enabled) {
        rawDeliverySwitch_ = 1;
        rawSurface_.Set(nullptr);
        std::string bufferName = "rawImage";
        rawSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        auto rawSurface = rawSurface_.Get();
        CHECK_RETURN_RET_ELOG(rawSurface == nullptr, CAMERA_OK, "raw surface create faild");
        ret = SetBufferProducerInfo(bufferName, rawSurface->GetProducer());
        SetRawCallbackUnLock();
    } else {
        rawDeliverySwitch_ = 0;
        rawSurface_.Set(nullptr);
    }
    return ret;
}

// LCOV_EXCL_START
int32_t HStreamCapture::EnableMovingPhoto(bool enabled)
{
    if (enabled) {
        movingPhotoSwitch_ = 1;
    } else {
        movingPhotoSwitch_ = 0;
    }
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t HStreamCapture::SetBufferProducerInfo(const std::string& bufName, const sptr<OHOS::IBufferProducer> &producer)
{
    std::string resStr = "";
    if (bufName == "rawImage") {
        if (producer != nullptr) {
            rawBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            rawBufferQueue_.Set(nullptr);
            resStr += bufName + ",";
        }
    }
    if (bufName == "gainmapImage") {
        if (producer != nullptr) {
            gainmapBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            gainmapBufferQueue_.Set(nullptr);
            resStr += bufName + ",";
        }
    }
    if (bufName == "deepImage") {
        if (producer != nullptr) {
            deepBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            deepBufferQueue_.Set(nullptr);
            resStr += bufName + ",";
        }
    }
    if (bufName == "exifImage") {
        if (producer != nullptr) {
            exifBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            exifBufferQueue_.Set(nullptr);
            resStr += bufName + ",";
        }
    }
    if (bufName == "debugImage") {
        if (producer != nullptr) {
            debugBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            debugBufferQueue_.Set(nullptr);
            resStr += bufName + ",";
        }
    }
    MEDIA_INFO_LOG("HStreamCapture::SetBufferProducerInfo bufferQueue whether is nullptr: %{public}s", resStr.c_str());
    return CAMERA_OK;
}

int32_t HStreamCapture::DeferImageDeliveryFor(int32_t type)
{
    MEDIA_INFO_LOG("HStreamCapture::DeferImageDeliveryFor type: %{public}d", type);
    if (type == OHOS::HDI::Camera::V1_2::STILL_IMAGE) {
        MEDIA_INFO_LOG("HStreamCapture STILL_IMAGE");
        deferredPhotoSwitch_ = 1;
    } else if (type == OHOS::HDI::Camera::V1_2::MOVING_IMAGE) {
        MEDIA_INFO_LOG("HStreamCapture MOVING_IMAGE");
        deferredVideoSwitch_ = 1;
    } else {
        MEDIA_INFO_LOG("HStreamCapture NONE");
        deferredPhotoSwitch_ = 0;
        deferredVideoSwitch_ = 0;
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::PrepareBurst(int32_t captureId)
{
    MEDIA_INFO_LOG("HStreamCapture::PrepareBurst captureId:%{public}d", captureId);
    isBursting_ = true;
    std::lock_guard<std::mutex> lock(burstLock_);
    curBurstKey_ = GenerateBurstUuid();
    burstkeyMap_.emplace(captureId, curBurstKey_);
    std::vector<std::string> imageList = {};
    burstImagesMap_.emplace(captureId, imageList);
    burstNumMap_.emplace(captureId, 0);
    burstNum_ = 0;
    return CAMERA_OK;
}

void HStreamCapture::ResetBurst()
{
    MEDIA_INFO_LOG("HStreamCapture::ResetBurst");
    curBurstKey_ = BURST_UUID_UNSET;
    isBursting_ = false;
}

void HStreamCapture::ResetBurstKey(int32_t captureId)
{
    if (burstkeyMap_.erase(captureId) > 0 &&
        burstImagesMap_.erase(captureId) > 0 &&
        burstNumMap_.erase(captureId) > 0) {
        MEDIA_INFO_LOG("HStreamCapture::ResetBurstKey captureId:%{public}d", captureId);
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::ResetBurstKey captureId not found");
    }
}

std::string HStreamCapture::GetBurstKey(int32_t captureId) const
{
    MEDIA_DEBUG_LOG("HStreamCapture::GetBurstKey captureId:%{public}d", captureId);
    std::string burstKey = BURST_UUID_UNSET;
    std::lock_guard<std::mutex> lock(burstLock_);
    auto iter = burstkeyMap_.find(captureId);
    if (iter != burstkeyMap_.end()) {
        burstKey = iter->second;
        MEDIA_DEBUG_LOG("HStreamCapture::GetBurstKey %{public}s", burstKey.c_str());
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::GetBurstKey not found");
    }
    return burstKey;
}

bool HStreamCapture::IsBurstCapture(int32_t captureId) const
{
    MEDIA_DEBUG_LOG("HStreamCapture::captureId:%{public}d", captureId);
    auto iter = burstkeyMap_.find(captureId);
    return iter != burstkeyMap_.end();
}

bool HStreamCapture::IsBurstCover(int32_t captureId) const
{
    MEDIA_DEBUG_LOG("HStreamCapture::IsBurstCover for captureId: %d", captureId);
    std::lock_guard<std::mutex> lock(burstLock_);
    auto iter = burstImagesMap_.find(captureId);
    return (iter != burstImagesMap_.end()) ? (iter->second.size() == 1) : false;
}

int32_t HStreamCapture::GetCurBurstSeq(int32_t captureId) const
{
    MEDIA_DEBUG_LOG("HStreamCapture::GetCurBurstSeq for captureId: %d", captureId);
    std::lock_guard<std::mutex> lock(burstLock_);
    auto iter = burstImagesMap_.find(captureId);
    CHECK_RETURN_RET(iter != burstImagesMap_.end(), iter->second.size());
    return -1;
}

void HStreamCapture::SetBurstImages(int32_t captureId, std::string imageId)
{
    MEDIA_DEBUG_LOG("HStreamCapture::SetBurstImages captureId:%{public}d imageId:%{public}s",
        captureId, imageId.c_str());
    std::lock_guard<std::mutex> lock(burstLock_);
    auto iter = burstImagesMap_.find(captureId);
    if (iter != burstImagesMap_.end()) {
        iter->second.emplace_back(imageId);
        MEDIA_DEBUG_LOG("HStreamCapture::SetBurstImages success");
    } else {
        MEDIA_ERR_LOG("HStreamCapture::SetBurstImages error");
    }
}

void HStreamCapture::CheckResetBurstKey(int32_t captureId)
{
    MEDIA_DEBUG_LOG("HStreamCapture::CheckResetBurstKey captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(burstLock_);
    auto numIter = burstNumMap_.find(captureId);
    auto imageIter = burstImagesMap_.find(captureId);
    if (numIter != burstNumMap_.end() && imageIter != burstImagesMap_.end()) {
        // LCOV_EXCL_START
        int32_t burstSum = numIter->second;
        size_t curBurstSum = imageIter->second.size();
        MEDIA_DEBUG_LOG("CheckResetBurstKey: burstSum=%d, curBurstSum=%zu", burstSum, curBurstSum);
        CHECK_EXECUTE(static_cast<size_t>(burstSum) == curBurstSum, ResetBurstKey(captureId));
        // LCOV_EXCL_STOP
    } else {
        MEDIA_DEBUG_LOG("CheckResetBurstKey: captureId %d not found in one or both maps", captureId);
    }
}


int32_t HStreamCapture::CheckBurstCapture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings,
                                          const int32_t &preparedCaptureId)
{
    MEDIA_INFO_LOG("CheckBurstCapture start!");
    camera_metadata_item_t item;
    CHECK_RETURN_RET_ELOG(captureSettings == nullptr, CAMERA_INVALID_STATE, "captureSettings is nullptr");
    int32_t result = OHOS::Camera::FindCameraMetadataItem(captureSettings->get(), OHOS_CONTROL_BURST_CAPTURE, &item);
    if (result == CAM_META_SUCCESS && item.count > 0) {
    // LCOV_EXCL_START
        CameraBurstCaptureEnum burstState = static_cast<CameraBurstCaptureEnum>(item.data.u8[0]);
        MEDIA_INFO_LOG("CheckBurstCapture get burstState:%{public}d", item.data.u8[0]);
        if (burstState) {
            std::string burstUuid = GetBurstKey(preparedCaptureId);
            CHECK_RETURN_RET_ELOG(burstUuid != BURST_UUID_UNSET || isBursting_, CAMERA_INVALID_STATE,
                "CheckBurstCapture faild!");
            PrepareBurst(preparedCaptureId);
            MEDIA_INFO_LOG("CheckBurstCapture ready!");
        }
    }
    // LCOV_EXCL_STOP
    return CAM_META_SUCCESS;
}

void ConcurrentMap::Insert(const int32_t& key, const std::shared_ptr<PhotoAssetIntf>& value)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    map_[key] = value;
    step_[key] = 1;
    if (!cv_.count(key)) {
        cv_[key] = std::make_shared<std::condition_variable>();
    }
    if (!mutexes_.count(key)) {
        mutexes_[key] = std::make_shared<std::mutex>();
    }
    cv_[key]->notify_all();
}
 
std::shared_ptr<PhotoAssetIntf> ConcurrentMap::Get(const int32_t& key)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    auto it = map_.find(key);
    return it != map_.end() ? it->second : nullptr;
}

bool ConcurrentMap::WaitForUnlock(const int32_t& key, const int32_t& step, const int32_t& mode,
    const std::chrono::seconds& timeout)
{
    std::shared_ptr<std::mutex> keyMutexPtr;
    std::shared_ptr<std::condition_variable> cvPtr;
    {
        std::lock_guard<std::mutex> lock(map_mutex_);
        if (!cv_.count(key)) {
            cv_[key] = std::make_shared<std::condition_variable>();
        }
        if (!mutexes_.count(key)) {
            mutexes_[key] = std::make_shared<std::mutex>();
        }
        keyMutexPtr = mutexes_[key];
        cvPtr = cv_[key];
    }
    
    std::unique_lock<std::mutex> lock(*keyMutexPtr);
    return cvPtr->wait_for(lock, timeout, [&] {
        return ReadyToUnlock(key, step, mode);
    });
}

bool ConcurrentMap::ReadyToUnlock(const int32_t& key, const int32_t& step, const int32_t& mode)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    if (mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::CAPTURE) ||
      mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::QUICK_SHOT_PHOTO) ||
      mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PORTRAIT) ||
      mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::CAPTURE_MACRO)) {
        return step_.count(key) > 0 && step_[key] == step;
    } else {
        return map_.count(key) > 0;
    }
}

// LCOV_EXCL_START
void ConcurrentMap::IncreaseCaptureStep(const int32_t& key)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    if (key < 0 || key > INT32_MAX) {
        return;
    }
    if (step_.count(key) == 0) {
        step_[key] = 1;
    } else {
        step_[key] = step_[key] + 1;
    }
    CHECK_RETURN(!cv_.count(key));
    cv_[key]->notify_all();
}
// LCOV_EXCL_STOP

void ConcurrentMap::Erase(const int32_t& key)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    mutexes_.erase(key);
    map_.erase(key);
    cv_.erase(key);
    step_.erase(key);
}

void ConcurrentMap::Release()
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    map_.clear();
    mutexes_.clear();
    cv_.clear();
    step_.clear();
}

int32_t HStreamCapture::CreateMediaLibraryPhotoAssetProxy(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("CreateMediaLibraryPhotoAssetProxy E captureId:%{public}d", captureId);
    constexpr int32_t imageShotType = 0;
    constexpr int32_t movingPhotoShotType = 2;
    constexpr int32_t burstShotType = 3;
    int32_t cameraShotType = imageShotType;
    if (movingPhotoSwitch_) {
        cameraShotType = movingPhotoShotType;
    } else if (isBursting_) {
        cameraShotType = burstShotType;
    }
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(
        cameraShotType, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingTokenID());
    CHECK_RETURN_RET_ELOG(photoAssetProxy == nullptr, CAMERA_ALLOC_ERROR,
        "HStreamCapture::CreateMediaLibraryPhotoAssetProxy get photoAssetProxy fail");
    photoAssetProxy_.Insert(captureId, photoAssetProxy);
    MEDIA_DEBUG_LOG("CreateMediaLibraryPhotoAssetProxy X captureId:%{public}d", captureId);
    return CAMERA_OK;
}

std::shared_ptr<PhotoAssetIntf> HStreamCapture::GetPhotoAssetInstance(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    const int32_t getPhotoAssetStep = 2;
    if (!photoAssetProxy_.WaitForUnlock(captureId, getPhotoAssetStep, GetMode(), std::chrono::seconds(1))) {
        MEDIA_ERR_LOG("GetPhotoAsset faild wait timeout, captureId:%{public}d", captureId);
        return nullptr;
    }
    std::shared_ptr<PhotoAssetIntf> proxy = photoAssetProxy_.Get(captureId);
    photoAssetProxy_.Erase(captureId);
    return proxy;
}

bool HStreamCapture::GetAddPhotoProxyEnabled()
{
    return thumbnailSwitch_;
}

int32_t HStreamCapture::AcquireBufferToPrepareProxy(int32_t captureId)
{
    MEDIA_DEBUG_LOG("HStreamCapture::AcquireBufferToPrepareProxy start");
    CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo(captureId);
    MEDIA_DEBUG_LOG("HStreamCapture::AcquireBufferToPrepareProxy end");
    return CAMERA_OK;
}

int32_t HStreamCapture::Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::Capture Entry, streamId:%{public}d", GetFwkStreamId());
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET(streamOperator == nullptr, CAMERA_INVALID_STATE);
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(isCaptureReady_ == false, CAMERA_OPERATION_NOT_ALLOWED,
        "HStreamCapture::Capture failed due to capture not ready");
    auto preparedCaptureId = GetPreparedCaptureId();
    CHECK_RETURN_RET_ELOG(preparedCaptureId != CAPTURE_ID_UNSET, CAMERA_INVALID_STATE,
        "HStreamCapture::Capture, Already started with captureID: %{public}d", preparedCaptureId);
    int32_t ret = PrepareCaptureId();
    preparedCaptureId = GetPreparedCaptureId();
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET, ret,
        "HStreamCapture::Capture Failed to allocate a captureId");
    ret = CheckBurstCapture(captureSettings, preparedCaptureId);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HStreamCapture::Capture Failed with burst state error");

    CaptureDfxInfo captureDfxInfo;
    captureDfxInfo.captureId = preparedCaptureId;
    captureDfxInfo.isSystemApp = CheckSystemApp();
    captureDfxInfo.bundleName = BmsAdapter::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
    CameraReportDfxUtils::GetInstance()->SetFirstBufferStartInfo(captureDfxInfo);

    CaptureInfo captureInfoPhoto;
    captureInfoPhoto.streamIds_ = { GetHdiStreamId() };
    ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings, preparedCaptureId);
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    const std::string permissionName = "ohos.permission.CAMERA";
    AddCameraPermissionUsedRecord(callingTokenId, permissionName);

    // report capture performance dfx
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureMetadataSetting_ = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(captureInfoPhoto.captureSetting_, captureMetadataSetting_);
    if (captureMetadataSetting_ == nullptr) {
        captureMetadataSetting_ = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    DfxCaptureInfo captureInfo;
    captureInfo.captureId = preparedCaptureId;
    captureInfo.caller = CameraReportUtils::GetCallerInfo();
    CameraReportUtils::GetInstance().SetCapturePerfStartInfo(captureInfo);
    MEDIA_INFO_LOG("HStreamCapture::Capture Starting photo capture with capture ID: %{public}d", preparedCaptureId);
    HStreamCommon::PrintCaptureDebugLog(captureMetadataSetting_);
    CamRetCode rc = (CamRetCode)(streamOperator->Capture(preparedCaptureId, captureInfoPhoto, isBursting_));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        ResetCaptureId();
        captureIdForConfirmCapture_ = CAPTURE_ID_UNSET;
        MEDIA_ERR_LOG("HStreamCapture::Capture failed with error Code: %{public}d", rc);
        camera_metadata_item_t item;
        uint8_t connectionType = 0;
        if (captureSettings != nullptr) {
            ret = OHOS::Camera::FindCameraMetadataItem(
                captureSettings->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
            if (ret == CAM_META_SUCCESS && item.count > 0) {
                connectionType = item.data.u8[0];
            }
        }
        CameraReportUtils::ReportCameraErrorForUsb(
            "HStreamCapture::Capture", rc, true, std::to_string(connectionType), CameraReportUtils::GetCallerInfo());
        ret = HdiToServiceError(rc);
    }
    camera_metadata_item_t item;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN_RET_ELOG(cameraAbility_ == nullptr, CAMERA_INVALID_STATE,
            "HStreamCapture::cameraAbility_ is null");
        int32_t result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION,
                                                              &item);
        if (result == CAM_META_SUCCESS && item.count > 0) {
            cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        }
    }

    bool isNightMode = (GetMode() == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::NIGHT));
    CHECK_RETURN_RET(isNightMode && cameraPosition == OHOS_CAMERA_POSITION_BACK, ret);
    ResetCaptureId();

    uint32_t major;
    uint32_t minor;
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    // intercept when streamOperatorCallback support onCaptureReady
    if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_2 && !isBursting_) {
        MEDIA_INFO_LOG("HStreamCapture::Capture set capture not ready");
        isCaptureReady_ = false;
    }
    if (!isBursting_) {
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy E");
        CHECK_PRINT_ELOG(CreateMediaLibraryPhotoAssetProxy(preparedCaptureId) != CAMERA_OK,
            "HStreamCapture::Capture Failed with CreateMediaLibraryPhotoAssetProxy");
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy X");
    }
    return ret;
    // LCOV_EXCL_STOP
}

void HStreamCapture::ProcessCaptureInfoPhoto(CaptureInfo& captureInfoPhoto,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings, int32_t captureId)
{
    if (!OHOS::Camera::GetCameraMetadataItemCount(captureSettings->get())) {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, captureInfoPhoto.captureSetting_);
    } else {
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureSettings, captureInfoPhoto.captureSetting_);
    }
    captureInfoPhoto.enableShutterCallback_ = true;
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureMetadataSetting_ = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(captureInfoPhoto.captureSetting_, captureMetadataSetting_);
    if (captureMetadataSetting_ != nullptr) {
        // convert rotation with application set rotation
        SetRotation(captureMetadataSetting_, captureId);

        // update settings
        std::vector<uint8_t> finalSetting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureMetadataSetting_, finalSetting);
        captureInfoPhoto.captureSetting_ = finalSetting;
    }
    GetLocation(captureMetadataSetting_);
}

void HStreamCapture::SetRotation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_,
    int32_t captureId)
{
    // set orientation for capture
    // sensor orientation, counter-clockwise rotation
    int32_t sensorOrientation = 0;
    int result;
    camera_metadata_item_t item;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN(cameraAbility_ == nullptr);
        // LCOV_EXCL_START
        result = GetCorrectedCameraOrientation(usePhysicalCameraOrientation_, cameraAbility_, sensorOrientation);
        CHECK_RETURN(result != CAM_META_SUCCESS);
        MEDIA_INFO_LOG("set rotation sensor orientation %{public}d", sensorOrientation);

        result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        if (result == CAM_META_SUCCESS && item.count > 0) {
            cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        }
        MEDIA_INFO_LOG("set rotation camera position %{public}d", cameraPosition);
    }

    // rotation from application
    int32_t rotationValue = 0;
    int32_t rotation = 0;
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result == CAM_META_SUCCESS && item.count > 0) {
        rotationValue = item.data.i32[0];
    }
    MEDIA_INFO_LOG("set rotation app rotationValue %{public}d", rotationValue); // 0 270 270+270=180
    // real rotation
    if (enableCameraPhotoRotation_) {
        rotation = rotationValue;
    } else {
        rotation = sensorOrientation + rotationValue;
        if (rotation >= CAPTURE_ROTATE_360) {
            rotation = rotation - CAPTURE_ROTATE_360;
        }
    }
    {
        uint8_t connectType = 0;
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN(cameraAbility_ == nullptr);
        int ret = OHOS::Camera::FindCameraMetadataItem(
            cameraAbility_->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
        if (ret == CAM_META_SUCCESS && item.count > 0) {
            connectType = item.data.u8[0];
        }
        if (connectType == OHOS_CAMERA_CONNECTION_TYPE_REMOTE) {
            rotation = rotationValue;
        }
        MEDIA_INFO_LOG("set rotation camera real rotation %{public}d", rotation);
    }
    UpdateJpegBasicInfo(captureMetadataSetting_, rotation);
    auto hStreamOperator = hStreamOperator_.promote();
    CHECK_EXECUTE(hStreamOperator, hStreamOperator->UpdateOrientationBaseGravity(rotation, sensorOrientation,
        cameraPosition, rotation));
    bool status = false;
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    } else if (result == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    }
    rotationMap_.EnsureInsert(captureId, rotation);
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    CHECK_PRINT_ELOG(result != CAM_META_SUCCESS, "set rotation Failed to find OHOS_JPEG_ORIENTATION tag");
    CHECK_PRINT_ELOG(!status, "set rotation Failed to set Rotation");
    // LCOV_EXCL_STOP
}

void HStreamCapture::UpdateJpegBasicInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting,
    int32_t& rotation)
{
#ifdef HOOK_CAMERA_OPERATOR
    bool isMirror = false;
    if (!CameraRotatePlugin::GetInstance()->HookCaptureStreamStart(GetBasicInfo(), rotation, isMirror)) {
        MEDIA_ERR_LOG("HStreamRepeat::HookCaptureStreamStart is failed %{public}d", isMirror);
        return;
    }
    bool status = false;
    camera_metadata_item_t item;
    int result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting->get(),
        OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &isMirror, 1);
    } else if (result == CAM_META_SUCCESS) {
        status = captureMetadataSetting->updateEntry(OHOS_CONTROL_CAPTURE_MIRROR, &isMirror, 1);
    }
    CHECK_PRINT_ELOG(!status, "HStreamCapture::UpdateJpegBasicInfo Failed to set mirror");
#endif
}

int32_t HStreamCapture::CancelCapture()
{
    CAMERA_SYNC_TRACE;
    // Cancel capture dummy till continuous/burst mode is supported
    StopStream();
    return CAMERA_OK;
}

void HStreamCapture::SetMode(int32_t modeName)
{
    modeName_ = modeName;
    MEDIA_DEBUG_LOG("HStreamCapture SetMode modeName = %{public}d", modeName);
}

int32_t HStreamCapture::GetMode()
{
    MEDIA_INFO_LOG("HStreamCapture GetMode modeName = %{public}d", modeName_);
    return modeName_;
}

int32_t HStreamCapture::ConfirmCapture()
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET(streamOperator == nullptr, CAMERA_INVALID_STATE);
    // LCOV_EXCL_START
    int32_t ret = 0;

    // end burst capture
    if (isBursting_) {
        MEDIA_INFO_LOG("HStreamCapture::ConfirmCapture when burst capture");
        std::vector<uint8_t> settingVector;
        std::shared_ptr<OHOS::Camera::CameraMetadata> burstCaptureSettings = nullptr;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, settingVector);
        OHOS::Camera::MetadataUtils::ConvertVecToMetadata(settingVector, burstCaptureSettings);
        if (burstCaptureSettings == nullptr) {
            burstCaptureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
        }
        EndBurstCapture(burstCaptureSettings);
        ret = Capture(burstCaptureSettings);
        CHECK_PRINT_ELOG(ret != CAMERA_OK, "HStreamCapture::ConfirmCapture end burst faild!");
        return ret;
    }

    auto preparedCaptureId = captureIdForConfirmCapture_;
    MEDIA_INFO_LOG("HStreamCapture::ConfirmCapture with capture ID: %{public}d", preparedCaptureId);
    sptr<HDI::Camera::V1_2::IStreamOperator> streamOperatorV1_2 =
        OHOS::HDI::Camera::V1_2::IStreamOperator::CastFrom(streamOperator);
    CHECK_RETURN_RET_ELOG(streamOperatorV1_2 == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamCapture::ConfirmCapture streamOperatorV1_2 castFrom failed!");
    OHOS::HDI::Camera::V1_2::CamRetCode rc =
        (HDI::Camera::V1_2::CamRetCode)(streamOperatorV1_2->ConfirmCapture(preparedCaptureId));
    if (rc != HDI::Camera::V1_2::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamCapture::ConfirmCapture failed with error Code: %{public}d", rc);
        ret = HdiToServiceErrorV1_2(rc);
    }
    ResetCaptureId();
    captureIdForConfirmCapture_ = CAPTURE_ID_UNSET;
    return ret;
    // LCOV_EXCL_STOP
}

void HStreamCapture::EndBurstCapture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureMetadataSetting)
{
    CHECK_RETURN(captureMetadataSetting == nullptr);
    MEDIA_INFO_LOG("HStreamCapture::EndBurstCapture");
    camera_metadata_item_t item;
    bool status = false;
    int result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting->get(), OHOS_CONTROL_BURST_CAPTURE, &item);
    uint8_t burstState = 0;
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting->addEntry(OHOS_CONTROL_BURST_CAPTURE, &burstState, 1);
    } else if (result == CAM_META_SUCCESS) {
        status = captureMetadataSetting->updateEntry(OHOS_CONTROL_BURST_CAPTURE, &burstState, 1);
    }

    CHECK_PRINT_ELOG(!status, "HStreamCapture::EndBurstCapture Failed");
}

int32_t HStreamCapture::Release()
{
    return ReleaseStream(false);
}

int32_t HStreamCapture::ReleaseStream(bool isDelay)
{
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        streamCaptureCallback_ = nullptr;
    }
    int32_t errorCode = HStreamCommon::ReleaseStream(isDelay);
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    if (hStreamOperatorSptr_ && mSwitchToOfflinePhoto_) {
        hStreamOperatorSptr_->Release();
        streamOperatorOffline_ = nullptr;
    }
    mSwitchToOfflinePhoto_ = false;
    return errorCode;
}

int32_t HStreamCapture::SetCallback(const sptr<IStreamCaptureCallback> &callback)
{
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetCallback input is null");
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_DEBUG_LOG("HStreamCapture::SetCallback");
    streamCaptureCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamCapture::SetPhotoAvailableCallback(const sptr<IStreamCapturePhotoCallback> &callback)
{
    MEDIA_INFO_LOG("HSetPhotoAvailableCallback E");
    CHECK_RETURN_RET_ELOG(
        surface_ == nullptr, CAMERA_INVALID_ARG, "HSetPhotoAvailableCallback surface is null");
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HSetPhotoAvailableCallback callback is null");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    photoAvaiableCallback_.Set(callback);
    CHECK_RETURN_RET_ELOG(photoAssetListener_ != nullptr, CAMERA_OK, "wait to set raw callback");
    photoListener_.Set(nullptr);
    photoListener_.Set(new (std::nothrow) PhotoBufferConsumer(this, false));
    auto photoListener = photoListener_.Get();
    surface_->UnregisterConsumerListener();
    SurfaceError ret = surface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
    auto photoTask = photoTask_.Get();
    CHECK_EXECUTE(photoTask == nullptr, InitCaptureThread());
    photoSubTask_ = nullptr;
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register photoConsume failed:%{public}d", ret);
    return CAMERA_OK;
}

int32_t HStreamCapture::UnSetPhotoAvailableCallback()
{
    MEDIA_INFO_LOG("HUnSetPhotoAvailableCallback E");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    photoAvaiableCallback_.Set(nullptr);
    photoListener_.Set(nullptr);
    return CAMERA_OK;
}

void HStreamCapture::SetRawCallbackUnLock()
{
    MEDIA_INFO_LOG("HStreamCapture::SetRawCallbackUnLock E");
    auto photoAvaiableCallback = photoAvaiableCallback_.Get();
    CHECK_RETURN_ELOG(photoAvaiableCallback == nullptr, "SetRawCallbackUnLock callback is null");
    auto rawSurface = rawSurface_.Get();
    CHECK_RETURN_ELOG(rawSurface == nullptr, "HStreamCapture::SetRawCallbackUnLock callback is null");
    photoListener_.Set(nullptr);
    photoListener_.Set(new (std::nothrow) PhotoBufferConsumer(this, true));
    rawSurface->UnregisterConsumerListener();
    auto photoListener = photoListener_.Get();
    SurfaceError ret = rawSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
    auto photoTask = photoTask_.Get();
    CHECK_EXECUTE(photoTask == nullptr, InitCaptureThread());
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register rawConsumer failed:%{public}d", ret);
    return;
}

int32_t HStreamCapture::SetPhotoAssetAvailableCallback(const sptr<IStreamCapturePhotoAssetCallback> &callback)
{
    MEDIA_INFO_LOG("HSetPhotoAssetAvailableCallback E, isYuv:%{public}d", isYuvCapture_);
    CHECK_RETURN_RET_ELOG(
        surface_ == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetPhotoAssetAvailableCallback surface is null");
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetPhotoAssetAvailableCallback callback is null");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    photoAssetAvaiableCallback_ = callback;
    // register photoAsset surface buffer consumer
    if (photoAssetListener_ == nullptr) {
        photoAssetListener_ = new (std::nothrow) PhotoAssetBufferConsumer(this);
    }
    surface_->UnregisterConsumerListener();
    SurfaceError ret = surface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoAssetListener_);
    auto photoTask = photoTask_.Get();
    CHECK_EXECUTE(photoTask == nullptr, InitCaptureThread());
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "registerConsumerListener failed:%{public}d", ret);
    // register auxiliary buffer consumer
    CHECK_EXECUTE(isYuvCapture_, RegisterAuxiliaryConsumers());
    return CAMERA_OK;
}

int32_t HStreamCapture::UnSetPhotoAssetAvailableCallback()
{
    MEDIA_INFO_LOG("HUnSetPhotoAssetAvailableCallback E");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    photoAssetAvaiableCallback_ = nullptr;
    photoAssetListener_ = nullptr;
    return CAMERA_OK;
}

int32_t HStreamCapture::RequireMemorySize(int32_t requiredMemSizeKB)
{
    #ifdef MEMMGR_OVERRID
    int32_t pid = getpid();
    const std::string reason = "HW_CAMERA_TO_PHOTO";
    std::string clientName = SYSTEM_CAMERA;
    int32_t ret = Memory::MemMgrClient::GetInstance().RequireBigMem(pid, reason, requiredMemSizeKB, clientName);
    MEDIA_INFO_LOG("HCameraDevice::RequireMemory reason:%{public}s, clientName:%{public}s, ret:%{public}d",
        reason.c_str(), clientName.c_str(), ret);
    if (ret == 0) {
        return CAMERA_OK;
    }
    #endif
    return CAMERA_UNKNOWN_ERROR;
}

int32_t HStreamCapture::SetThumbnailCallback(const sptr<IStreamCaptureThumbnailCallback> &callback)
{
    MEDIA_INFO_LOG("HSetThumbnailCallback E");
    CHECK_RETURN_RET_ELOG(
        thumbnailSurface_ == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetThumbnailCallback surface is null");
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetThumbnailCallback callback is null");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    thumbnailAvaiableCallback_ = callback;
    // register thumbnail buffer consumer
    if (thumbnailListener_ == nullptr) {
        thumbnailListener_ = new (std::nothrow) ThumbnailBufferConsumer(this);
    }
    thumbnailSurface_->UnregisterConsumerListener();
    MEDIA_INFO_LOG("SetThumbnailCallback GetUniqueId: %{public}" PRIu64, thumbnailSurface_->GetUniqueId());
    SurfaceError ret = thumbnailSurface_->RegisterConsumerListener(
        (sptr<IBufferConsumerListener> &)thumbnailListener_);
    CHECK_EXECUTE(thumbnailTask_ == nullptr, InitCaptureThread());
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "registerConsumerListener failed:%{public}d", ret);
    return CAMERA_OK;
}

int32_t HStreamCapture::UnSetThumbnailCallback()
{
    MEDIA_INFO_LOG("HUnSetThumbnailCallback E");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    thumbnailAvaiableCallback_ = nullptr;
    thumbnailListener_ = nullptr;
    if (thumbnailSurface_) {
        thumbnailSurface_->UnregisterConsumerListener();
    }
    return CAMERA_OK;
}

void HStreamCapture::InitCaptureThread()
{
    MEDIA_INFO_LOG("HStreamCapture::InitCaptureThread E");
    auto photoTask = photoTask_.Get();
    if (photoTask == nullptr) {
        photoTask_.Set(std::make_shared<DeferredProcessing::TaskManager>("photoTask", TASKMANAGER_ONE, false));
    }
    if (isYuvCapture_ && photoSubTask_ == nullptr) {
        photoSubTask_ = std::make_shared<DeferredProcessing::TaskManager>("photoSubTask", TASKMANAGER_FOUR, false);
    }
    if (thumbnailSurface_ && thumbnailTask_ == nullptr) {
        thumbnailTask_ = std::make_shared<DeferredProcessing::TaskManager>("thumbnailTask", TASKMANAGER_ONE, false);
    }
}

void HStreamCapture::RegisterAuxiliaryConsumers()
{
    MEDIA_INFO_LOG("RegisterAuxiliaryConsumers E");
    CHECK_RETURN_ELOG(pictureAssembler_ == nullptr, "pictureAssembler is null");
    pictureAssembler_->RegisterAuxiliaryConsumers();
}

// LCOV_EXCL_START
int32_t HStreamCapture::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamCaptureCallback_ = nullptr;
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t HStreamCapture::OnCaptureStarted(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr, streamCaptureCallback_->OnCaptureStarted(captureId));
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureStarted(int32_t captureId, uint32_t exposureTime)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr,
        streamCaptureCallback_->OnCaptureStarted(captureId, exposureTime));
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureEnded(int32_t captureId, int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr, streamCaptureCallback_->OnCaptureEnded(captureId, frameCount));
    MEDIA_INFO_LOG("HStreamCapture::Capture, notify OnCaptureEnded with capture ID: %{public}d", captureId);
    int32_t offlineOutputCnt = mSwitchToOfflinePhoto_ ?
        HStreamOperatorManager::GetInstance()->GetOfflineOutputSize() : 0;
    CameraReportUtils::GetInstance().SetCapturePerfEndInfo(captureId, mSwitchToOfflinePhoto_, offlineOutputCnt);
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_INFO_LOG("HStreamCapture::OnCaptureEnded capturId = %{public}d already used, need release",
                       preparedCaptureId);
        ResetCaptureId();
        captureIdForConfirmCapture_ = CAPTURE_ID_UNSET;
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureError(int32_t captureId, int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        // LCOV_EXCL_START
        int32_t captureErrorCode;
        if (errorCode == BUFFER_LOST) {
            captureErrorCode = CAMERA_STREAM_BUFFER_LOST;
        } else {
            captureErrorCode = CAMERA_UNKNOWN_ERROR;
        }
        CAMERA_SYSEVENT_FAULT(CreateMsg("Photo OnCaptureError! captureId:%d & "
                                        "errorCode:%{public}d", captureId, captureErrorCode));
        streamCaptureCallback_->OnCaptureError(captureId, captureErrorCode);
        // LCOV_EXCL_STOP
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        // LCOV_EXCL_START
        MEDIA_INFO_LOG("HStreamCapture::OnCaptureError capturId = %{public}d already used, need release",
                       preparedCaptureId);
        ResetCaptureId();
        captureIdForConfirmCapture_ = CAPTURE_ID_UNSET;
        // LCOV_EXCL_STOP
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnFrameShutter(int32_t captureId, uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr,
        streamCaptureCallback_->OnFrameShutter(captureId, timestamp));
    return CAMERA_OK;
}

int32_t HStreamCapture::OnFrameShutterEnd(int32_t captureId, uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr,
        streamCaptureCallback_->OnFrameShutterEnd(captureId, timestamp));
    if (isBursting_) {
        burstNum_++;
        MEDIA_DEBUG_LOG("HStreamCapture::OnFrameShutterEnd burstNum:%{public}d", burstNum_);
    }
    return CAMERA_OK;
}


int32_t HStreamCapture::OnCaptureReady(int32_t captureId, uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_INFO_LOG("HStreamCapture::Capture, notify OnCaptureReady with capture ID: %{public}d", captureId);
    isCaptureReady_ = true;
    CHECK_EXECUTE(streamCaptureCallback_ != nullptr,
        streamCaptureCallback_->OnCaptureReady(captureId, timestamp));
    std::lock_guard<std::mutex> burstLock(burstLock_);
    if (IsBurstCapture(captureId)) {
        burstNumMap_[captureId] = burstNum_;
        ResetBurst();
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp, bool isRaw)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAvailable is called!");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    auto photoAvaiableCallback = photoAvaiableCallback_.Get();
    if (photoAvaiableCallback != nullptr) {
        photoAvaiableCallback->OnPhotoAvailable(surfaceBuffer, timestamp, isRaw);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnPhotoAssetAvailable(
    const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAssetAvailable is called!");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    if (photoAssetAvaiableCallback_ != nullptr) {
        photoAssetAvaiableCallback_->OnPhotoAssetAvailable(captureId, uri, cameraShotType, burstKey);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnThumbnailAvailable is called!");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    if (thumbnailAvaiableCallback_ != nullptr) {
        thumbnailAvaiableCallback_->OnThumbnailAvailable(surfaceBuffer, timestamp);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::EnableOfflinePhoto(bool isEnable)
{
    mEnableOfflinePhoto_ = isEnable;
    return CAMERA_OK;
}

bool HStreamCapture::IsHasEnableOfflinePhoto()
{
    return mEnableOfflinePhoto_;
}

void HStreamCapture::SwitchToOffline()
{
    mSwitchToOfflinePhoto_ = true;
    streamOperatorOffline_ = GetStreamOperator();
}

bool HStreamCapture::IsHasSwitchToOffline()
{
    return mSwitchToOfflinePhoto_;
}

void HStreamCapture::DumpStreamInfo(CameraInfoDumper& infoDumper)
{
    infoDumper.Title("capture stream");
    infoDumper.Msg("ThumbnailSwitch:[" + std::to_string(thumbnailSwitch_) + "]");
    infoDumper.Msg("RawDeliverSwitch:[" + std::to_string(rawDeliverySwitch_) + "]");
    if (thumbnailBufferQueue_) {
        infoDumper.Msg(
            "ThumbnailBuffer producer Id:[" + std::to_string(thumbnailBufferQueue_->producer_->GetUniqueId()) + "]");
    }
    HStreamCommon::DumpStreamInfo(infoDumper);
}

int32_t HStreamCapture::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IStreamCaptureIpcCode>(interfaceCode)) {
        case IStreamCaptureIpcCode::COMMAND_CAPTURE: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_RETURN_RET_ELOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HStreamCapture::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                "is %{public}d", callerToken_, callerToken);
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "HStreamCapture::OperatePermissionCheck fail");
    switch (static_cast<IStreamCaptureIpcCode>(code)) {
        case IStreamCaptureIpcCode::COMMAND_SET_THUMBNAIL:
        case IStreamCaptureIpcCode::COMMAND_ENABLE_RAW_DELIVERY:
        case IStreamCaptureIpcCode::COMMAND_DEFER_IMAGE_DELIVERY_FOR:
        case IStreamCaptureIpcCode::COMMAND_CONFIRM_CAPTURE:
        case IStreamCaptureIpcCode::COMMAND_ENABLE_OFFLINE_PHOTO : {
            CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamCapture::CheckSystemApp fail");
            break;
        }
        case IStreamCaptureIpcCode::COMMAND_ENABLE_MOVING_PHOTO: {
            uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
            int32_t errCode = CheckPermission(OHOS_PERMISSION_MICROPHONE, callerToken);
            CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, CAMERA_NO_PERMISSION, "check microphone permission failed.");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

int32_t HStreamCapture::IsDeferredPhotoEnabled()
{
    MEDIA_INFO_LOG("HStreamCapture IsDeferredPhotoEnabled  deferredPhotoSwitch_: %{public}d", deferredPhotoSwitch_);
    CHECK_RETURN_RET(deferredPhotoSwitch_ == 1, 1);
    MEDIA_INFO_LOG("HStreamCapture IsDeferredPhotoEnabled return 0");
    return 0;
}

int32_t HStreamCapture::IsDeferredVideoEnabled()
{
    MEDIA_INFO_LOG("HStreamCapture IsDeferredVideoEnabled  deferredVideoSwitch_: %{public}d", deferredVideoSwitch_);
    CHECK_RETURN_RET(deferredVideoSwitch_ == 1, 1);
    return 0;
}

int32_t HStreamCapture::GetMovingPhotoVideoCodecType()
{
    MEDIA_INFO_LOG("HStreamCapture GetMovingPhotoVideoCodecType videoCodecType_: %{public}d", videoCodecType_);
    return videoCodecType_;
}

int32_t HStreamCapture::SetMovingPhotoVideoCodecType(int32_t videoCodecType)
{
    MEDIA_INFO_LOG("HStreamCapture SetMovingPhotoVideoCodecType videoCodecType_: %{public}d", videoCodecType);
    videoCodecType_ = videoCodecType;
    return 0;
}

int32_t HStreamCapture::SetCameraPhotoRotation(bool isEnable)
{
    enableCameraPhotoRotation_ = isEnable;
    return 0;
}

// LCOV_EXCL_START
void HStreamCapture::GetLocation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting)
{
    MEDIA_INFO_LOG("GetLocation E");
    camera_metadata_item_t item;
    const int32_t targetCount = 2;
    const int32_t latIndex = 0;
    const int32_t lonIndex = 1;
    const int32_t altIndex = 2;
    int result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting->get(), OHOS_JPEG_GPS_COORDINATES, &item);
    if (result == CAM_META_SUCCESS && item.count > targetCount) {
        latitude_ = item.data.d[latIndex];
        longitude_ = item.data.d[lonIndex];
        altitude_ = item.data.d[altIndex];
    }
}

void HStreamCapture::SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy)
{
    MEDIA_INFO_LOG("SetCameraPhotoProxyInfo get captureStream");
    cameraPhotoProxy->SetDisplayName(CreateDisplayName(format_ == OHOS_CAMERA_FORMAT_HEIC ? suffixHeif : suffixJpeg));
    cameraPhotoProxy->SetShootingMode(GetMode());
    MEDIA_INFO_LOG("SetCameraPhotoProxyInfo quality:%{public}d, format:%{public}d",
        cameraPhotoProxy->GetPhotoQuality(), cameraPhotoProxy->GetFormat());
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    CHECK_RETURN(hStreamOperatorSptr_ == nullptr);

    camera_metadata_item_t item;
    if (hStreamOperatorSptr_->GetDeviceAbilityByMeta(OHOS_ABILITY_MOVING_PHOTO_MICRO_VIDEO_ENHANCE, &item)) {
        uint8_t status = item.data.u8[0];
        cameraPhotoProxy->SetStageVideoTaskStatus(status);
    }
}

int32_t HStreamCapture::UpdateMediaLibraryPhotoAssetProxy(sptr<CameraServerPhotoProxy> cameraPhotoProxy)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(
        isBursting_ || (GetMode() == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO)),
        CAMERA_UNSUPPORTED);
    const int32_t updateMediaLibraryStep = 1;
    if (!photoAssetProxy_.WaitForUnlock(cameraPhotoProxy->GetCaptureId(), updateMediaLibraryStep, GetMode(),
                                        std::chrono::seconds(1))) {
        return CAMERA_UNKNOWN_ERROR;
    }
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = photoAssetProxy_.Get(cameraPhotoProxy->GetCaptureId());
    CHECK_RETURN_RET_ELOG(
        photoAssetProxy == nullptr, CAMERA_UNKNOWN_ERROR, "HStreamCapture UpdateMediaLibraryPhotoAssetProxy failed");
    MEDIA_DEBUG_LOG(
        "HStreamCapture UpdateMediaLibraryPhotoAssetProxy E captureId(%{public}d)", cameraPhotoProxy->GetCaptureId());
    SetCameraPhotoProxyInfo(cameraPhotoProxy);
    MEDIA_DEBUG_LOG("HStreamCapture AddPhotoProxy E");
    photoAssetProxy->AddPhotoProxy(cameraPhotoProxy);
    MEDIA_DEBUG_LOG("HStreamCapture AddPhotoProxy X");
    photoAssetProxy_.IncreaseCaptureStep(cameraPhotoProxy->GetCaptureId());
    MEDIA_DEBUG_LOG(
        "HStreamCapture UpdateMediaLibraryPhotoAssetProxy X captureId(%{public}d)", cameraPhotoProxy->GetCaptureId());
    return CAMERA_OK;
}

void HStreamCapture::SetStreamOperator(wptr<HStreamOperator> hStreamOperator)
{
    hStreamOperator_ = hStreamOperator;
}

int32_t HStreamCapture::CreateMediaLibrary(std::shared_ptr<PictureIntf> picture,
    sptr<CameraServerPhotoProxy> &cameraPhotoProxy, std::string &uri, int32_t &cameraShotType, std::string &burstKey,
    int64_t timestamp)
{
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    if (hStreamOperatorSptr_) {
        CHECK_RETURN_RET_ELOG(
            cameraPhotoProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CreateMediaLibrary with null PhotoProxy");
        cameraPhotoProxy->SetLatitude(latitude_);
        cameraPhotoProxy->SetLongitude(longitude_);
        hStreamOperatorSptr_->CreateMediaLibrary(picture, cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::CreateMediaLibrary(sptr<CameraServerPhotoProxy> &cameraPhotoProxy, std::string &uri,
    int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    if (hStreamOperatorSptr_) {
        CHECK_RETURN_RET_ELOG(
            cameraPhotoProxy == nullptr, CAMERA_UNKNOWN_ERROR, "CreateMediaLibrary with null PhotoProxy");
        cameraPhotoProxy->SetLatitude(latitude_);
        cameraPhotoProxy->SetLongitude(longitude_);
        hStreamOperatorSptr_->CreateMediaLibrary(cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::CreateMediaLibrary(const sptr<CameraPhotoProxy> &photoProxy, std::string &uri,
    int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    MessageParcel data;
    photoProxy->WriteToParcel(data);
    photoProxy->CameraFreeBufferHandle();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->ReadFromParcel(data);
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    CHECK_RETURN_RET_ELOG(!hStreamOperatorSptr_, CAMERA_UNKNOWN_ERROR, "CreateMediaLibrary with null operator");
    CHECK_RETURN_RET_ELOG(!cameraPhotoProxy, CAMERA_UNKNOWN_ERROR, "CreateMediaLibrary with null photoProxy");
    cameraPhotoProxy->SetLatitude(latitude_);
    cameraPhotoProxy->SetLongitude(longitude_);
    hStreamOperatorSptr_->CreateMediaLibrary(cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp);
    return CAMERA_OK;
}
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS
