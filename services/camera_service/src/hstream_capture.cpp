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
#include <algorithm>
#include <functional>
#include <memory>
#include <uuid.h>

#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "camera_report_uitls.h"
#include "camera_server_photo_proxy.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "photo_asset_interface.h"
#include "photo_asset_proxy.h"
#include "metadata_utils.h"
#include "camera_report_dfx_uitls.h"
#include "bms_adapter.h"
#include "picture_interface.h"
#include "hstream_operator_manager.h"
#include "hstream_operator.h"
#include "hcamera_device.h"
#include "camera_metadata.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "picture_proxy.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif
#include "camera_buffer_manager/photo_buffer_consumer.h"
#include "camera_buffer_manager/photo_asset_buffer_consumer.h"
#include "camera_buffer_manager/photo_asset_auxiliary_consumer.h"
#include "camera_buffer_manager/thumbnail_buffer_consumer.h"
#include "camera_buffer_manager/picture_assembler.h"
#include "camera_surface_buffer_util.h"
#include "watch_dog.h"
#include "image_receiver.h"
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#include "mem_mgr_constant.h"
#endif
#include "task_manager.h"
#include <string>
#include "res_sched_client.h"
#include "res_type.h"
#include "json_parse.h"
#include "v1_7/types.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::HDI::Display::Graphic::Common::V2_1;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
static const int32_t CAPTURE_ROTATE_360 = 360;
static const int8_t PHOTO_ASSET_TIMEOUT = 10;
static const std::string BURST_UUID_BEGIN = "";
static std::string g_currentBurstUuid = BURST_UUID_BEGIN;
static const uint32_t TASKMANAGER_ONE = 1;
static const int32_t AUXILIARY_PHOTO_TYPE_OXYGEN = 0;
static const int32_t AUXILIARY_PHOTO_TYPE_PIGMENTATION = 1;
static const float AUX_PHOTO_DEFAULT_ZOOM_RATIO = 1.0f;
#ifdef CAMERA_CAPTURE_YUV
static const uint32_t PHOTO_SAVE_MAX_NUM = 3;
static const uint32_t PHOTO_STATE_TIMEOUT = 20; // 20s
static std::atomic<uint32_t> g_unsavedPhotoCount = 0;
static std::mutex g_captureReadyMutex;
static std::condition_variable g_captureReadyCv;
#endif

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
#ifdef CAMERA_MOVING_PHOTO
    movingPhotoSwitch_ = 0;
#endif
}

HStreamCapture::HStreamCapture(int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::CAPTURE, format, width, height)
{
    // LCOV_EXCL_START
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
#ifdef CAMERA_MOVING_PHOTO
    movingPhotoSwitch_ = 0;
#endif
    isYuvCapture_ = format == OHOS_CAMERA_FORMAT_YCRCB_420_SP;
#ifdef CAMERA_CAPTURE_YUV
    g_unsavedPhotoCount = 0;
#endif
    CreateCaptureSurface();
    // LCOV_EXCL_STOP
}

void HStreamCapture::CreateCaptureSurface()
{
    // LCOV_EXCL_START
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
    // LCOV_EXCL_STOP
}

void HStreamCapture::CreateAuxiliarySurfaces()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CreateAuxiliarySurfaces E");
    CHECK_RETURN_ELOG(pictureAssembler_ != nullptr, "pictureAssembler has been set");
    pictureAssembler_ = new (std::nothrow) PictureAssembler(this);
    CHECK_RETURN_ELOG(pictureAssembler_ == nullptr, "create pictureAssembler faild");

    std::string retStr = "";
    int32_t ret = 0;
    auto gainmapSurfaceObj = gainmapSurface_.Get();
    if (gainmapSurfaceObj == nullptr) {
        std::string bufferName = "gainmapImage";
        gainmapSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        gainmapSurfaceObj = gainmapSurface_.Get();
        if (gainmapSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliarySurfaces 1 surfaceId: %{public}" PRIu64, gainmapSurfaceObj->GetUniqueId());
            ret = SetBufferProducerInfo(bufferName, gainmapSurfaceObj->GetProducer());
            retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
        }
    }
    auto deepSurfaceObj = deepSurface_.Get();
    if (deepSurfaceObj == nullptr) {
        std::string bufferName = "deepImage";
        deepSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        deepSurfaceObj = deepSurface_.Get();
        if (deepSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliarySurfaces 2 surfaceId: %{public}" PRIu64, deepSurfaceObj->GetUniqueId());
            ret = SetBufferProducerInfo(bufferName, deepSurfaceObj->GetProducer());
            retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
        }
    }
    auto exifSurfaceObj = exifSurface_.Get();
    if (exifSurfaceObj == nullptr) {
        std::string bufferName = "exifImage";
        exifSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        exifSurfaceObj = exifSurface_.Get();
        if (exifSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliarySurfaces 3 surfaceId: %{public}" PRIu64, exifSurfaceObj->GetUniqueId());
            ret = SetBufferProducerInfo(bufferName, exifSurfaceObj->GetProducer());
            retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
        }
    }
    auto debugSurfaceObj = debugSurface_.Get();
    if (debugSurfaceObj == nullptr) {
        std::string bufferName = "debugImage";
        debugSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        debugSurfaceObj = debugSurface_.Get();
        if (debugSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliarySurfaces 4 surfaceId: %{public}" PRIu64, debugSurfaceObj->GetUniqueId());
            ret = SetBufferProducerInfo(bufferName, debugSurfaceObj->GetProducer());
            retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
        }
    }
    auto lhdrGainmapSurfaceObj = lhdrGainmapSurface_.Get();
    if (lhdrGainmapSurfaceObj == nullptr) {
        std::string bufferName = "lhdrGainmapImage";
        lhdrGainmapSurface_.Set(Surface::CreateSurfaceAsConsumer(bufferName));
        lhdrGainmapSurfaceObj = lhdrGainmapSurface_.Get();
        if (lhdrGainmapSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliarySurfaces 5 surfaceId: %{public}" PRIu64,
                lhdrGainmapSurfaceObj->GetUniqueId());
            ret = SetBufferProducerInfo(bufferName, lhdrGainmapSurfaceObj->GetProducer());
            retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
        }
    }
    MEDIA_INFO_LOG("CreateAuxiliarySurfaces X, res:%{public}s", retStr.c_str());
    // LCOV_EXCL_STOP
}

HStreamCapture::~HStreamCapture()
{
    // LCOV_EXCL_START
    auto photoTask = photoTask_.Get();
    if (photoTask != nullptr) {
        photoTask->CancelAllTasks();
        photoTask_.Set(nullptr);
    }
    if (photoSubExifTask_ != nullptr) {
        photoSubExifTask_->CancelAllTasks();
        photoSubExifTask_ = nullptr;
    }
    if (photoSubGainMapTask_ != nullptr) {
        photoSubGainMapTask_->CancelAllTasks();
        photoSubGainMapTask_ = nullptr;
    }
    if (photoSubDebugTask_ != nullptr) {
        photoSubDebugTask_->CancelAllTasks();
        photoSubDebugTask_ = nullptr;
    }
    if (photoSubDeepTask_ != nullptr) {
        photoSubDeepTask_->CancelAllTasks();
        photoSubDeepTask_ = nullptr;
    }
    if (photoSubAuxPhotoTask_ != nullptr) {
        photoSubAuxPhotoTask_->CancelAllTasks();
        photoSubAuxPhotoTask_ = nullptr;
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

void HStreamCapture::FillingPictureExtendStreamInfos(StreamInfo_V1_5 &streamInfo, int32_t format)
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

void HStreamCapture::FillingRawAndThumbnailStreamInfo(StreamInfo_V1_5 &streamInfo)
{
    bool isRawDeliveryEnabled = rawDeliverySwitch_ && format_ != OHOS_CAMERA_FORMAT_DNG_XDRAW;
    if (isRawDeliveryEnabled) {
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
    CHECK_RETURN(!thumbnailSwitch_);
    MEDIA_DEBUG_LOG("HStreamCapture::SetStreamInfo Set thumbnail info, dataspace:%{public}d", dataSpace_);
    int32_t pixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    pixelFormat = dataSpace_ == CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL ? GRAPHIC_PIXEL_FMT_YCRCB_P010 : pixelFormat;
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo = {
        .type = HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL,
        .width = 0,
        .height = 0,
        .format = pixelFormat,   // HDR: YCRCB_P010 P3: nv21
        .dataspace = dataSpace_, // HDR: BT2020_HLG_FULL P3: P3
        .bufferQueue = thumbnailBufferQueue_.Get(),
    };
    streamInfo.extendedStreamInfos.push_back(extendedStreamInfo);
}

void HStreamCapture::FillingPictureExtendLhdrGainmapStreamInfos(StreamInfo_V1_5 &streamInfo)
{
    MEDIA_INFO_LOG("HStreamCapture::FillingPictureExtendLhdrGainmapStreamInfos enter.");
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
    streamInfo.v1_0.format_ = GRAPHIC_PIXEL_FMT_YCRCB_420_SP; // NV21
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo = {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_7::EXTENDED_STREAM_OHOS_ENHANCED_GAINMAP),
        .width = width_,
        .height = height_,
        .format = GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
        .dataspace = dataSpace_,
        .bufferQueue = lhdrGainmapBufferQueue_.Get(),
    };
    streamInfo.extendedStreamInfos.push_back(extendedStreamInfo);
}

void HStreamCapture::FillingAuxiliaryPhotoStreamInfos(StreamInfo_V1_5 &streamInfo, int32_t format)
{
    // Snapshot the enabled types under the lock, the switch vector is written by the enable IPC.
    std::vector<int32_t> enabledTypes;
    {
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        enabledTypes = enabledAuxPhotoTypes_;
    }
    if (enabledTypes.empty()) {
        return;
    }
    MEDIA_INFO_LOG("HStreamCapture::FillingAuxiliaryPhotoStreamInfos enter, format:%{public}d", format);
    auto fillAuxStreamInfo = [this, &streamInfo, format](int32_t hdiExtendedType,
        const sptr<BufferProducerSequenceable>& bufferQueue) {
        if (bufferQueue == nullptr) {
            return;
        }
        HDI::Camera::V1_1::ExtendedStreamInfo auxStreamInfo = {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(hdiExtendedType),
            .width = width_ / 2, // auxiliary photo size is half of the main photo
            .height = height_ / 2,
            .format = format,
            .dataspace = static_cast<int32_t>(CM_ColorSpaceType_V2_1::CM_SRGB_FULL),
            .bufferQueue = bufferQueue,
        };
        streamInfo.extendedStreamInfos.push_back(auxStreamInfo);
    };
    for (auto type : enabledTypes) {
        if (type == AUXILIARY_PHOTO_TYPE_OXYGEN) {
            fillAuxStreamInfo(HDI::Camera::V1_7::EXTENDED_STREAM_INFO_OXYGEN_PHOTO, oxygenBufferQueue_.Get());
        } else if (type == AUXILIARY_PHOTO_TYPE_PIGMENTATION) {
            fillAuxStreamInfo(HDI::Camera::V1_7::EXTENDED_STREAM_INFO_PIGMENTATION_PHOTO,
                pigmentationBufferQueue_.Get());
        }
    }
}

void HStreamCapture::CreateAuxiliaryPhotoSurfaces()
{
    MEDIA_INFO_LOG("HStreamCapture::CreateAuxiliaryPhotoSurfaces E");
    if (photoSubAuxPhotoTask_ == nullptr) {
        photoSubAuxPhotoTask_ = std::make_shared<DeferredProcessing::TaskManager>(
            "photoSubAuxPhotoTask_", TASKMANAGER_ONE, false);
    }
    SurfaceError ret;
    auto oxygenSurfaceObj = oxygenSurface_.Get();
    if (oxygenSurfaceObj == nullptr) {
        oxygenSurface_.Set(Surface::CreateSurfaceAsConsumer("oxygenImage"));
        oxygenSurfaceObj = oxygenSurface_.Get();
        if (oxygenSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliaryPhotoSurfaces oxygen surfaceId: %{public}" PRIu64,
                oxygenSurfaceObj->GetUniqueId());
            oxygenBufferQueue_.Set(new BufferProducerSequenceable(oxygenSurfaceObj->GetProducer()));
            oxygenListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_OXYGEN_PHOTO, this);
            CHECK_RETURN_ELOG(oxygenListener_ == nullptr, "oxygenListener_ is null");
            ret = oxygenSurfaceObj->RegisterConsumerListener((sptr<IBufferConsumerListener> &)oxygenListener_);
            CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register oxygen consumer failed:%{public}d", ret);
        }
    }
    auto pigmentationSurfaceObj = pigmentationSurface_.Get();
    if (pigmentationSurfaceObj == nullptr) {
        pigmentationSurface_.Set(Surface::CreateSurfaceAsConsumer("pigmentationImage"));
        pigmentationSurfaceObj = pigmentationSurface_.Get();
        if (pigmentationSurfaceObj != nullptr) {
            MEDIA_INFO_LOG("CreateAuxiliaryPhotoSurfaces pigmentation surfaceId: %{public}" PRIu64,
                pigmentationSurfaceObj->GetUniqueId());
            pigmentationBufferQueue_.Set(
                new BufferProducerSequenceable(pigmentationSurfaceObj->GetProducer()));
            pigmentationListener_ = new (std::nothrow) AuxiliaryBufferConsumer(S_PIGMENTATION_PHOTO, this);
            CHECK_RETURN_ELOG(pigmentationListener_ == nullptr, "pigmentationListener_ is null");
            ret = pigmentationSurfaceObj->RegisterConsumerListener(
                (sptr<IBufferConsumerListener> &)pigmentationListener_);
            CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register pigmentation consumer failed:%{public}d", ret);
        }
    }
    MEDIA_INFO_LOG("HStreamCapture::CreateAuxiliaryPhotoSurfaces X");
}

void HStreamCapture::SetDataSpaceForCapture(StreamInfo_V1_5 &streamInfo)
{
    // LCOV_EXCL_START
    switch (streamInfo.v1_0.dataspace_) {
        case CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL:
        case CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT:
            // HDR Video Session need P3 for captureStream
            streamInfo.v1_0.dataspace_ =  CM_ColorSpaceType_V2_1::CM_P3_FULL;
            break;
        case CM_ColorSpaceType_V2_1::CM_BT709_LIMIT:
            // SDR Video Session need SRGB for captureStream
            streamInfo.v1_0.dataspace_ = CM_ColorSpaceType_V2_1::CM_SRGB_FULL;
            break;
        default:
            break;
    }
    // LCOV_EXCL_STOP
    MEDIA_DEBUG_LOG("HStreamCapture::SetDataSpaceForCapture current HDI dataSpace: %{public}d",
        streamInfo.v1_0.dataspace_);
}

void HStreamCapture::SetStreamInfo(StreamInfo_V1_5 &streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    MEDIA_INFO_LOG("HStreamCapture::SetStreamInfo streamId:%{public}d format:%{public}d", GetFwkStreamId(), format_);
    streamInfo.v1_0.intent_ = STILL_CAPTURE;

    // 录像抓拍场景下添加拍照流的色域信息转换
    SetDataSpaceForCapture(streamInfo);

    // LCOV_EXCL_START
    if (format_ == OHOS_CAMERA_FORMAT_HEIC) {
        streamInfo.v1_0.encodeType_ =
            static_cast<HDI::Camera::V1_0::EncodeType>(HDI::Camera::V1_3::ENCODE_TYPE_HEIC);
        streamInfo.v1_0.format_ = GRAPHIC_PIXEL_FMT_BLOB;
        FillingAuxiliaryPhotoStreamInfos(streamInfo, GRAPHIC_PIXEL_FMT_BLOB);
    } else if (format_ == OHOS_CAMERA_FORMAT_YCRCB_420_SP) { // NV21
        streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
        streamInfo.v1_0.format_ = GRAPHIC_PIXEL_FMT_YCRCB_420_SP; // NV21
        if (GetMode() != static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::TIMELAPSE_PHOTO)) {
            FillingPictureExtendStreamInfos(streamInfo, GRAPHIC_PIXEL_FMT_YCRCB_420_SP);
        }
        bool isDeferredImageDeliveryEnabled = false;
        auto hStreamOperatorSptr = hStreamOperator_.promote();
        CHECK_EXECUTE(hStreamOperatorSptr != nullptr,
            isDeferredImageDeliveryEnabled = hStreamOperatorSptr->GetDeferredImageDeliveryEnabled());
        if (isNeedLhdrGainmap_ && !isDeferredImageDeliveryEnabled) {
            FillingPictureExtendLhdrGainmapStreamInfos(streamInfo);
        }
        FillingAuxiliaryPhotoStreamInfos(streamInfo, GRAPHIC_PIXEL_FMT_YCRCB_420_SP);
    } else if (format_ == OHOS_CAMERA_FORMAT_DNG_XDRAW) {
        streamInfo.v1_0.encodeType_ =
            static_cast<HDI::Camera::V1_0::EncodeType>(HDI::Camera::V1_4::ENCODE_TYPE_DNG_XDRAW);
    } else if (format_ == OHOS_CAMERA_FORMAT_DNG) {
    } else {
        streamInfo.v1_0.encodeType_ = ENCODE_TYPE_JPEG;
        FillingAuxiliaryPhotoStreamInfos(streamInfo, GRAPHIC_PIXEL_FMT_BLOB);
    }
    // LCOV_EXCL_STOP
    FillingRawAndThumbnailStreamInfo(streamInfo);
}

int32_t HStreamCapture::SetThumbnail(bool isEnabled)
{
    MEDIA_INFO_LOG("HStreamCapture::SetThumbnail E, isEnabled:%{public}d", isEnabled);
    if (isEnabled) {
        thumbnailSwitch_ = 1;
        thumbnailSurface_.Set(Surface::CreateSurfaceAsConsumer("quickThumbnail"));
        auto thumbnailSurfaceObj = thumbnailSurface_.Get();
        CHECK_RETURN_RET_ELOG(thumbnailSurfaceObj == nullptr, CAMERA_OK, "thumbnail surface create faild");
        thumbnailBufferQueue_.Set(new BufferProducerSequenceable(thumbnailSurfaceObj->GetProducer()));
    } else {
        thumbnailSwitch_ = 0;
        thumbnailSurface_.Set(nullptr);
        thumbnailBufferQueue_.Set(nullptr);
    }
    MEDIA_INFO_LOG("HStreamCapture::SetThumbnail thumbnailSwitch_:%{public}d", thumbnailSwitch_);
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
#ifdef CAMERA_MOVING_PHOTO
    if (enabled) {
        movingPhotoSwitch_ = 1;
    } else {
        movingPhotoSwitch_ = 0;
    }
#endif
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
    if (bufName == "lhdrGainmapImage") {
        if (producer != nullptr) {
            lhdrGainmapBufferQueue_.Set(new BufferProducerSequenceable(producer));
        } else {
            lhdrGainmapBufferQueue_.Set(nullptr);
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
    bool isAllMapsErased =
        burstkeyMap_.erase(captureId) > 0 && burstImagesMap_.erase(captureId) > 0 && burstNumMap_.erase(captureId) > 0;
    if (isAllMapsErased) {
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
    return iter != burstImagesMap_.end() ? static_cast<int64_t>(iter->second.size()) : -1;
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
    bool isBurstKeyResettable = numIter != burstNumMap_.end() && imageIter != burstImagesMap_.end();
    if (isBurstKeyResettable) {
        // LCOV_EXCL_START
        int32_t burstSum = numIter->second;
        size_t curBurstSum = imageIter->second.size();
        MEDIA_DEBUG_LOG("CheckResetBurstKey: burstSum=%d, curBurstSum=%zu", burstSum, curBurstSum);
        if (static_cast<size_t>(burstSum) == curBurstSum) {
            ResetBurstKey(captureId);
        }
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
    bool isBurstModeEnabled = result == CAM_META_SUCCESS && item.count > 0;
    if (isBurstModeEnabled) {
        // LCOV_EXCL_START
        CameraBurstCaptureEnum burstState = static_cast<CameraBurstCaptureEnum>(item.data.u8[0]);
        MEDIA_INFO_LOG("CheckBurstCapture get burstState:%{public}d", item.data.u8[0]);
        if (burstState) {
            std::string burstUuid = GetBurstKey(preparedCaptureId);
            CHECK_RETURN_RET_ELOG(
                burstUuid != BURST_UUID_UNSET || isBursting_, CAMERA_INVALID_STATE, "CheckBurstCapture faild!");
            PrepareBurst(preparedCaptureId);
            MEDIA_INFO_LOG("CheckBurstCapture ready!");
        }
    }
    // LCOV_EXCL_STOP
    return CAM_META_SUCCESS;
}

#ifdef CAMERA_CAPTURE_YUV
int32_t HStreamCapture::OnPhotoAvailable(std::shared_ptr<PictureIntf> picture)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAvailable picture is called!");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    auto photoAvaiableCallback = photoAvaiableCallback_.Get();
    if (photoAvaiableCallback != nullptr) {
        photoAvaiableCallback->OnPhotoAvailable(picture);
    }
    return CAMERA_OK;
}


std::shared_ptr<PhotoAssetIntf> HStreamCapture::GetPhotoAssetInstanceForPub(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    const int32_t getPhotoAssetStep = 1;
    if (!photoAssetProxy_.WaitForUnlock(captureId, getPhotoAssetStep, GetMode(), std::chrono::seconds(1))) {
        MEDIA_ERR_LOG("GetPhotoAsset faild wait timeout, captureId:%{public}d", captureId);
        return nullptr;
    }
    std::shared_ptr<PhotoAssetIntf> proxy = photoAssetProxy_.Get(captureId);
    photoAssetProxy_.Erase(captureId);
    return proxy;
}

void PhotoLevelManager::SetPhotoLevelInfo(int32_t pictureId, bool level)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    photoLevelMap_[pictureId] = level;
}

bool PhotoLevelManager::GetPhotoLevelInfo(int32_t pictureId)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto it = photoLevelMap_.find(pictureId);
    if (it != photoLevelMap_.end()) {
        return it->second;
    }
    return false;
}

void PhotoLevelManager::ClearPhotoLevelInfo()
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    photoLevelMap_.clear();
}
#endif

namespace {
// Mutex tag rules for oxygen/pigmentation auxiliary photo delivery: a rule conflicts when the
// app-submitted configuration carries a conflicting control value. Scoped to tags the framework
// can observe; watermark/night-enhancement/personalized-color-card have no control tag and are
// backstopped by HAL.
struct AuxPhotoMutexTagRule {
    const char* name;
    uint32_t tag;
    std::function<bool(const camera_metadata_item_t& item)> isConflict;
};

const std::vector<AuxPhotoMutexTagRule>& GetAuxPhotoMutexTagRules()
{
    static const std::vector<AuxPhotoMutexTagRule> rules = {
        {"beauty", OHOS_CONTROL_BEAUTY_TYPE, [](const camera_metadata_item_t& item) {
            return item.data.u8[0] != OHOS_CAMERA_BEAUTY_TYPE_OFF;
        }},
        {"zoomRatio", OHOS_CONTROL_ZOOM_RATIO, [](const camera_metadata_item_t& item) {
            return item.data.f[0] != AUX_PHOTO_DEFAULT_ZOOM_RATIO;
        }},
        {"macro", OHOS_CONTROL_CAMERA_MACRO, [](const camera_metadata_item_t& item) {
            return item.data.u8[0] == OHOS_CAMERA_MACRO_ENABLE;
        }},
        {"virtualAperture", OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE,
            [](const camera_metadata_item_t& item) { return item.data.f[0] > 0; }},
        {"autoHighQuality", OHOS_CONTROL_HIGH_QUALITY_MODE, [](const camera_metadata_item_t& item) {
            return item.data.u8[0] != 0;
        }},
        {"cloudImageEnhance", OHOS_CONTROL_AUTO_CLOUD_IMAGE_ENHANCE, [](const camera_metadata_item_t& item) {
            return item.data.u8[0] != 0;
        }},
        {"aigcPhoto", OHOS_CONTROL_AUTO_AIGC_PHOTO, [](const camera_metadata_item_t& item) {
            return item.data.u8[0] != 0;
        }},
    };
    return rules;
}

bool IsAuxPhotoMutexHitInMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    for (const auto& rule : GetAuxPhotoMutexTagRules()) {
        camera_metadata_item_t item;
        int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), rule.tag, &item);
        if (ret == CAM_META_SUCCESS && item.count > 0 && rule.isConflict(item)) {
            MEDIA_ERR_LOG("AuxPhotoMutex rule hit: %{public}s", rule.name);
            return true;
        }
    }
    return false;
}
}

int32_t HStreamCapture::CheckAuxiliaryPhotoMutex()
{
    MEDIA_INFO_LOG("HStreamCapture::CheckAuxiliaryPhotoMutex E");
    // Only single-segment capture is supported: deferred (multi-segment) photo conflicts.
    if (deferredPhotoSwitch_ == 1) {
        MEDIA_ERR_LOG("CheckAuxiliaryPhotoMutex deferred photo (multi-segment) is enabled");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    // The photo asset callback is the segmented photo delivery channel and is mutually exclusive
    // with auxiliary photos, which are delivered only via onCapturePhotoAvailable.
    if (photoAssetAvaiableCallback_ != nullptr) {
        MEDIA_ERR_LOG("CheckAuxiliaryPhotoMutex photo asset callback is registered");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    auto hStreamOperatorSptr = hStreamOperator_.promote();
    CHECK_RETURN_RET_ELOG(hStreamOperatorSptr == nullptr, CAMERA_OK,
        "HStreamCapture::CheckAuxiliaryPhotoMutex hStreamOperator is null, skip check");
    auto cameraDevice = hStreamOperatorSptr->GetCameraDevice();
    CHECK_RETURN_RET_ELOG(cameraDevice == nullptr, CAMERA_OK,
        "HStreamCapture::CheckAuxiliaryPhotoMutex cameraDevice is null, skip check");
    // Scan the cached settings under the device lock without cloning: this check runs per
    // capture, a full metadata deep copy on the hot path is too expensive.
    bool isMutexHit = false;
    cameraDevice->ReadCachedSettings(
        [&isMutexHit](const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) {
            isMutexHit = IsAuxPhotoMutexHitInMetadata(settings);
        });
    CHECK_RETURN_RET_ELOG(isMutexHit, CAMERA_OPERATION_NOT_ALLOWED,
        "HStreamCapture::CheckAuxiliaryPhotoMutex mutex rule hit");
    MEDIA_INFO_LOG("HStreamCapture::CheckAuxiliaryPhotoMutex X, no mutex conflict");
    return CAMERA_OK;
}

int32_t HStreamCapture::SetAutoAuxiliaryPhotosDeliveryEnabled(
    const std::vector<int32_t>& auxPhotoTypes, bool enabled)
{
    MEDIA_INFO_LOG("HStreamCapture::SetAutoAuxiliaryPhotosDeliveryEnabled E, enabled:%{public}d, size:%{public}zu",
        enabled, auxPhotoTypes.size());
    constexpr size_t maxAuxiliaryPhotoCount = 2;
    if (auxPhotoTypes.empty()) {
        // An empty enable list is invalid, an empty disable list is a no-op.
        CHECK_RETURN_RET_ELOG(enabled, CAMERA_INVALID_ARG,
            "SetAutoAuxiliaryPhotosDeliveryEnabled enable with an empty type list");
        return CAMERA_OK;
    }
    bool isTypesInvalid = auxPhotoTypes.size() > maxAuxiliaryPhotoCount;
    for (size_t i = 0; !isTypesInvalid && i < auxPhotoTypes.size(); i++) {
        isTypesInvalid = (auxPhotoTypes[i] != AUXILIARY_PHOTO_TYPE_OXYGEN &&
            auxPhotoTypes[i] != AUXILIARY_PHOTO_TYPE_PIGMENTATION) ||
            std::find(auxPhotoTypes.begin() + static_cast<std::ptrdiff_t>(i) + 1, auxPhotoTypes.end(),
                auxPhotoTypes[i]) != auxPhotoTypes.end();
    }
    if (isTypesInvalid) {
        MEDIA_ERR_LOG("SetAutoAuxiliaryPhotosDeliveryEnabled auxPhotoTypes is invalid");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
    // Per-type incremental switch: enable merges the types into the enabled set, disable removes
    // them, so a type enabled or disabled by an earlier call is kept unless it is in this list.
    std::vector<int32_t> newTypes = enabledAuxPhotoTypes_;
    for (auto auxPhotoType : auxPhotoTypes) {
        auto it = std::find(newTypes.begin(), newTypes.end(), auxPhotoType);
        if (enabled && it == newTypes.end()) {
            newTypes.push_back(auxPhotoType);
        } else if (!enabled && it != newTypes.end()) {
            newTypes.erase(it);
        }
    }
    bool isChanged = (newTypes != enabledAuxPhotoTypes_);
    if (enabled) {
        int32_t ret = CheckAuxiliaryPhotoMutex();
        CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
            "SetAutoAuxiliaryPhotosDeliveryEnabled mutex check failed: %{public}d", ret);
        CreateAuxiliaryPhotoSurfaces();
    }
    enabledAuxPhotoTypes_ = newTypes;
    // The control tag is delivered after CommitStreams on the next config commit (deferred-effective);
    // mark dirty only when there is a non-empty type set to send, an empty set cannot be written as
    // a metadata entry (count 0 is rejected by the metadata API).
    if (isChanged) {
        isAuxControlTagDirty_ = !enabledAuxPhotoTypes_.empty();
    }
    MEDIA_INFO_LOG("HStreamCapture::SetAutoAuxiliaryPhotosDeliveryEnabled X, size:%{public}zu, dirty:%{public}d",
        enabledAuxPhotoTypes_.size(), isAuxControlTagDirty_.load());
    return CAMERA_OK;
}

bool HStreamCapture::IsAuxPhotoEnabled()
{
    std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
    return !enabledAuxPhotoTypes_.empty();
}

bool HStreamCapture::IsAuxPhotoDegraded(int32_t captureId)
{
    std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
    auto itDegrade = captureIdAuxDegradeMap_.find(captureId);
    return itDegrade != captureIdAuxDegradeMap_.end() && itDegrade->second != 0;
}

uint32_t HStreamCapture::GetArrivedAuxPhotoCount(int32_t captureId)
{
    std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
    uint32_t arrivedCount = 0;
    if (captureIdOxygenMap_.count(captureId) > 0) {
        arrivedCount++;
    }
    if (captureIdPigmentationMap_.count(captureId) > 0) {
        arrivedCount++;
    }
    return arrivedCount;
}

uint32_t HStreamCapture::StartAuxPhotoWatchdog(int32_t captureId, int64_t timestamp)
{
    uint32_t pictureHandle = 0;
    constexpr uint32_t delayMilli = 1 * 1000;
    wptr<HStreamCapture> thisPtr(this);
    DeferredProcessing::Watchdog::GetGlobalWatchdog().StartMonitor(
        pictureHandle, delayMilli, [thisPtr, captureId, timestamp](uint32_t handle) {
            MEDIA_INFO_LOG("StartWaitAuxPhotoTask Watchdog executed, handle: %{public}d, captureId:%{public}d",
                static_cast<int>(handle), captureId);
            auto ptr = thisPtr.promote();
            CHECK_RETURN(ptr == nullptr);
            ptr->AssembleCompressedPhotoWithAux(timestamp, captureId);
        });
    return pictureHandle;
}

// Caller must hold g_photoImageMutex.
bool HStreamCapture::ArmAuxPhotoConsumerTrigger(int32_t captureId, uint32_t pictureHandle,
    uint32_t expectedCount)
{
    captureIdHandleMap_[captureId] = pictureHandle;
    captureIdCountMap_[captureId] = static_cast<int32_t>(expectedCount);
    int32_t arrivedCount = captureIdAuxiliaryCountMap_.count(captureId) > 0 ?
        captureIdAuxiliaryCountMap_[captureId] : 0;
    // True when all auxiliary buffers arrived while the monitor was being registered.
    return arrivedCount != -1 && arrivedCount >= static_cast<int32_t>(expectedCount);
}

void HStreamCapture::StartWaitAuxPhotoTask(int32_t captureId, int64_t timestamp,
    sptr<SurfaceBuffer>& mainBuffer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("StartWaitAuxPhotoTask E, captureId:%{public}d", captureId);
    uint32_t expectedCount = 0;
    bool isComplete = false;
    {
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        if (captureIdMainPhotoMap_.count(captureId) > 0) {
            MEDIA_WARNING_LOG("StartWaitAuxPhotoTask captureId:%{public}d already waiting", captureId);
            return;
        }
        captureIdMainPhotoMap_[captureId] = mainBuffer;
        int32_t imageCount = CameraSurfaceBufferUtil::GetImageCount(mainBuffer);
        int32_t imageAuxCount = imageCount - 1;
        expectedCount = imageAuxCount > 0 ? static_cast<uint32_t>(imageAuxCount) : 0;
        // Auxiliary buffers may have arrived before the main photo, check by map presence.
        uint32_t arrivedCount = GetArrivedAuxPhotoCount(captureId);
        isComplete = arrivedCount >= expectedCount;
        MEDIA_INFO_LOG("StartWaitAuxPhotoTask expect auxiliary photos, captureId:%{public}d, "
            "imageCount:%{public}d, expectedCount:%{public}u, arrivedCount:%{public}u",
            captureId, imageCount, expectedCount, arrivedCount);
    }
    // Assemble outside the lock: the delivery callback sends an IPC, keep the photo mutex hold
    // time minimal. The main photo map guard in the assemble makes re-entry a no-op.
    if (isComplete) {
        MEDIA_INFO_LOG("StartWaitAuxPhotoTask auxiliary photos complete, captureId:%{public}d", captureId);
        AssembleCompressedPhotoWithAux(timestamp, captureId);
        return;
    }
    uint32_t pictureHandle = StartAuxPhotoWatchdog(captureId, timestamp);
    {
        // Arm the consumer trigger only after the handle is stored, so the consumer equality
        // path never fires DoTimeout with an unset (zero) handle.
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        isComplete = ArmAuxPhotoConsumerTrigger(captureId, pictureHandle, expectedCount);
    }
    if (isComplete) {
        DeferredProcessing::Watchdog::GetGlobalWatchdog().StopMonitor(pictureHandle);
        AssembleCompressedPhotoWithAux(timestamp, captureId);
        return;
    }
    MEDIA_INFO_LOG("StartWaitAuxPhotoTask monitor started, pictureHandle:%{public}u, captureId:%{public}d",
        pictureHandle, captureId);
}

void HStreamCapture::AssembleCompressedPhotoWithAux(int64_t timestamp, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AssembleCompressedPhotoWithAux E, captureId:%{public}d", captureId);
    sptr<SurfaceBuffer> mainBuffer = nullptr;
    sptr<SurfaceBuffer> oxygenBuffer = nullptr;
    sptr<SurfaceBuffer> pigmentationBuffer = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        auto itMain = captureIdMainPhotoMap_.find(captureId);
        if (itMain == captureIdMainPhotoMap_.end()) {
            MEDIA_WARNING_LOG("AssembleCompressedPhotoWithAux captureId:%{public}d already assembled", captureId);
            return;
        }
        mainBuffer = itMain->second;
        captureIdMainPhotoMap_.erase(itMain);
        auto itOxygen = captureIdOxygenMap_.find(captureId);
        if (itOxygen != captureIdOxygenMap_.end() && itOxygen->second != nullptr) {
            oxygenBuffer = itOxygen->second;
        }
        auto itPigmentation = captureIdPigmentationMap_.find(captureId);
        if (itPigmentation != captureIdPigmentationMap_.end() && itPigmentation->second != nullptr) {
            pigmentationBuffer = itPigmentation->second;
        }
        // Do not stop the watchdog here: the manual-trigger path (consumer DoTimeout) invokes this
        // function synchronously with the watchdog mutex held, and a nested StopMonitor would
        // deadlock on that non-recursive mutex. The callers stop the monitor themselves, and a late
        // timeout fire is a no-op due to the main photo map guard above.
        CleanAuxPhotoState(captureId);
        captureIdHandleMap_.erase(captureId);
        captureIdAuxiliaryCountMap_.erase(captureId);
        captureIdCountMap_.erase(captureId);
    }
    CHECK_RETURN_ELOG(mainBuffer == nullptr, "AssembleCompressedPhotoWithAux mainBuffer is nullptr");
    OnPhotoAvailable(mainBuffer, oxygenBuffer, pigmentationBuffer, timestamp, false);
    MEDIA_INFO_LOG("AssembleCompressedPhotoWithAux X, captureId:%{public}d", captureId);
}

void HStreamCapture::SendAuxiliaryPhotoControlTagIfDirty()
{
    if (!isAuxControlTagDirty_.load()) {
        return;
    }
    // Snapshot the enabled types under the lock, the switch vector is written by the enable IPC.
    std::vector<int32_t> controlTypes;
    {
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        for (auto type : enabledAuxPhotoTypes_) {
            controlTypes.push_back(type);
        }
    }
    if (controlTypes.empty()) {
        // Nothing valid to send: an empty type set cannot be written as a metadata entry
        // (count 0 is rejected by the metadata API), the disable takes effect through the
        // stream configuration (aux streams are removed on the next commit).
        isAuxControlTagDirty_ = false;
        return;
    }
    MEDIA_INFO_LOG("SendAuxiliaryPhotoControlTagIfDirty E, size:%{public}zu", controlTypes.size());
    constexpr int32_t defaultItemCount = 1;
    constexpr int32_t defaultDataLength = 8;
    auto changedMetadata = std::make_shared<OHOS::Camera::CameraMetadata>(defaultItemCount, defaultDataLength);
    CHECK_RETURN_ELOG(changedMetadata == nullptr, "SendAuxiliaryPhotoControlTagIfDirty metadata is null");
    bool status = AddOrUpdateMetadata(changedMetadata, OHOS_CONTROL_AUTO_AUXILIARY_PHOTOS_DELIVERY,
        controlTypes.data(), controlTypes.size());
    CHECK_RETURN_ELOG(!status, "SendAuxiliaryPhotoControlTagIfDirty AddOrUpdateMetadata failed");
    auto hStreamOperatorSptr = hStreamOperator_.promote();
    CHECK_RETURN_ELOG(hStreamOperatorSptr == nullptr, "SendAuxiliaryPhotoControlTagIfDirty operator is null");
    auto cameraDevice = hStreamOperatorSptr->GetCameraDevice();
    CHECK_RETURN_ELOG(cameraDevice == nullptr, "SendAuxiliaryPhotoControlTagIfDirty cameraDevice is null");
    // Tag delivery failure does not roll back the committed streams: keep the dirty flag so the
    // next successful commit retries.
    int32_t errCode = cameraDevice->UpdateSetting(changedMetadata);
    CHECK_RETURN_ELOG(errCode != CAMERA_OK, "SendAuxiliaryPhotoControlTagIfDirty UpdateSetting failed: %{public}d",
        errCode);
    isAuxControlTagDirty_ = false;
    MEDIA_INFO_LOG("SendAuxiliaryPhotoControlTagIfDirty X");
}

void HStreamCapture::CleanAuxPhotoState(int32_t captureId)
{
    std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
    captureIdAuxDegradeMap_.erase(captureId);
    captureIdOxygenMap_.erase(captureId);
    captureIdPigmentationMap_.erase(captureId);
    captureIdMainPhotoMap_.erase(captureId);
    captureIdHandleMap_.erase(captureId);
    captureIdAuxiliaryCountMap_.erase(captureId);
    captureIdCountMap_.erase(captureId);
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
    bool isOperationRequired = mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::CAPTURE) ||
        mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::QUICK_SHOT_PHOTO) ||
        mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PORTRAIT) ||
        mode == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::CAPTURE_MACRO);
    return isOperationRequired ? step_.count(key) > 0 && step_[key] == step : map_.count(key) > 0;
}

// LCOV_EXCL_START
void ConcurrentMap::IncreaseCaptureStep(const int32_t& key)
{
    std::lock_guard<std::mutex> lock(map_mutex_);
    CHECK_RETURN(key < 0 || key > INT32_MAX);
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
#ifdef CAMERA_CAPTURE_YUV
    PhotoLevelManager::GetInstance().ClearPhotoLevelInfo();
#endif
}

int32_t HStreamCapture::SetEditData(const std::string& editData)
{
    MEDIA_INFO_LOG("SetEditData: %{public}s", editData.c_str());
    std::lock_guard<std::mutex> lock(editDataLock_);
    editData_ = editData;
    return SUCCESS;
}

int32_t HStreamCapture::SetShotParam(int32_t captureId, const std::string& shotParam)
{
    MEDIA_INFO_LOG("SetShotParam captureId:%{public}d: %{public}s", captureId, shotParam.c_str());
    std::lock_guard<std::mutex> lock(editDataLock_);
    if (!IsOriginalImageEnable()) {
        return SUCCESS;
    }
    auto it = captureId2EditData_.find(captureId);
    std::string editData;
    if (it != captureId2EditData_.end()) {
        editData = it->second;
        editData = MergeShotParam(editData, shotParam);
        captureId2EditData_[captureId] = editData;
        MEDIA_INFO_LOG("SetShotParam editData update to: %{public}s", editData.c_str());
    } else {
        MEDIA_ERR_LOG("not found captureId:%{public}d", captureId);
    }
    return SUCCESS;
}

int32_t HStreamCapture::EnableOriginalImage(bool enabled)
{
    MEDIA_INFO_LOG("EnableOriginalImage: %{public}d", enabled);
    std::lock_guard<std::mutex> lock(editDataLock_);
    enableOriginImage_ = enabled;
    return SUCCESS;
}

int32_t HStreamCapture::SetEditData(int32_t captureId, const std::string& editData)
{
    MEDIA_INFO_LOG("SetEditData: captureId:%{public}d, editData:%{public}s", captureId, editData.c_str());
    std::lock_guard<std::mutex> lock(editDataLock_);
    captureId2EditData_[captureId] = editData;
    return SUCCESS;
}

std::string HStreamCapture::GetEditData(int32_t captureId)
{
    std::lock_guard<std::mutex> lock(editDataLock_);
    if (!IsOriginalImageEnable()) {
        return "";
    }
    auto it = captureId2EditData_.find(captureId);
    std::string editData;
    if (it != captureId2EditData_.end()) {
        editData = it->second;
        captureId2EditData_.erase(it);
        return editData;
    }
    MEDIA_ERR_LOG("not found captureId:%{public}d", captureId);
    return "";
}

bool HStreamCapture::IsOriginalImageEnable()
{
    return enableOriginImage_;
}

int32_t HStreamCapture::CreateMediaLibraryPhotoAssetProxy(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("HStreamCapture CreateMediaLibraryPhotoAssetProxy E");
    constexpr int32_t imageShotType = 0;
    constexpr int32_t burstShotType = 3;
    int32_t cameraShotType = imageShotType;
#ifdef CAMERA_MOVING_PHOTO
    constexpr int32_t movingPhotoShotType = 2;
    if (movingPhotoSwitch_) {
        cameraShotType = movingPhotoShotType;
    } else if (isBursting_) {
        cameraShotType = burstShotType;
    }
#else
    if (isBursting_) {
        cameraShotType = burstShotType;
    }
#endif
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(
        cameraShotType, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingTokenID(), 0, enableOriginImage_ ? 2 : 1);
    if (photoAssetProxy == nullptr) {
        HILOG_COMM_ERROR("HStreamCapture::CreateMediaLibraryPhotoAssetProxy get photoAssetProxy fail");
        CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::MEDIALIBRARY_ERROR, captureId);
        return CAMERA_ALLOC_ERROR;
    }
    photoAssetProxy_.Insert(captureId, photoAssetProxy);
    MEDIA_INFO_LOG("CreateMediaLibraryPhotoAssetProxy X captureId:%{public}d", captureId);
    return CAMERA_OK;
}

std::shared_ptr<PhotoAssetIntf> HStreamCapture::GetPhotoAssetInstance(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    const int32_t getPhotoAssetStep = IsOriginalImageEnable() ? 1 : 2;
    CHECK_RETURN_RET_ELOG(!photoAssetProxy_.WaitForUnlock(
                              captureId, getPhotoAssetStep, GetMode(), std::chrono::seconds(PHOTO_ASSET_TIMEOUT)),
        nullptr, "GetPhotoAsset faild wait timeout, captureId:%{public}d", captureId);
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
    CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::CAPTURE_FWK, CAPTURE_ID_UNSET);
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamCapture::Capture failed, stream not linked (hdi operator null), streamId:%{public}d",
        GetFwkStreamId());
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(isCaptureReady_ == false, CAMERA_CAPTURE_NOT_READY,
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
    // Auxiliary photos apply to normal single captures only. Burst captures and captures whose
    // mutex conditions drifted after enable (e.g. zoom/beauty changed) degrade to main photo
    // delivery without waiting for auxiliary buffers.
    if (IsAuxPhotoEnabled()) {
        // Burst always degrades: check it first so the burst shots skip the expensive
        // mutex re-check (CloneCachedSettings per capture).
        bool isDegraded = IsBurstCapture(preparedCaptureId) || (CheckAuxiliaryPhotoMutex() != CAMERA_OK);
        std::lock_guard<std::recursive_mutex> lock{g_photoImageMutex};
        captureIdAuxDegradeMap_[preparedCaptureId] = isDegraded ? 1 : 0;
        MEDIA_INFO_LOG("Capture aux degrade flag, captureId:%{public}d, degraded:%{public}d",
            preparedCaptureId, isDegraded);
    }

    CaptureDfxInfo captureDfxInfo;
    captureDfxInfo.captureId = preparedCaptureId;
    captureDfxInfo.pid = IPCSkeleton::GetCallingPid();
    captureDfxInfo.isSystemApp = CheckSystemApp();
    captureDfxInfo.bundleName = BmsAdapter::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
    CameraReportDfxUtils::GetInstance()->SetFirstBufferStartInfo(captureDfxInfo);

    CaptureInfo captureInfoPhoto;
    captureInfoPhoto.streamIds_ = { GetHdiStreamId() };
    ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings, preparedCaptureId);

    AddCameraPermissionUsedRecord();

    // report capture performance dfx
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureMetadataSetting_ = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(captureInfoPhoto.captureSetting_, captureMetadataSetting_);
    if (captureMetadataSetting_ == nullptr) {
        captureMetadataSetting_ = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    DfxCaptureInfo captureInfo;
    captureInfo.captureId = preparedCaptureId;
    captureInfo.caller = CameraReportUtils::GetCallerInfo();
    int32_t rotation = 0;
    rotationMap_.Find(preparedCaptureId, rotation);
    captureInfo.rotation = rotation;
    CameraReportUtils::GetInstance().SetCapturePerfStartInfo(captureInfo);
    CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::CAPTURE_START, preparedCaptureId);
    MEDIA_DEBUG_LOG("HStreamCapture::Capture is Bursting_ %{public}d", isBursting_);
    HILOG_COMM_INFO("HStreamCapture::Capture Starting photo capture with capture ID: %{public}d", preparedCaptureId);
    HStreamCommon::PrintCaptureDebugLog(captureMetadataSetting_);
#ifdef CAMERA_CAPTURE_YUV
    bool isSystemApp = CheckSystemApp();
    PhotoLevelManager::GetInstance().SetPhotoLevelInfo(preparedCaptureId, isSystemApp);
    MEDIA_INFO_LOG("HStreamCapture::Capture SetPhotoLevelInfo captureId:%{public}d isSystemApp:%{public}d",
        preparedCaptureId, isSystemApp);
#endif
    if (!editData_.empty()) {
        MEDIA_INFO_LOG("HStreamCapture::Capture SetEditData captureId:%{public}d, editData:%{public}s",
            preparedCaptureId, editData_.c_str());
        SetEditData(preparedCaptureId, editData_);
    }
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
        CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::HAL_ERROR, preparedCaptureId);
        ret = HdiToServiceError(rc);
    }
    camera_metadata_item_t item;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN_RET_ELOG(
            cameraAbility_ == nullptr, CAMERA_INVALID_STATE, "HStreamCapture::cameraAbility_ is null");
        int32_t result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION,
                                                              &item);
        bool isCameraPositionValid = result == CAM_META_SUCCESS && item.count > 0;
        if (isCameraPositionValid) {
            cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        }
    }

    bool isNightMode = (GetMode() == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::NIGHT));
    bool isNightModeAndBackCamera = isNightMode && cameraPosition == OHOS_CAMERA_POSITION_BACK;
    if (photoAssetAvaiableCallback_ != nullptr && isNightModeAndBackCamera) {
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy E");
        CHECK_PRINT_ELOG(CreateMediaLibraryPhotoAssetProxy(preparedCaptureId) != CAMERA_OK,
            "HStreamCapture::Capture Failed with CreateMediaLibraryPhotoAssetProxy");
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy X");
        return ret;
    }
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
    if (photoAssetAvaiableCallback_ != nullptr && !isBursting_) {
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy E");
        CHECK_PRINT_ELOG(CreateMediaLibraryPhotoAssetProxy(preparedCaptureId) != CAMERA_OK,
            "HStreamCapture::Capture Failed with CreateMediaLibraryPhotoAssetProxy");
        MEDIA_DEBUG_LOG("HStreamCapture::Capture CreateMediaLibraryPhotoAssetProxy X");
#ifdef CAMERA_CAPTURE_YUV
        if (!isSystemApp && isYuvCapture_) {
            g_unsavedPhotoCount++;
            MEDIA_INFO_LOG("HStreamCapture::Capture current unsaved photo count: %{public}d",
                g_unsavedPhotoCount.load());
            CHECK_EXECUTE(photoStateCallback_ == nullptr,
                photoStateCallback_ = HStreamCapture::OnPhotoStateCallback);
            auto mediaLibraryManagerProxy = MediaLibraryManagerProxy::GetMediaLibraryManagerProxy();
            CHECK_RETURN_RET_ELOG(mediaLibraryManagerProxy == nullptr, CAMERA_ALLOC_ERROR,
                "HStreamCapture::Capture get MediaLibraryManagerProxy fail");
            std::call_once(photoStateFlag_, [&]() {
                MEDIA_DEBUG_LOG("HStreamCapture::Capture RegisterPhotoStateCallback is called");
                mediaLibraryManagerProxy->RegisterPhotoStateCallback(photoStateCallback_);
            });
        }
#endif
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
    if (captureMetadataSetting_ == nullptr) {
        captureMetadataSetting_ = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
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
        result = GetCorrectedCameraOrientation(
            usePhysicalCameraOrientation_, sensorOrientation, cameraAbility_, HStreamCommon::GetClientName());
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
    CHECK_RETURN_ELOG(!CameraRotatePlugin::GetInstance()->HookCaptureStreamStart(GetBasicInfo(), rotation, isMirror),
        "HStreamRepeat::HookCaptureStreamStart is failed %{public}d", isMirror);
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
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamCapture::ConfirmCapture failed, stream not linked (hdi operator null)");
    // LCOV_EXCL_START
    int32_t ret = 0;

    // end burst capture
    if (isBursting_) {
        MEDIA_INFO_LOG("HStreamCapture::ConfirmCapture when burst capture");
        std::vector<uint8_t> settingVector;
        std::shared_ptr<OHOS::Camera::CameraMetadata> burstCaptureSettings = nullptr;
        {
            std::lock_guard<std::mutex> lock(cameraAbilityLock_);
            OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, settingVector);
        }
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
#ifdef CAMERA_CAPTURE_YUV
    if (photoStateCallback_) {
        MEDIA_DEBUG_LOG("HStreamCapture::Release UnregisterPhotoStateCallback is called");
        auto mediaLibraryManagerProxy = MediaLibraryManagerProxy::GetMediaLibraryManagerProxy();
        CHECK_EXECUTE(mediaLibraryManagerProxy,
            mediaLibraryManagerProxy->UnregisterPhotoStateCallback());
        photoStateCallback_ = nullptr;
    }
    MediaLibraryManagerProxy::FreeMediaLibraryDynamiclibDelayed();
#endif
    int32_t errorCode = HStreamCommon::ReleaseStream(isDelay);
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    bool isSwitchToOfflinePhoto = hStreamOperatorSptr_ && mSwitchToOfflinePhoto_;
    if (isSwitchToOfflinePhoto) {
        hStreamOperatorSptr_->Release();
    }
    std::lock_guard<std::mutex> lock(streamOperatorLock_);
    if (streamOperatorOffline_ != nullptr) {
        streamOperatorOffline_ = nullptr;
    }
    mSwitchToOfflinePhoto_ = false;
    return errorCode;
}

int32_t HStreamCapture::SetCallback(const sptr<IStreamCaptureCallback> &callback)
{
    // LCOV_ECL_START
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetCallback input is null");
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_DEBUG_LOG("HStreamCapture::SetCallback");
    streamCaptureCallback_ = callback;
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::SetPhotoAvailableCallback(const sptr<IStreamCapturePhotoCallback> &callback)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HSetPhotoAvailableCallback E");
    CHECK_RETURN_RET_ELOG(surface_ == nullptr, CAMERA_INVALID_ARG, "HSetPhotoAvailableCallback surface is null");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HSetPhotoAvailableCallback callback is null");
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
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register photoConsume failed:%{public}d", ret);
    // register auxiliary buffer consumer
#ifdef CAMERA_CAPTURE_YUV
    CHECK_EXECUTE(!CheckSystemApp() && isYuvCapture_, RegisterAuxiliaryConsumers());
#endif
    return CAMERA_OK;
    // LCOV_EXCL_STOP
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
    // LCOV_EXCL_START
    auto rawSurface = rawSurface_.Get();
    CHECK_RETURN_ELOG(rawSurface == nullptr, "HStreamCapture::SetRawCallbackUnLock callback is null");
    photoListener_.Set(nullptr);
    photoListener_.Set(new (std::nothrow) PhotoBufferConsumer(this, true));
    auto photoListener = photoListener_.Get();
    rawSurface->UnregisterConsumerListener();
    SurfaceError ret = rawSurface->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoListener);
    auto photoTask = photoTask_.Get();
    CHECK_EXECUTE(photoTask == nullptr, InitCaptureThread());
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register rawConsumer failed:%{public}d", ret);
    return;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::SetPhotoAssetAvailableCallback(const sptr<IStreamCapturePhotoAssetCallback> &callback)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HSetPhotoAssetAvailableCallback E, isYuv:%{public}d", isYuvCapture_);
    CHECK_RETURN_RET_ELOG(
        surface_ == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetPhotoAssetAvailableCallback surface is null");
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetPhotoAssetAvailableCallback callback is null");
    // Segmented photo delivery (photo asset callback) is mutually exclusive with auxiliary
    // photos, which are delivered only via onCapturePhotoAvailable.
    CHECK_RETURN_RET_ELOG(IsAuxPhotoEnabled(), CAMERA_OPERATION_NOT_ALLOWED,
        "HStreamCapture::SetPhotoAssetAvailableCallback auxiliary photos are enabled");
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
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::UnSetPhotoAssetAvailableCallback()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HUnSetPhotoAssetAvailableCallback E");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    photoAssetAvaiableCallback_ = nullptr;
    photoAssetListener_ = nullptr;
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::RequireMemorySize(int32_t requiredMemSizeKB)
{
    // LCOV_EXCL_START
    #ifdef MEMMGR_OVERRID
    int32_t pid = getpid();
    const std::string reason = "HW_CAMERA_TO_PHOTO";
    std::string clientName = SYSTEM_CAMERA;
    int32_t ret = Memory::MemMgrClient::GetInstance().RequireBigMem(pid, reason, requiredMemSizeKB, clientName);
    MEDIA_INFO_LOG("HCameraDevice::RequireMemory reason:%{public}s, clientName:%{public}s, ret:%{public}d",
        reason.c_str(), clientName.c_str(), ret);
    CHECK_RETURN_RET(ret == 0, CAMERA_OK);
    #endif
    return CAMERA_UNKNOWN_ERROR;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::SetThumbnailCallback(const sptr<IStreamCaptureThumbnailCallback> &callback)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HSetThumbnailCallback E");
    auto thumbnailSurfaceObj = thumbnailSurface_.Get();
    CHECK_RETURN_RET_ELOG(
        thumbnailSurfaceObj == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetThumbnailCallback surface is null");
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetThumbnailCallback callback is null");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    thumbnailAvaiableCallback_ = callback;
    // register thumbnail buffer consumer
    if (thumbnailListener_ == nullptr) {
        thumbnailListener_ = new (std::nothrow) ThumbnailBufferConsumer(this);
    }
    thumbnailSurfaceObj->UnregisterConsumerListener();
    MEDIA_INFO_LOG("SetThumbnailCallback GetUniqueId: %{public}" PRIu64, thumbnailSurfaceObj->GetUniqueId());
    SurfaceError ret = thumbnailSurfaceObj->RegisterConsumerListener(
        (sptr<IBufferConsumerListener> &)thumbnailListener_);
    CHECK_EXECUTE(thumbnailTask_ == nullptr, InitCaptureThread());
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "registerConsumerListener failed:%{public}d", ret);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::UnSetThumbnailCallback()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HUnSetThumbnailCallback E");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    thumbnailAvaiableCallback_ = nullptr;
    thumbnailListener_ = nullptr;
    auto thumbnailSurfaceObj = thumbnailSurface_.Get();
    if (thumbnailSurfaceObj) {
        thumbnailSurfaceObj->UnregisterConsumerListener();
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void HStreamCapture::InitCaptureThread()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HStreamCapture::InitCaptureThread E");
    wptr<HStreamCapture> thisPtr(this);
    auto photoTask = photoTask_.Get();
    if (photoTask == nullptr) {
        photoTask_.Set(std::make_shared<DeferredProcessing::TaskManager>("photoTask", TASKMANAGER_ONE, false));
        photoTask = photoTask_.Get();
        photoTask->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate asset thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    if (isYuvCapture_ && photoSubExifTask_ == nullptr) {
        photoSubExifTask_ = std::make_shared<DeferredProcessing::TaskManager>("photoSubExifTask_",
                TASKMANAGER_ONE, false);
        photoSubExifTask_->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate asset thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    if (isYuvCapture_ && photoSubGainMapTask_ == nullptr) {
        photoSubGainMapTask_ = std::make_shared<DeferredProcessing::TaskManager>("photoSubGainMapTask_",
                TASKMANAGER_ONE, false);
        photoSubGainMapTask_->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate gainMap thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    if (isYuvCapture_ && photoSubDebugTask_ == nullptr) {
        photoSubDebugTask_ = std::make_shared<DeferredProcessing::TaskManager>("photoSubDebugTask_",
                TASKMANAGER_ONE, false);
        photoSubDebugTask_->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate debug thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    if (isYuvCapture_ && photoSubDeepTask_ == nullptr) {
        photoSubDeepTask_ = std::make_shared<DeferredProcessing::TaskManager>("photoSubDeepTask_",
                TASKMANAGER_ONE, false);
        photoSubDeepTask_->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate deep thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    if (thumbnailSurface_.Get() && thumbnailTask_ == nullptr) {
        thumbnailTask_ = std::make_shared<DeferredProcessing::TaskManager>("thumbnailTask", TASKMANAGER_ONE, false);
        thumbnailTask_->SubmitTask([thisPtr]() {
            MEDIA_INFO_LOG("initCaptureThread elevate thumbnail thread priority");
            auto hStreamCapture = thisPtr.promote();
            CHECK_EXECUTE(hStreamCapture, hStreamCapture->ElevateThreadPriority());
        });
    }
    // LCOV_EXCL_STOP
}

void HStreamCapture::RegisterAuxiliaryConsumers()
{
    MEDIA_INFO_LOG("RegisterAuxiliaryConsumers E");
    CHECK_RETURN_ELOG(pictureAssembler_ == nullptr, "pictureAssembler is null");
    pictureAssembler_->RegisterAuxiliaryConsumers();
}

int32_t HStreamCapture::UnSetCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamCaptureCallback_ = nullptr;
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::OnCaptureStarted(int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureStarted(captureId);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureStarted(int32_t captureId, uint32_t exposureTime)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureStarted(captureId, exposureTime);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureEnded(int32_t captureId, int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureEnded(captureId, frameCount);
    }
    MEDIA_INFO_LOG("HStreamCapture::Capture, notify OnCaptureEnded with capture ID: %{public}d", captureId);
    int32_t offlineOutputCnt = mSwitchToOfflinePhoto_ ?
        HStreamOperatorManager::GetInstance()->GetOfflineOutputSize() : 0;
    bool isDeferredImageDeliveryEnabled = false;
    auto hStreamOperatorSptr_ = hStreamOperator_.promote();
    CHECK_EXECUTE(hStreamOperatorSptr_ != nullptr,
        isDeferredImageDeliveryEnabled = hStreamOperatorSptr_->GetDeferredImageDeliveryEnabled());
#ifdef CAMERA_MOVING_PHOTO
    CameraReportUtils::GetInstance().SetCapturePerfEndInfo(captureId, mSwitchToOfflinePhoto_, offlineOutputCnt,
        movingPhotoSwitch_, isDeferredImageDeliveryEnabled);
#else
    CameraReportUtils::GetInstance().SetCapturePerfEndInfo(captureId, mSwitchToOfflinePhoto_, offlineOutputCnt,
        false, isDeferredImageDeliveryEnabled);
#endif
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
    // Clean the per-capture auxiliary state BEFORE taking callbackLock_: the buffer consumer
    // path holds g_photoImageMutex and acquires photoCallbackLock_ (via OnPhotoAvailable), so
    // acquiring g_photoImageMutex while holding callbackLock_ here would invert the lock order.
    CleanAuxPhotoState(captureId);
    {
        std::lock_guard<std::recursive_mutex> auxLock{g_photoImageMutex};
        captureIdHandleMap_.erase(captureId);
        captureIdAuxiliaryCountMap_.erase(captureId);
        captureIdCountMap_.erase(captureId);
    }
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
    CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::HAL_ON_ERROR, captureId);
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
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnFrameShutter(captureId, timestamp);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnFrameShutterEnd(int32_t captureId, uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnFrameShutterEnd(captureId, timestamp);
    }
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
#ifdef CAMERA_CAPTURE_YUV
    bool isDeffered = (photoAssetAvaiableCallback_ != nullptr && !isBursting_);
    bool isSystemApp = PhotoLevelManager::GetInstance().GetPhotoLevelInfo(captureId);
    MEDIA_DEBUG_LOG("HStreamCapture::OnCaptureReady with isDeffered:%{public}d, isSystemApp:%{public}d",
        isDeffered, isSystemApp);
    if (!isSystemApp && isYuvCapture_ && isDeffered) {
        std::unique_lock<std::mutex> lock(g_captureReadyMutex);
        MEDIA_DEBUG_LOG("HStreamCapture::OnCaptureReady need limit photoes number, current photoes number:%{public}d",
            g_unsavedPhotoCount.load());
        if (!g_captureReadyCv.wait_for(lock, std::chrono::seconds(PHOTO_STATE_TIMEOUT),
            [=] { return g_unsavedPhotoCount.load() < PHOTO_SAVE_MAX_NUM; })) {
            MEDIA_INFO_LOG("HStreamCapture::OnCaptureReady wait timeout, continue to process");
        }
        isCaptureReady_ = true;
        CHECK_EXECUTE(streamCaptureCallback_ != nullptr,
            streamCaptureCallback_->OnCaptureReady(captureId, timestamp));
    } else {
        isCaptureReady_ = true;
        if (streamCaptureCallback_ != nullptr) {
            streamCaptureCallback_->OnCaptureReady(captureId, timestamp);
        }
    }
#else
    isCaptureReady_ = true;
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureReady(captureId, timestamp);
    }
#endif
    std::lock_guard<std::mutex> burstLock(burstLock_);
    if (IsBurstCapture(captureId)) {
        burstNumMap_[captureId] = burstNum_;
        ResetBurst();
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp, bool isRaw)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAvailable surfaceBuffer is called!");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    auto photoAvaiableCallback = photoAvaiableCallback_.Get();
    if (photoAvaiableCallback != nullptr) {
        photoAvaiableCallback->OnPhotoAvailable(surfaceBuffer, timestamp, isRaw);
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::OnPhotoAvailable(sptr<SurfaceBuffer> mainBuffer, sptr<SurfaceBuffer> oxygenBuffer,
    sptr<SurfaceBuffer> pigmentationBuffer, const int64_t timestamp, bool isRaw)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAvailable with auxiliary is called!");
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    auto photoAvaiableCallback = photoAvaiableCallback_.Get();
    if (photoAvaiableCallback != nullptr) {
        photoAvaiableCallback->OnPhotoAvailable(mainBuffer, oxygenBuffer, pigmentationBuffer, timestamp, isRaw);
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::OnPhotoAssetAvailable(
    const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnPhotoAssetAvailable is called! captureId = %{public}d, "
        "burstKey = %{public}s", captureId, burstKey.c_str());
    std::lock_guard<std::mutex> lock(photoCallbackLock_);
    if (photoAssetAvaiableCallback_ != nullptr) {
        photoAssetAvaiableCallback_->OnPhotoAssetAvailable(captureId, uri, cameraShotType, burstKey);
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, const int64_t timestamp)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::OnThumbnailAvailable is called!");
    std::lock_guard<std::mutex> lock(thumbnailCallbackLock_);
    if (thumbnailAvaiableCallback_ != nullptr) {
        thumbnailAvaiableCallback_->OnThumbnailAvailable(surfaceBuffer, timestamp);
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCapture::EnableOfflinePhoto(bool isEnable)
{
    // LCOV_EXCL_START
    mEnableOfflinePhoto_ = isEnable;
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

bool HStreamCapture::IsHasEnableOfflinePhoto()
{
    return mEnableOfflinePhoto_;
}

void HStreamCapture::SwitchToOffline()
{
    // LCOV_EXCL_START
    mSwitchToOfflinePhoto_ = true;
    std::lock_guard<std::mutex> lock(streamOperatorLock_);
    CHECK_RETURN(streamOperatorOffline_ != nullptr);
    streamOperatorOffline_ = streamOperator_.promote();
    // LCOV_EXCL_STOP
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
    auto thumbnailBufferQueueObject = thumbnailBufferQueue_.Get();
    if (thumbnailBufferQueueObject && thumbnailBufferQueueObject->producer_ != nullptr) {
        infoDumper.Msg("ThumbnailBuffer producer Id:[" + std::to_string(
            thumbnailBufferQueueObject->producer_->GetUniqueId()) + "]");
    }
    HStreamCommon::DumpStreamInfo(infoDumper);
}

int32_t HStreamCapture::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IStreamCaptureIpcCode>(interfaceCode)) {
        case IStreamCaptureIpcCode::COMMAND_CAPTURE: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_RETURN_RET_ELOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HStreamCapture::OperatePermissionCheck fail, callerToken not legal");
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
        case IStreamCaptureIpcCode::COMMAND_SET_EDIT_DATA:
        case IStreamCaptureIpcCode::COMMAND_ENABLE_ORIGINAL_IMAGE:
        case IStreamCaptureIpcCode::COMMAND_ENABLE_OFFLINE_PHOTO : {
            CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamCapture::CheckSystemApp fail");
            break;
        }
        case IStreamCaptureIpcCode::COMMAND_ENABLE_MOVING_PHOTO: {
            // LCOV_EXCL_START
            uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
            int32_t errCode = CheckPermission(OHOS_PERMISSION_MICROPHONE, callerToken);
            CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, CAMERA_NO_PERMISSION, "check microphone permission failed.");
            break;
            // LCOV_EXCL_START
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
    return deferredVideoSwitch_ == 1 ? 1 : 0;
}

#ifdef CAMERA_MOVING_PHOTO
int32_t HStreamCapture::GetMovingPhotoVideoCodecType()
{
    MEDIA_INFO_LOG("HStreamCapture GetMovingPhotoVideoCodecType videoCodecType_: %{public}d", videoCodecType_);
    return videoCodecType_;
}
#endif

int32_t HStreamCapture::SetMovingPhotoVideoCodecType(int32_t videoCodecType)
{
#ifdef CAMERA_MOVING_PHOTO
    MEDIA_INFO_LOG("HStreamCapture SetMovingPhotoVideoCodecType videoCodecType_: %{public}d", videoCodecType);
    videoCodecType_ = videoCodecType;
#endif
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
    CHECK_RETURN_RET(isBursting_ ||
            (GetMode() == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO)) ||
            IsOriginalImageEnable(),
        CAMERA_UNSUPPORTED);
    const int32_t updateMediaLibraryStep = 1;
    if (!photoAssetProxy_.WaitForUnlock(
            cameraPhotoProxy->GetCaptureId(), updateMediaLibraryStep, GetMode(),
            std::chrono::seconds(PHOTO_ASSET_TIMEOUT))) {
        return CAMERA_UNKNOWN_ERROR;
    }
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = photoAssetProxy_.Get(cameraPhotoProxy->GetCaptureId());
    CHECK_RETURN_RET_ELOG(
        photoAssetProxy == nullptr, CAMERA_UNKNOWN_ERROR, "HStreamCapture UpdateMediaLibraryPhotoAssetProxy failed");
    MEDIA_DEBUG_LOG(
        "HStreamCapture UpdateMediaLibraryPhotoAssetProxy E captureId(%{public}d)", cameraPhotoProxy->GetCaptureId());
    SetCameraPhotoProxyInfo(cameraPhotoProxy);
    MEDIA_DEBUG_LOG("HStreamCapture AddPhotoProxy E");
    photoAssetProxy->AddPhotoProxy(cameraPhotoProxy, cameraPhotoProxy, "");
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
        hStreamOperatorSptr_->CreateMediaLibrary(picture, cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp,
            enableOriginImage_ ? 2 : 1, GetEditData(cameraPhotoProxy->GetCaptureId()));
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
        hStreamOperatorSptr_->CreateMediaLibrary(cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp,
            enableOriginImage_ ? 2 : 1, GetEditData(cameraPhotoProxy->GetCaptureId()));
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
    hStreamOperatorSptr_->CreateMediaLibrary(cameraPhotoProxy, uri, cameraShotType, burstKey, timestamp,
        enableOriginImage_ ? 2 : 1, GetEditData(cameraPhotoProxy->GetCaptureId()));
    return CAMERA_OK;
}

void HStreamCapture::ElevateThreadPriority()
{
    MEDIA_INFO_LOG("ElevateThreadPriority set qos enter");
    int32_t qosLevel = 7;  //  7 设置 qos 7 优先级41; -1 取消 qos 7；其他无效
    std::string strBundleName = "camera_service";
    std::string strPid = std::to_string(getpid());  // 提升优先级的进程id
    std::string strTid = std::to_string(gettid());  // 提升优先级的线程id
    std::string strQos = std::to_string(qosLevel);
    std::unordered_map<std::string, std::string> mapPayLoad;
    mapPayLoad["pid"] = strPid;
    mapPayLoad[strTid] = strQos;  // 支持多个tid，{{tid0,qos0},{tid1,qos1}}
    mapPayLoad["bundleName"] = strBundleName;
    uint32_t type = OHOS::ResourceSchedule::ResType::RES_TYPE_THREAD_QOS_CHANGE;
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, 0, mapPayLoad);  // 异步IPC，优先级提升到41
}

#ifdef CAMERA_CAPTURE_YUV
void HStreamCapture::OnPhotoStateCallback(int32_t photoNum)
{
    MEDIA_DEBUG_LOG("OnPhotoStateCallback, photoNum:%{public}d", photoNum);
    std::lock_guard<std::mutex> lock(g_captureReadyMutex);
    g_unsavedPhotoCount = photoNum;
    g_captureReadyCv.notify_all();
}
#endif
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS
