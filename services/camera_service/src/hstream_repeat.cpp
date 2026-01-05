/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hstream_repeat.h"
#include "iproxy_broker.h"

#include <cstdint>
#include <mutex>

#ifdef NOTIFICATION_ENABLE
#include "camera_beauty_notification.h"
#include "camera_notification_interface.h"
#endif
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_metadata.h"
#include "camera_metadata_operator.h"
#include "display_manager_lite.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "istream_repeat_callback.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"
#include "parameters.h"
#include "session/capture_scene_const.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif
#include "av_codec_proxy.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
constexpr int32_t INT32_ZERO = 0;
constexpr int32_t INT32_ONE = 1;
constexpr int32_t INT32_TWO = 2;
HStreamRepeat::HStreamRepeat(
    sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height, RepeatStreamType type)
    : HStreamCommon(StreamType::REPEAT, producer, format, width, height), repeatStreamType_(type)
{
    MEDIA_INFO_LOG("HStreamRepeat::HStreamRepeat construct, format:%{public}d size:%{public}dx%{public}d "
                   "repeatType:%{public}d, streamId:%{public}d",
        format, width, height, type, GetFwkStreamId());
}

HStreamRepeat::~HStreamRepeat()
{
    MEDIA_INFO_LOG("HStreamRepeat::~HStreamRepeat deconstruct, format:%{public}d size:%{public}dx%{public}d "
                   "repeatType:%{public}d, streamId:%{public}d, hdiStreamId:%{public}d",
        format_, width_, height_, repeatStreamType_, GetFwkStreamId(), GetHdiStreamId());
#ifdef NOTIFICATION_ENABLE
    CancelNotification();
#endif
    RemoveStreamOperatorDeathRecipient();
}

int32_t HStreamRepeat::LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG(
        "HStreamRepeat::LinkInput streamId:%{public}d ,repeatStreamType:%{public}d",
        GetFwkStreamId(), repeatStreamType_);
    int32_t ret = HStreamCommon::LinkInput(streamOperator, cameraAbility);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "HStreamRepeat::LinkInput err, streamId:%{public}d ,err:%{public}d",
        GetFwkStreamId(), ret);
    if (repeatStreamType_ != RepeatStreamType::VIDEO) {
        SetStreamTransform();
    } else {
#ifdef HOOK_CAMERA_OPERATOR
        if (!CameraRotatePlugin::GetInstance()->
            HookCreateVideoOutput(GetBasicInfo(), GetStreamProducer())) {
            MEDIA_ERR_LOG("HCameraService::CreateVideoOutput HookCreateVideoOutput is failed");
        }
#endif
    }
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    if (repeatStreamType_ == RepeatStreamType::MOVIE_FILE_CINEMATIC_VIDEO) {
        streamRepeatDeathRecipient_.Set(new StreamRepeatDeathRecipient(this));
        const sptr<IRemoteObject> &remote =
            OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_0::IStreamOperator>(streamOperator.promote());
        auto streamRepeatDeathRecipient = streamRepeatDeathRecipient_.Get();
        CHECK_PRINT_ELOG(!remote->AddDeathRecipient(streamRepeatDeathRecipient),
                         "AddDeathRecipient for IStreamOperator failed.");
    }
#endif
    return CAMERA_OK;
}

void HStreamRepeat::UpdateHalRoateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
#ifdef HOOK_CAMERA_OPERATOR
    int32_t rotateAngle = -1;
    if (CameraRotatePlugin::GetInstance()->
        HookPreviewStreamStart(GetBasicInfo(), GetStreamProducer(), rotateAngle) && rotateAngle >= 0) {
        CHECK_PRINT_ELOG(settings == nullptr, "HStreamRepeat::UpdateHalRoateSettings settings is nullptr");
        bool status = false;
        camera_metadata_item_t item;

        MEDIA_DEBUG_LOG("HStreamRepeat::UpdateHalRoateSettings rotateAngle is %{public}d", rotateAngle);
        int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_ROTATE_ANGLE, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateAngle, 1);
        } else if (ret == CAM_META_SUCCESS) {
            status = settings->updateEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateAngle, 1);
        }
        CHECK_PRINT_ELOG(!status, "UpdateHalRoateSettings Failed");
        if (static_cast<uint32_t>(rotateAngle) & 0x1FFF) {  // Bit0~12 for angle and mirror
            enableCameraRotation_ = true;
        }
    }
#endif
}

int32_t HStreamRepeat::SetCurrentMode(int32_t mode)
{
    MEDIA_DEBUG_LOG("HStreamRepeat::SetCurentMode current mode:%{public}d", mode);
    currentMode_ = mode;
    return 0;
}

void HStreamRepeat::InitWhiteList()
{
    if (!whiteList_.empty()) {
        return;
    }
    std::string whiteListStr = system::GetParameter("const.display_rotation.package.list", "default");
    if (whiteListStr == "default") {
        return;
    }
    std::stringstream ss(whiteListStr);
    std::string whiteListItem;
    while (std::getline(ss, whiteListItem, ';')) {
        if (!whiteListItem.empty()) {
            whiteList_.insert(whiteListItem);
        }
    }
}

bool HStreamRepeat::CheckInWhiteList()
{
    std::string clientName = GetClientBundle(IPCSkeleton::GetCallingUid());
    return whiteList_.find(clientName) != whiteList_.end();
}

bool HStreamRepeat::CheckVideoModeForSystemApp(int32_t sceneMode)
{
    CHECK_RETURN_RET_ILOG(!CheckSystemApp(), false, "CheckVideoModeForSystemApp is not SystemApp");
    std::vector<SceneMode> videoModeVec = {
        VIDEO,
        SLOW_MOTION,
        VIDEO_MACRO,
        PROFESSIONAL_VIDEO,
        HIGH_FRAME_RATE,
        TIMELAPSE_PHOTO,
        APERTURE_VIDEO,
        CINEMATIC_VIDEO
    };
    auto iterator = std::find(videoModeVec.begin(), videoModeVec.end(), static_cast<SceneMode>(sceneMode));
    CHECK_RETURN_RET_ILOG(iterator != videoModeVec.end(), true,
        "HStreamRepeat::CheckVideoModeForSystemApp current sceneMode: %{public}d", sceneMode);
    return false;
}

void HStreamRepeat::SetStreamInfo(StreamInfo_V1_5& streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    auto metaProducerSequenceable = metaProducer_ == nullptr ? nullptr : new BufferProducerSequenceable(metaProducer_);
    HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(4), .width = 0, .height = 0, .format = 0,
        .dataspace = 0, .bufferQueue = metaProducerSequenceable
    };
    switch (repeatStreamType_) {
        case RepeatStreamType::LIVEPHOTO_XTSTYLE_RAW:
            UpdateStreamSupplementaryInfoSettings(cameraAbility_);
            [[fallthrough]];
        case RepeatStreamType::LIVEPHOTO:
            streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
            streamInfo.extendedStreamInfos = { metaExtendedStreamInfo };
            break;
        case RepeatStreamType::VIDEO:
            SetVideoStreamInfo(streamInfo);
            break;
        case RepeatStreamType::MOVIE_FILE:
            SetVideoStreamInfo(streamInfo);
            break;
        case RepeatStreamType::MOVIE_FILE_CINEMATIC_VIDEO:
            SetMovieFileStreamInfo(streamInfo);
            break;
        case RepeatStreamType::MOVIE_FILE_RAW_VIDEO:
            SetMovieFileRawVideoStreamInfo(streamInfo);
            UpdateStreamSupplementaryInfoSettings(cameraAbility_);
            break;
        case RepeatStreamType::PREVIEW:
            DataSpaceLimit2Full(streamInfo);
            UpdateBandwidthCompressionSetting(streamSettingsMeta_);
            SetPreviewStreamInfo(streamInfo);
            break;
        case RepeatStreamType::SKETCH:
            DataSpaceLimit2Full(streamInfo);
            SetSketchStreamInfo(streamInfo);
            break;
        case RepeatStreamType::COMPOSITION:
            SetCompositionStreamInfo(streamInfo);
            break;
    }
}

void HStreamRepeat::DataSpaceLimit2Full(StreamInfo_V1_5& streamInfo)
{
    CHECK_RETURN(!CheckVideoModeForSystemApp(currentMode_));
    MEDIA_DEBUG_LOG("HStreamRepeat::SetSketchStreamInfo current colorSpace : %{public}d", streamInfo.v1_0.dataspace_);
    static const std::unordered_map<CM_ColorSpaceType_V2_1, CM_ColorSpaceType_V2_1> LIMIT2FULL_MAP={
        {CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT,CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL},
        {CM_ColorSpaceType_V2_1::CM_BT709_LIMIT,CM_ColorSpaceType_V2_1::CM_BT709_FULL}
    };
    auto& space = streamInfo.v1_0.dataspace_;
    auto it =LIMIT2FULL_MAP.find(static_cast<CM_ColorSpaceType_V2_1>(space));
    CHECK_RETURN(it == LIMIT2FULL_MAP.end());
    space = it->second;
}

void HStreamRepeat::SetVideoStreamInfo(StreamInfo_V1_5& streamInfo)
{
    streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
    MEDIA_INFO_LOG("HStreamRepeat::SetVideoStreamInfo Enter");
    HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO),
        .width = 0, .height = 0, .format = 0, .dataspace = 0, .bufferQueue = metaSurfaceBufferQueueHolder.Get()
    };
    streamInfo.extendedStreamInfos.emplace_back(metaExtendedStreamInfo);
    streamInfo.v1_0.dataspace_ =
        (streamInfo.v1_0.dataspace_ == CM_ColorSpaceType_V2_1::CM_BT2020_LOG_FULL)
        ? CM_ColorSpaceType_V2_1::CM_BT2020_LOG_LIMIT
        : streamInfo.v1_0.dataspace_;
    MEDIA_INFO_LOG("HStreamRepeat::SetVideoStreamInfo end");
    streamInfo.extendedStreamInfos = { metaExtendedStreamInfo };
}

void HStreamRepeat::SetMovieFileStreamInfo(StreamInfo_V1_5& streamInfo)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetMovieFileStreamInfo Enter");
    streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
    if (producer_ != nullptr) {
        MEDIA_DEBUG_LOG("HStreamRepeat:producer is not null");
        streamInfo.v1_0.bufferQueue_ = new BufferProducerSequenceable(producer_);
    }
    // add debug extended stream
    auto movieDebugProducer = movieDebugProducer_.Get();
    if (movieDebugProducer != nullptr) {
        auto debugSurfaceBufferQueue = new BufferProducerSequenceable(movieDebugProducer);
        HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO),
            .width = 0,
            .height = 0,
            .format = 0,
            .dataspace = 0,
            .bufferQueue = debugSurfaceBufferQueue
        };
        streamInfo.extendedStreamInfos.emplace_back(metaExtendedStreamInfo);
    }
}

void HStreamRepeat::SetMovieFileRawVideoStreamInfo(StreamInfo_V1_5& streamInfo)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetMovieFileRawVideoStreamInfo Enter");
    streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
    if (producer_ != nullptr) {
        streamInfo.v1_0.bufferQueue_ = new BufferProducerSequenceable(producer_);
    }
    // add preY extended stream
    auto preyProducer = preyProducer_.Get();
    if (preyProducer != nullptr) {
        auto preySurfaceBufferQueue = new BufferProducerSequenceable(preyProducer);
        HDI::Camera::V1_1::ExtendedStreamInfo preyExtendedStreamInfo {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_PRE_Y),
            .width = 960,
            .height = 540,
            .format = GRAPHIC_PIXEL_FMT_YCRCB_P010,
            .dataspace = CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT,
            .bufferQueue = preySurfaceBufferQueue
        };
        streamInfo.extendedStreamInfos.emplace_back(preyExtendedStreamInfo);
    }
    // add depth extended stream
    auto depthProducer = depthProducer_.Get();
    if (depthProducer != nullptr) {
        auto depthSurfaceBufferQueue = new BufferProducerSequenceable(depthProducer);
        HDI::Camera::V1_1::ExtendedStreamInfo depthExtendedStreamInfo {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH),
            .width = 512,
            .height = 288,
            .format = GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
            .dataspace = CM_ColorSpaceType_V2_1::CM_BT709_LIMIT,
            .bufferQueue = depthSurfaceBufferQueue
        };
        streamInfo.extendedStreamInfos.emplace_back(depthExtendedStreamInfo);
    }
    // add meta extended stream
    if (metaProducer_ != nullptr) {
        auto metaSurfaceBufferQueue = new BufferProducerSequenceable(metaProducer_);
        HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_META),
            .width = 0,
            .height = 0,
            .format = 0,
            .dataspace = 0,
            .bufferQueue = metaSurfaceBufferQueue
        };
        streamInfo.extendedStreamInfos.emplace_back(metaExtendedStreamInfo);
    }
    // add debug extended stream
    auto rawDebugProducer = rawDebugProducer_.Get();
    if (rawDebugProducer != nullptr) {
        auto debugSurfaceBufferQueue = new BufferProducerSequenceable(rawDebugProducer);
        HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
            .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO),
            .width = 0,
            .height = 0,
            .format = 0,
            .dataspace = 0,
            .bufferQueue = debugSurfaceBufferQueue
        };
        streamInfo.extendedStreamInfos.emplace_back(metaExtendedStreamInfo);
    }
}

void HStreamRepeat::SetPreviewStreamInfo(StreamInfo_V1_5& streamInfo)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewStreamInfo E");
    streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
    // set HEBC value
    std::vector<uint8_t> streamSettings;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(streamSettingsMeta_, streamSettings);
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewStreamInfo streamSettings size:%zu", streamSettings.size());
    streamInfo.settings = streamSettings;
    SetPreviewExtendedStreamInfoForSecure(streamInfo);
    SetPreviewExtendedStreamInfoForStitching(streamInfo);
}

void HStreamRepeat::SetPreviewExtendedStreamInfoForSecure(StreamInfo_V1_5& streamInfo)
{
    CHECK_RETURN(!mEnableSecure);
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewExtendedStreamInfoForSecure Enter");
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_SECURE),
        .width = 0,
        .height = 0,
        .format = 0,
        .dataspace = 0,
        .bufferQueue = nullptr
    };
    streamInfo.extendedStreamInfos = { extendedStreamInfo };
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewExtendedStreamInfoForSecure end");
}

void HStreamRepeat::SetPreviewExtendedStreamInfoForStitching(StreamInfo_V1_5& streamInfo)
{
    CHECK_RETURN(!mEnableStitching);
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewExtendedStreamInfoForStitching Enter");
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_PHOTO_STITCHING),
        .width = 0,
        .height = 0,
        .format = 0,
        .dataspace = 0,
        .bufferQueue = nullptr
    };
    streamInfo.extendedStreamInfos.push_back(extendedStreamInfo);
    MEDIA_INFO_LOG("HStreamRepeat::SetPreviewExtendedStreamInfoForStitching end");
}

bool HStreamRepeat::IsLivephotoStream()
{
    return repeatStreamType_ == RepeatStreamType::LIVEPHOTO_XTSTYLE_RAW ||
        repeatStreamType_ == RepeatStreamType::LIVEPHOTO;
}

void HStreamRepeat::SetSketchStreamInfo(StreamInfo_V1_5& streamInfo)
{
    MEDIA_DEBUG_LOG("HStreamRepeat::SetSketchStreamInfo enter");
    streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo{
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_2::EXTENDED_STREAM_INFO_SKETCH),
        .width = 0,
        .height = 0,
        .format = 0,
        .dataspace = 0,
        .bufferQueue = nullptr
    };
    streamInfo.extendedStreamInfos = { extendedStreamInfo };
    MEDIA_DEBUG_LOG("HStreamRepeat::SetSketchStreamInfo end");
}

void HStreamRepeat::SetCompositionStreamInfo(StreamInfo_V1_5& streamInfo)
{
    MEDIA_DEBUG_LOG("HStreamRepeat::SetCompositionStreamInfo enter");
    streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_COMPOSITION),
        .width = 0,
        .height = 0,
        .format = 0,
        .dataspace = 0,
        .bufferQueue = nullptr
    };
    streamInfo.extendedStreamInfos ={extendedStreamInfo};
    MEDIA_DEBUG_LOG("HStreamRepeat::SetCompositionStreamInfo end");
}

void HStreamRepeat::SetPreyProducer(sptr<OHOS::IBufferProducer> preyProducer)
{
    preyProducer_.Set(preyProducer);
}

void HStreamRepeat::SetDepthProducer(sptr<OHOS::IBufferProducer> depthProducer)
{
    depthProducer_.Set(depthProducer);
}

void HStreamRepeat::SetMovieDebugProducer(sptr<OHOS::IBufferProducer> movieDebugProducer)
{
    movieDebugProducer_.Set(movieDebugProducer);
}

void HStreamRepeat::SetRawDebugProducer(sptr<OHOS::IBufferProducer> rawDebugProducer)
{
    rawDebugProducer_ .Set(rawDebugProducer);
}

void HStreamRepeat::SetMetaProducer(sptr<OHOS::IBufferProducer> metaProducer)
{
    std::lock_guard<std::mutex> lock(producerLock_);
    metaProducer_ = metaProducer;
}

#ifdef CAMERA_MOVING_PHOTO
void HStreamRepeat::SetMovingPhotoStartCallback(std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(movingPhotoCallbackLock_);
    startMovingPhotoCallback_ = callback;
}
#endif

void HStreamRepeat::UpdateSketchStatus(SketchStatus status)
{
    CHECK_RETURN(repeatStreamType_ != RepeatStreamType::SKETCH);
    auto parent = parentStreamRepeat_.promote();
    CHECK_RETURN(parent == nullptr);
    CHECK_RETURN(sketchStatus_ == status);
    sketchStatus_ = status;
    parent->OnSketchStatusChanged(sketchStatus_);
}

void HStreamRepeat::StartSketchStream(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream Enter");
    sptr<HStreamRepeat> sketchStreamRepeat;
    {
        std::lock_guard<std::mutex> lock(sketchStreamLock_);
        bool shouldStartSketchStream = sketchStreamRepeat_ == nullptr || sketchStreamRepeat_->sketchRatio_ <= 0;
        CHECK_RETURN_DLOG(shouldStartSketchStream,
            "HStreamRepeat::StartSketchStream sketchStreamRepeat_ is null or ratio is illegal");
        sketchStreamRepeat = sketchStreamRepeat_;
    }
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    CHECK_RETURN_DLOG(ret != CAM_META_SUCCESS || item.count <= 0,
        "HStreamRepeat::StartSketchStream get OHOS_CONTROL_ZOOM_RATIO fail");
    float tagRatio = *item.data.f;
    MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        tagRatio, sketchStreamRepeat->sketchRatio_);
    bool shouldStartSketchStream = sketchStreamRepeat->sketchRatio_ > 0 &&
        tagRatio - sketchStreamRepeat->sketchRatio_ >= -std::numeric_limits<float>::epsilon();
    if (shouldStartSketchStream) {
        sketchStreamRepeat->Start();
    }
    MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream Exit");
}

void HStreamRepeat::SetUsedAsPosition(camera_position_enum_t cameraPosition)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetUsedAsPosition %{public}d", cameraPosition);
    cameraUsedAsPosition_ = cameraPosition;
    SetStreamTransform();
}

int32_t HStreamRepeat::Start(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, bool isUpdateSeetings)
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET(streamOperator == nullptr, CAMERA_INVALID_STATE);
    auto preparedCaptureId = GetPreparedCaptureId();
    CHECK_RETURN_RET_ELOG(!isUpdateSeetings && preparedCaptureId != CAPTURE_ID_UNSET, CAMERA_INVALID_STATE,
        "HStreamRepeat::Start, Already started with captureID: %{public}d", preparedCaptureId);
    // If current is sketch/composition stream, check parent is start or not.
    if (repeatStreamType_ == RepeatStreamType::SKETCH || repeatStreamType_ == RepeatStreamType::COMPOSITION) {
        auto parentRepeat = parentStreamRepeat_.promote();
        CHECK_RETURN_RET_ELOG(parentRepeat == nullptr || parentRepeat->GetPreparedCaptureId() == CAPTURE_ID_UNSET,
            CAMERA_INVALID_STATE, "HStreamRepeat::Start sketch/composition parent state is illegal");
    }
    if (!isUpdateSeetings) {
        int32_t ret = PrepareCaptureId();
        preparedCaptureId = GetPreparedCaptureId();
        CHECK_RETURN_RET_ELOG(ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET, ret,
            "HStreamRepeat::Start Failed to allocate a captureId");
    }
    UpdateSketchStatus(SketchStatus::STARTING);
    SetFrameRate(settings);

    std::vector<uint8_t> ability;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(ability, dynamicSetting);
    if (dynamicSetting == nullptr) {
        dynamicSetting = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    // open video dfx switch for hal, no need close
    if (repeatStreamType_ == RepeatStreamType::PREVIEW) {
        OpenVideoDfxSwitch(dynamicSetting);
    }
    bool isNeedUpdateVideoSetting = repeatStreamType_ == RepeatStreamType::VIDEO
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
        || IsLivephotoStream()
        || repeatStreamType_ == RepeatStreamType::MOVIE_FILE
        || repeatStreamType_ == RepeatStreamType::MOVIE_FILE_CINEMATIC_VIDEO
        || repeatStreamType_ == RepeatStreamType::MOVIE_FILE_RAW_VIDEO;
#else
        || IsLivephotoStream();
#endif
    if (isNeedUpdateVideoSetting) {
        UpdateVideoSettings(dynamicSetting, enableMirror_);
    }
    if (repeatStreamType_ == RepeatStreamType::PREVIEW || repeatStreamType_ == RepeatStreamType::VIDEO) {
        UpdateHalRoateSettings(dynamicSetting);
        UpdateFrameRateSettings(dynamicSetting);
    }
    if (repeatStreamType_ == RepeatStreamType::VIDEO) {
#ifdef HOOK_CAMERA_OPERATOR
        bool mirror = 0;
        if (CameraRotatePlugin::GetInstance()->
            HookVideoStreamStart(GetBasicInfo(), GetStreamProducer(), mirror)) {
            UpdateVideoSettings(dynamicSetting, mirror);
        }
#endif
    }
    if (settings != nullptr) {
        UpdateFrameMuteSettings(settings, dynamicSetting);
        UpdateFrameMechSettings(settings, dynamicSetting);
    }
#ifdef NOTIFICATION_ENABLE
    bool isNeedBeautyNotification = IsNeedBeautyNotification();
    auto notification = CameraBeautyNotification::GetInstance();
    CHECK_EXECUTE(isNeedBeautyNotification && notification != nullptr &&
        notification->GetBeautyStatus() == BEAUTY_STATUS_ON, UpdateBeautySettings(dynamicSetting));
#endif
    std::vector<uint8_t> captureSetting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(dynamicSetting, captureSetting);

    CaptureInfo captureInfo;
    captureInfo.streamIds_ = { GetHdiStreamId() };
    captureInfo.captureSetting_ = captureSetting;
    captureInfo.enableShutterCallback_ = false;
    HILOG_COMM_INFO("HStreamRepeat::Start streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d, "
        "repeatStreamType:%{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId, repeatStreamType_);
    if (repeatStreamType_ == RepeatStreamType::VIDEO) {
        auto callingTokenId = IPCSkeleton::GetCallingTokenID();
        const std::string permissionName = "ohos.permission.CAMERA";
        AddCameraPermissionUsedRecord(callingTokenId, permissionName);
    }
    int32_t ret = 0;
    {
        std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
        HStreamCommon::PrintCaptureDebugLog(dynamicSetting);
        CamRetCode rc = (CamRetCode)(streamOperator->Capture(preparedCaptureId, captureInfo, true));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            ResetCaptureId();
            camera_metadata_item_t item;
            uint8_t connectionType = 0;
            if (settings != nullptr) {
                ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
                if (ret == CAM_META_SUCCESS && item.count > 0 ) {
                    connectionType = item.data.u8[0];
                }
            }
            MEDIA_ERR_LOG("HStreamRepeat::Start Failed with error Code:%{public}d", rc);
            CameraReportUtils::ReportCameraErrorForUsb(
                "HStreamRepeat::Start", rc, true, std::to_string(connectionType), CameraReportUtils::GetCallerInfo());
            ret = HdiToServiceError(rc);
            UpdateSketchStatus(SketchStatus::STOPED);
        } else {
            repeatStreamStatus_ = RepeatStreamStatus::STARTED;
        }
    }
    if (settings != nullptr) {
        StartSketchStream(settings);
    }
#ifdef NOTIFICATION_ENABLE
    if (isNeedBeautyNotification) {
        auto notification = CameraBeautyNotification::GetInstance();
        CHECK_EXECUTE(notification != nullptr, notification->PublishNotification(true));
    }
#endif
    return ret;
}

int32_t HStreamRepeat::Start()
{
    return Start(nullptr);
}

int32_t HStreamRepeat::Stop()
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET_ELOG(
        streamOperator == nullptr, CAMERA_INVALID_STATE, "HStreamRepeat::Stop streamOperator is null");
    auto preparedCaptureId = GetPreparedCaptureId();
    MEDIA_INFO_LOG("HStreamRepeat::Stop streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d, "
                   "repeatStreamType:%{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId, repeatStreamType_);
    CHECK_RETURN_RET_ELOG(
        preparedCaptureId == CAPTURE_ID_UNSET, CAMERA_INVALID_STATE, "HStreamRepeat::Stop, Stream not started yet");
    UpdateSketchStatus(SketchStatus::STOPPING);
    int32_t ret = CAMERA_OK;
    {
        std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
        ret = StopStream();
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("HStreamRepeat::Stop Failed with errorCode:%{public}d, curCaptureID_: %{public}d",
                          ret, preparedCaptureId);
        } else {
            repeatStreamStatus_ = RepeatStreamStatus::STOPED;
        }
    }
    {
        std::lock_guard<std::mutex> lock(sketchStreamLock_);
        if (sketchStreamRepeat_ != nullptr) {
            sketchStreamRepeat_->Stop();
        }
    }
    return ret;
}

int32_t HStreamRepeat::Release()
{
    return ReleaseStream(false);
}

int32_t HStreamRepeat::ReleaseStream(bool isDelay)
{
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        streamRepeatCallback_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(sketchStreamLock_);
        if (sketchStreamRepeat_ != nullptr) {
            sketchStreamRepeat_->Release();
        }
    }

    {
        std::lock_guard<std::mutex> lock(compositionStreamLock_);
        if (compositionStreamRepeat_!= nullptr) {
            compositionStreamRepeat_->Release();
        }
    }

    {
        std::lock_guard<std::mutex> lockSketch(sketchStreamLock_);
        std::lock_guard<std::mutex> lockComposition(compositionStreamLock_);
        parentStreamRepeat_ = nullptr;
    }
    auto recorder = recorder_.Get();
    if (recorder != nullptr) {
        recorder->Stop();
        recorder_.Set(nullptr);
    }
    RemoveStreamOperatorDeathRecipient();
    return HStreamCommon::ReleaseStream(isDelay);
}

int32_t HStreamRepeat::SetCallback(const sptr<IStreamRepeatCallback>& callback)
{
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamRepeat::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamRepeatCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamRepeat::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamRepeatCallback_ = nullptr;
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnFrameStarted()
{
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        if (streamRepeatCallback_ != nullptr) {
            streamRepeatCallback_->OnFrameStarted();
        }
    }
    if (repeatStreamType_ == RepeatStreamType::VIDEO) {
        // report video start dfx
        DfxCaptureInfo captureInfo;
        captureInfo.captureId = 1;
        captureInfo.caller = CameraReportUtils::GetCallerInfo();
        CameraReportUtils::GetInstance().SetVideoStartInfo(captureInfo);
    }

    UpdateSketchStatus(SketchStatus::STARTED);
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnFrameEnded(int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        if (streamRepeatCallback_ != nullptr) {
            streamRepeatCallback_->OnFrameEnded(frameCount);
        }
    }
    if (repeatStreamType_ == RepeatStreamType::VIDEO) {
        // report video end dfx
        CameraReportUtils::GetInstance().SetVideoEndInfo(1);
    }
    UpdateSketchStatus(SketchStatus::STOPED);
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnDeferredVideoEnhancementInfo(CaptureEndedInfoExt captureEndedInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamRepeat::OnDeferredVideoEnhancementInfo");
    if (repeatStreamType_ == RepeatStreamType::VIDEO || repeatStreamType_ == RepeatStreamType::MOVIE_FILE) {
        // report video end dfx
        CameraReportUtils::GetInstance().SetVideoEndInfo(1);
        std::lock_guard<std::mutex> lock(callbackLock_);
        if (streamRepeatCallback_ != nullptr) {
            streamRepeatCallback_->OnDeferredVideoEnhancementInfo(captureEndedInfo);
        }
    } else {
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
        if (repeatStreamType_ == RepeatStreamType::MOVIE_FILE_RAW_VIDEO) {
            auto recorder = recorder_.Get();
            CHECK_RETURN_RET_ELOG(
                recorder == nullptr, CAMERA_UNKNOWN_ERROR, "recorder_ is null, failed to update photo proxy");
            MEDIA_DEBUG_LOG("update the videoId and enhancementType of photo proxy");
            recorder->UpdatePhotoProxy(captureEndedInfo.videoId, captureEndedInfo.isDeferredVideoEnhancementAvailable);
        }
#endif
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnFrameError(int32_t errorType)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_DEBUG_LOG("HStreamRepeat::OnFrameError %{public}d, %{public}d", errorType, streamRepeatCallback_ == nullptr);
    if (errorType == HDI::Camera::V1_3::HIGH_TEMPERATURE_ERROR) {
        UpdateSketchStatus(SketchStatus::STOPED);
    }
    if (streamRepeatCallback_ != nullptr) {
        int32_t repeatErrorCode;
        if (errorType == BUFFER_LOST) {
            repeatErrorCode = CAMERA_STREAM_BUFFER_LOST;
        } else {
            repeatErrorCode = CAMERA_UNKNOWN_ERROR;
        }
        CAMERA_SYSEVENT_FAULT(CreateMsg("Preview OnFrameError! errorCode:%d", repeatErrorCode));
        streamRepeatCallback_->OnFrameError(repeatErrorCode);
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnSketchStatusChanged(SketchStatus status)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_DEBUG_LOG("HStreamRepeat::OnSketchStatusChanged %{public}d", status);
    if (streamRepeatCallback_ != nullptr) {
        streamRepeatCallback_->OnSketchStatusChanged(status);
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer)
{
    MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface called");
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        CHECK_RETURN_RET_ELOG(
            producer == nullptr, CAMERA_INVALID_ARG, "HStreamRepeat::AddDeferredSurface producer is null");
        producer_ = producer;
    }

    if (repeatStreamType_ == RepeatStreamType::SKETCH) {
        MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface sketch add deferred surface");
        auto parent = parentStreamRepeat_.promote();
        if (parent != nullptr) {
            std::lock_guard<std::mutex> lock(parent->producerLock_);
            parent->SyncTransformToSketch();
        } else {
            MEDIA_ERR_LOG("HStreamRepeat::AddDeferredSurface sketch add deferred surface parent is nullptr");
        }
    } else {
        SetStreamTransform();
    }
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamRepeat::CreateAndHandleDeferredStreams(), streamOperator_ == null");
    MEDIA_INFO_LOG("HStreamRepeat::AttachBufferQueue start streamId:%{public}d, hdiStreamId:%{public}d",
        GetFwkStreamId(), GetHdiStreamId());
    sptr<BufferProducerSequenceable> bufferProducerSequenceable;
    CamRetCode rc;
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        bufferProducerSequenceable = new BufferProducerSequenceable(producer_);
    }
    rc = (CamRetCode)(streamOperator->AttachBufferQueue(GetHdiStreamId(), bufferProducerSequenceable));
    CHECK_PRINT_ELOG(rc != HDI::Camera::V1_0::NO_ERROR,
        "HStreamRepeat::AttachBufferQueue(), Failed to AttachBufferQueue %{public}d", rc);
    MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface end %{public}d", rc);
#ifdef CAMERA_MOVING_PHOTO
    std::lock_guard<std::mutex> lock(movingPhotoCallbackLock_);
    if (startMovingPhotoCallback_) {
        startMovingPhotoCallback_();
        startMovingPhotoCallback_ = nullptr;
    }
#endif
    return CAMERA_OK;
}

int32_t HStreamRepeat::RemoveDeferredSurface()
{
    MEDIA_INFO_LOG("HStreamRepeat::RemoveDeferredSurface called");
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        producer_ = nullptr;
    }
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamRepeat::RemoveDeferredSurface(), streamOperator_ == null");
    MEDIA_INFO_LOG("HStreamRepeat::DetachBufferQueue start streamId:%{public}d, hdiStreamId:%{public}d",
        GetFwkStreamId(), GetHdiStreamId());
    CamRetCode rc = (CamRetCode)(streamOperator->DetachBufferQueue(GetHdiStreamId()));
    CHECK_PRINT_ELOG(rc != HDI::Camera::V1_0::NO_ERROR,
        "HStreamRepeat::DetachBufferQueue(), Failed to DetachBufferQueue %{public}d", rc);
    MEDIA_INFO_LOG("HStreamRepeat::RemoveDeferredSurface end %{public}d", rc);
    return CAMERA_OK;
}

int32_t HStreamRepeat::ForkSketchStreamRepeat(
    int32_t width, int32_t height, sptr<IRemoteObject>& sketchStream, float sketchRatio)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    CHECK_RETURN_RET_ELOG(
        width <= 0 || height <= 0, CAMERA_INVALID_ARG, "HCameraService::ForkSketchStreamRepeat args is illegal");
    if (sketchStreamRepeat_ != nullptr) {
        sketchStreamRepeat_->Release();
    }

    auto streamRepeat = new (std::nothrow) HStreamRepeat(nullptr, format_, width, height, RepeatStreamType::SKETCH);
    CHECK_RETURN_RET_ELOG(streamRepeat == nullptr, CAMERA_ALLOC_ERROR,
        "HStreamRepeat::ForkSketchStreamRepeat HStreamRepeat allocation failed");
    MEDIA_DEBUG_LOG(
        "HStreamRepeat::ForkSketchStreamRepeat para is:%{public}dx%{public}d,%{public}f", width, height, sketchRatio);
    sketchStream = streamRepeat->AsObject();
    sketchStreamRepeat_ = streamRepeat;
    sketchStreamRepeat_->sketchRatio_ = sketchRatio;
    sketchStreamRepeat_->parentStreamRepeat_ = this;
    MEDIA_INFO_LOG("HCameraService::ForkSketchStreamRepeat end");
    return CAMERA_OK;
}

int32_t HStreamRepeat::RemoveSketchStreamRepeat()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    CHECK_RETURN_RET(sketchStreamRepeat_ == nullptr, CAMERA_OK);
    sketchStreamRepeat_->Release();
    sketchStreamRepeat_->parentStreamRepeat_ = nullptr;
    sketchStreamRepeat_ = nullptr;

    return CAMERA_OK;
}

int32_t HStreamRepeat::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    streamFrameRateRange_ = {minFrameRate, maxFrameRate};
    std::vector<uint8_t> ability;
    std::vector<uint8_t> repeatSettings;
    CHECK_RETURN_RET_ELOG(cameraAbility_ == nullptr, CAMERA_OK, "HStreamRepeat::SetFrameRate cameraAbility_ is null");
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
        std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = nullptr;
        OHOS::Camera::MetadataUtils::ConvertVecToMetadata(ability, dynamicSetting);
        if (dynamicSetting == nullptr) {
            dynamicSetting = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
        }
        CHECK_RETURN_RET_ELOG(
            dynamicSetting == nullptr, CAMERA_INVALID_ARG, "HStreamRepeat::SetFrameRate dynamicSetting is nullptr.");
        bool status = AddOrUpdateMetadata(
            dynamicSetting, OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
        CHECK_PRINT_ELOG(!status, "HStreamRepeat::SetFrameRate Failed to set frame range");
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(dynamicSetting, repeatSettings);
    }
    auto streamOperator = GetStreamOperator();

    CamRetCode rc = HDI::Camera::V1_0::NO_ERROR;
    if (streamOperator != nullptr) {
        std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
        if (repeatStreamStatus_ == RepeatStreamStatus::STARTED) {
            CaptureInfo captureInfo;
            captureInfo.streamIds_ = {GetHdiStreamId()};
            captureInfo.captureSetting_ = repeatSettings;
            captureInfo.enableShutterCallback_ = false;
            int32_t currentCaptureId = GetPreparedCaptureId();
            MEDIA_INFO_LOG("HStreamRepeat::SetFramRate stream:%{public}d, with settingCapture ID:%{public}d",
                           GetFwkStreamId(), currentCaptureId);
            rc = (CamRetCode)(streamOperator->Capture(currentCaptureId, captureInfo, true));
        } else {
            MEDIA_INFO_LOG("HStreamRepeat::SetFramRate stream The stream is not started. Save the parameters.");
        }
        CHECK_PRINT_ELOG(
            rc != HDI::Camera::V1_0::NO_ERROR, "HStreamRepeat::SetFrameRate Failed with error Code:%{public}d", rc);
    }
    return rc;
}

int32_t HStreamRepeat::SetMirror(bool isEnable)
{
    enableMirror_ = isEnable;
    return CAMERA_OK;
}

int32_t HStreamRepeat::GetMirror(bool& isEnable)
{
    isEnable = enableMirror_;
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetBandwidthCompression(bool isEnable)
{
    enableBandwidthCompression_ = isEnable;
    UpdateBandwidthCompressionSetting(streamSettingsMeta_);
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetPreviewRotation(std::string &deviceClass)
{
    enableStreamRotate_ = true;
    deviceClass_ = deviceClass;
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetCameraRotation(bool isEnable, int32_t rotation)
{
    enableCameraRotation_ = isEnable;
    CHECK_RETURN_RET(rotation > STREAM_ROTATE_360 || rotation < STREAM_ROTATE_0 || rotation % STREAM_ROTATE_90 != 0,
        CAMERA_INVALID_ARG);
    setCameraRotation_ = STREAM_ROTATE_360 - rotation;
    SetStreamTransform();
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetCameraApi(uint32_t apiCompatibleVersion)
{
    apiCompatibleVersion_ = apiCompatibleVersion;
    return CAMERA_OK;
}

bool HStreamRepeat::SetMirrorForLivePhoto(bool isEnable, int32_t mode)
{
    camera_metadata_item_t item;
    const int32_t canMirrorVideoAndPhoto = 2;
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN_RET(cameraAbility_ == nullptr, false);
        res = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(),
            OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    }

    bool isMirrorSupported = false;
    if (res == CAM_META_SUCCESS) {
        int step = 2;
        for (int i = 0; i < static_cast<int>(item.count); i += step) {
            MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d, u8[%{public}d], %{public}d",
                i, item.data.u8[i], i + 1, item.data.u8[i + 1]);
            if (mode == static_cast<int>(item.data.u8[i])) {
                isMirrorSupported = (item.data.u8[i + 1] == canMirrorVideoAndPhoto) ? true : false;
            }
        }
    }
    if (isMirrorSupported) {
        enableMirror_ = isEnable;
        Start(nullptr, true);
    } else {
        MEDIA_ERR_LOG("HStreamRepeat::SetMirrorForLivePhoto not supported mirror with mode:%{public}d", mode);
    }
    return isMirrorSupported;
}

int32_t HStreamRepeat::UpdateSketchRatio(float sketchRatio)
{
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    CHECK_RETURN_RET_ELOG(sketchStreamRepeat_ == nullptr, CAMERA_INVALID_STATE,
        "HCameraService::UpdateSketchRatio sketch stream not create!");
    sketchStreamRepeat_->sketchRatio_ = sketchRatio;
    return CAMERA_OK;
}

sptr<HStreamRepeat> HStreamRepeat::GetSketchStream()
{
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    return sketchStreamRepeat_;
}

sptr<HStreamRepeat> HStreamRepeat::GetCompositionStream()
{
    std::lock_guard<std::mutex> lock(compositionStreamLock_);
    return compositionStreamRepeat_;
}

void HStreamRepeat::SetCompositionStream(sptr<HStreamRepeat> compositionStream)
{
    std::lock_guard<std::mutex> lock(compositionStreamLock_);
    if(compositionStreamRepeat_){
        compositionStreamRepeat_->Release();
    }
    compositionStreamRepeat_ = compositionStream;
    compositionStream->parentStreamRepeat_ = wptr<HStreamRepeat>(this);
}

RepeatStreamType HStreamRepeat::GetRepeatStreamType()
{
    return repeatStreamType_;
}

void HStreamRepeat::DumpStreamInfo(CameraInfoDumper& infoDumper)
{
    infoDumper.Title("repeat stream");
    HStreamCommon::DumpStreamInfo(infoDumper);
}

void HStreamRepeat::SyncTransformToSketch()
{
    CHECK_RETURN_ELOG(producer_ == nullptr, "HStreamRepeat::SyncTransformToSketch producer_ is null");
    GraphicTransformType previewTransform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    int ret = producer_->GetTransform(previewTransform);
    MEDIA_INFO_LOG("HStreamRepeat::SyncTransformToSketch previewTransform is %{public}d", previewTransform);
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "HStreamRepeat::SyncTransformToSketch GetTransform fail %{public}d", ret);
    auto sketchStream = GetSketchStream();
    CHECK_RETURN_ELOG(sketchStream == nullptr, "HStreamRepeat::SyncTransformToSketch sketchStream is null");
    std::lock_guard<std::mutex> lock(sketchStream->producerLock_);
    CHECK_RETURN_ELOG(
        sketchStream->producer_ == nullptr, "HStreamRepeat::SyncTransformToSketch sketchStream->producer_ is null");
    ret = sketchStream->producer_->SetTransform(previewTransform);
    CHECK_RETURN_ELOG(ret != GSERROR_OK, "HStreamRepeat::SyncTransformToSketch SetTransform fail %{public}d", ret);
}

void HStreamRepeat::SetStreamTransform(int displayRotation)
{
    InitWhiteList();
    camera_metadata_item_t item;
    int32_t sensorOrientation;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    int32_t curDisplayRotation = 0;
    int32_t ret = GetDisplayRotation(curDisplayRotation);
    CHECK_RETURN_ELOG(ret != CAMERA_OK, "HStreamRepeat::SetStreamTransform GetDisplayRotation Failed");
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN(cameraAbility_ == nullptr);
        int ret = GetCorrectedCameraOrientation(usePhysicalCameraOrientation_, cameraAbility_, sensorOrientation);
        CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS, "HStreamRepeat::SetStreamTransform get sensor "
            "orientation failed");
        MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform sensor orientation %{public}d", sensorOrientation);

        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS, "HStreamRepeat::SetStreamTransform get camera position failed");
        cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform camera position: %{public}d", cameraPosition);
    }
    std::lock_guard<std::mutex> lock(producerLock_);
    CHECK_RETURN_ELOG(
        producer_ == nullptr, "HStreamRepeat::SetStreamTransform failed, producer is null or GetDefaultDisplay failed");
    if (cameraUsedAsPosition_ != OHOS_CAMERA_POSITION_OTHER) {
        cameraPosition = cameraUsedAsPosition_;
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform used camera position: %{public}d", cameraPosition);
    }
    if (enableCameraRotation_) {
        ProcessCameraSetRotation(sensorOrientation);
    }
    if (apiCompatibleVersion_ >= CAMERA_API_VERSION_BASE) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    int mOritation = displayRotation;
    if (enableStreamRotate_) {
        if (mOritation == -1) {
            CHECK_RETURN_ELOG(producer_ == nullptr, "HStreamRepeat::SetStreamTransform failed, producer is null");
            mOritation = curDisplayRotation;
        }
        int32_t streamRotation = GetStreamRotation(sensorOrientation, cameraPosition, mOritation, deviceClass_);
        ProcessCameraPosition(streamRotation, cameraPosition);
    } else {
        ProcessFixedTransform(sensorOrientation, cameraPosition);
    }
    SyncTransformToSketch();
}

void HStreamRepeat::ProcessCameraSetRotation(int32_t& sensorOrientation)
{
    sensorOrientation = STREAM_ROTATE_360 - setCameraRotation_;
    CHECK_RETURN(sensorOrientation != GRAPHIC_ROTATE_NONE);
    int ret = producer_->SetTransform(GRAPHIC_ROTATE_NONE);
    MEDIA_ERR_LOG("HStreamRepeat::CameraSetRotation failed %{public}d", ret);
}

void HStreamRepeat::ProcessFixedTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    if (enableCameraRotation_) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    bool isTableFlag = system::GetBoolParameter("const.multimedia.enable_camera_rotation_compensation", 0);
    bool isNeedChangeRotation = system::GetBoolParameter("const.multimedia.enable_camera_rotation_change", 0);
    if (isTableFlag && !CheckInWhiteList()) { // LCOV_EXCL_LINE
        ProcessFixedDiffDeviceTransform(sensorOrientation, cameraPosition);
        return;
    }
    if (isTableFlag) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    if (isNeedChangeRotation) { // LCOV_EXCL_LINE
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    if (IsVerticalDevice()) { // LCOV_EXCL_LINE
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    } else {
        ProcessFixedDiffDeviceTransform(sensorOrientation, cameraPosition);
    }
}

void HStreamRepeat::ProcessFixedDiffDeviceTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    MEDIA_INFO_LOG("HStreamRepeat::ProcessFixedDiffDeviceTransform is called");
    int ret = SurfaceError::SURFACE_ERROR_OK;
#ifdef HOOK_CAMERA_OPERATOR
    int32_t cameraPositionTemp = static_cast<int32_t>(cameraPosition);
    if (CameraRotatePlugin::GetInstance()->HookPreviewTransform(GetBasicInfo(), producer_,
        sensorOrientation, cameraPositionTemp)) {
        int32_t streamRotation = sensorOrientation;
        if (cameraPositionTemp == OHOS_CAMERA_POSITION_FRONT) {
            ret = HandleCameraTransform(streamRotation, true);
        } else {
            streamRotation = STREAM_ROTATE_360 - sensorOrientation;
            ret = HandleCameraTransform(streamRotation, false);
        }
        return;
    }
    MEDIA_ERR_LOG("HStreamRepeat::ProcessFixedDiffDeviceTransform HookPreviewTransform is failed");
#endif
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        ret = producer_->SetTransform(GRAPHIC_FLIP_H);
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform filp for wide side devices");
    } else {
        ret = producer_->SetTransform(GRAPHIC_ROTATE_NONE);
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform none rotate");
    }
    CHECK_PRINT_ELOG(
        ret != SurfaceError::SURFACE_ERROR_OK, "HStreamRepeat::ProcessFixedTransform failed %{public}d", ret);
}

void HStreamRepeat::ProcessVerticalCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    MEDIA_DEBUG_LOG("HStreamRepeat::ProcessVerticalCameraPosition is called");
    int ret = SurfaceError::SURFACE_ERROR_OK;
#ifdef HOOK_CAMERA_OPERATOR
    int32_t cameraPositionTemp = static_cast<int32_t>(cameraPosition);
    if (!CameraRotatePlugin::GetInstance()->HookPreviewTransform(GetBasicInfo(), producer_,
        sensorOrientation, cameraPositionTemp)) {
        MEDIA_ERR_LOG("HStreamRepeat::ProcessVerticalCameraPosition  HookPreviewTransform is failed");
    }
    cameraPosition = static_cast<camera_position_enum_t>(cameraPositionTemp);
#endif
    int32_t streamRotation = sensorOrientation;
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        ret = HandleCameraTransform(streamRotation, true);
    } else {
        streamRotation = STREAM_ROTATE_360 - sensorOrientation;
        ret = HandleCameraTransform(streamRotation, false);
    }
    CHECK_PRINT_ELOG(ret != SurfaceError::SURFACE_ERROR_OK,
        "HStreamRepeat::ProcessVerticalCameraPosition failed %{public}d", ret);
}

void HStreamRepeat::ProcessCameraPosition(int32_t& streamRotation, camera_position_enum_t& cameraPosition)
{
    MEDIA_INFO_LOG("HStreamRepeat::ProcessCameraPosition is called");
    int ret = SurfaceError::SURFACE_ERROR_OK;
#ifdef HOOK_CAMERA_OPERATOR
    int32_t cameraPositionTemp = static_cast<int32_t>(cameraPosition);
    if (!CameraRotatePlugin::GetInstance()->HookPreviewTransform(GetBasicInfo(), producer_,
        streamRotation, cameraPositionTemp)) {
        MEDIA_ERR_LOG("HStreamRepeat::ProcessCameraPosition HookPreviewTransform is failed");
    }
    cameraPosition = static_cast<camera_position_enum_t>(cameraPositionTemp);
#endif
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        ret = HandleCameraTransform(streamRotation, true);
    } else {
        ret = HandleCameraTransform(streamRotation, false);
    }
    CHECK_PRINT_ELOG(ret != SurfaceError::SURFACE_ERROR_OK, "HStreamRepeat::ProcessCameraPosition "
        "failed %{public}d", ret);
}

int32_t HStreamRepeat::HandleCameraTransform(int32_t& streamRotation, bool isFrontCamera)
{
    int32_t ret = SurfaceError::SURFACE_ERROR_OK;
    switch (streamRotation) {
        case STREAM_ROTATE_0: {
            ret = producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H : GRAPHIC_ROTATE_NONE);
            break;
        }
        case STREAM_ROTATE_90: {
            ret = producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT90 : GRAPHIC_ROTATE_90);
            break;
        }
        case STREAM_ROTATE_180: {
            ret = producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT180 : GRAPHIC_ROTATE_180);
            break;
        }
        case STREAM_ROTATE_270: {
            ret = producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT270 : GRAPHIC_ROTATE_270);
            break;
        }
        default: {
            ret = producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H : GRAPHIC_ROTATE_NONE);
            break;
        }
    }
    if (isFrontCamera) {
        MEDIA_INFO_LOG("HStreamRepeat::HandleCameraTransform flip rotate %{public}d", streamRotation);
    } else {
        MEDIA_INFO_LOG("HStreamRepeat::HandleCameraTransform not flip rotate %{public}d", streamRotation);
    }
    return ret;
}

int32_t HStreamRepeat::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IStreamRepeatIpcCode>(interfaceCode)) {
        case IStreamRepeatIpcCode::COMMAND_START:
        case IStreamRepeatIpcCode::COMMAND_FORK_SKETCH_STREAM_REPEAT: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_RETURN_RET_ELOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HStreamRepeat::OperatePermissionCheck fail, callerToken not legal");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "HStreamRepeat::OperatePermissionCheck fail");
    switch (static_cast<IStreamRepeatIpcCode>(code)) {
        case IStreamRepeatIpcCode::COMMAND_ADD_DEFERRED_SURFACE:
        case IStreamRepeatIpcCode::COMMAND_FORK_SKETCH_STREAM_REPEAT:
        case IStreamRepeatIpcCode::COMMAND_UPDATE_SKETCH_RATIO: {
            CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamRepeat::CheckSystemApp fail");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

void HStreamRepeat::OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    bool status = false;
    camera_metadata_item_t item;
    uint8_t dfxSwitch = true;
    CHECK_RETURN_ELOG(settings == nullptr, "HStreamRepeat::OpenVideoDfxSwitch fail, setting is null!");
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &dfxSwitch, 1);
        MEDIA_INFO_LOG("HStreamRepeat::OpenVideoDfxSwitch success!");
    } else {
        status = true;
    }
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::OpenVideoDfxSwitch fail!");
}

int32_t HStreamRepeat::EnableSecure(bool isEnabled)
{
    mEnableSecure = isEnabled;
    return CAMERA_OK;
}

int32_t HStreamRepeat::EnableStitching(bool isEnabled)
{
    mEnableStitching = isEnabled;
    return CAMERA_OK;
}

void HStreamRepeat::UpdateBandwidthCompressionSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    MEDIA_INFO_LOG("HStreamRepeat::UpdateBandwidthCompressionSetting switch:%{public}d", enableBandwidthCompression_);
    CHECK_RETURN(settings == nullptr);
    bool status = AddOrUpdateMetadata(
        settings, OHOS_CONTROL_BANDWIDTH_COMPRESSION, &enableBandwidthCompression_, 1);
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateBandwidthCompressionSetting Failed");
}

void HStreamRepeat::UpdateVideoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, uint8_t mirror)
{
    CHECK_RETURN_ELOG(settings == nullptr, "HStreamRepeat::UpdateVideoSettings settings is nullptr");
    MEDIA_DEBUG_LOG("HStreamRepeat::UpdateVideoSettings set Mirror %{public}d", mirror);
    bool status = AddOrUpdateMetadata(settings, OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    CHECK_PRINT_ELOG(!status, "UpdateVideoSettings Failed to set mirroring in VideoSettings");
}

void HStreamRepeat::UpdateStreamSupplementaryInfoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    std::lock_guard<std::mutex> lock(cameraAbilityLock_);
    CHECK_RETURN_ELOG(settings == nullptr, "HStreamRepeat::UpdateStreamSupplementaryInfoSettings settings is nullptr");
    bool status = false;
    camera_metadata_item_t item;

    int32_t rawVideoStreamId = GetHdiStreamId();
    MEDIA_INFO_LOG(
        "HStreamRepeat::UpdateStreamSupplementaryInfoSettings set rawVideoStreamId: %{public}d", rawVideoStreamId);
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_STREAM_SUPPLEMENTARY_INFO, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_STREAM_SUPPLEMENTARY_INFO, &rawVideoStreamId, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = settings->updateEntry(OHOS_STREAM_SUPPLEMENTARY_INFO, &rawVideoStreamId, 1);
    }
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateStreamSupplementaryInfoSettings failed to set rawVideoStreamId");
}

void HStreamRepeat::UpdateFrameRateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    CHECK_RETURN(settings == nullptr);
    CHECK_RETURN(streamFrameRateRange_.size() == 0);
    bool status = AddOrUpdateMetadata(
        settings, OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::SetFrameRate Failed to set frame range");
}

void HStreamRepeat::UpdateFrameMuteSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                            std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting)
{
    CHECK_RETURN(settings == nullptr);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_MUTE_MODE, &item);
    CHECK_RETURN(ret == CAM_META_ITEM_NOT_FOUND || item.count == 0);
    auto mode = item.data.u8[0];
    int32_t count = 1;
    CHECK_RETURN_ELOG(dynamicSetting == nullptr, "dynamicSetting is nullptr");
    bool status = AddOrUpdateMetadata(dynamicSetting, OHOS_CONTROL_MUTE_MODE, &mode, count);
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateFrameMuteSettings Failed to set frame mute");
}

void HStreamRepeat::UpdateFrameMechSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                            std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting)
{
    CHECK_RETURN(settings == nullptr);
    bool status = false;
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FOCUS_TRACKING_MECH, &item);
    CHECK_RETURN(ret == CAM_META_ITEM_NOT_FOUND || item.count == 0);

    auto mode = item.data.u8[0];
    int32_t count = 1;
    ret = OHOS::Camera::FindCameraMetadataItem(dynamicSetting->get(), OHOS_CONTROL_FOCUS_TRACKING_MECH, &item);
    if (ret == CAM_META_SUCCESS) {
        status = dynamicSetting->updateEntry(OHOS_CONTROL_FOCUS_TRACKING_MECH, &mode, count);
    } else {
        status = dynamicSetting->addEntry(OHOS_CONTROL_FOCUS_TRACKING_MECH, &mode, count);
    }
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateFrameMechSettings Failed to set frame mech");
}

#ifdef NOTIFICATION_ENABLE
void HStreamRepeat::UpdateBeautySettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    CHECK_RETURN_ELOG(settings == nullptr, "HStreamRepeat::UpdateBeautySettings settings is nullptr");
    MEDIA_INFO_LOG("HStreamRepeat::UpdateBeautySettings enter");
    bool status = false;
    int32_t count = 1;
    uint8_t beautyType = OHOS_CAMERA_BEAUTY_TYPE_AUTO;
    uint8_t beautyLevel = BEAUTY_LEVEL;

    status = AddOrUpdateMetadata(settings, OHOS_CONTROL_BEAUTY_TYPE, &beautyType, count);
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateBeautySettings Failed to set beauty type");

    status = AddOrUpdateMetadata(settings, OHOS_CONTROL_BEAUTY_AUTO_VALUE, &beautyLevel, count);
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateBeautySettings Failed to set beauty level");
}

void HStreamRepeat::CancelNotification()
{
    auto notification = CameraBeautyNotification::GetInstance();
    CHECK_RETURN_ELOG(notification == nullptr, "Get CameraBeautyNotification instance failed");
    notification->CancelNotification();
}

// LCOV_EXCL_START
bool HStreamRepeat::IsNeedBeautyNotification()
{
    bool ret = false;
    CHECK_RETURN_RET(streamFrameRateRange_.size() == 0, ret);
    std::string notificationInfo = system::GetParameter("const.camera.notification_info", "");
    CHECK_RETURN_RET(notificationInfo.empty(), ret);

    int uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundle(uid);

    const int32_t CONFIG_SIZE = 3;
    std::vector<std::string> configInfos = SplitString(notificationInfo, '#');
    for (uint32_t i = 0; i < configInfos.size(); ++i) {
        std::vector<std::string> configInfo = SplitString(configInfos[i], '|');
        CHECK_CONTINUE(configInfo.size() < CONFIG_SIZE);
        CHECK_CONTINUE(!isIntegerRegex(configInfo[INT32_ONE]) || !isIntegerRegex(configInfo[INT32_TWO]));
        std::string configBundleName = configInfo[INT32_ZERO];
        int32_t configMinFPS = std::atoi(configInfo[INT32_ONE].c_str());
        int32_t configMAXFPS = std::atoi(configInfo[INT32_TWO].c_str());
        if (configBundleName == bundleName && configMinFPS == streamFrameRateRange_[INT32_ZERO] &&
            configMAXFPS == streamFrameRateRange_[INT32_ONE]) {
            ret = true;
            break;
        }
    }
    return ret;
}
// LCOV_EXCL_STOP
#endif

bool HStreamRepeat::IsLive()
{
    bool ret = false;
    CHECK_RETURN_RET(streamFrameRateRange_.size() == 0, ret);
    std::string config = system::GetParameter("const.camera.live_stream_config", "");
    CHECK_RETURN_RET(config.empty(), ret);

    int uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundle(uid);

    std::vector<std::string> configInfos = SplitString(config, '#');
    for (uint32_t i = 0; i < configInfos.size(); ++i) {
        std::vector<std::string> configInfo = SplitString(configInfos[i], '|');
        CHECK_CONTINUE(configInfo.size() < INT32_TWO);
        std::string configBundleName = configInfo[INT32_ZERO];
        CHECK_CONTINUE(configBundleName != bundleName);
        for (int j = INT32_ONE; j < configInfo.size(); ++j) {
            CHECK_CONTINUE(!isIntegerRegex(configInfo[j]));
            int32_t configFPS = std::atoi(configInfo[j].c_str());
            if (configFPS == streamFrameRateRange_[INT32_ZERO] && configFPS == streamFrameRateRange_[INT32_ONE]) {
                ret = true;
                break;
            }
        }
    }
    return ret;
}

void HStreamRepeat::UpdateLiveSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    CHECK_RETURN_ELOG(settings == nullptr, "HStreamRepeat::UpdateLiveSettings settings is nullptr");
    int32_t type =  static_cast<int32_t>(GetRepeatStreamType());
    MEDIA_INFO_LOG("HStreamRepeat::UpdateLiveSettings enter, type:%{public}d", type);
    bool status = false;
    int32_t count = 1;
    uint32_t mode = OHOS_CAMERA_APP_HINT_LIVE_STREAM;

    status = AddOrUpdateMetadata(settings, OHOS_CONTROL_APP_HINT, &mode, count);
    CHECK_PRINT_ELOG(!status, "HStreamRepeat::UpdateLiveSettings Failed");
}

void HStreamRepeat::SetFrameRate(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    CHECK_RETURN(settings == nullptr);
    camera_metadata_item_t item;
    int res = OHOS::Camera::CameraMetadata::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FPS_RANGES, &item);
    CHECK_RETURN(res != CAM_META_SUCCESS);
    int32_t minFrameRate = item.data.i32[0];
    int32_t maxFrameRate = item.data.i32[1];
    streamFrameRateRange_ = {minFrameRate, maxFrameRate};
}

int32_t HStreamRepeat::AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType)
{
    MEDIA_INFO_LOG("HStreamRepeat::AttachMetaSurface called");
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamRepeat::AttachMetaSurface:SystemApi is called");
    CHECK_RETURN_RET_ELOG(producer == nullptr, CAMERA_INVALID_ARG, "HStreamRepeat::AttachMetaSurface producer is null");
    SetMetaSurface(producer, videoMetaType);
    return CAMERA_OK;
}

void HStreamRepeat::SetMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType)
{
    metaSurfaceBufferQueueHolder.Set(new BufferProducerSequenceable(producer));
}

std::vector<int32_t> HStreamRepeat::GetFrameRateRange()
{
    return streamFrameRateRange_;
}

int32_t HStreamRepeat::OnFramePaused()
{
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        CHECK_EXECUTE(streamRepeatCallback_, streamRepeatCallback_->OnFramePaused());
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnFrameResumed()
{
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        CHECK_EXECUTE(streamRepeatCallback_, streamRepeatCallback_->OnFrameResumed());
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::GetMaxFps()
{
    constexpr int32_t validSize = 2;
    constexpr int32_t defaultFps = 30;
    return streamFrameRateRange_.size() < validSize ? defaultFps : streamFrameRateRange_[1];
}

int32_t HStreamRepeat::GetMuxerRotation(int32_t motionRotation)
{
    MEDIA_INFO_LOG("GetMuxerRotation is called, motionRotation: %{public}d", motionRotation);
    camera_metadata_item_t item;
    int32_t sensorOrientation = 0;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_RETURN_RET(cameraAbility_ == nullptr, -1);
        int ret = GetCorrectedCameraOrientation(HStreamCommon::GetUsePhysicalCameraOrientation(),
            cameraAbility_, sensorOrientation);
        CHECK_RETURN_RET_ELOG(
            ret != CAM_META_SUCCESS, -1, "HStreamRepeat::GetMuxerRotation get sensor orientation failed");
        MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform sensor orientation %{public}d", sensorOrientation);

        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        CHECK_RETURN_RET_ELOG(
            ret != CAM_META_SUCCESS, -1, "HStreamRepeat::GetMuxerRotation get camera position failed");
        cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        MEDIA_DEBUG_LOG("HStreamRepeat::GetMuxerRotation camera position: %{public}d", cameraPosition);
    }
    int32_t sign = cameraPosition == OHOS_CAMERA_POSITION_BACK ? 1 : -1;
    // if motionRotation is 0 or 180, and mirror is enabled, there will be a 180 compensation
    int32_t mirrorCompensation = 0;
    if (enableMirror_ && (motionRotation == STREAM_ROTATE_0 || motionRotation == STREAM_ROTATE_180)) {
        mirrorCompensation = 180;
    }
    int32_t muxerRotation = (sensorOrientation + sign * motionRotation + mirrorCompensation + STREAM_ROTATE_360)
        % STREAM_ROTATE_360;
    MEDIA_INFO_LOG("GetMuxerRotation: muxerRotation=%{public}d, based on sensorOrientation=%{public}d, "
                   "cameraPosition=%{public}d, motionRotation=%{public}d, mirrorCompensation=%{public}d",
                   muxerRotation, sensorOrientation, cameraPosition, motionRotation, mirrorCompensation);
    return muxerRotation;
}

void HStreamRepeat::SetRecorderUserMeta(std::string key, std::string val)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetRecorderUserMeta is called");
    auto recorder = recorder_.Get();
    CHECK_RETURN_ELOG(recorder == nullptr, "HStreamRepeat::SetRecorderUserMeta failed, recorder_ is null");
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    if (repeatStreamType_ == RepeatStreamType::MOVIE_FILE_RAW_VIDEO) {
        recorder->SetUserMeta(key, val);
    }
#endif
}

void HStreamRepeat::SetRecorderUserMeta(std::string key, std::vector<uint8_t> val)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetRecorderUserMeta is called");
    auto recorder = recorder_.Get();
    CHECK_RETURN_ELOG(recorder == nullptr, "HStreamRepeat::SetRecorderUserMeta failed, recorder_ is null");
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    if (repeatStreamType_ == RepeatStreamType::MOVIE_FILE_RAW_VIDEO) {
        recorder->SetUserMeta(key, val);
    }
#endif
}

sptr<ICameraRecorder> HStreamRepeat::GetCameraRecorder()
{
    MEDIA_INFO_LOG("HStreamRepeat::GetCameraRecorder is called");
    return recorder_.Get();
}
void HStreamRepeat::SetCameraRecorder(sptr<ICameraRecorder> recorder)
{
    MEDIA_INFO_LOG("HStreamRepeat::SetCameraRecorder is called");
    recorder_.Set(recorder);
}

int32_t HStreamRepeat::SetOutputSettings(const MovieSettings& movieSettings)
{
    movieSettings_ = movieSettings;
    MEDIA_INFO_LOG("HStreamRepeat::SetOutputSettings movieSettings_ has_value, bitrate:%{public}d",
        movieSettings_.videoBitrate);
    return CAMERA_OK;
}

int32_t HStreamRepeat::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_RET_ELOG(avCodecProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "avCodecProxy is null");
    avCodecProxy->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    MEDIA_DEBUG_LOG("Supported Video Codec Types: %{public}s",
                    Container2String(supportedVideoCodecTypes.begin(), supportedVideoCodecTypes.end()).c_str());
    return CAMERA_OK;
}

int32_t HStreamRepeat::UnlinkInput()
{
    MEDIA_DEBUG_LOG("HStreamRepeat::UnlinkInput is called");
    auto recorder = recorder_.Get();
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    if (repeatStreamType_ == RepeatStreamType::MOVIE_FILE_CINEMATIC_VIDEO && recorder) {
        MEDIA_DEBUG_LOG("HStreamRepeat::UnlinkInput start release recorder");
        recorder->Release();
    }
#endif
    return HStreamCommon::UnlinkInput();
}

void HStreamRepeat::StreamRepeatDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    MEDIA_ERR_LOG("HStreamRepeat Remote died.");
    auto streamRepeat = streamRepeat_.promote();
    CHECK_RETURN(!streamRepeat);
    auto recorder = streamRepeat->recorder_.Get();
    CHECK_RETURN(!recorder);
    MEDIA_DEBUG_LOG("HStreamRepeat OnRemoteDied stop recorder");
    recorder->Stop(false);
}

void HStreamRepeat::RemoveStreamOperatorDeathRecipient()
{
    MEDIA_DEBUG_LOG("RemoveStreamOperatorDeathRecipient is called");
    auto streamOperator = GetStreamOperator();
    auto streamRepeatDeathRecipient = streamRepeatDeathRecipient_.Get();
    CHECK_RETURN_DLOG(streamOperator == nullptr || streamRepeatDeathRecipient == nullptr,
        "streamOperator or streamRepeatDeathRecipient_ is nullptr, return.");
    const sptr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_0::IStreamOperator>(streamOperator);
    CHECK_PRINT_ELOG(!remote->RemoveDeathRecipient(streamRepeatDeathRecipient),
        "RemoveDeathRecipient for IStreamOperator failed.");
    streamRepeatDeathRecipient_.Set(nullptr);
    MEDIA_INFO_LOG("StreamOperator DeathRecipient is removed");
}

int64_t HStreamRepeat::GetFirstFrameTimestamp()
{
    int64_t ts = -1;
    auto recorder = recorder_.Get();
    if (recorder != nullptr) {
        recorder->GetFirstFrameTimestamp(ts);
    }
    MEDIA_DEBUG_LOG("GetFirstFrameTimestamp ts: %{public}" PRId64, ts);
    return ts;
}

int32_t HStreamRepeat::GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer)
{
    MEDIA_DEBUG_LOG("called");
    auto recorder = recorder_.Get();
    if (recorder != nullptr) {
        recorder->GetDetectedObjectLifecycleBuffer(buffer);
    }
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
