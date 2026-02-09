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
// LCOV_EXCL_START
#include "hstream_operator.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <sched.h>
#include <string>
#include <map>
#include <sync_fence.h>
#include <utility>
#include <vector>

#include "blocking_queue.h"
#include "bundle_mgr_interface.h"
#include "camera_dynamic_loader.h"
#include "camera_info_dumper.h"
#include "camera_log.h"
#include "camera_report_uitls.h"
#include "camera_server_photo_proxy.h"
#include "camera_timer.h"
#include "camera_util.h"
#include "datetime_ex.h"
#include "deferred_processing_service.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "display_lite.h"
#include "display_manager_lite.h"
#include "errors.h"
#include "fixed_size_list.h"
#include "hcamera_device_manager.h"
#include "hcamera_restore_param.h"
#include "hstream_capture.h"
#include "hstream_common.h"
#include "hstream_depth_data.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "iconsumer_surface.h"
#include "image_type.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "istream_common.h"
#include "photo_asset_proxy.h"
#include "picture_interface.h"
#include "metadata_utils.h"
#ifdef CAMERA_MOVING_PHOTO
#include "moving_photo_proxy.h"
#include "moving_photo_interface.h"
#endif
#include "parameters.h"
#include "refbase.h"
#include "smooth_zoom.h"
#include "surface.h"
#include "surface_buffer.h"
#include "system_ability_definition.h"
#include "v1_0/types.h"
#include "v1_5/types.h"
#include "camera_report_dfx_uitls.h"
#include "hstream_operator_manager.h"
#include "camera_device_ability_items.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif

using namespace OHOS::AAFwk;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;
namespace {
#ifdef CAMERA_USE_SENSOR
constexpr int32_t POSTURE_INTERVAL = 100000000; //100ms
constexpr int VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT = 3;
constexpr int32_t ROTATION_45_DEGREES = 45;
constexpr int32_t ROTATION_90_DEGREES = 90;
constexpr int32_t ROTATION_360_DEGREES = 360;
#endif
static GravityData gravityData = {0.0, 0.0, 0.0};
static int32_t sensorRotation = 0;
} // namespace

constexpr int32_t IMAGE_SHOT_TYPE = 0;
constexpr int32_t MOVING_PHOTO_SHOT_TYPE = 2;
constexpr int32_t BURST_SHOT_TYPE = 3;
static bool g_isNeedFilterMetadata = false;

bool IsHdr(ColorSpace colorSpace)
{
    std::vector<ColorSpace> hdrColorSpaces = {BT2020_HLG, BT2020_PQ, BT2020_HLG_LIMIT, BT2020_PQ_LIMIT};
    auto it = std::find(hdrColorSpaces.begin(), hdrColorSpaces.end(), colorSpace);
    return it != hdrColorSpaces.end();
}

sptr<HStreamOperator> HStreamOperator::NewInstance(const uint32_t callerToken, int32_t opMode)
{
    sptr<HStreamOperator> hStreamOperator = new HStreamOperator();
    CHECK_RETURN_RET(hStreamOperator->Initialize(callerToken, opMode) == CAMERA_OK, hStreamOperator);
    return nullptr;
}

int32_t HStreamOperator::Initialize(const uint32_t callerToken, int32_t opMode)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = static_cast<uint32_t>(IPCSkeleton::GetCallingUid());
    callerToken_ = callerToken;
    opMode_ = opMode;
    MEDIA_INFO_LOG("HStreamOperator::Initialize opMode_= %{public}d", opMode_);
    InitDefaultColortSpace(static_cast<SceneMode>(opMode));
#ifdef CAMERA_MOVING_PHOTO
    movingPhotoManagerProxy_.Set(MovingPhotoManagerProxy::CreateMovingPhotoManagerProxy());
#endif
    return CAMERA_OK;
}

void HStreamOperator::InitDefaultColortSpace(SceneMode opMode)
{
    static const std::unordered_map<SceneMode, ColorSpace> colorSpaceMap = {
        {SceneMode::NORMAL, ColorSpace::SRGB},
        {SceneMode::CAPTURE, ColorSpace::SRGB},
        {SceneMode::VIDEO, ColorSpace::BT709_LIMIT},
        {SceneMode::PORTRAIT, ColorSpace::DISPLAY_P3},
        {SceneMode::NIGHT, ColorSpace::DISPLAY_P3},
        {SceneMode::PROFESSIONAL, ColorSpace::DISPLAY_P3},
        {SceneMode::SLOW_MOTION, ColorSpace::BT709_LIMIT},
        {SceneMode::SCAN, ColorSpace::BT709_LIMIT},
        {SceneMode::CAPTURE_MACRO, ColorSpace::DISPLAY_P3},
        {SceneMode::VIDEO_MACRO, ColorSpace::BT709_LIMIT},
        {SceneMode::PROFESSIONAL_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::PROFESSIONAL_VIDEO, ColorSpace::BT709_LIMIT},
        {SceneMode::HIGH_FRAME_RATE, ColorSpace::BT709_LIMIT},
        {SceneMode::HIGH_RES_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::SECURE, ColorSpace::SRGB},
        {SceneMode::QUICK_SHOT_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::LIGHT_PAINTING, ColorSpace::DISPLAY_P3},
        {SceneMode::PANORAMA_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::TIMELAPSE_PHOTO, ColorSpace::BT709_LIMIT},
        {SceneMode::APERTURE_VIDEO, ColorSpace::BT709_LIMIT},
        {SceneMode::FLUORESCENCE_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::CINEMATIC_VIDEO, ColorSpace::BT709_LIMIT},
    };
    auto it = colorSpaceMap.find(opMode);
    currColorSpace_ = it != colorSpaceMap.end() ? it->second : ColorSpace::SRGB;
    MEDIA_DEBUG_LOG("HStreamOperator::InitDefaultColortSpace colorSpace:%{public}d", currColorSpace_);
}

ColorStylePhotoType HStreamOperator::GetSupportRedoXtStyle()
{
    CHECK_RETURN_RET(supportXtStyleRedoFlag_ != ColorStylePhotoType::UNSET, supportXtStyleRedoFlag_);
    CHECK_RETURN_RET_ELOG(cameraDevice_ == nullptr, supportXtStyleRedoFlag_,
        "HStreamOperator::GetSupportRedoXtStyle cameraDevice is nullptr");
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice_->GetDeviceAbility();
    CHECK_RETURN_RET(!ability, supportXtStyleRedoFlag_);
    camera_metadata_item_t item;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_OUTPUT_COLOR_STYLE_PHOTO_TYPE, &item);
    CHECK_RETURN_RET_ELOG(retFindMeta == CAM_META_ITEM_NOT_FOUND, supportXtStyleRedoFlag_,
        "HStreamOperator::GetSupportRedoXtStyle() metadata not found");
    supportXtStyleRedoFlag_ = static_cast<ColorStylePhotoType>(item.data.u8[0]);
    MEDIA_INFO_LOG("HStreamOperator::GetSupportRedoXtStyle()  supportXtStyleRedoFlag %{public}u.",
        static_cast<uint32_t>(item.data.u8[0]));
    return supportXtStyleRedoFlag_;
}

HStreamOperator::HStreamOperator()
{
    pid_ = 0;
    uid_ = 0;
    callerToken_ = 0;
    opMode_ = 0;
}

HStreamOperator::HStreamOperator(const uint32_t callingTokenId, int32_t opMode)
{
    Initialize(callingTokenId, opMode);
    ResetHdiStreamId();
}

HStreamOperator::~HStreamOperator()
{
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(motionPhotoStatusLock_);
        curMotionPhotoStatus_.clear();
    }
    Release();
#ifdef CAMERA_MOVING_PHOTO
    UnloadMovingPhoto();
#endif
}

#ifdef CAMERA_MOVING_PHOTO
void HStreamOperator::SetDeferredVideoEnhanceFlag(
    int32_t captureId, uint32_t deferredVideoEnhanceFlag, std::string videoId)
{
    // LCOV_EXCL_START
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "movingPhotoManagerProxy is null");
    MEDIA_INFO_LOG("HStreamOperator::GetDeferredVideoEnhanceFlag is called");
    movingPhotoManagerProxy->SetDeferredVideoEnhanceFlag(
        captureId, deferredVideoEnhanceFlag, videoId, GetSupportRedoXtStyle(), isXtStyleEnabled_);
    // LCOV_EXCL_STOP
}

void HStreamOperator::StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId)
{
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "not support moving photo");
    CHECK_RETURN(!isSetMotionPhoto_);
    // LCOV_EXCL_START
    {
        std::lock_guard<std::mutex> lock(motionPhotoStatusLock_);
        curMotionPhotoStatus_[captureId] = isSetMotionPhoto_;
        MEDIA_DEBUG_LOG("HStreamOperator::StartMovingPhotoEncode captureId : %{public}d, isSetMotionPhoto : %{public}d",
            captureId, isSetMotionPhoto_);
    }
    bool isNeedMirrorOffset = isMovingPhotoMirror_ && (rotation % STREAM_ROTATE_180);
    CHECK_EXECUTE(isNeedMirrorOffset, rotation = (rotation + STREAM_ROTATE_180) % STREAM_ROTATE_360);
    MEDIA_INFO_LOG("Moving Photo Rotation is : %{public}d", rotation);
    movingPhotoManagerProxy->StartRecord(timestamp, rotation, captureId, GetSupportRedoXtStyle(), isXtStyleEnabled_);
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_RET_ELOG(movingPhotoManagerProxy == nullptr, CAMERA_UNSUPPORTED, "not support moving photo");
    if (!isConfig) {
        isMovingPhotoMirror_ = isMirror;
        return CAMERA_OK;
    }
    CHECK_RETURN_RET(!isSetMotionPhoto_ || isMirror == isMovingPhotoMirror_, CAMERA_OK);
    // LCOV_EXCL_START
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    auto itLivePhoto = std::find_if(repeatStreams.begin(), repeatStreams.end(), [](auto& stream) {
        return CastStream<HStreamRepeat>(stream)->GetRepeatStreamType() == RepeatStreamType::LIVEPHOTO;
    });
    CHECK_RETURN_RET(itLivePhoto == repeatStreams.end(), CAMERA_OK);
    MEDIA_INFO_LOG("restart movingphoto stream.");
    auto streamLivePhoto = CastStream<HStreamRepeat>(*itLivePhoto);
    CHECK_RETURN_RET(!streamLivePhoto->SetMirrorForLivePhoto(isMirror, opMode_), CAMERA_OK);
    isMovingPhotoMirror_ = isMirror;
    // set clear cache flag
    movingPhotoManagerProxy->SetClearFlag();
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void HStreamOperator::ReleaseTargetMovingphotoStream(VideoType type)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ReleaseTargetMovingphotoStream type:%{public}d E", static_cast<int32_t>(type));
    std::vector<int32_t> hdiStreamIds;
    auto streamRepeat = GetMovingPhotoStreamStruct(type).streamRepeat;
    CHECK_RETURN_ELOG(!streamRepeat, "TYPE:%{public}d streamRepeat is nullptr", static_cast<int32_t>(type));
    auto hdiStreamId = streamRepeat->GetHdiStreamId();
    if (hdiStreamId != STREAM_ID_UNSET) {
        hdiStreamIds.emplace_back(hdiStreamId);
    }
    streamRepeat->ReleaseStream(true);
    streamContainer_.RemoveStream(streamRepeat);
    if (!hdiStreamIds.empty()) {
        ReleaseStreams(hdiStreamIds);
    }
}

void HStreamOperator::ReleaseMovingphotoStreams()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ReleaseMovingphotoStream E");
    std::vector<int32_t> hdiStreamIds;

    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->IsLivephotoStream()) {
            auto hdiStreamId = stream->GetHdiStreamId();
            if (hdiStreamId != STREAM_ID_UNSET) {
                hdiStreamIds.emplace_back(hdiStreamId);
            }
            stream->ReleaseStream(true);
            streamContainer_.RemoveStream(stream);
        }
    }
    if (!hdiStreamIds.empty()) {
        ReleaseStreams(hdiStreamIds);
    }
}

int32_t HStreamOperator::EnableMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    bool isEnable, int32_t sensorOritation)
{
    MEDIA_INFO_LOG("HStreamOperator::EnableMovingPhoto is %{public}d", isEnable);
    isSetMotionPhoto_ = isEnable;
    deviceSensorOritation_ = sensorOritation;
    StartMovingPhotoStream(settings);
    GetMovingPhotoBufferDuration();
    GetMovingPhotoStartAndEndTime();
    return CAMERA_OK;
}

void HStreamOperator::StartMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    sptr<HStreamRepeat>& curStreamRepeat)
{
    auto thisPtr = wptr<HStreamOperator>(this);
    curStreamRepeat->SetMovingPhotoStartCallback([thisPtr, settings]() {
        auto sessionPtr = thisPtr.promote();
        CHECK_RETURN(!sessionPtr);
        MEDIA_INFO_LOG("StartMovingPhotoStream when addDeferedSurface");
        sessionPtr->StartMovingPhotoStream(settings);
    });
}

void HStreamOperator::ChangeListenerXtstyleType()
{
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "not support moving photo");
    movingPhotoManagerProxy->ChangeListenerSetXtStyleType(isXtStyleEnabled_);
}

void HStreamOperator::ClearMovingPhotoRepeatStream(VideoType videoType)
{
    CAMERA_SYNC_TRACE;
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "not support moving photo");
    MEDIA_INFO_LOG(
        "Enter HStreamOperator::ClearMovingPhotoRepeatStream() type:%{public}d", static_cast<int32_t>(videoType));
    // Already added session lock in BeginConfig()
    StopMovingPhoto(videoType);
    movingPhotoManagerProxy->ReleaseStreamStruct(videoType);
    auto streamRepeat = GetMovingPhotoStreamStruct(videoType).streamRepeat;
    CHECK_RETURN(streamRepeat == nullptr);
    MEDIA_DEBUG_LOG("ClearLivePhotoRepeatStream() stream id is:%{public}d", streamRepeat->GetFwkStreamId());
    RemoveOutputStream(streamRepeat);
    MEDIA_INFO_LOG("Exit HStreamOperator::ClearLivePhotoRepeatStream()");
}

void HStreamOperator::StopMovingPhoto(VideoType type) __attribute__((no_sanitize("cfi")))
{
    // LCOV_EXCL_START
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "not support moving photo");
    auto allStreams = streamContainer_.GetAllStreams();
    for (auto& item : allStreams) {
        if (item->GetStreamType() == StreamType::REPEAT) {
            auto repeatStream = CastStream<HStreamRepeat>(item);
            CHECK_RETURN_ELOG(repeatStream == nullptr, "current repeatStream is nullptr.");
            if (repeatStream->IsLivephotoStream() && isSetMotionPhoto_) {
                movingPhotoManagerProxy->StopMovingPhoto(type);
            }
        }
    }
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::GetMovingPhotoBufferDuration()
{
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_RET_ELOG(movingPhotoManagerProxy == nullptr, CAMERA_UNSUPPORTED, "movingPhotoManagerProxy is null");
    uint32_t preBufferDuration = 0;
    uint32_t postBufferDuration = 0;
    camera_metadata_item_t item;
    bool ret = GetDeviceAbilityByMeta(OHOS_MOVING_PHOTO_BUFFER_DURATION, &item);
    CHECK_RETURN_RET_ELOG(!ret, CAMERA_OK, "HStreamOperator::GetMovingPhotoBufferDuration get buffer duration failed");
    preBufferDuration = item.data.ui32[0];
    postBufferDuration = item.data.ui32[1];
    movingPhotoManagerProxy->SetBufferDuration(preBufferDuration, postBufferDuration);
    return CAMERA_OK;
}

void HStreamOperator::GetMovingPhotoStartAndEndTime()
{
    CHECK_RETURN_ELOG(cameraDevice_ == nullptr, "HCaptureSession::GetMovingPhotoStartAndEndTime device is null");
    cameraDevice_->SetMovingPhotoStartTimeCallback([this](int32_t captureId, int64_t startTimeStamp) {
        MEDIA_INFO_LOG("SetMovingPhotoStartTimeCallback function enter");
        auto manager = movingPhotoManagerProxy_.Get();
        CHECK_EXECUTE(manager, manager->InsertStartTime(captureId, startTimeStamp));
    });

    cameraDevice_->SetMovingPhotoEndTimeCallback([this](int32_t captureId, int64_t endTimeStamp) {
        auto manager = movingPhotoManagerProxy_.Get();
        CHECK_EXECUTE(manager, manager->InsertEndTime(captureId, endTimeStamp));
    });
}

void HStreamOperator::ExpandXtStyleMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "movingPhotoManagerProxy is null");
    MEDIA_DEBUG_LOG("ExpandXtStyleMovingPhotoRepeatStream enter");
    CHECK_RETURN_ELOG(GetSupportRedoXtStyle() != ORIGIN_AND_EFFECT || !isXtStyleEnabled_,
        "HStreamOperator::ExpandXtStyleMovingPhotoRepeatStream fail");
    ExpandMovingPhotoRepeatStream(XT_ORIGIN_VIDEO);
    movingPhotoManagerProxy->SetBrotherListener();
    MEDIA_INFO_LOG("ExpandXtStyleMovingPhotoRepeatStream Exit");
}

void HStreamOperator::ExpandMovingPhotoRepeatStream(VideoType videoType)
{
    CAMERA_SYNC_TRACE;
    auto movingPhotoManagerProxy = movingPhotoManagerProxy_.Get();
    CHECK_RETURN_ELOG(movingPhotoManagerProxy == nullptr, "movingPhotoManagerProxy is null");
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream enter");
    sptr<HStreamRepeat> streamRepeat = FindPreviewStreamRepeat();
    CHECK_RETURN_ELOG(streamRepeat == nullptr, "preview streamRepeat is null");
    int32_t format = streamRepeat->format_;
    int32_t width = streamRepeat->width_;
    int32_t height = streamRepeat->height_;
    auto& streamStruct = GetMovingPhotoStreamStruct(videoType);
    streamStruct.videoSurface = Surface::CreateSurfaceAsConsumer("movingPhoto");
    streamStruct.metaSurface = Surface::CreateSurfaceAsConsumer("movingPhotoMeta");
    sptr<AvcodecTaskManagerIntf> avcodecTaskManagerProxy = nullptr;
    movingPhotoManagerProxy->ExpandMovingPhoto(videoType, width, height, currColorSpace_,
        streamStruct.videoSurface, streamStruct.metaSurface, avcodecTaskManagerProxy);
    CreateMovingPhotoStreamRepeat(format, width, height, videoType);
    HStreamOperatorManager::GetInstance()->AddTaskManager(streamOperatorId_, avcodecTaskManagerProxy);
    MEDIA_INFO_LOG("ExpandMovingPhotoRepeatStream Exit");
}

int32_t HStreamOperator::CreateMovingPhotoStreamRepeat(int32_t format, int32_t width, int32_t height, VideoType type)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(livePhotoStreamLock_);
    CHECK_RETURN_RET_ELOG(width <= 0 || height <= 0, CAMERA_INVALID_ARG, "width or height is invalid");
    auto& streamStruct = GetMovingPhotoStreamStruct(type);
    sptr<Surface> videoSurface = streamStruct.videoSurface;
    sptr<Surface> metaSurface = streamStruct.metaSurface;
    CHECK_RETURN_RET_ELOG(videoSurface == nullptr || metaSurface == nullptr, CAMERA_INVALID_ARG, "surface is null");
    CHECK_EXECUTE(streamStruct.streamRepeat, streamStruct.streamRepeat->Release());
    auto streamRepeat = sptr<HStreamRepeat>::MakeSptr(
        videoSurface->GetProducer(), format, width, height, GetRepeatStreamType(type));
    CHECK_RETURN_RET_ELOG(streamRepeat == nullptr, CAMERA_ALLOC_ERROR, "HStreamRepeat allocation failed");
    streamStruct.streamRepeat = streamRepeat;
    streamRepeat->SetMetaProducer(metaSurface->GetProducer());
    streamRepeat->SetMirror(isMovingPhotoMirror_);
    AddOutputStream(streamRepeat);
    MEDIA_INFO_LOG("HCameraService::CreateLivePhotoStreamRepeat end");
    return CAMERA_OK;
}

void HStreamOperator::StartMovingPhotoStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t errorCode = 0;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    bool isPreviewStarted = std::any_of(repeatStreams.begin(), repeatStreams.end(), [](auto& stream) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(stream);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        CHECK_RETURN_RET(repeatType != RepeatStreamType::PREVIEW, false);
        return curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET && curStreamRepeat->producer_ != nullptr;
    });
    CHECK_RETURN_ELOG(!isPreviewStarted, "EnableMovingPhoto, preview is not streaming");

    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        CHECK_CONTINUE(!curStreamRepeat->IsLivephotoStream());
        if (isSetMotionPhoto_) {
            errorCode = curStreamRepeat->Start(settings);
            auto manager = movingPhotoManagerProxy_.Get();
            CHECK_EXECUTE(manager, manager->StartAudioCapture());
        } else {
            errorCode = curStreamRepeat->Stop();
            StopMovingPhoto();
        }
    }
    MEDIA_INFO_LOG("HStreamOperator::StartMovingPhotoStream result:%{public}d", errorCode);
}

void HStreamOperator::UnloadMovingPhoto()
{
    auto videoSurface = movingPhotoStreamStruct_.videoSurface;
    CHECK_EXECUTE(videoSurface, videoSurface->UnregisterConsumerListener());
    auto metaSurface = movingPhotoStreamStruct_.metaSurface;
    CHECK_EXECUTE(metaSurface, metaSurface->UnregisterConsumerListener());
    videoSurface = xtStyleMovingPhotoStreamStruct_.videoSurface;
    CHECK_EXECUTE(videoSurface, videoSurface->UnregisterConsumerListener());
    metaSurface = xtStyleMovingPhotoStreamStruct_.metaSurface;
    CHECK_EXECUTE(metaSurface, metaSurface->UnregisterConsumerListener());
    movingPhotoStreamStruct_= {};
    xtStyleMovingPhotoStreamStruct_= {};
    movingPhotoManagerProxy_.Set(nullptr);
}
#endif

int32_t HStreamOperator::GetCurrentStreamInfos(std::vector<StreamInfo_V1_5>& streamInfos)
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream) { // LCOV_EXCL_LINE
            StreamInfo_V1_5 curStreamInfo;
            stream->SetStreamInfo(curStreamInfo);
            if (stream->GetStreamType() != StreamType::METADATA) {
                streamInfos.push_back(curStreamInfo);
            }
        }
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::AddOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(stream == nullptr, CAMERA_INVALID_ARG, "HStreamOperator::AddOutputStream stream is null");
    MEDIA_INFO_LOG("HStreamOperator::AddOutputStream streamId:%{public}d streamType:%{public}d",
        stream->GetFwkStreamId(), stream->GetStreamType());
    CHECK_RETURN_RET_ELOG(
        stream->GetFwkStreamId() == STREAM_ID_UNSET && stream->GetStreamType() != StreamType::METADATA,
        CAMERA_INVALID_ARG, "HStreamOperator::AddOutputStream stream is released!");
    bool isAddSuccess = streamContainer_.AddStream(stream);
    CHECK_RETURN_RET_ELOG(
        !isAddSuccess, CAMERA_INVALID_SESSION_CFG, "HStreamOperator::AddOutputStream add stream fail");
    if (stream->GetStreamType() == StreamType::CAPTURE) {
        auto captureStream = CastStream<HStreamCapture>(stream);
        captureStream->SetMode(opMode_);
    }
    MEDIA_INFO_LOG("HCaptureSession::AddOutputStream stream colorSpace:%{public}d", currColorSpace_);
    stream->SetColorSpace(currColorSpace_);
    return CAMERA_OK;
}

void HStreamOperator::DisplayRotationListener::OnChange(OHOS::Rosen::DisplayId displayId)
{
    sptr<Rosen::DisplayLite> display = Rosen::DisplayManagerLite::GetInstance().GetDefaultDisplay();
    if (display == nullptr) { // LCOV_EXCL_LINE
        MEDIA_INFO_LOG("Get display info failed, display:%{public}" PRIu64 "", displayId);
        display = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(0);
        CHECK_RETURN_ELOG(display == nullptr, "Get display info failed, display is nullptr");
    }
    {
        Rosen::Rotation currentRotation = display->GetRotation();
        std::lock_guard<std::mutex> lock(mStreamManagerLock_);
        for (auto& repeatStream : repeatStreamList_) {
            CHECK_EXECUTE(repeatStream, repeatStream->SetStreamTransform(static_cast<int>(currentRotation)));
        }
    }
}

void HStreamOperator::DisplayRotationListener::AddHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
{
    std::lock_guard<std::mutex> lock(mStreamManagerLock_);
    CHECK_RETURN(!repeatStream);
    repeatStreamList_.push_back(repeatStream);
}

void HStreamOperator::DisplayRotationListener::RemoveHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
{
    std::lock_guard<std::mutex> lock(mStreamManagerLock_);
    CHECK_RETURN(!repeatStream);
    repeatStreamList_.erase(
        std::remove(repeatStreamList_.begin(), repeatStreamList_.end(), repeatStream), repeatStreamList_.end());
}

void HStreamOperator::RegisterDisplayListener(sptr<HStreamRepeat> repeat)
{
    if (displayListener_ == nullptr) {
        displayListener_ = new DisplayRotationListener();
        OHOS::Rosen::DisplayManagerLite::GetInstance().RegisterDisplayListener(displayListener_);
    }
    displayListener_->AddHstreamRepeatForListener(repeat);
}

void HStreamOperator::UnRegisterDisplayListener(sptr<HStreamRepeat> repeatStream)
{
    CHECK_RETURN(!displayListener_);
    displayListener_->RemoveHstreamRepeatForListener(repeatStream);
}

int32_t HStreamOperator::SetPreviewRotation(const std::string &deviceClass)
{
    enableStreamRotate_ = true;
    deviceClass_ = deviceClass;
    return CAMERA_OK;
}

int32_t HStreamOperator::AddOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HStreamOperator::AddOutput stream is null");
        CameraReportUtils::ReportCameraError(
            "HStreamOperator::AddOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    // Temp hack to fix the library linking issue
    sptr<IConsumerSurface> captureSurface = IConsumerSurface::Create();
    if (streamType == StreamType::CAPTURE) {
        HStreamCapture* captureSteam = static_cast<HStreamCapture*>(stream.GetRefPtr());
        errorCode = AddOutputStream(captureSteam);
        captureSteam->SetStreamOperator(this);
    } else if (streamType == StreamType::REPEAT) {
        HStreamRepeat* repeatSteam = static_cast<HStreamRepeat*>(stream.GetRefPtr());
        bool isEnableAndPreview = enableStreamRotate_ && repeatSteam != nullptr &&
            repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW;
        if (isEnableAndPreview) {
            RegisterDisplayListener(repeatSteam);
            repeatSteam->SetPreviewRotation(deviceClass_);
        }
        errorCode = AddOutputStream(repeatSteam);
    } else if (streamType == StreamType::METADATA) {
        errorCode = AddOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
    } else if (streamType == StreamType::DEPTH) {
        errorCode = AddOutputStream(static_cast<HStreamDepthData*>(stream.GetRefPtr()));
    }
    MEDIA_INFO_LOG("HStreamOperator::AddOutput with with %{public}d, rc = %{public}d", streamType, errorCode);
    return errorCode;
}

int32_t HStreamOperator::RemoveOutput(StreamType streamType, sptr<IStreamCommon> stream)
{
    int32_t errorCode = CAMERA_INVALID_ARG;
    if (stream == nullptr) {
        MEDIA_ERR_LOG("HStreamOperator::RemoveOutput stream is null");
        CameraReportUtils::ReportCameraError(
            "HStreamOperator::RemoveOutput", errorCode, false, CameraReportUtils::GetCallerInfo());
        return errorCode;
    }
    auto remote = stream->AsObject();
    CHECK_RETURN_RET_ELOG(
        remote && remote->IsProxyObject(), CAMERA_INVALID_ARG, "Please use stream created by service");
    if (streamType == StreamType::CAPTURE) {
        errorCode = RemoveOutputStream(static_cast<HStreamCapture*>(stream.GetRefPtr()));
    } else if (streamType == StreamType::REPEAT) {
        HStreamRepeat* repeatSteam = static_cast<HStreamRepeat*>(stream.GetRefPtr());
        bool isEnableAndPreview = enableStreamRotate_ && repeatSteam != nullptr &&
            repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW;
        if (isEnableAndPreview) {
            UnRegisterDisplayListener(repeatSteam);
        }
        errorCode = RemoveOutputStream(repeatSteam);
    } else if (streamType == StreamType::METADATA) {
        errorCode = RemoveOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
    }
    return errorCode;
}

int32_t HStreamOperator::RemoveOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(stream == nullptr, CAMERA_INVALID_ARG, "HStreamOperator::RemoveOutputStream stream is null");
    MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream,streamType:%{public}d, streamId:%{public}d",
        stream->GetStreamType(), stream->GetFwkStreamId());
    bool isRemoveSuccess = streamContainer_.RemoveStream(stream);
    CHECK_RETURN_RET_ELOG(
        !isRemoveSuccess, CAMERA_INVALID_SESSION_CFG, "HStreamOperator::RemoveOutputStream Invalid output");
    CHECK_RETURN_RET(stream->GetStreamType() != StreamType::CAPTURE, CAMERA_OK);
    HStreamCapture* captureSteam = static_cast<HStreamCapture*>(stream.GetRefPtr());
    bool hasEnableOffline = captureSteam && captureSteam->IsHasEnableOfflinePhoto();
    CHECK_RETURN_RET(!hasEnableOffline, CAMERA_OK);

    bool isAddSuccess = streamContainerOffline_.AddStream(stream);
    MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream,streamsize:%{public}zu", streamContainerOffline_.Size());
    if (streamContainerOffline_.Size() > 0) {
        auto allStream = streamContainerOffline_.GetAllStreams();
        for (auto& streamTemp : allStream) {
            MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream fkwstreamid is %{public}d hdistreamid"
                "is %{public}d", streamTemp->GetFwkStreamId(), streamTemp->GetHdiStreamId());
        }
    }
    captureSteam->SwitchToOffline();
    CHECK_RETURN_RET_ELOG(
        !isAddSuccess, CAMERA_INVALID_SESSION_CFG, "HStreamOperator::AddOutputStream add stream fail");
    return CAMERA_OK;
}

std::list<sptr<HStreamCommon>> HStreamOperator::GetAllStreams()
{
    return streamContainer_.GetAllStreams();
}

int32_t HStreamOperator::GetStreamsSize()
{
    return streamContainer_.Size();
}

void HStreamOperator::GetStreamOperator()
{
    CHECK_RETURN_ILOG(cameraDevice_ == nullptr, "HStreamOperator::GetStreamOperator cameraDevice_ is nullptr");
    std::lock_guard<std::mutex> lock(streamOperatorLock_);
    CHECK_RETURN(streamOperator_ != nullptr);
    cameraDevice_->GetStreamOperator(this, streamOperator_);
}

bool HStreamOperator::IsOfflineCapture()
{
    std::list<sptr<HStreamCommon>> allStream = streamContainer_.GetAllStreams();
    std::list<sptr<HStreamCommon>> allOfflineStreams = streamContainerOffline_.GetAllStreams();
    allStream.insert(allStream.end(), allOfflineStreams.begin(), allOfflineStreams.end());
    return std::any_of(allStream.begin(), allStream.end(), [](auto& stream) {
        CHECK_RETURN_RET(stream->GetStreamType() != StreamType::CAPTURE, false);
        return static_cast<HStreamCapture*>(stream.GetRefPtr())->IsHasSwitchToOffline();
    });
}

bool HStreamOperator::GetDeviceAbilityByMeta(uint32_t item, camera_metadata_item_t* metadataItem)
{
    CHECK_RETURN_RET_ELOG(cameraDevice_ == nullptr, false, "cameraDevice is nullptr.");
    auto ability = cameraDevice_->GetDeviceAbility();
    CHECK_RETURN_RET(ability == nullptr, false);
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), item, metadataItem);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, false, "get ability failed.");
    return true;
}

bool HStreamOperator::GetDeferredImageDeliveryEnabled()
{
    bool isDeferredImageDeliveryEnabled = false;
    CHECK_RETURN_RET_ELOG(cameraDevice_ == nullptr, isDeferredImageDeliveryEnabled,
        "HStreamOperator::GetDeviceCachedSetting cameraDevice is nullptr");
    auto ability = cameraDevice_->CloneCachedSettings();
    CHECK_RETURN_RET(!ability, isDeferredImageDeliveryEnabled);
    camera_metadata_item_t item;
    int retFindMeta =
        OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &item);
    CHECK_RETURN_RET_ELOG(retFindMeta != CAM_META_SUCCESS || item.count <= 0, isDeferredImageDeliveryEnabled,
        "HStreamOperator::GetDeviceCachedSetting metadata not found");
    isDeferredImageDeliveryEnabled = static_cast<bool>(item.data.u8[0]);
    MEDIA_INFO_LOG("HStreamOperator::GetDeviceCachedSetting  IsDeferredImageDeliveryEnabled %{public}d.",
        isDeferredImageDeliveryEnabled);
    return isDeferredImageDeliveryEnabled;
}

int32_t HStreamOperator::LinkInputAndOutputs(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    int32_t opMode)
{
    int32_t rc;
    std::vector<StreamInfo_V1_5> allStreamInfos;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        CHECK_RETURN_RET_ELOG(cameraDevice_ == nullptr, 0, "HStreamOperator::LinkInputAndOutputs cameraDevice is null");
        stream->SetUsePhysicalCameraOrientation(cameraDevice_->GetUsePhysicalCameraOrientation());
        stream->SetClientName(cameraDevice_->GetClientName());
        SetBasicInfo(stream);
        rc = stream->LinkInput(streamOperator_, settings);
        CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, rc, "HStreamOperator::LinkInputAndOutputs IsValidMode false");
        if (stream->GetHdiStreamId() == STREAM_ID_UNSET) {
            stream->SetHdiStreamId(GenerateHdiStreamId());
        }
        MEDIA_INFO_LOG(
            "HStreamOperator::LinkInputAndOutputs streamType:%{public}d, streamId:%{public}d ,hdiStreamId:%{public}d",
            stream->GetStreamType(), stream->GetFwkStreamId(), stream->GetHdiStreamId());
        StreamInfo_V1_5 curStreamInfo;
        HStreamRepeat* repeatStream = nullptr;
        if (stream->GetStreamType() == StreamType::REPEAT) {
            repeatStream = static_cast<HStreamRepeat*>(stream.GetRefPtr());
            CHECK_EXECUTE(opMode == static_cast<SceneMode>(opMode), repeatStream->SetCurrentMode(opMode));
        }
        stream->SetStreamInfo(curStreamInfo);
        CHECK_EXECUTE(stream->GetStreamType() != StreamType::METADATA,
            allStreamInfos.push_back(curStreamInfo));
    }

    rc = CreateAndCommitStreams(allStreamInfos, settings, opMode);
    MEDIA_INFO_LOG("HStreamOperator::LinkInputAndOutputs execute success");
    return rc;
}

void HStreamOperator::SetBasicInfo(sptr<HStreamCommon> stream)
{
#ifdef HOOK_CAMERA_OPERATOR
    CHECK_RETURN_DLOG(cameraDevice_ == nullptr, "HStreamOperator::SetBasicInfo() cameraDevice is null");
    std::map<int32_t, std::string> basicParam;
    basicParam[PLUGIN_BUNDLE_NAME] = cameraDevice_->GetClientName();
    basicParam[PLUGIN_CAMERA_ID] = cameraDevice_->GetCameraId();
    basicParam[PLUGIN_CAMERA_CONNECTION_TYPE] = to_string(cameraDevice_->GetCameraConnectType());
    basicParam[PLUGIN_CAMERA_POSITION] = to_string(cameraDevice_->GetCameraPosition());
    basicParam[PLUGIN_SENSOR_ORIENTATION] = to_string(cameraDevice_->GetSensorOrientation());
    MEDIA_INFO_LOG("HStreamOperator::SetBasicInfo cameraDevice_ is %{public}s ",
        basicParam[PLUGIN_CAMERA_ID].c_str());
    stream->SetBasicInfo(basicParam);
#endif
}

int32_t HStreamOperator::UnlinkInputAndOutputs()
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_UNKNOWN_ERROR;
    std::vector<int32_t> fwkStreamIds;
    std::vector<int32_t> hdiStreamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        fwkStreamIds.emplace_back(stream->GetFwkStreamId());
        hdiStreamIds.emplace_back(stream->GetHdiStreamId());
        stream->UnlinkInput();
    }
    MEDIA_INFO_LOG("HStreamOperator::UnlinkInputAndOutputs() streamIds size() = %{public}zu, streamIds:%{public}s, "
        "hdiStreamIds:%{public}s",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());
    ReleaseStreams(hdiStreamIds);
    std::vector<StreamInfo_V1_5> emptyStreams;
    UpdateStreams(emptyStreams);
    ResetHdiStreamId();
    return rc;
}

int32_t HStreamOperator::UnlinkOfflineInputAndOutputs()
{
    CAMERA_SYNC_TRACE;
    int32_t rc = CAMERA_UNKNOWN_ERROR;
    std::vector<int32_t> fwkStreamIds;
    std::vector<int32_t> hdiStreamIds;
    auto allStream = streamContainerOffline_.GetAllStreams();
    for (auto& stream : allStream) {
        fwkStreamIds.emplace_back(stream->GetFwkStreamId());
        hdiStreamIds.emplace_back(stream->GetHdiStreamId());
        CastStream<HStreamCapture>(stream)->Release();
    }
    MEDIA_INFO_LOG("HStreamOperator::UnlinkOfflineInputAndOutputs() streamIds size() = %{public}zu,"
        "streamIds:%{public}s, hdiStreamIds:%{public}s",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());
    return rc;
}

void HStreamOperator::ExpandSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ExpandSketchRepeatStream()");
    std::set<sptr<HStreamCommon>> sketchStreams;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repeatStreams.begin(), repeatStreams.end(), [&](auto& stream) {
        CHECK_RETURN(!stream);
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        // skip SKETCH stream
        CHECK_RETURN(streamRepeat->GetRepeatStreamType() == RepeatStreamType::SKETCH);
        sptr<HStreamRepeat> sketchStream = streamRepeat->GetSketchStream();
        CHECK_RETURN(!sketchStream);
        sketchStreams.insert(sketchStream);
    });

    MEDIA_DEBUG_LOG("HStreamOperator::ExpandSketchRepeatStream() sketch size is:%{public}zu", sketchStreams.size());
    for (auto& stream : sketchStreams) {
        AddOutputStream(stream);
    }
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ExpandSketchRepeatStream()");
}

void HStreamOperator::ExpandCompositionRepeatStream()
{
    MEDIA_INFO_LOG("HStreamOperator::ExpandCompositionRepeatStream enter");
    CHECK_RETURN_ELOG(!IsSupportedCompositionStream(),
        "HStreamOperator::ExpandCompositionRepeatStream not supported composition stream, return");
    auto supportedSizes = GetSupportedRecommendedPictureSize();
    CHECK_RETURN_ELOG(
        supportedSizes.empty(), "HStreamOperator::ExpandCompositionRepeatStream supportedSizes is empty, return");
    std::set<sptr<HStreamCommon>> compositionStreams;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repeatStreams.begin(), repeatStreams.end(), [&](auto& stream) {
        CHECK_RETURN(!stream);
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        // expend composition stream for preview
        CHECK_RETURN(streamRepeat->GetRepeatStreamType() != RepeatStreamType::PREVIEW);
        auto [width, height] = FindNearestRatioSize({ streamRepeat->width_, streamRepeat->height_ }, supportedSizes);
        CHECK_RETURN_ELOG(width <= 0 || height <= 0,
            "HStreamRepeat::ExpandCompositionRepeatStream size is illegal");
        const int32_t CAMERA_FORMAT_YUV_420_SP = 1003;
        auto compositionStream = sptr<HStreamRepeat>::MakeSptr(
            nullptr, CAMERA_FORMAT_YUV_420_SP, width, height, RepeatStreamType::COMPOSITION);
        CHECK_RETURN_ELOG(compositionStream == nullptr,
            "HStreamOperator::ExpandCompositionRepeatStream HStreamRepeat allocation failed");
        streamRepeat->SetCompositionStream(compositionStream);
        compositionStreams.insert(compositionStream);
    });

    MEDIA_DEBUG_LOG("HStreamOperator::ExpandCompositionRepeatStream() size is:%{public}zu", compositionStreams.size());
    for (auto& stream : compositionStreams) {
        AddOutputStream(stream);
    }
    MEDIA_INFO_LOG("Exit HStreamOperator::ExpandCompositionRepeatStream()");
}

std::vector<sptr<HStreamRepeat>> HStreamOperator::GetCompositionStreams()
{
    MEDIA_INFO_LOG("HStreamOperator::GetCompositionRepeatStream enter");
    std::set<sptr<HStreamRepeat>> compositionStreams;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repeatStreams.begin(), repeatStreams.end(), [&](auto& stream) {
        CHECK_RETURN(!stream);
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        // find composition stream
        CHECK_RETURN(streamRepeat->GetRepeatStreamType() != RepeatStreamType::PREVIEW);
        auto compositionStream = streamRepeat->GetCompositionStream();
        CHECK_RETURN(!compositionStream);
        compositionStreams.insert(compositionStream);
    });

    MEDIA_DEBUG_LOG("HStreamOperator::GetCompositionRepeatStream() size is:%{public}zu", compositionStreams.size());
    return { compositionStreams.begin(), compositionStreams.end() };
}

bool HStreamOperator::IsSupportedCompositionStream(){
    switch (opMode_) {
        case SceneMode::CAPTURE:
        case SceneMode::PORTRAIT:
        case SceneMode::NIGHT:
            break;
        default:
            MEDIA_WARNING_LOG("HStreamOperator::IsSupportedCompositionStream mode check fail");
            return false;
    }

    camera_metadata_item_t item;
    bool ret = GetDeviceAbilityByMeta(OHOS_ABILITY_COMPOSITION_EFFECT_PREVIEW, &item);
    CHECK_RETURN_RET_ELOG(!ret,false, "HStreamOperator::IsSupportedCompositionStream get metadata failed");
    CHECK_RETURN_RET_ELOG(item.count <= 0,false, "HStreamOperator::IsSupportedCompositionStream count is 0");
    return static_cast<bool>(item.data.u8[0]);
}

std::vector<Size> HStreamOperator::GetSupportedRecommendedPictureSize()
{
    MEDIA_INFO_LOG("HStreamOperator::GetSupportedRecommendedPictureSize is called");
    camera_metadata_item_t item;
    bool ret = GetDeviceAbilityByMeta(OHOS_ABILITY_COMPOSITION_RECOMMENDED_PICTURE_SIZE, &item);
    CHECK_RETURN_RET_ELOG(!ret, {}, "HStreamOperator::GetSupportedRecommendedPictureSize get item failed");
    CHECK_RETURN_RET_ELOG(item.count <= 0, {}, "HStreamOperator::GetSupportedRecommendedPictureSize count is 0");
    std::vector<Size> supportedPictureSizes;
    const int32_t STEP = 2;
    for (uint32_t i = 0; i + 1 < item.count; i += STEP) {
        uint32_t w = item.data.ui32[i];
        uint32_t h = item.data.ui32[i + 1];
        supportedPictureSizes.emplace_back(Size { w, h });
        MEDIA_DEBUG_LOG(
            "HStreamOperator::GetSupportedRecommendedPictureSize supportedPictureSizes w: %{public}u, h: %{public}u", w,
            h);
    }
    MEDIA_INFO_LOG("HStreamOperator::GetSupportedRecommendedPictureSize supportedPictureSizes size: %{public}zu",
        supportedPictureSizes.size());
    return supportedPictureSizes;
}

Size HStreamOperator::FindNearestRatioSize(Size toFitSize,const std::vector<Size>& supportedSizes)
{
    Size defaultSize { 0, 0 };
    CHECK_RETURN_RET(toFitSize.height == 0, defaultSize);
    float ratioToMatch = 1.0 * toFitSize.width / toFitSize.height;
    float minDis = std::numeric_limits<float>::max();
    const int32_t UNAVAILABLE = -1;
    int32_t matchedIndex = UNAVAILABLE;
    for (size_t i = 0; i < supportedSizes.size(); ++i) {
        auto [w, h] = supportedSizes[i];
        CHECK_CONTINUE(h == 0);
        float ratio = 1.0 * w / h;
        float dis = std::abs(ratio - ratioToMatch);
        if (dis < minDis) {
            minDis = dis;
            matchedIndex = i;
        }
    }
    if (matchedIndex == UNAVAILABLE) {
        return { 0, 0 };
    }
    return supportedSizes[matchedIndex];
}

sptr<HStreamRepeat> HStreamOperator::FindPreviewStreamRepeat()
{
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        CHECK_RETURN_RET(
            streamRepeat && streamRepeat->GetRepeatStreamType() == RepeatStreamType::PREVIEW, streamRepeat);
    }
    return nullptr;
}

const sptr<HStreamCommon> HStreamOperator::GetStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetStream(streamId) != nullptr ? streamContainer_.GetStream(streamId) :
        streamContainerOffline_.GetStream(streamId);

    CHECK_PRINT_ELOG(
        stream == nullptr, "HStreamOperator::GetStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

const sptr<HStreamCommon> HStreamOperator::GetHdiStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetHdiStream(streamId) != nullptr ? streamContainer_.GetHdiStream(streamId) :
        streamContainerOffline_.GetHdiStream(streamId);
    CHECK_PRINT_DLOG(
        stream == nullptr, "HStreamOperator::GetHdiStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

void HStreamOperator::ClearSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ClearSketchRepeatStream()");

    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repeatStreams.begin(), repeatStreams.end(), [this](auto& repeatStream) {
        CHECK_RETURN(!repeatStream);
        auto sketchStream = CastStream<HStreamRepeat>(repeatStream);
        CHECK_RETURN(sketchStream->GetRepeatStreamType() != RepeatStreamType::SKETCH);
        MEDIA_DEBUG_LOG(
            "HStreamOperator::ClearSketchRepeatStream() stream id is:%{public}d", sketchStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    });
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ClearSketchRepeatStream()");
}

void HStreamOperator::ClearCompositionRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ClearCompositionRepeatStream()");

    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repeatStreams.begin(), repeatStreams.end(), [this](auto& repeatStream) {
        CHECK_RETURN(!repeatStream);
        auto compositionStream= CastStream<HStreamRepeat>(repeatStream);
        CHECK_RETURN(compositionStream->GetRepeatStreamType() != RepeatStreamType::COMPOSITION);
        MEDIA_DEBUG_LOG("HStreamOperator::ClearCompositionRepeatStream() stream id is: %{public}d",
            compositionStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    });
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ClearCompositionRepeatStream()");
}

int32_t HStreamOperator::GetActiveColorSpace(ColorSpace& colorSpace)
{
    colorSpace = currColorSpace_;
    return CAMERA_OK;
}

int32_t HStreamOperator::SetColorSpace(ColorSpace colorSpace, bool isNeedUpdate)
{
    int32_t result = CAMERA_OK;
    CHECK_RETURN_RET_ELOG(
        colorSpace == currColorSpace_, result, "HStreamOperator::SetColorSpace() colorSpace no need to update.");
    MEDIA_INFO_LOG("HStreamOperator::SetColorSpace() old ColorSpace: %{public}d, new ColorSpace: %{public}d",
        currColorSpace_, colorSpace);
    result = CheckIfColorSpaceMatchesFormat(colorSpace);
    if (result != CAMERA_OK) {
        CHECK_RETURN_RET_ELOG(opMode_ != static_cast<int32_t>(SceneMode::VIDEO) || isNeedUpdate, result,
            "HStreamOperator::SetColorSpace() Failed, format and colorSpace not match.");

        MEDIA_ERR_LOG("HStreamOperator::SetColorSpace() %{public}d, format and colorSpace: %{public}d not match.",
            result, colorSpace);
        currColorSpace_ = ColorSpace::BT709;
    } else {
        currColorSpace_ = colorSpace;
    }
    SetColorSpaceForStreams();
    MEDIA_INFO_LOG("HStreamOperator::SetColorSpace() colorSpace: %{public}d, isNeedUpdate: %{public}d",
        currColorSpace_, isNeedUpdate);
    return result;
}

void HStreamOperator::SetColorSpaceForStreams()
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        MEDIA_DEBUG_LOG("HStreamOperator::SetColorSpaceForStreams() streams type %{public}d", stream->GetStreamType());
        stream->SetColorSpace(currColorSpace_);
    }
}

void HStreamOperator::CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_5>& streamInfos)
{
    MEDIA_INFO_LOG("HStreamOperator::CancelStreamsAndGetStreamInfos enter.");
    auto streams = streamContainer_.GetAllStreams();

    std::for_each(streams.begin(), streams.end(), [this, &streamInfos](auto& stream) {
        CHECK_RETURN(stream->GetStreamType() == StreamType::METADATA);
        if (stream->GetStreamType() == StreamType::CAPTURE && isSessionStarted_) {
            static_cast<HStreamCapture*>(stream.GetRefPtr())->CancelCapture();
        } else if (stream->GetStreamType() == StreamType::REPEAT && isSessionStarted_) {
            static_cast<HStreamRepeat*>(stream.GetRefPtr())->Stop();
        }
        StreamInfo_V1_5 curStreamInfo;
        stream->SetStreamInfo(curStreamInfo);
        streamInfos.push_back(curStreamInfo);
    });
}

void HStreamOperator::RestartStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    MEDIA_INFO_LOG("HStreamOperator::RestartStreams() enter.");
    auto repStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    std::for_each(repStreams.begin(), repStreams.end(), [&settings](auto& stream) {
        auto repStream = CastStream<HStreamRepeat>(stream);
        CHECK_RETURN(repStream->GetRepeatStreamType() != RepeatStreamType::PREVIEW);
        repStream->Start(settings);
    });
}

int32_t HStreamOperator::UpdateStreamInfos(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    std::vector<StreamInfo_V1_5> streamInfos;
    CancelStreamsAndGetStreamInfos(streamInfos);
    int errorCode = UpdateStreams(streamInfos);
    CHECK_RETURN_RET_DLOG(
        errorCode != CAMERA_OK, errorCode, "HStreamOperator::UpdateStreamInfos err %{public}d", errorCode);
    RestartStreams(settings);
    return CAMERA_OK;
}

int32_t HStreamOperator::VerifyCaptureModeColorSpace(ColorSpace colorSpace)
{
    // check format and color space pair for non-sys capture mode
    int32_t result = CAMERA_OK;
    CHECK_RETURN_RET(CheckSystemApp() || opMode_ != static_cast<int32_t>(SceneMode::CAPTURE), result);
    bool isBT2020ColorSpace = colorSpace == ColorSpace::BT2020_HLG || colorSpace == ColorSpace::BT2020_PQ ||
                              colorSpace == ColorSpace::BT2020_HLG_LIMIT || colorSpace == ColorSpace::BT2020_PQ_LIMIT;
    auto repStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (const auto& stream : repStreams) {
        sptr<HStreamRepeat> repStream = CastStream<HStreamRepeat>(stream);
        CHECK_CONTINUE(repStream->GetRepeatStreamType() != RepeatStreamType::PREVIEW);
        bool isP010Format = repStream->format_ == OHOS_CAMERA_FORMAT_YCBCR_P010 ||
                            repStream->format_ == OHOS_CAMERA_FORMAT_YCRCB_P010;
        bool isValidPair = (isBT2020ColorSpace == isP010Format);
        CHECK_RETURN_RET_ELOG(!isValidPair, CAMERA_OPERATION_NOT_ALLOWED,
                              "VerifyCaptureModeColorSpace failed, for StreamType %{public}d: Format - %{public}d and "
                              "ColorSpace - %{public}d is not a valid pair",
                              repStream->GetStreamType(), repStream->format_, colorSpace);
    }
    return result;
}

int32_t HStreamOperator::CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace)
{
    int32_t result = VerifyCaptureModeColorSpace(colorSpace);
    CHECK_RETURN_RET_ELOG(result != CAMERA_OK, result, "VerifyCaptureModeColorSpace failed, ret: %{public}d", result);
    CHECK_RETURN_RET(!(colorSpace == ColorSpace::BT2020_HLG || colorSpace == ColorSpace::BT2020_PQ ||
                         colorSpace == ColorSpace::BT2020_HLG_LIMIT || colorSpace == ColorSpace::BT2020_PQ_LIMIT),
        CAMERA_OK);
    MEDIA_DEBUG_LOG("HStreamOperator::CheckIfColorSpaceMatchesFormat start");
    // 选择BT2020，需要匹配10bit的format；若不匹配，返回error
    auto capStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    for (auto& capStream : capStreams) {
        CHECK_RETURN_RET_ELOG(
            !(capStream->format_ == OHOS_CAMERA_FORMAT_JPEG || capStream->format_ == OHOS_CAMERA_FORMAT_YCRCB_420_SP ||
                capStream->format_ == OHOS_CAMERA_FORMAT_HEIC),
            CAMERA_OPERATION_NOT_ALLOWED, "HStreamOperator::CheckFormat, streamType:%{public}d format not match",
            capStream->GetStreamType());
    }

    auto repStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& repStream : repStreams) {
        CHECK_RETURN_RET_ELOG(!(repStream->format_ == OHOS_CAMERA_FORMAT_YCBCR_P010 ||
                                  repStream->format_ == OHOS_CAMERA_FORMAT_YCRCB_P010),
            CAMERA_OPERATION_NOT_ALLOWED, "HStreamOperator::CheckFormat, streamType:%{public}d format not match",
            repStream->GetStreamType());
    }

    MEDIA_DEBUG_LOG("HStreamOperator::CheckIfColorSpaceMatchesFormat end");
    return CAMERA_OK;
}

int32_t HStreamOperator::StartPreviewStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    camera_position_enum_t cameraPosition)
{
    int32_t errorCode = CAMERA_OK;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
#ifdef CAMERA_MOVING_PHOTO
    bool hasDerferedPreview = false;
#endif
    // start preview
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        CHECK_CONTINUE(repeatType != RepeatStreamType::PREVIEW);
        CHECK_CONTINUE(curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET);
        curStreamRepeat->SetUsedAsPosition(cameraPosition);
        errorCode = curStreamRepeat->Start(settings);
#ifdef CAMERA_MOVING_PHOTO
        hasDerferedPreview = curStreamRepeat->producer_ == nullptr;
        bool isMotionPhotoWithDeferredPreview = isSetMotionPhoto_ && hasDerferedPreview;
        if (isMotionPhotoWithDeferredPreview) {
            StartMovingPhoto(settings, curStreamRepeat);
        }
#endif
        CHECK_BREAK_ELOG(
            errorCode != CAMERA_OK, "HStreamOperator::Start(), Failed to start preview, rc: %{public}d", errorCode);
    }
#ifdef CAMERA_MOVING_PHOTO
    // start movingPhoto
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        CHECK_CONTINUE(!curStreamRepeat->IsLivephotoStream());
        int32_t movingPhotoErrorCode = CAMERA_OK;
        bool isMotionPhotoWithoutDeferredPreview = isSetMotionPhoto_ && !hasDerferedPreview;
        if (isMotionPhotoWithoutDeferredPreview) {
            movingPhotoErrorCode = curStreamRepeat->Start(settings);
            auto manager = movingPhotoManagerProxy_.Get();
            CHECK_EXECUTE(manager, manager->StartAudioCapture());
        }
        CHECK_BREAK_ELOG(
            movingPhotoErrorCode != CAMERA_OK, "Failed to start movingPhoto, rc: %{public}d", movingPhotoErrorCode);
    }
#endif
    return errorCode;
}

int32_t HStreamOperator::UpdateSettingForFocusTrackingMech(bool isEnableMech)
{
    MEDIA_INFO_LOG("%{public}s is called!", __FUNCTION__);
    std::lock_guard<std::mutex> mechLock(mechCallbackLock_);
    CHECK_RETURN_RET(!streamOperator_, CAMERA_INVALID_STATE);
    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    streamOperator_->GetVersion(majorVer, minorVer);
    CHECK_RETURN_RET_DLOG(GetVersionId(majorVer, minorVer) < HDI_VERSION_ID_1_3, CAMERA_OK,
        "UpdateSettingForFocusTrackingMech version: %{public}d.%{public}d", majorVer, minorVer);
    sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperatorV1_3 =
        OHOS::HDI::Camera::V1_3::IStreamOperator::CastFrom(streamOperator_);
    CHECK_RETURN_RET(!streamOperatorV1_3, CAMERA_UNKNOWN_ERROR);
    const int32_t DEFAULT_ITEMS = 1;
    const int32_t DEFAULT_DATA_LENGTH = 10;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata4Types =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    bool needAddMetadataType = true;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        if (stream->GetStreamType() != StreamType::METADATA) {
            continue;
        }
        auto streamMetadata = CastStream<HStreamMetadata>(stream);
        auto types = streamMetadata->GetMetadataObjectTypes();
        if (std::find(types.begin(), types.end(), static_cast<int32_t>(MetadataObjectType::FACE)) != types.end()) {
            needAddMetadataType = false;
            break;
        }
    }
    g_isNeedFilterMetadata = needAddMetadataType;
    std::vector<uint8_t> typeTagToHal;
    typeTagToHal.emplace_back(static_cast<int32_t>(MetadataObjectType::BASE_TRACKING_REGION));
    if (needAddMetadataType) {
        typeTagToHal.emplace_back(static_cast<int32_t>(MetadataObjectType::FACE));
    }
    uint32_t count = typeTagToHal.size();
    uint8_t* typesToEnable = typeTagToHal.data();
    bool status = metadata4Types->addEntry(OHOS_CONTROL_STATISTICS_DETECT_SETTING, typesToEnable, count);
    CHECK_RETURN_RET_ELOG(!status, CAMERA_UNKNOWN_ERROR, "set_camera_metadata failed!");
    std::vector<uint8_t> settings;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metadata4Types, settings);
    if (isEnableMech) {
        MEDIA_INFO_LOG("%{public}s EnableResult start!", __FUNCTION__);
        streamOperatorV1_3->EnableResult(-1, settings);
    } else {
        MEDIA_INFO_LOG("%{public}s DisableResult start!", __FUNCTION__);
        streamOperatorV1_3->DisableResult(-1, settings);
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::Stop()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    MEDIA_INFO_LOG("HStreamOperator::Stop prepare execute");
    auto allStreams = streamContainer_.GetAllStreams();
    for (auto& item : allStreams) {
        if (item->GetStreamType() == StreamType::REPEAT) {
            auto repeatStream = CastStream<HStreamRepeat>(item);
            if (repeatStream->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
                errorCode = repeatStream->Stop();
            } else if (repeatStream->IsLivephotoStream()) {
                repeatStream->Stop();
#ifdef CAMERA_MOVING_PHOTO
                StopMovingPhoto();
#endif
            } else {
                repeatStream->Stop();
            }
        } else if (item->GetStreamType() == StreamType::METADATA) {
            CastStream<HStreamMetadata>(item)->Stop();
        } else if (item->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(item)->CancelCapture();
        } else if (item->GetStreamType() == StreamType::DEPTH) {
            CastStream<HStreamDepthData>(item)->Stop();
        } else {
            MEDIA_ERR_LOG("HStreamOperator::Stop(), get unknow stream, streamType: %{public}d, streamId:%{public}d",
                item->GetStreamType(), item->GetFwkStreamId());
        }
        CHECK_PRINT_ELOG(errorCode != CAMERA_OK,
            "HStreamOperator::Stop(), Failed to stop stream, rc: %{public}d, streamId:%{public}d", errorCode,
            item->GetFwkStreamId());
    }
    MEDIA_INFO_LOG("HStreamOperator::Stop execute success");
    return errorCode;
}

void HStreamOperator::ReleaseStreams()
{
    CAMERA_SYNC_TRACE;
    std::vector<int32_t> fwkStreamIds;
    std::vector<int32_t> hdiStreamIds;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        if (stream->GetStreamType() == StreamType::CAPTURE &&
            CastStream<HStreamCapture>(stream)->IsHasSwitchToOffline()) {
            continue;
        }
        auto fwkStreamId = stream->GetFwkStreamId();
        if (fwkStreamId != STREAM_ID_UNSET) {
            fwkStreamIds.emplace_back(fwkStreamId);
        }
        auto hdiStreamId = stream->GetHdiStreamId();
        if (hdiStreamId != STREAM_ID_UNSET) {
            hdiStreamIds.emplace_back(hdiStreamId);
        }
        stream->ReleaseStream(true);
        streamContainer_.RemoveStream(stream);
    }
    MEDIA_INFO_LOG("HStreamOperator::ReleaseStreams() streamIds size() = %{public}zu, fwkStreamIds:%{public}s, "
        "hdiStreamIds:%{public}s,",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());
    CHECK_RETURN(hdiStreamIds.empty());
    ReleaseStreams(hdiStreamIds);
}

int32_t HStreamOperator::GetOfflineOutptSize()
{
    std::list<sptr<HStreamCommon>> captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    std::list<sptr<HStreamCommon>> captureStreamsOffline = streamContainerOffline_.GetStreams(StreamType::CAPTURE);
    captureStreams.insert(captureStreams.end(), captureStreamsOffline.begin(), captureStreamsOffline.end());
    return std::count_if(captureStreams.begin(), captureStreams.end(),
        [](auto& stream) { return CastStream<HStreamCapture>(stream)->IsHasEnableOfflinePhoto(); });
}

int32_t HStreamOperator::ReleaseStreams(std::vector<int32_t>& releaseStreamIds)
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetHDIStreamOperator();
    CHECK_RETURN_RET(streamOperator == nullptr || releaseStreamIds.empty(), CAMERA_OK);
    MEDIA_INFO_LOG("HStreamOperator::ReleaseStreams %{public}s",
        Container2String(releaseStreamIds.begin(), releaseStreamIds.end()).c_str());
    int32_t rc = streamOperator->ReleaseStreams(releaseStreamIds);
    if (rc != HDI::Camera::V1_0::NO_ERROR) { // LCOV_EXCL_LINE
        MEDIA_ERR_LOG("HCameraDevice::ClearStreamOperator ReleaseStreams fail, error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::ReleaseStreams", rc, true, CameraReportUtils::GetCallerInfo());
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::Release()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    {
        std::lock_guard<std::mutex> lock(releaseOperatorLock_);
        if (displayListener_) {
            OHOS::Rosen::DisplayManagerLite::GetInstance().UnregisterDisplayListener(displayListener_);
            displayListener_ = nullptr;
        }
        auto streamOperator = GetHDIStreamOperator();
        if (streamOperator != nullptr) {
            ResetHDIStreamOperator();
            MEDIA_INFO_LOG("HStreamOperator::Release ResetHDIStreamOperator");
        }
        HStreamOperatorManager::GetInstance()->RemoveStreamOperator(streamOperatorId_);
    }
#ifdef CAMERA_MOVING_PHOTO
    auto manager = movingPhotoManagerProxy_.Get();
    CHECK_EXECUTE(manager, manager->Release());
    HStreamOperatorManager::GetInstance()->RemoveTaskManager(streamOperatorId_);
#endif

#ifdef CAMERA_USE_SENSOR
    UnRegisterSensorCallback();
#endif
    MEDIA_INFO_LOG("HStreamOperator::Release execute success");
    return errorCode;
}

int32_t HStreamOperator::CreateAndCommitStreams(std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode)
{
    AdjustStreamInfosByMode(streamInfos, operationMode);
    int retCode = CreateStreams(streamInfos);
    CHECK_RETURN_RET(retCode != CAMERA_OK, retCode);
    return CommitStreams(deviceSettings, operationMode);
}

void HStreamOperator::AdjustStreamInfosByMode(
    std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos, int32_t operationMode)
{
    MEDIA_INFO_LOG("enter");
    CHECK_RETURN(operationMode != OHOS::HDI::Camera::V1_5::OperationMode::STITCHING_PHOTO);

    // stitching mode: set thumbnail size to the same as that of preview before CommitStreams
    auto isPreWindowsExtStream = [](const HDI::Camera::V1_1::ExtendedStreamInfo& extInfo) {
        return extInfo.type ==
            static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                HDI::Camera::V1_5::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_PHOTO_STITCHING);
    };
    auto itPre = std::find_if(streamInfos.begin(), streamInfos.end(), [&isPreWindowsExtStream](const auto& streamInfo) {
        return streamInfo.v1_0.intent_ == StreamIntent::PREVIEW &&
            !std::any_of(
                streamInfo.extendedStreamInfos.begin(), streamInfo.extendedStreamInfos.end(), isPreWindowsExtStream);
    });
    CHECK_RETURN_ELOG(itPre == streamInfos.end(), "not find preview streamInfo!");

    auto isThumbExtStream = [](const HDI::Camera::V1_1::ExtendedStreamInfo& extInfo) {
        return extInfo.type == HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
    };
    auto itThumb = std::find_if(streamInfos.begin(), streamInfos.end(), [&isThumbExtStream](const auto& streamInfo) {
        return streamInfo.v1_0.intent_ == STILL_CAPTURE &&
            std::any_of(streamInfo.extendedStreamInfos.begin(), streamInfo.extendedStreamInfos.end(), isThumbExtStream);
    });
    CHECK_RETURN_ELOG(itThumb == streamInfos.end(), "not find capture thumbnail streamInfo!");

    auto itThumbExt =
        std::find_if(itThumb->extendedStreamInfos.begin(), itThumb->extendedStreamInfos.end(), isThumbExtStream);
    itThumbExt->width = itPre->v1_0.width_;
    itThumbExt->height = itPre->v1_0.height_;
    MEDIA_INFO_LOG("reset thumbnail W H to %{public}d x %{public}d", itThumbExt->width, itThumbExt->height);
}

int32_t HStreamOperator::CommitStreams(
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    uint32_t major;
    uint32_t minor;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    std::lock_guard<std::mutex> lock(opMutex_);
    streamOperator = GetHDIStreamOperator();
    CHECK_RETURN_RET_ELOG(
        streamOperator == nullptr, CAMERA_UNKNOWN_ERROR, "HStreamOperator::CommitStreams GetStreamOperator is null!");
    // get higher streamOperator version
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG(
        "HStreamOperator::CommitStreams streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    // LCOV_EXCL_START
    if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_1) {
        MEDIA_DEBUG_LOG("HStreamOperator::CommitStreams IStreamOperator cast to V1_1");
        streamOperatorV1_1 = OHOS::HDI::Camera::V1_1::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_1 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::CommitStreams IStreamOperator cast to V1_1 error");
            streamOperatorV1_1 = static_cast<OHOS::HDI::Camera::V1_1::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }

    std::vector<uint8_t> setting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(deviceSettings, setting);
    MEDIA_INFO_LOG("HStreamOperator::CommitStreams, commit mode %{public}d", operationMode);
    if (streamOperatorV1_1 != nullptr) {
        MEDIA_DEBUG_LOG("HStreamOperator::CommitStreams IStreamOperator V1_1");
        hdiRc = (CamRetCode)(streamOperatorV1_1->CommitStreams_V1_1(
            static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(operationMode), setting));
    } else {
        MEDIA_DEBUG_LOG("HStreamOperator::CommitStreams IStreamOperator V1_0");
        OperationMode opMode = OperationMode::NORMAL;
        hdiRc = (CamRetCode)(streamOperator->CommitStreams(opMode, setting));
    }
    if (hdiRc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamOperator::CommitStreams failed with error Code:%d", hdiRc);
        CameraReportUtils::ReportCameraError(
            "HStreamOperator::CommitStreams", hdiRc, true, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_DEBUG_LOG("HStreamOperator::CommitStreams end");
    return HdiToServiceError(hdiRc);
}
// LCOV_EXCL_STOP

void HStreamOperator::GetOutputStatus(int32_t &status)
{
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        // LCOV_EXCL_START
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::VIDEO) {
            if (streamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET) {
                const int32_t videoStartStatus = 2;
                status = videoStartStatus;
            }
        }
        // LCOV_EXCL_STOP
    }
}

#ifdef CAMERA_USE_SENSOR
void HStreamOperator::RegisterSensorCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(sensorLock_);
    CHECK_RETURN_ILOG(
        isRegisterSensorSuccess_, "HCaptureSession::RegisterSensorCallback isRegisterSensorSuccess return");
    MEDIA_INFO_LOG("HCaptureSession::RegisterSensorCallback start");
    user.callback = GravityDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, subscribeRet: %{public}d", subscribeRet);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_GRAVITY, &user, POSTURE_INTERVAL, 0);
    MEDIA_INFO_LOG("RegisterSensorCallback, setBatchRet: %{public}d", setBatchRet);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, activateRet: %{public}d", activateRet);
    isRegisterSensorSuccess_ = subscribeRet == CAMERA_OK && setBatchRet == CAMERA_OK && activateRet == CAMERA_OK;
    if (!isRegisterSensorSuccess_) { // LCOV_EXCL_LINE
        MEDIA_INFO_LOG("RegisterSensorCallback failed.");
    }
    // LCOV_EXCL_STOP
}

void HStreamOperator::UnRegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    // LCOV_EXCL_START
    if (deactivateRet == CAMERA_OK && unsubscribeRet == CAMERA_OK) {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback success.");
        isRegisterSensorSuccess_ = false;
    } else {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback failed.");
    }
    // LCOV_EXCL_STOP
}

void HStreamOperator::GravityDataCallbackImpl(SensorEvent* event)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("GravityDataCallbackImpl prepare execute");
    CHECK_RETURN_ELOG(event == nullptr, "SensorEvent is nullptr.");
    CHECK_RETURN_ELOG(event[0].data == nullptr, "SensorEvent[0].data is nullptr.");
    CHECK_RETURN_ELOG(event->sensorTypeId != SENSOR_TYPE_ID_GRAVITY, "SensorCallback error type.");
    // this data will be delete when callback execute finish
    GravityData* nowGravityData = reinterpret_cast<GravityData*>(event->data);
    gravityData = { nowGravityData->x, nowGravityData->y, nowGravityData->z };
    sensorRotation = CalcSensorRotation(CalcRotationDegree(gravityData));
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::CalcSensorRotation(int32_t sensorDegree)
{
    // LCOV_EXCL_START
    // Use ROTATION_0 when degree range is [0, 30]∪[330, 359]
    if (sensorDegree >= 0 && (sensorDegree <= 30 || sensorDegree >= 330)) {
        return STREAM_ROTATE_0;
    } else if (sensorDegree >= 60 && sensorDegree <= 120) { // Use ROTATION_90 when degree range is [60, 120]
        return STREAM_ROTATE_90;
    } else if (sensorDegree >= 150 && sensorDegree <= 210) { // Use ROTATION_180 when degree range is [150, 210]
        return STREAM_ROTATE_180;
    } else if (sensorDegree >= 240 && sensorDegree <= 300) { // Use ROTATION_270 when degree range is [240, 300]
        return STREAM_ROTATE_270;
    } else {
        return sensorRotation;
    }
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::CalcRotationDegree(GravityData data)
{
    // LCOV_EXCL_START
    float x = data.x;
    float y = data.y;
    float z = data.z;
    int degree = -1;
    CHECK_RETURN_RET((x * x + y * y) * VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT < z * z, degree);
    // arccotx = pi / 2 - arctanx, 90 is used to calculate acot(in degree); degree = rad / pi * 180
    degree = 90 - static_cast<int>(round(atan2(y, -x) / M_PI * 180));
    // Normalize the degree to the range of 0~360
    return degree >= 0 ? degree % 360 : degree % 360 + 360;
    // LCOV_EXCL_STOP
}
#endif

void HStreamOperator::UpdateOrientationBaseGravity(int32_t rotationValue, int32_t sensorOrientation,
    int32_t cameraPosition, int32_t& rotation)
{
    // LCOV_EXCL_START
    CHECK_RETURN_ELOG(cameraDevice_ == nullptr, "cameraDevice is nullptr.");
    CameraRotateStrategyInfo strategyInfo;
    CHECK_RETURN_ELOG(!(cameraDevice_->GetSigleStrategyInfo(strategyInfo)), "Update roteta angle not supported");
    OHOS::Rosen::FoldDisplayMode displayMode = OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode();
    std::string foldScreenType = system::GetParameter("const.window.foldscreen.type", "");
    bool isValidDisplayStatus = !foldScreenType.empty() && (foldScreenType[0] == '6') &&
        (displayMode == OHOS::Rosen::FoldDisplayMode::GLOBAL_FULL);
    bool isSpecialDisplayStatus = !foldScreenType.empty() && (foldScreenType[0] == '7') && (
        (displayMode == OHOS::Rosen::FoldDisplayMode::FULL) ||
        (displayMode == OHOS::Rosen::FoldDisplayMode::COORDINATION));
    CHECK_RETURN(!(isValidDisplayStatus || isSpecialDisplayStatus));
    int32_t imageRotation = (sensorRotation + ROTATION_45_DEGREES) / ROTATION_90_DEGREES * ROTATION_90_DEGREES;
    if (cameraPosition == OHOS_CAMERA_POSITION_BACK) {
        rotation = (imageRotation + sensorOrientation) % ROTATION_360_DEGREES;
    } else if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        rotation = (sensorOrientation - imageRotation + ROTATION_360_DEGREES) % ROTATION_360_DEGREES;
    }
    MEDIA_INFO_LOG("UpdateOrientationBaseGravity sensorOrientation: %{public}d, deviceDegree: %{public}d, "
        "rotation: %{public}d", sensorOrientation, imageRotation, rotation);

    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice_->GetDeviceAbility();
    CHECK_RETURN(ability == nullptr);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE, &item);
    bool isVariable = false;
    CHECK_EXECUTE(ret == CAM_META_SUCCESS, isVariable = item.count > 0 && item.data.u8[0]);
    CHECK_RETURN_ILOG(!isVariable, "HStreamOperator::UpdateOrientationBaseGravity isVariable is False");

    int32_t rotateDegree = strategyInfo.rotateDegree;
    int32_t captureDegreeOffset = 0;
    if (cameraPosition == OHOS_CAMERA_POSITION_BACK) {
        rotateDegree = strategyInfo.rotateBackDegree == -1 ? ROTATION_360_DEGREES - strategyInfo.rotateDegree :
            strategyInfo.rotateBackDegree;
        captureDegreeOffset = strategyInfo.captureBackDegree == -1 ? 0 : strategyInfo.captureBackDegree;
    } else if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        captureDegreeOffset = strategyInfo.captureDegree == -1 ? 0 : ROTATION_360_DEGREES - strategyInfo.captureDegree;
    }
    CHECK_EXECUTE(rotateDegree < 0 || rotateDegree > ROTATION_360_DEGREES, rotateDegree = 0);
    rotation = (rotation - rotateDegree + ROTATION_360_DEGREES + captureDegreeOffset) % ROTATION_360_DEGREES;
    MEDIA_INFO_LOG("UpdateOrientationBaseGravity rotation is : %{public}d, rotateDegree is %{public}d, "
        "captureDegree is %{public}d", rotation, rotateDegree, captureDegreeOffset);
    // LCOV_EXCL_STOP
}

std::string HStreamOperator::GetLastDisplayName()
{
    std::lock_guard<std::mutex> lock(lastDisplayNameMutex_);
    return lastDisplayName_;
}

void HStreamOperator::SetLastDisplayName(std::string& lastDisplayName)
{
    std::lock_guard<std::mutex> lock(lastDisplayNameMutex_);
    lastDisplayName_ = lastDisplayName;
}

std::string HStreamOperator::CreateDisplayName(const std::string& suffix)
{
    // LCOV_EXCL_START
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) { // LCOV_EXCL_LINE
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1)
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_mday
           << connector << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_hour
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_min
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    auto lastDisplayName = GetLastDisplayName();
    if (lastDisplayName == formattedTime) { // LCOV_EXCL_LINE
        saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(saveIndex);
        MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
        return formattedTime;
    }
    SetLastDisplayName(formattedTime);
    saveIndex = 0;
    MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
    // LCOV_EXCL_STOP
}

std::string HStreamOperator::CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId)
{
    // LCOV_EXCL_START
    struct tm currentTime;
    std::string formattedTime = "";
    std::stringstream ss;
    // a group of burst capture use the same prefix
    if (imageSeqId == 1) { // LCOV_EXCL_LINE
        CHECK_RETURN_RET_ELOG(!GetSystemCurrentTime(&currentTime), formattedTime, "Failed to get current time.");
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1) << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_mday << connector << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_hour << std::setw(otherWidth) << std::setfill(placeholder)
           << currentTime.tm_min << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec
           << connector << burstTag;
        lastBurstPrefix_ = ss.str();
        ss << std::setw(burstWidth) << std::setfill(placeholder) << seqId;
    } else {
        ss << lastBurstPrefix_ << std::setw(burstWidth) << std::setfill(placeholder) << seqId;
    }
    MEDIA_DEBUG_LOG("burst prefix is %{private}s", lastBurstPrefix_.c_str());

    if (seqId == 1) { // LCOV_EXCL_LINE
        ss << coverTag;
    }
    formattedTime = ss.str();
    MEDIA_INFO_LOG("CreateBurstDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
    // LCOV_EXCL_STOP
}

void HStreamOperator::SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy, int32_t &cameraShotType,
    bool &isBursting, std::string &burstKey)
{
    // LCOV_EXCL_START
    cameraPhotoProxy->SetShootingMode(opMode_);
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    std::string imageId = cameraPhotoProxy->GetPhotoId();
    isBursting = false;
    bool isCoverPhoto = false;
    int32_t invalidBurstSeqId = -1;
    std::list<sptr<HStreamCommon>> captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    std::list<sptr<HStreamCommon>> captureStreamsOffline = streamContainerOffline_.GetStreams(StreamType::CAPTURE);
    captureStreams.insert(captureStreams.end(), captureStreamsOffline.begin(), captureStreamsOffline.end());
    for (auto& stream : captureStreams) {
        CHECK_CONTINUE_WLOG(stream == nullptr, "stream is null");
        MEDIA_INFO_LOG("CreateMediaLibrary get captureStream");
        auto streamCapture = CastStream<HStreamCapture>(stream);
        isBursting = streamCapture->IsBurstCapture(captureId);
        if (isBursting) {
            burstKey = streamCapture->GetBurstKey(captureId);
            streamCapture->SetBurstImages(captureId, imageId);
            isCoverPhoto = streamCapture->IsBurstCover(captureId);
            int32_t burstSeqId = cameraPhotoProxy->GetBurstSeqId();
            int32_t imageSeqId = streamCapture->GetCurBurstSeq(captureId);
            int32_t displaySeqId = (burstSeqId != invalidBurstSeqId) ? burstSeqId : imageSeqId;
            cameraPhotoProxy->SetDisplayName(CreateBurstDisplayName(imageSeqId, displaySeqId));
            streamCapture->CheckResetBurstKey(captureId);
            MEDIA_INFO_LOG("isBursting burstKey:%{public}s isCoverPhoto:%{public}d", burstKey.c_str(), isCoverPhoto);
            cameraShotType = BURST_SHOT_TYPE;
            cameraPhotoProxy->SetBurstInfo(burstKey, isCoverPhoto);
            break;
        }
    }
    MEDIA_INFO_LOG("GetLocation latitude:%{private}f, quality:%{public}d, format:%{public}d,",
        cameraPhotoProxy->GetLatitude(), cameraPhotoProxy->GetPhotoQuality(), cameraPhotoProxy->GetFormat());
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::CreateMediaLibrary(sptr<CameraServerPhotoProxy>& cameraPhotoProxy, std::string& uri,
    int32_t& cameraShotType, std::string& burstKey, int64_t timestamp)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CreateMediaLibrary E");
    CAMERA_SYNC_TRACE;
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    bool isSetMotionPhoto = false;
    {
        std::lock_guard<std::mutex> lock(motionPhotoStatusLock_);
        isSetMotionPhoto = curMotionPhotoStatus_.find(captureId) != curMotionPhotoStatus_.end() &&
            curMotionPhotoStatus_[captureId];
        curMotionPhotoStatus_.erase(captureId);
    }
    MEDIA_DEBUG_LOG("HStreamOperator::CreateMediaLibrary current captureId: %{public}d, movingPhotoStatus: %{public}d",
        captureId, isSetMotionPhoto);
    cameraShotType = isSetMotionPhoto ? MOVING_PHOTO_SHOT_TYPE : IMAGE_SHOT_TYPE;
    cameraPhotoProxy->SetDisplayName(CreateDisplayName(suffixJpeg));
    bool isBursting = false;
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    std::shared_ptr<PhotoAssetProxy> photoAssetProxy =
        PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, uid_, callerToken_);
    if (photoAssetProxy == nullptr) {
        CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::MEDIALIBRARY_ERROR, captureId);
        MEDIA_ERR_LOG("HStreamOperator::CreateMediaLibrary get photoAssetProxy fail");
        return CAMERA_ALLOC_ERROR;
    }
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && isSetMotionPhoto) {
#ifdef CAMERA_MOVING_PHOTO
        auto manager = movingPhotoManagerProxy_.Get();
        CHECK_EXECUTE(manager, manager->SetVideoFd(timestamp, photoAssetProxy, captureId));
#endif
    } else {
        photoAssetProxy.reset();
    }
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    MEDIA_INFO_LOG("CreateMediaLibrary X");
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void RotatePicture(std::weak_ptr<PictureIntf> picture)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto ptr = picture.lock();
    CHECK_RETURN(!ptr);
    ptr->RotatePicture();
    // LCOV_EXCL_STOP
}

bool HStreamOperator::IsIpsRotateSupported()
{
    // LCOV_EXCL_START
    bool ipsRotateSupported = false;
    camera_metadata_item_t item;
    bool ret = GetDeviceAbilityByMeta(OHOS_ABILITY_ROTATION_IN_IPS_SUPPORTED, &item);
    if (ret && item.count > 0) {
        ipsRotateSupported = static_cast<bool>(item.data.u8[0]);
    }
    MEDIA_INFO_LOG("HstreamOperator IsIpsRotateSupported %{public}d", ipsRotateSupported);
    return ipsRotateSupported;
}

bool HStreamOperator::IsCaptureStreamExist()
{
    MEDIA_DEBUG_LOG("IsCaptureStreamExist E");
    const auto& captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    bool isCaptureStreamExist = !captureStreams.empty();
    MEDIA_DEBUG_LOG("IsCaptureStreamExist res:%{public}d", isCaptureStreamExist);
    return isCaptureStreamExist;
}

std::shared_ptr<PhotoAssetIntf> HStreamOperator::ProcessPhotoProxy(int32_t captureId,
    std::shared_ptr<PictureIntf> picturePtr, bool isBursting, sptr<CameraServerPhotoProxy> cameraPhotoProxy,
    std::string& uri)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("ProcessPhotoProxy E");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(picturePtr == nullptr, nullptr, "picturePtr is null");
    std::list<sptr<HStreamCommon>> captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    std::list<sptr<HStreamCommon>> captureStreamsOffline = streamContainerOffline_.GetStreams(StreamType::CAPTURE);
    captureStreams.insert(captureStreams.end(), captureStreamsOffline.begin(), captureStreamsOffline.end());
    CHECK_RETURN_RET_ELOG(captureStreams.empty(), nullptr, "not found captureStream, captureStream is null");
    sptr<HStreamCapture> captureStream = CastStream<HStreamCapture>(captureStreams.front());

    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = nullptr;
    std::thread taskThread;
#ifdef CAMERA_CAPTURE_YUV
    bool isSystemApp = PhotoLevelManager::GetInstance().GetPhotoLevelInfo(captureId);
    if (isBursting) {
        int32_t cameraShotType = 3;
        photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, uid_, callerToken_);
        if (photoAssetProxy == nullptr) {
            CameraReportDfxUtils::GetInstance()->SetCaptureState(CaptureState::MEDIALIBRARY_ERROR, captureId);
        }
    } else {
        if (isSystemApp) {
            photoAssetProxy = captureStream->GetPhotoAssetInstance(captureId);
        } else {
            photoAssetProxy = captureStream->GetPhotoAssetInstanceForPub(captureId);
        }
    }
#else
    int32_t cameraShotType = 3;
    photoAssetProxy = isBursting ?
        PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, uid_, callerToken_) :
        captureStream->GetPhotoAssetInstance(captureId);
#endif

    CHECK_RETURN_RET_ELOG(photoAssetProxy == nullptr, nullptr, "photoAssetProxy is null");
#ifdef CAMERA_CAPTURE_YUV
    if (!isBursting && picturePtr) {
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture E");
        bool isIpsRotateSupported = IsIpsRotateSupported();
        MEDIA_DEBUG_LOG("ProcessPhotoProxy IsIpsRotateSupported: %{public}d, isSystemApp: %{public}d",
            isIpsRotateSupported, isSystemApp);
        if (!isIpsRotateSupported && isSystemApp) {
            taskThread = std::thread(RotatePicture, picturePtr);
        }
    }
#else
    if (!isBursting) {
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture E");
        CHECK_EXECUTE(!IsIpsRotateSupported(), taskThread = std::thread(RotatePicture, picturePtr));
    }
#endif
    bool isProfessionalPhoto = (opMode_ == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO));
    if (isBursting || captureStream->GetAddPhotoProxyEnabled() == false || isProfessionalPhoto) {
        MEDIA_INFO_LOG("ProcessPhotoProxy AddPhotoProxy E");
        string pictureId = cameraPhotoProxy->GetTitle() + "." + cameraPhotoProxy->GetExtension();
        CameraReportDfxUtils::GetInstance()->SetPictureId(captureId, pictureId);
        photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
        MEDIA_INFO_LOG("ProcessPhotoProxy AddPhotoProxy X");
    }
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && taskThread.joinable()) {
        taskThread.join();
        MEDIA_DEBUG_LOG("ProcessPhotoProxy RotatePicture X");
    }
    MEDIA_INFO_LOG("ProcessPhotoProxy NotifyLowQualityImage E");
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyLowQualityImage(
        photoAssetProxy->GetUserId(), uri, picturePtr);
    MEDIA_INFO_LOG("ProcessPhotoProxy NotifyLowQualityImage X");
    return photoAssetProxy;
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::CreateMediaLibrary(
    std::shared_ptr<PictureIntf> picture, sptr<CameraServerPhotoProxy> &photoProxy, std::string &uri,
    int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CreateMediaLibrary with picture E");
    CAMERA_SYNC_TRACE;
    int32_t captureId = photoProxy->GetCaptureId();
    bool isSetMotionPhoto = false;
    {
        std::lock_guard<std::mutex> lock(motionPhotoStatusLock_);
        isSetMotionPhoto = curMotionPhotoStatus_.find(captureId) != curMotionPhotoStatus_.end() &&
            curMotionPhotoStatus_[captureId];
        curMotionPhotoStatus_.erase(captureId);
    }
    MEDIA_DEBUG_LOG("HStreamOperator::CreateMediaLibrary current captureId: %{public}d, isSetMotionPhoto: %{public}d",
        captureId, isSetMotionPhoto);
    cameraShotType = isSetMotionPhoto ? MOVING_PHOTO_SHOT_TYPE : IMAGE_SHOT_TYPE;
    PhotoFormat photoFormat = photoProxy->GetFormat();
    std::string formatSuffix = photoFormat == PhotoFormat::HEIF ? suffixHeif : suffixJpeg;
    photoProxy->SetDisplayName(CreateDisplayName(formatSuffix));
    bool isBursting = false;
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(photoProxy, cameraShotType, isBursting, burstKey);
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy =
        ProcessPhotoProxy(captureId, picture, isBursting, photoProxy, uri);
    CHECK_RETURN_RET_ELOG(photoAssetProxy == nullptr, CAMERA_INVALID_ARG, "photoAssetProxy is null");
    if (!isBursting && isSetMotionPhoto) {
#ifdef CAMERA_MOVING_PHOTO
        auto manager = movingPhotoManagerProxy_.Get();
        CHECK_EXECUTE(manager, manager->SetVideoFd(timestamp, photoAssetProxy, captureId));
#endif
    } else {
        photoAssetProxy.reset();
    }
    // xtStyleTaskManager_设置fd
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    MEDIA_INFO_LOG("CreateMediaLibrary with picture X");
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureStarted captureId:%{public}d, streamIds:%{public}s", captureId,
        Container2String(streamIds.begin(), streamIds.end()).c_str());
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        // LCOV_EXCL_START
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        CHECK_RETURN_RET_ELOG(!curStream, CAMERA_INVALID_ARG,
            "HStreamOperator::OnCaptureStarted StreamId: %{public}d not found", streamId);
        if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameStarted();
            CameraReportUtils::GetInstance().SetStreamInfo(streamContainer_.GetAllStreams());
            CameraReportUtils::GetInstance().SetOpenCamPerfEndInfo();
            CameraReportUtils::GetInstance().SetModeChangePerfEndInfo();
            CameraReportUtils::GetInstance().SetSwitchCamPerfEndInfo();
            CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO); // cache dynamiclib
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId);
        }
        // LCOV_EXCL_STOP
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::CreateStreams(std::vector<HDI::Camera::V1_5::StreamInfo_V1_5>& streamInfos)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    uint32_t major;
    uint32_t minor;
    CHECK_RETURN_RET_ELOG(streamInfos.empty(), CAMERA_OK, "HStreamOperator::CreateStreams streamInfos is empty!");
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(opMutex_);
    sptr<OHOS::HDI::Camera::V1_5::IStreamOperator> streamOperatorV1_5;
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = GetHDIStreamOperator();
    CHECK_RETURN_RET_ELOG(
        streamOperator == nullptr, CAMERA_UNKNOWN_ERROR, "HStreamOperator::CreateStreams GetStreamOperator is null!");
    // get higher streamOperator version
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("HStreamOperator::CreateStreams GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_5) {
        streamOperatorV1_5 = OHOS::HDI::Camera::V1_5::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_5 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::CreateStreams IStreamOperator cast to V1_5 error");
            streamOperatorV1_5 = static_cast<OHOS::HDI::Camera::V1_5::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    } else if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_1) {
        streamOperatorV1_1 = OHOS::HDI::Camera::V1_1::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_1 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::CreateStreams IStreamOperator cast to V1_1 error");
            streamOperatorV1_1 = static_cast<OHOS::HDI::Camera::V1_1::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }
    if (streamOperatorV1_5 != nullptr) {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_5");
        for (auto streamInfo : streamInfos) {
            if (streamInfo.settings.size() > 0) {
                MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamId:%{public}d settingsSize:%{public}zu ",
                    streamInfo.v1_0.streamId_,
                    streamInfo.settings.size());
            }
            if (streamInfo.extendedStreamInfos.size() > 0) {
                MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamId:%{public}d width:%{public}d height:%{public}d"
                               "format:%{public}d dataspace:%{public}d type:%{public}d",
                    streamInfo.v1_0.streamId_, streamInfo.v1_0.width_, streamInfo.v1_0.height_,
                    streamInfo.v1_0.format_, streamInfo.v1_0.dataspace_, streamInfo.extendedStreamInfos[0].type);
            }
        }
        hdiRc = (CamRetCode)(streamOperatorV1_5->CreateStreams_V1_5(streamInfos));
    } else if (streamOperatorV1_1 != nullptr) {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_1");
        std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos_V1_1;
        for (auto streamInfo : streamInfos) {
            if (streamInfo.extendedStreamInfos.size() > 0) {
                MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamId:%{public}d width:%{public}d height:%{public}d"
                    "format:%{public}d dataspace:%{public}d", streamInfo.v1_0.streamId_, streamInfo.v1_0.width_,
                    streamInfo.v1_0.height_, streamInfo.v1_0.format_, streamInfo.v1_0.dataspace_);
                MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_1 type %{public}d",
                    streamInfo.extendedStreamInfos[0].type);
            }
            StreamInfo_V1_1 streamInfo_V1_1;
            streamInfo_V1_1.v1_0 = streamInfo.v1_0;
            streamInfo_V1_1.extendedStreamInfos = streamInfo.extendedStreamInfos;
            streamInfos_V1_1.emplace_back(streamInfo_V1_1);
        }
        hdiRc = (CamRetCode)(streamOperatorV1_1->CreateStreams_V1_1(streamInfos_V1_1));
    } else {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_0");
        std::vector<StreamInfo> streamInfos_V1_0;
        for (auto streamInfo : streamInfos) {
            streamInfos_V1_0.emplace_back(streamInfo.v1_0);
        }
        hdiRc = (CamRetCode)(streamOperator->CreateStreams(streamInfos_V1_0));
    }
    if (hdiRc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamOperator::CreateStreams(), Failed to commit %{public}d", hdiRc);
        CameraReportUtils::ReportCameraError(
            "HStreamOperator::CreateStreams", hdiRc, true, CameraReportUtils::GetCallerInfo());
        std::vector<int32_t> streamIds;
        for (auto& streamInfo : streamInfos) {
            streamIds.emplace_back(streamInfo.v1_0.streamId_);
        }
        CHECK_PRINT_ELOG(!streamIds.empty() && streamOperator->ReleaseStreams(streamIds) != HDI::Camera::V1_0::NO_ERROR,
            "HStreamOperator::CreateStreams(), Failed to release streams");
    }
    for (auto& info : streamInfos) {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams stream id is:%{public}d, type:%{public}d", info.v1_0.streamId_,
                       info.v1_0.intent_);
    }
    return HdiToServiceError(hdiRc);
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::UpdateStreams(std::vector<StreamInfo_V1_5>& streamInfos)
{
    sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperatorV1_2;
    auto streamOperator = GetHDIStreamOperator();
    CHECK_RETURN_RET_ELOG(
        streamOperator == nullptr, CAMERA_UNKNOWN_ERROR, "HStreamOperator::UpdateStreams GetStreamOperator is null!");
    uint32_t major;
    uint32_t minor;
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("UpdateStreams::UpdateStreams GetVersion major:%{public}d, minor:%{public}d", major, minor);
    // LCOV_EXCL_START
    if (GetVersionId(major, minor) >= HDI_VERSION_ID_1_2) {
        streamOperatorV1_2 = OHOS::HDI::Camera::V1_2::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_2 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::UpdateStreams IStreamOperator cast to V1_2 error");
            streamOperatorV1_2 = static_cast<OHOS::HDI::Camera::V1_2::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }
    CamRetCode hdiRc = HDI::Camera::V1_0::CamRetCode::NO_ERROR;
    if (streamOperatorV1_2 != nullptr) {
        MEDIA_DEBUG_LOG("HStreamOperator::UpdateStreams streamOperator V1_2");
        std::vector<HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos_V1_1;
        for (auto streamInfo : streamInfos) {
            StreamInfo_V1_1 streamInfo_V1_1;
            streamInfo_V1_1.v1_0 = streamInfo.v1_0;
            streamInfo_V1_1.extendedStreamInfos = streamInfo.extendedStreamInfos;
            streamInfos_V1_1.emplace_back(streamInfo_V1_1);
        }
        hdiRc = (CamRetCode)(streamOperatorV1_2->UpdateStreams(streamInfos_V1_1));
    } else {
        MEDIA_DEBUG_LOG("HStreamOperator::UpdateStreams failed, streamOperator V1_2 is null.");
        return CAMERA_UNKNOWN_ERROR;
    }
    // LCOV_EXCL_STOP
    return HdiToServiceError(hdiRc);
}

int32_t HStreamOperator::OnCaptureStarted_V1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureStarted_V1_2 captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        CHECK_RETURN_RET_ELOG(!curStream, CAMERA_INVALID_ARG,
            "HStreamOperator::OnCaptureStarted_V1_2 StreamId: %{public}d not found."
            " exposureTime: %{public}u",
            captureInfo.streamId_, captureInfo.exposureTime_);
        if (curStream->GetStreamType() == StreamType::CAPTURE) {
            MEDIA_DEBUG_LOG("HStreamOperator::OnCaptureStarted_V1_2 StreamId: %{public}d."
                            " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId, captureInfo.exposureTime_);
        }
    }
    return CAMERA_OK;
}

// LCOV_EXCL_START
int32_t HStreamOperator::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureEnded");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureEnded StreamId: %{public}d not found."
                          " Framecount: %{public}d",
                captureInfo.streamId_, captureInfo.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameEnded(captureInfo.frameCount_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureEnded(captureId, captureInfo.frameCount_);
        }
    }
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t HStreamOperator::OnCaptureEndedExt(int32_t captureId,
    const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureEndedExt captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureEndedExt StreamId: %{public}d not found."
                          " Framecount: %{public}d",
                captureInfo.streamId_, captureInfo.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameEnded(captureInfo.frameCount_);
            CaptureEndedInfoExt extInfo;
            extInfo.streamId = captureInfo.streamId_;
            extInfo.frameCount = captureInfo.frameCount_;
            extInfo.isDeferredVideoEnhancementAvailable = captureInfo.isDeferredVideoEnhancementAvailable_;
            extInfo.videoId = captureInfo.videoId_;
            MEDIA_INFO_LOG("HStreamOperator::OnCaptureEndedExt captureId:%{public}d videoId:%{public}s "
                           "isDeferredVideo:%{public}d",
                captureId, extInfo.videoId.c_str(), extInfo.isDeferredVideoEnhancementAvailable);
            CastStream<HStreamRepeat>(curStream)->OnDeferredVideoEnhancementInfo(extInfo);
        }
    }
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t HStreamOperator::OnCaptureEndedExt_V1_4(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_5::CaptureEndedInfoExt_v1_4>& infos)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureEndedExt_V1_4, captureId is %{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto &captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.captureEndedInfoExt.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureEndedExt_V1_4 StreamId: %{public}d not found."
                          " Framecount: %{public}d",
                captureInfo.captureEndedInfoExt.streamId_,
                captureInfo.captureEndedInfoExt.frameCount_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            auto repeatStream = CastStream<HStreamRepeat>(curStream);
            ProcessRepeatStream(repeatStream, captureId, captureInfo);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureEnded(
                captureId, captureInfo.captureEndedInfoExt.frameCount_);
            uint32_t deferredFlag = 0;
            std::string videoId = captureInfo.captureEndedInfoExt.videoId_;
            if (captureInfo.metadata_) {
                int ret = captureInfo.metadata_->Get("deferredVideoEnhanceFlag", deferredFlag);
                MEDIA_DEBUG_LOG("GET deferredVideoEnhanceFlag result: %{public}d", ret);
            }
#ifdef CAMERA_MOVING_PHOTO
            SetDeferredVideoEnhanceFlag(captureId, deferredFlag, videoId);
#endif
        }
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void HStreamOperator::ProcessRepeatStream(const sptr<HStreamRepeat>& repeatStream, int32_t captureId,
    const OHOS::HDI::Camera::V1_5::CaptureEndedInfoExt_v1_4& captureInfo)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("ProcessRepeatStream is called");
    repeatStream->OnFrameEnded(captureInfo.captureEndedInfoExt.frameCount_);
    CaptureEndedInfoExt extInfo;
    extInfo.streamId = captureInfo.captureEndedInfoExt.streamId_;
    extInfo.frameCount = captureInfo.captureEndedInfoExt.frameCount_;
    extInfo.isDeferredVideoEnhancementAvailable =
        captureInfo.captureEndedInfoExt.isDeferredVideoEnhancementAvailable_;
    extInfo.videoId = captureInfo.captureEndedInfoExt.videoId_;
    extInfo.deferredVideoEnhanceFlag = 0;
    if (captureInfo.metadata_) {
        int ret = captureInfo.metadata_->Get("deferredVideoEnhanceFlag", extInfo.deferredVideoEnhanceFlag);
        MEDIA_DEBUG_LOG("GET deferredVideoEnhanceFlag result: %{public}d", ret);
    }
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureEndedExt_V1_4 captureId:%{public}d videoId:%{public}s "
                    "isDeferredVideo:%{public}d, deferredVideoEnhanceFlag:%{public}u",
        captureId, extInfo.videoId.c_str(), extInfo.isDeferredVideoEnhancementAvailable,
        extInfo.deferredVideoEnhanceFlag);
    repeatStream->OnDeferredVideoEnhancementInfo(extInfo);
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    if (repeatStream->GetRepeatStreamType() == RepeatStreamType::MOVIE_FILE_RAW_VIDEO) {
        MEDIA_DEBUG_LOG("Process Stream Type of MOVIE_FILE_RAW_VIDEO");
        CHECK_RETURN_ELOG(cameraDevice_ == nullptr, "cameraDevice is nullptr.");
        int64_t firstFrameTimestamp = repeatStream->GetFirstFrameTimestamp();
        std::vector<uint8_t> keyFrameInfo = cameraDevice_->GetKeyFrameInfoBuffer(firstFrameTimestamp);
        repeatStream->SetRecorderUserMeta("com.openharmony.cinemaKeyFrameInfo", keyFrameInfo);
        if (captureInfo.metadata_) {
            int ret = captureInfo.metadata_->Get("eisStartInfo", extInfo.eisStartInfo);
            MEDIA_DEBUG_LOG("GET eisStartInfo: %{public}s, ret: %{public}d", extInfo.eisStartInfo.c_str(), ret);
            std::vector<uint8_t> eisBuffer(extInfo.eisStartInfo.begin(), extInfo.eisStartInfo.end());
            repeatStream->SetRecorderUserMeta("com.openharmony.eisStartAlgo", eisBuffer);
        }
        std::vector<uint8_t> lifecycleBuffer;
        repeatStream->GetDetectedObjectLifecycleBuffer(lifecycleBuffer);
        repeatStream->SetRecorderUserMeta("com.openharmony.objectLifecycle", lifecycleBuffer);
        repeatStream->SetRecorderUserMeta("com.openharmony.videoId", extInfo.videoId);
        repeatStream->SetRecorderUserMeta("com.openharmony.deferredVideoEnhanceFlag",
            std::to_string(extInfo.deferredVideoEnhanceFlag));
    }
#endif
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    MEDIA_DEBUG_LOG("HStreamOperator::OnCaptureError");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& errInfo : infos) {
        // LCOV_EXCL_START
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(errInfo.streamId_);
        CHECK_RETURN_RET_ELOG(!curStream, CAMERA_INVALID_ARG,
            "HStreamOperator::OnCaptureError StreamId: %{public}d not found."
            " Error: %{public}d",
            errInfo.streamId_, errInfo.error_);
        if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameError(errInfo.error_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnCaptureError(captureId, errInfo.error_);
        }
        // LCOV_EXCL_STOP
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::OnFrameShutter(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_INFO_LOG("HStreamOperator::OnFrameShutter ts is:%{public}" PRIu64, timestamp);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        bool isCaptureStream = (curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE);
        if (isCaptureStream) {
            // LCOV_EXCL_START
            auto captureStream = CastStream<HStreamCapture>(curStream);
            int32_t rotation = 0;
            captureStream->rotationMap_.Find(captureId, rotation);
#ifdef CAMERA_MOVING_PHOTO
            StartMovingPhotoEncode(rotation, timestamp, captureStream->format_, captureId);
#endif
            captureStream->OnFrameShutter(captureId, timestamp);
            // LCOV_EXCL_STOP
        } else {
            MEDIA_ERR_LOG("HStreamOperator::OnFrameShutter StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::OnFrameShutterEnd(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_INFO_LOG("HStreamOperator::OnFrameShutterEnd ts is:%{public}" PRIu64, timestamp);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        bool isCaptureStream = (curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE);
        if (isCaptureStream) {
            // LCOV_EXCL_START
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnFrameShutterEnd(captureId, timestamp);
            mlastCaptureId = captureId;
            // LCOV_EXCL_STOP
        } else {
            MEDIA_ERR_LOG("HStreamOperator::OnFrameShutterEnd StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::OnCaptureReady(
    int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    MEDIA_DEBUG_LOG("HStreamOperator::OnCaptureReady");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        bool isCaptureStream = (curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE);
        if (isCaptureStream) {
            CastStream<HStreamCapture>(curStream)->OnCaptureReady(captureId, timestamp);
        } else {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureReady StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        }
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::OnResult(int32_t streamId, const std::vector<uint8_t>& result)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("HStreamOperator::OnResult");
    CHECK_RETURN_RET(result.size() == 0, CAMERA_OK);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    {
        std::lock_guard<std::mutex> mechLock(mechCallbackLock_);
        CHECK_EXECUTE(mechCallback_ != nullptr && cameraResult!= nullptr, mechCallback_(streamId, cameraResult));
        if (g_isNeedFilterMetadata) {
            CHECK_RETURN_RET_ELOG(cameraResult == nullptr, CAMERA_INVALID_ARG,
                "HStreamOperator::OnResult cameraResult is null");
            OHOS::Camera::DeleteCameraMetadataItem(cameraResult->get(), OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS);
        }
    }
    sptr<HStreamCommon> curStream;
    const int32_t metaStreamId = -1;
    curStream = streamId == metaStreamId ? GetStreamByStreamID(streamId) : GetHdiStreamByStreamID(streamId);
    CHECK_RETURN_RET_ELOG(!curStream || curStream->GetStreamType() != StreamType::METADATA, CAMERA_INVALID_ARG,
        "HStreamOperator::OnResult StreamId: %{public}d is null or not Not adapted", streamId);
    CastStream<HStreamMetadata>(curStream)->OnMetaResult(streamId, cameraResult);
    CastStream<HStreamMetadata>(curStream)->ProcessDetectedObjectLifecycle(result);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::OnCapturePaused(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HStreamOperator::OnCapturePaused captureId:%{public}d, streamIds:%{public}s", captureId,
        Container2String(streamIds.begin(), streamIds.end()).c_str());
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        CHECK_CONTINUE_WLOG(
            curStream == nullptr, "HStreamOperator::OnCapturePaused StreamId: %{public}d not found", streamId);
        CHECK_CONTINUE(curStream->GetStreamType() != StreamType::REPEAT);
        CastStream<HStreamRepeat>(curStream)->OnFramePaused();
        CameraReportUtils::GetInstance().SetOpenCamPerfEndInfo();
        CameraReportUtils::GetInstance().SetModeChangePerfEndInfo();
        CameraReportUtils::GetInstance().SetSwitchCamPerfEndInfo();
        CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO); // cache dynamiclib
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamOperator::OnCaptureResumed(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureResumed captureId:%{public}d, streamIds:%{public}s", captureId,
        Container2String(streamIds.begin(), streamIds.end()).c_str());
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        CHECK_CONTINUE_WLOG(
            curStream == nullptr, "HStreamOperator::OnCaptureResumed StreamId: %{public}d not found", streamId);
        CHECK_CONTINUE(curStream->GetStreamType() != StreamType::REPEAT);
        CastStream<HStreamRepeat>(curStream)->OnFrameResumed();
        CameraReportUtils::GetInstance().SetOpenCamPerfEndInfo();
        CameraReportUtils::GetInstance().SetModeChangePerfEndInfo();
        CameraReportUtils::GetInstance().SetSwitchCamPerfEndInfo();
        CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO); // cache dynamiclib
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

std::vector<int32_t> HStreamOperator::GetFrameRateRange()
{
    // LCOV_EXCL_START
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        CHECK_RETURN_RET(repeatType == RepeatStreamType::PREVIEW, curStreamRepeat->GetFrameRateRange());
    }
    return {};
    // LCOV_EXCL_STOP
}

bool StreamContainer::AddStream(sptr<HStreamCommon> stream)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    if (it == list.end()) {
        list.emplace_back(stream);
        return true;
    }
    return false;
    // LCOV_EXCL_STOP
}

bool StreamContainer::RemoveStream(sptr<HStreamCommon> stream)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    CHECK_RETURN_RET(it == list.end(), false);
    list.erase(it);
    return true;
    // LCOV_EXCL_STOP
}

sptr<HStreamCommon> StreamContainer::GetStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        // LCOV_EXCL_START
        for (auto& stream : pair.second) {
            CHECK_RETURN_RET(stream->GetFwkStreamId() == streamId, stream);
        }
        // LCOV_EXCL_STOP
    }
    return nullptr;
}

sptr<HStreamCommon> StreamContainer::GetHdiStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            CHECK_RETURN_RET(stream->GetHdiStreamId() == streamId, stream);
        }
    }
    return nullptr;
}

void StreamContainer::Clear()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(streamsLock_);
    streams_.clear();
    // LCOV_EXCL_STOP
}

size_t StreamContainer::Size()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(streamsLock_);
    size_t totalSize = 0;
    for (auto& pair : streams_) {
        totalSize += pair.second.size();
    }
    return totalSize;
    // LCOV_EXCL_STOP
}

std::list<sptr<HStreamCommon>> StreamContainer::GetStreams(const StreamType streamType)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& stream : streams_[streamType]) {
        // LCOV_EXCL_START
        if (!stream) {
            MEDIA_WARNING_LOG("stream is nullptr!, skip");
            continue;
        }
        auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
            [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
        totalOrderedStreams.emplace(insertPos, stream);
        // LCOV_EXCL_STOP
    }
    return totalOrderedStreams;
}

std::list<sptr<HStreamCommon>> StreamContainer::GetAllStreams()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            // LCOV_EXCL_START
            if (!stream) {
                MEDIA_WARNING_LOG("stream is nullptr!, skip");
                continue;
            }
            auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
                [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
            totalOrderedStreams.emplace(insertPos, stream);
            // LCOV_EXCL_STOP
        }
    }
    return totalOrderedStreams;
}

void HStreamOperator::SetMechCallback(std::function<void(int32_t,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>&)> callback)
{
    std::lock_guard<std::mutex> lock(mechCallbackLock_);
    mechCallback_ = callback;
}

int32_t HStreamOperator::GetSensorRotation()
{
    int32_t innerRotation = sensorRotation;
    MEDIA_INFO_LOG("GetSensorRotation is called, current sensorRotation: %{public}d", innerRotation);
    if (system::GetParameter("const.system.sensor_correction_enable", "0") == "1") {
        std::string clientName = "";
        CHECK_EXECUTE(cameraDevice_ != nullptr, clientName = cameraDevice_->GetClientName());
        bool isCorrect = false;
        CameraApplistManager::GetInstance()->GetNaturalDirectionCorrectByBundleName(clientName, isCorrect);
        if (isCorrect) {
            std::string foldScreenType = system::GetParameter("const.window.foldscreen.type", "");
            CHECK_EXECUTE(!foldScreenType.empty() && foldScreenType[0] == '6',
                innerRotation = (innerRotation + STREAM_ROTATE_90) % STREAM_ROTATE_360);
            MEDIA_INFO_LOG("GetSensorRotation Correct, current sensorRotation: %{public}d", innerRotation);
            return innerRotation;
        }
        int32_t customLogicDirection = 0;
        CameraApplistManager::GetInstance()->GetCustomLogicDirection(clientName, customLogicDirection);
        innerRotation =
            (innerRotation - customLogicDirection * STREAM_ROTATE_90 + STREAM_ROTATE_360) % STREAM_ROTATE_360;
        MEDIA_INFO_LOG("GetSensorRotation Correct, current sensorRotation: %{public}d", innerRotation);
    }
    return innerRotation;
}
} // namespace CameraStandard
} // namespace OHOS