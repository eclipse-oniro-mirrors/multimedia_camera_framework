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
#include <sync_fence.h>
#include <utility>
#include <vector>

#include "avcodec_task_manager.h"
#include "blocking_queue.h"
#include "bundle_mgr_interface.h"
#include "camera_dynamic_loader.h"
#include "camera_info_dumper.h"
#include "camera_log.h"
#include "camera_report_uitls.h"
#include "camera_server_photo_proxy.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_timer.h"
#include "camera_util.h"
#include "datetime_ex.h"
#include "deferred_processing_service.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "display_manager.h"
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
#include "media_library/photo_asset_interface.h"
#include "media_library/photo_asset_proxy.h"
#include "metadata_utils.h"
#include "moving_photo/moving_photo_surface_wrapper.h"
#include "moving_photo_video_cache.h"
#include "parameters.h"
#include "picture_interface.h"
#include "refbase.h"
#include "smooth_zoom.h"
#include "surface.h"
#include "surface_buffer.h"
#include "system_ability_definition.h"
#include "v1_0/types.h"
#include "camera_report_dfx_uitls.h"
#include "hstream_operator_manager.h"
#include "res_type.h"
#include "res_sched_client.h"
#include "camera_device_ability_items.h"

using namespace OHOS::AAFwk;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;
namespace {
#ifdef CAMERA_USE_SENSOR
constexpr int32_t POSTURE_INTERVAL = 100000000; //100ms
constexpr int VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT = 3;
#endif
static GravityData gravityData = {0.0, 0.0, 0.0};
static int32_t sensorRotation = 0;
} // namespace

sptr<HStreamOperator> HStreamOperator::NewInstance(const uint32_t callerToken, int32_t opMode)
{
    sptr<HStreamOperator> hStreamOperator = new HStreamOperator();
    CHECK_ERROR_RETURN_RET(hStreamOperator->Initialize(callerToken, opMode) == CAMERA_OK, hStreamOperator);
    return nullptr;
}

int32_t HStreamOperator::Initialize(const uint32_t callerToken, int32_t opMode)
{
    pid_ = IPCSkeleton::GetCallingPid();
    uid_ = static_cast<uint32_t>(IPCSkeleton::GetCallingUid());
    callerToken_ = callerToken;
    opMode_ = opMode;
    MEDIA_INFO_LOG(
        "HStreamOperator::opMode_= %{public}d", opMode_);
    InitDefaultColortSpace(static_cast<SceneMode>(opMode));
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
        {SceneMode::TIMELAPSE_PHOTO, ColorSpace::DISPLAY_P3},
        {SceneMode::APERTURE_VIDEO, ColorSpace::BT709_LIMIT},
        {SceneMode::FLUORESCENCE_PHOTO, ColorSpace::DISPLAY_P3},
    };
    auto it = colorSpaceMap.find(opMode);
    if (it != colorSpaceMap.end()) {
        currColorSpace_ = it->second;
    } else {
        currColorSpace_ = ColorSpace::SRGB;
    }
    MEDIA_DEBUG_LOG("HStreamOperator::InitDefaultColortSpace colorSpace:%{public}d", currColorSpace_);
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
}

HStreamOperator::~HStreamOperator()
{
    CAMERA_SYNC_TRACE;
    Release();
}

int32_t HStreamOperator::GetCurrentStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream) {
            StreamInfo_V1_1 curStreamInfo;
            stream->SetStreamInfo(curStreamInfo);
            CHECK_EXECUTE(stream->GetStreamType() != StreamType::METADATA, streamInfos.push_back(curStreamInfo));
        }
    }
    return CAMERA_OK;
}

int32_t HStreamOperator::AddOutputStream(sptr<HStreamCommon> stream)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CAMERA_INVALID_ARG,
        "HStreamOperator::AddOutputStream stream is null");
    MEDIA_INFO_LOG("HStreamOperator::AddOutputStream streamId:%{public}d streamType:%{public}d",
        stream->GetFwkStreamId(), stream->GetStreamType());
    CHECK_ERROR_RETURN_RET_LOG(
        stream->GetFwkStreamId() == STREAM_ID_UNSET && stream->GetStreamType() != StreamType::METADATA,
        CAMERA_INVALID_ARG, "HStreamOperator::AddOutputStream stream is released!");
    bool isAddSuccess = streamContainer_.AddStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(!isAddSuccess, CAMERA_INVALID_SESSION_CFG,
        "HStreamOperator::AddOutputStream add stream fail");
    if (stream->GetStreamType() == StreamType::CAPTURE) {
        auto captureStream = CastStream<HStreamCapture>(stream);
        captureStream->SetMode(opMode_);
        CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO); // cache dynamiclib
    }
    MEDIA_INFO_LOG("HCaptureSession::AddOutputStream stream colorSpace:%{public}d", currColorSpace_);
    stream->SetColorSpace(currColorSpace_);
    return CAMERA_OK;
}

void HStreamOperator::StartMovingPhotoStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t errorCode = 0;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    bool isPreviewStarted = false;
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::PREVIEW) {
            continue;
        }
        if (curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET && curStreamRepeat->producer_ != nullptr) {
            isPreviewStarted = true;
            break;
        }
    }
    CHECK_ERROR_RETURN_LOG(!isPreviewStarted, "EnableMovingPhoto, preview is not streaming");
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::LIVEPHOTO) {
            continue;
        }
        if (isSetMotionPhoto_) {
            errorCode = curStreamRepeat->Start(settings);
            #ifdef MOVING_PHOTO_ADD_AUDIO
            std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
            audioCapturerSession_ != nullptr && audioCapturerSession_->StartAudioCapture();
            #endif
        } else {
            errorCode = curStreamRepeat->Stop();
            StopMovingPhoto();
        }
        break;
    }
    MEDIA_INFO_LOG("HStreamOperator::StartMovingPhotoStream result:%{public}d", errorCode);
}

class DisplayRotationListener : public OHOS::Rosen::DisplayManager::IDisplayListener {
public:
    explicit DisplayRotationListener() {};
    virtual ~DisplayRotationListener() = default;
    void OnCreate(OHOS::Rosen::DisplayId) override {}
    void OnDestroy(OHOS::Rosen::DisplayId) override {}
    void OnChange(OHOS::Rosen::DisplayId displayId) override
    {
        sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
        if (display == nullptr) {
            MEDIA_INFO_LOG("Get display info failed, display:%{public}" PRIu64 "", displayId);
            display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
            CHECK_ERROR_RETURN_LOG(display == nullptr, "Get display info failed, display is nullptr");
        }
        {
            Rosen::Rotation currentRotation = display->GetRotation();
            std::lock_guard<std::mutex> lock(mStreamManagerLock_);
            for (auto& repeatStream : repeatStreamList_) {
                CHECK_EXECUTE(repeatStream, repeatStream->SetStreamTransform(static_cast<int>(currentRotation)));
            }
        }
    }

    void AddHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
    {
        std::lock_guard<std::mutex> lock(mStreamManagerLock_);
        CHECK_EXECUTE(repeatStream, repeatStreamList_.push_back(repeatStream));
    }

    void RemoveHstreamRepeatForListener(sptr<HStreamRepeat> repeatStream)
    {
        std::lock_guard<std::mutex> lock(mStreamManagerLock_);
        if (repeatStream) {
            repeatStreamList_.erase(
                std::remove(repeatStreamList_.begin(), repeatStreamList_.end(), repeatStream), repeatStreamList_.end());
        }
    }

public:
    std::list<sptr<HStreamRepeat>> repeatStreamList_;
    std::mutex mStreamManagerLock_;
};

void HStreamOperator::RegisterDisplayListener(sptr<HStreamRepeat> repeat)
{
    if (displayListener_ == nullptr) {
        displayListener_ = new DisplayRotationListener();
        OHOS::Rosen::DisplayManager::GetInstance().RegisterDisplayListener(displayListener_);
    }
    displayListener_->AddHstreamRepeatForListener(repeat);
}

void HStreamOperator::UnRegisterDisplayListener(sptr<HStreamRepeat> repeatStream)
{
    CHECK_EXECUTE(displayListener_, displayListener_->RemoveHstreamRepeatForListener(repeatStream));
}

int32_t HStreamOperator::SetPreviewRotation(std::string &deviceClass)
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
        if (enableStreamRotate_ && repeatSteam != nullptr &&
            repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            RegisterDisplayListener(repeatSteam);
            repeatSteam->SetPreviewRotation(deviceClass_);
        }
        errorCode = AddOutputStream(repeatSteam);
    } else if (streamType == StreamType::METADATA) {
        errorCode = AddOutputStream(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
    } else if (streamType == StreamType::DEPTH) {
        errorCode = AddOutputStream(static_cast<HStreamDepthData*>(stream.GetRefPtr()));
    }
    MEDIA_INFO_LOG("CaptureSession::AddOutput with with %{public}d, rc = %{public}d", streamType, errorCode);
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
    if (streamType == StreamType::CAPTURE) {
        errorCode = RemoveOutputStream(static_cast<HStreamCapture*>(stream.GetRefPtr()));
    } else if (streamType == StreamType::REPEAT) {
        HStreamRepeat* repeatSteam = static_cast<HStreamRepeat*>(stream.GetRefPtr());
        if (enableStreamRotate_ && repeatSteam != nullptr &&
            repeatSteam->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
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
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CAMERA_INVALID_ARG,
        "HStreamOperator::RemoveOutputStream stream is null");
    MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream,streamType:%{public}d, streamId:%{public}d",
        stream->GetStreamType(), stream->GetFwkStreamId());
    bool isRemoveSuccess = streamContainer_.RemoveStream(stream);
    CHECK_ERROR_RETURN_RET_LOG(!isRemoveSuccess, CAMERA_INVALID_SESSION_CFG,
        "HStreamOperator::RemoveOutputStream Invalid output");
    if (stream->GetStreamType() != StreamType::CAPTURE) {
        return CAMERA_OK;
    }
    HStreamCapture* captureSteam = static_cast<HStreamCapture*>(stream.GetRefPtr());
    if (captureSteam != nullptr && captureSteam->IsHasEnableOfflinePhoto()) {
        bool isAddSuccess = streamContainerOffline_.AddStream(stream);
        MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream,streamsize:%{public}zu",
            streamContainerOffline_.Size());
        if (streamContainerOffline_.Size() > 0) {
            auto allStream = streamContainerOffline_.GetAllStreams();
            for (auto& streamTemp : allStream) {
                MEDIA_INFO_LOG("HStreamOperator::RemoveOutputStream fkwstreamid is %{public}d hdistreamid"
                    "is %{public}d", streamTemp->GetFwkStreamId(), streamTemp->GetHdiStreamId());
            }
        }
        captureSteam->SwitchToOffline();
        CHECK_ERROR_RETURN_RET_LOG(!isAddSuccess, CAMERA_INVALID_SESSION_CFG,
            "HStreamOperator::AddOutputStream add stream fail");
    }
    return CAMERA_OK;
}

std::list<sptr<HStreamCommon>> HStreamOperator::GetAllStreams()
{
    return streamContainer_.GetAllStreams();
}

int32_t HStreamOperator::GetStreamsSize()
{
    return streamContainer_.Size() ;
}

void  HStreamOperator::GetStreamOperator()
{
    if (cameraDevice_ == nullptr) {
        MEDIA_INFO_LOG("HStreamOperator::GetStreamOperator cameraDevice_ is nullptr");
        return;
    }
    cameraDevice_->GetStreamOperator(this, streamOperator_);
}

bool HStreamOperator::IsOfflineCapture()
{
    std::list<sptr<HStreamCommon>> allStream = streamContainer_.GetAllStreams();
    std::list<sptr<HStreamCommon>> allOfflineStreams = streamContainerOffline_.GetAllStreams();
    allStream.insert(allStream.end(), allOfflineStreams.begin(), allOfflineStreams.end());
    for (auto& stream : allStream) {
        if (stream->GetStreamType() != StreamType::CAPTURE) {
            continue;
        }
        HStreamCapture* captureStream = static_cast<HStreamCapture*>(stream.GetRefPtr());
        if (captureStream->IsHasSwitchToOffline()) {
            return true;
        }
    }
    return false;
}

int32_t HStreamOperator::LinkInputAndOutputs(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    int32_t opMode)
{
    int32_t rc;
    std::vector<StreamInfo_V1_1> allStreamInfos;
    auto allStream = streamContainer_.GetAllStreams();
    for (auto& stream : allStream) {
        rc = stream->LinkInput(streamOperator_, settings);
        if (rc == CAMERA_OK) {
            CHECK_EXECUTE(stream->GetHdiStreamId() == STREAM_ID_UNSET,
                stream->SetHdiStreamId(GenerateHdiStreamId()));
        }
        MEDIA_INFO_LOG(
            "HStreamOperator::LinkInputAndOutputs streamType:%{public}d, streamId:%{public}d ,hdiStreamId:%{public}d",
            stream->GetStreamType(), stream->GetFwkStreamId(), stream->GetHdiStreamId());
        CHECK_ERROR_RETURN_RET_LOG(rc != CAMERA_OK, rc, "HStreamOperator::LinkInputAndOutputs IsValidMode false");
        StreamInfo_V1_1 curStreamInfo;
        stream->SetStreamInfo(curStreamInfo);
        CHECK_EXECUTE(stream->GetStreamType() != StreamType::METADATA,
            allStreamInfos.push_back(curStreamInfo));
    }

    rc = CreateAndCommitStreams(allStreamInfos, settings, opMode);
    MEDIA_INFO_LOG("HStreamOperator::LinkInputAndOutputs execute success");
    return rc;
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
    std::vector<StreamInfo_V1_1> emptyStreams;
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
        stream->UnlinkInput();
    }
    MEDIA_INFO_LOG("HStreamOperator::UnlinkOfflineInputAndOutputs() streamIds size() = %{public}zu,"
        "streamIds:%{public}s, hdiStreamIds:%{public}s",
        fwkStreamIds.size(), Container2String(fwkStreamIds.begin(), fwkStreamIds.end()).c_str(),
        Container2String(hdiStreamIds.begin(), hdiStreamIds.end()).c_str());
    ReleaseStreams(hdiStreamIds);
    ResetHdiStreamId();
    return rc;
}

void HStreamOperator::ExpandSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ExpandSketchRepeatStream()");
    std::set<sptr<HStreamCommon>> sketchStreams;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::SKETCH) {
            continue;
        }
        sptr<HStreamRepeat> sketchStream = streamRepeat->GetSketchStream();
        if (sketchStream == nullptr) {
            continue;
        }
        sketchStreams.insert(sketchStream);
    }
    MEDIA_DEBUG_LOG("HStreamOperator::ExpandSketchRepeatStream() sketch size is:%{public}zu", sketchStreams.size());
    for (auto& stream : sketchStreams) {
        AddOutputStream(stream);
    }
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ExpandSketchRepeatStream()");
}

void HStreamOperator::ExpandMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream enter");
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat && streamRepeat->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
            auto movingPhotoSurfaceWrapper =
                MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(streamRepeat->width_, streamRepeat->height_);
            if (movingPhotoSurfaceWrapper == nullptr) {
                MEDIA_ERR_LOG("HStreamOperator::ExpandMovingPhotoRepeatStream CreateMovingPhotoSurfaceWrapper fail.");
                continue;
            }
            auto producer = movingPhotoSurfaceWrapper->GetProducer();
            metaSurface_ = Surface::CreateSurfaceAsConsumer("movingPhotoMeta");
            auto metaCache = make_shared<FixedSizeList<pair<int64_t, sptr<SurfaceBuffer>>>>(3);
            CHECK_WARNING_CONTINUE_LOG(producer == nullptr, "get producer fail.");
            livephotoListener_ = new (std::nothrow) MovingPhotoListener(movingPhotoSurfaceWrapper,
                metaSurface_, metaCache, preCacheFrameCount_, postCacheFrameCount_);
            CHECK_WARNING_CONTINUE_LOG(livephotoListener_ == nullptr, "failed to new livephotoListener_!");
            movingPhotoSurfaceWrapper->SetSurfaceBufferListener(livephotoListener_);
            livephotoMetaListener_ = new(std::nothrow) MovingPhotoMetaListener(metaSurface_, metaCache);
            CHECK_WARNING_CONTINUE_LOG(livephotoMetaListener_ == nullptr, "failed to new livephotoMetaListener_!");
            metaSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)livephotoMetaListener_);
            CreateMovingPhotoStreamRepeat(streamRepeat->format_, streamRepeat->width_, streamRepeat->height_, producer);
            std::lock_guard<std::mutex> streamLock(livePhotoStreamLock_);
            AddOutputStream(livePhotoStreamRepeat_);
            if (!audioCapturerSession_) {
                audioCapturerSession_ = new AudioCapturerSession();
            }
            if (!taskManager_ && audioCapturerSession_) {
                taskManager_ = new AvcodecTaskManager(audioCapturerSession_, VideoCodecType::VIDEO_ENCODE_TYPE_HEVC,
                    currColorSpace_);
                taskManager_->SetVideoBufferDuration(preCacheFrameCount_, postCacheFrameCount_);
            }
            if (!videoCache_ && taskManager_) {
                videoCache_ = new MovingPhotoVideoCache(taskManager_);
            }
            break;
        }
    }
    MEDIA_DEBUG_LOG("ExpandMovingPhotoRepeatStream Exit");
}

int32_t HStreamOperator::CreateMovingPhotoStreamRepeat(
    int32_t format, int32_t width, int32_t height, sptr<OHOS::IBufferProducer> producer)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(livePhotoStreamLock_);
    CHECK_ERROR_RETURN_RET_LOG(
        width <= 0 || height <= 0, CAMERA_INVALID_ARG, "HCameraService::CreateLivePhotoStreamRepeat args is illegal");
    CHECK_EXECUTE(livePhotoStreamRepeat_ != nullptr, livePhotoStreamRepeat_->Release());
    auto streamRepeat = new (std::nothrow) HStreamRepeat(producer, format, width, height, RepeatStreamType::LIVEPHOTO);
    CHECK_ERROR_RETURN_RET_LOG(streamRepeat == nullptr, CAMERA_ALLOC_ERROR, "HStreamRepeat allocation failed");
    MEDIA_DEBUG_LOG("para is:%{public}dx%{public}d,%{public}d", width, height, format);
    livePhotoStreamRepeat_ = streamRepeat;
    streamRepeat->SetMetaProducer(metaSurface_->GetProducer());
    streamRepeat->SetMirror(isMovingPhotoMirror_);
    MEDIA_INFO_LOG("HCameraService::CreateLivePhotoStreamRepeat end");
    return CAMERA_OK;
}

const sptr<HStreamCommon> HStreamOperator::GetStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetStream(streamId) != nullptr ? streamContainer_.GetStream(streamId) :
        streamContainerOffline_.GetStream(streamId);

    CHECK_ERROR_PRINT_LOG(stream == nullptr,
        "HStreamOperator::GetStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

const sptr<HStreamCommon> HStreamOperator::GetHdiStreamByStreamID(int32_t streamId)
{
    auto stream = streamContainer_.GetHdiStream(streamId) != nullptr ? streamContainer_.GetHdiStream(streamId) :
        streamContainerOffline_.GetHdiStream(streamId);
    CHECK_ERROR_PRINT_LOG(stream == nullptr,
        "HStreamOperator::GetHdiStreamByStreamID get stream fail, streamId is:%{public}d", streamId);
    return stream;
}

void HStreamOperator::ClearSketchRepeatStream()
{
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ClearSketchRepeatStream()");

    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& repeatStream : repeatStreams) {
        if (repeatStream == nullptr) {
            continue;
        }
        auto sketchStream = CastStream<HStreamRepeat>(repeatStream);
        if (sketchStream->GetRepeatStreamType() != RepeatStreamType::SKETCH) {
            continue;
        }
        MEDIA_DEBUG_LOG(
            "HStreamOperator::ClearSketchRepeatStream() stream id is:%{public}d", sketchStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    }
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ClearSketchRepeatStream()");
}

void HStreamOperator::ClearMovingPhotoRepeatStream()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter HStreamOperator::ClearMovingPhotoRepeatStream()");
    // Already added session lock in BeginConfig()
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& repeatStream : repeatStreams) {
        if (repeatStream == nullptr) {
            continue;
        }
        auto movingPhotoStream = CastStream<HStreamRepeat>(repeatStream);
        if (movingPhotoStream->GetRepeatStreamType() != RepeatStreamType::LIVEPHOTO) {
            continue;
        }
        StopMovingPhoto();
        std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
        livephotoListener_ = nullptr;
        videoCache_ = nullptr;
        MEDIA_DEBUG_LOG("HStreamOperator::ClearLivePhotoRepeatStream() stream id is:%{public}d",
            movingPhotoStream->GetFwkStreamId());
        RemoveOutputStream(repeatStream);
    }
    MEDIA_DEBUG_LOG("Exit HStreamOperator::ClearLivePhotoRepeatStream()");
}

void HStreamOperator::StopMovingPhoto() __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter HStreamOperator::StopMovingPhoto");
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    CHECK_EXECUTE(livephotoListener_, livephotoListener_->StopDrainOut());
    CHECK_EXECUTE(videoCache_, videoCache_->ClearCache());
#ifdef MOVING_PHOTO_ADD_AUDIO
    CHECK_EXECUTE(audioCapturerSession_, audioCapturerSession_->Stop());
#endif
    CHECK_EXECUTE(taskManager_, taskManager_->Stop());
}

int32_t HStreamOperator::GetActiveColorSpace(ColorSpace& colorSpace)
{
    colorSpace = currColorSpace_;
    return CAMERA_OK;
}

int32_t HStreamOperator::SetColorSpace(ColorSpace colorSpace, bool isNeedUpdate)
{
    int32_t result = CAMERA_OK;
    CHECK_ERROR_RETURN_RET_LOG(colorSpace == currColorSpace_, result,
        "HStreamOperator::SetColorSpace() colorSpace no need to update.");
    currColorSpace_ = colorSpace;
    MEDIA_INFO_LOG("HStreamOperator::SetColorSpace() old ColorSpace : %{public}d, old ColorSpace : %{public}d",
        currColorSpace_, colorSpace);
    result = CheckIfColorSpaceMatchesFormat(colorSpace);
    if (result != CAMERA_OK) {
        if (opMode_ == static_cast<int32_t>(SceneMode::VIDEO) && !isNeedUpdate) {
            MEDIA_ERR_LOG(
                "HStreamOperator::SetColorSpace() %{public}d, format and colorSpace : %{public}d not match.",
                result, colorSpace);
            currColorSpace_ = ColorSpace::BT709;
        } else {
            MEDIA_ERR_LOG("HStreamOperator::SetColorSpace() Failed, format and colorSpace not match.");
            return result;
        }
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

void HStreamOperator::CancelStreamsAndGetStreamInfos(std::vector<StreamInfo_V1_1>& streamInfos)
{
    MEDIA_INFO_LOG("HStreamOperator::CancelStreamsAndGetStreamInfos enter.");
    StreamInfo_V1_1 curStreamInfo;
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream && stream->GetStreamType() == StreamType::METADATA) {
            continue;
        }
        if (stream && stream->GetStreamType() == StreamType::CAPTURE && isSessionStarted_) {
            static_cast<HStreamCapture*>(stream.GetRefPtr())->CancelCapture();
        } else if (stream && stream->GetStreamType() == StreamType::REPEAT && isSessionStarted_) {
            static_cast<HStreamRepeat*>(stream.GetRefPtr())->Stop();
        }
        if (stream) {
            stream->SetStreamInfo(curStreamInfo);
            streamInfos.push_back(curStreamInfo);
        }
    }
}

void HStreamOperator::RestartStreams(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    MEDIA_INFO_LOG("HStreamOperator::RestartStreams() enter.");
    auto streams = streamContainer_.GetAllStreams();
    for (auto& stream : streams) {
        if (stream && stream->GetStreamType() == StreamType::REPEAT &&
            CastStream<HStreamRepeat>(stream)->GetRepeatStreamType() == RepeatStreamType::PREVIEW) {
            CastStream<HStreamRepeat>(stream)->Start(settings);
        }
    }
}

int32_t HStreamOperator::UpdateStreamInfos(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    std::vector<StreamInfo_V1_1> streamInfos;
    CancelStreamsAndGetStreamInfos(streamInfos);
    int errorCode = UpdateStreams(streamInfos);
    if (errorCode == CAMERA_OK) {
        RestartStreams(settings);
    } else {
        MEDIA_DEBUG_LOG("HStreamOperator::UpdateStreamInfos err %{public}d", errorCode);
    }
    return errorCode;
}

int32_t HStreamOperator::CheckIfColorSpaceMatchesFormat(ColorSpace colorSpace)
{
    if (!(colorSpace == ColorSpace::BT2020_HLG || colorSpace == ColorSpace::BT2020_PQ ||
        colorSpace == ColorSpace::BT2020_HLG_LIMIT || colorSpace == ColorSpace::BT2020_PQ_LIMIT)) {
        return CAMERA_OK;
    }
    MEDIA_DEBUG_LOG("HStreamOperator::CheckIfColorSpaceMatchesFormat start");
    // 选择BT2020，需要匹配10bit的format；若不匹配，返回error
    auto streams = streamContainer_.GetAllStreams();
    for (auto& curStream : streams) {
        if (!curStream) {
            continue;
        }
        if (curStream->GetStreamType() == StreamType::CAPTURE) {
            if (!(curStream->format_ == OHOS_CAMERA_FORMAT_YCRCB_420_SP ||
                curStream->format_ == OHOS_CAMERA_FORMAT_JPEG ||
                curStream->format_ == OHOS_CAMERA_FORMAT_HEIC)) {
                MEDIA_ERR_LOG("HCaptureSession::CheckFormat, streamType: %{public}d, format not match",
                    curStream->GetStreamType());
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            if (!(curStream->format_ == OHOS_CAMERA_FORMAT_YCRCB_P010 ||
                curStream->format_ == OHOS_CAMERA_FORMAT_YCBCR_P010)) {
                MEDIA_ERR_LOG("HCaptureSession::CheckFormat, streamType: %{public}d, format not match",
                    curStream->GetStreamType());
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
        }
    }
    MEDIA_DEBUG_LOG("HStreamOperator::CheckIfColorSpaceMatchesFormat end");
    return CAMERA_OK;
}

int32_t HStreamOperator::GetMovingPhotoBufferDuration()
{
    uint32_t preBufferDuration = 0;
    uint32_t postBufferDuration = 0;
    constexpr int32_t MILLSEC_MULTIPLE = 1000;
    CHECK_ERROR_RETURN_RET_LOG(
        cameraDevice_ == nullptr, 0, "HCaptureSession::GetMovingPhotoBufferDuration() cameraDevice is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = cameraDevice_->GetDeviceAbility();
    CHECK_ERROR_RETURN_RET(ability == nullptr, 0);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_MOVING_PHOTO_BUFFER_DURATION, &item);
    CHECK_ERROR_RETURN_RET_LOG(
        ret != CAM_META_SUCCESS, 0, "HCaptureSession::GetMovingPhotoBufferDuration get buffer duration failed");
    preBufferDuration = item.data.ui32[0];
    postBufferDuration = item.data.ui32[1];
    preCacheFrameCount_ = preBufferDuration == 0
                              ? preCacheFrameCount_
                              : static_cast<uint32_t>(float(preBufferDuration) / MILLSEC_MULTIPLE * VIDEO_FRAME_RATE);
    postCacheFrameCount_ = preBufferDuration == 0
                               ? postCacheFrameCount_
                               : static_cast<uint32_t>(float(postBufferDuration) / MILLSEC_MULTIPLE * VIDEO_FRAME_RATE);
    MEDIA_INFO_LOG(
        "HStreamOperator::GetMovingPhotoBufferDuration preBufferDuration : %{public}u, "
        "postBufferDuration : %{public}u, preCacheFrameCount_ : %{public}u, postCacheFrameCount_ : %{public}u",
        preBufferDuration, postBufferDuration, preCacheFrameCount_, postCacheFrameCount_);
    return CAMERA_OK;
}


void HStreamOperator::GetMovingPhotoStartAndEndTime()
{
    CHECK_ERROR_RETURN_LOG(cameraDevice_ == nullptr, "HCaptureSession::GetMovingPhotoStartAndEndTime device is null");
    cameraDevice_->SetMovingPhotoStartTimeCallback([this](int32_t captureId, int64_t startTimeStamp) {
        MEDIA_INFO_LOG("SetMovingPhotoStartTimeCallback function enter");
        CHECK_ERROR_RETURN_LOG(this->taskManager_ == nullptr, "Set start time callback taskManager_ is null");
        std::lock_guard<mutex> lock(this->taskManager_->startTimeMutex_);
        if (this->taskManager_->mPStartTimeMap_.count(captureId) == 0) {
            MEDIA_INFO_LOG("Save moving photo start info, captureId : %{public}d, start timestamp : %{public}" PRIu64,
                captureId, startTimeStamp);
            this->taskManager_->mPStartTimeMap_.insert(make_pair(captureId, startTimeStamp));
        }
    });

    cameraDevice_->SetMovingPhotoEndTimeCallback([this](int32_t captureId, int64_t endTimeStamp) {
        CHECK_ERROR_RETURN_LOG(this->taskManager_ == nullptr, "Set end time callback taskManager_ is null");
        std::lock_guard<mutex> lock(this->taskManager_->endTimeMutex_);
        if (this->taskManager_->mPEndTimeMap_.count(captureId) == 0) {
            MEDIA_INFO_LOG("Save moving photo end info, captureId : %{public}d, end timestamp : %{public}" PRIu64,
                captureId, endTimeStamp);
            this->taskManager_->mPEndTimeMap_.insert(make_pair(captureId, endTimeStamp));
        }
    });
}

int32_t HStreamOperator::EnableMovingPhoto(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    bool isEnable, int32_t sensorOritation)
{
    MEDIA_INFO_LOG("HStreamOperator::EnableMovingPhoto is %{public}d", isEnable);
    isSetMotionPhoto_ = isEnable;
    deviceSensorOritation_ = sensorOritation;
    StartMovingPhotoStream(settings);
    CHECK_EXECUTE(cameraDevice_ != nullptr, cameraDevice_->EnableMovingPhoto(isEnable));
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
        if (sessionPtr != nullptr) {
            MEDIA_INFO_LOG("StartMovingPhotoStream when addDeferedSurface");
            sessionPtr->StartMovingPhotoStream(settings);
        }
    });
}

int32_t HStreamOperator::StartPreviewStream(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings,
    camera_position_enum_t cameraPosition)
{
    int32_t errorCode = CAMERA_OK;
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    bool hasDerferedPreview = false;
    // start preview
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::PREVIEW) {
            continue;
        }
        if (curStreamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET) {
            continue;
        }
        curStreamRepeat->SetUsedAsPosition(cameraPosition);
        errorCode = curStreamRepeat->Start(settings);
        hasDerferedPreview = curStreamRepeat->producer_ == nullptr;
        if (isSetMotionPhoto_ && hasDerferedPreview) {
            StartMovingPhoto(settings, curStreamRepeat);
        }
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HStreamOperator::Start(), Failed to start preview, rc: %{public}d", errorCode);
            break;
        }
    }
    // start movingPhoto
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType != RepeatStreamType::LIVEPHOTO) {
            continue;
        }
        int32_t movingPhotoErrorCode = CAMERA_OK;
        if (isSetMotionPhoto_ && !hasDerferedPreview) {
            movingPhotoErrorCode = curStreamRepeat->Start(settings);
            #ifdef MOVING_PHOTO_ADD_AUDIO
            std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
            audioCapturerSession_ != nullptr && audioCapturerSession_->StartAudioCapture();
            #endif
        }
        if (movingPhotoErrorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to start movingPhoto, rc: %{public}d", movingPhotoErrorCode);
            break;
        }
    }
    return errorCode;
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
            } else if (repeatStream->GetRepeatStreamType() == RepeatStreamType::LIVEPHOTO) {
                repeatStream->Stop();
                StopMovingPhoto();
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
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HStreamOperator::Stop(), Failed to stop stream, rc: %{public}d, streamId:%{public}d",
                errorCode, item->GetFwkStreamId());
        }
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
    if (!hdiStreamIds.empty()) {
        ReleaseStreams(hdiStreamIds);
    }
    if (GetAllOutptSize() == 0) {
        Release();
    }
}

int32_t HStreamOperator::GetOfflineOutptSize()
{
    std::list<sptr<HStreamCommon>> captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    std::list<sptr<HStreamCommon>> captureStreamsOffline = streamContainerOffline_.GetStreams(StreamType::CAPTURE);
    captureStreams.insert(captureStreams.end(), captureStreamsOffline.begin(), captureStreamsOffline.end());
    int32_t offlineCount = 0;
    for (auto& stream : captureStreams) {
        if (stream->GetStreamType() == StreamType::CAPTURE &&
            CastStream<HStreamCapture>(stream)->IsHasEnableOfflinePhoto()) {
            offlineCount++;
        } else {
            continue;
        }
    }
    return offlineCount;
}

int32_t HStreamOperator::GetAllOutptSize()
{
    int32_t outputCount = streamContainerOffline_.Size() + streamContainer_.Size();
    return outputCount;
}

int32_t HStreamOperator::ReleaseStreams(std::vector<int32_t>& releaseStreamIds)
{
    CAMERA_SYNC_TRACE;
    if (streamOperator_ != nullptr && !releaseStreamIds.empty()) {
        MEDIA_INFO_LOG("HStreamOperator::ReleaseStreams %{public}s",
            Container2String(releaseStreamIds.begin(), releaseStreamIds.end()).c_str());
        int32_t rc = streamOperator_->ReleaseStreams(releaseStreamIds);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::ClearStreamOperator ReleaseStreams fail, error Code:%{public}d", rc);
            CameraReportUtils::ReportCameraError(
                "HCameraDevice::ReleaseStreams", rc, true, CameraReportUtils::GetCallerInfo());
        }
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
            OHOS::Rosen::DisplayManager::GetInstance().UnregisterDisplayListener(displayListener_);
            displayListener_ = nullptr;
        }
        if (streamOperator_) {
            UnlinkOfflineInputAndOutputs();
            streamOperator_ = nullptr;
            MEDIA_INFO_LOG("HStreamOperator::Release streamOperator_ is nullptr");
        }
        HStreamOperatorManager::GetInstance()->RemoveStreamOperator(streamOperatorId_);
    }
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    CHECK_EXECUTE(livephotoListener_, livephotoListener_ = nullptr);
    CHECK_EXECUTE(videoCache_, videoCache_ = nullptr);
    if (taskManager_) {
        taskManager_->ClearTaskResource();
        taskManager_ = nullptr;
    }
    streamContainer_.Clear();
    streamContainerOffline_.Clear();
    MEDIA_INFO_LOG("HStreamOperator::Release execute success");
    return errorCode;
}

int32_t HStreamOperator::CreateAndCommitStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode)
{
    int retCode = CreateStreams(streamInfos);
    CHECK_ERROR_RETURN_RET(retCode != CAMERA_OK, retCode);
    return CommitStreams(deviceSettings, operationMode);
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
    streamOperator = streamOperator_;
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamOperator::CommitStreams GetStreamOperator is null!");
    // get higher streamOperator version
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG(
        "HStreamOperator::CommitStreams streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_1) {
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

int32_t HStreamOperator::EnableMovingPhotoMirror(bool isMirror, bool isConfig)
{
    if (!isConfig) {
        isMovingPhotoMirror_ = isMirror;
        return CAMERA_OK;
    }
    if (!isSetMotionPhoto_ || isMirror == isMovingPhotoMirror_) {
        return CAMERA_OK;
    }
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::LIVEPHOTO) {
            MEDIA_INFO_LOG("restart movingphoto stream.");
            if (streamRepeat->SetMirrorForLivePhoto(isMirror, opMode_)) {
                isMovingPhotoMirror_ = isMirror;
                // set clear cache flag
                std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
                livephotoListener_->SetClearFlag();
            }
            break;
        }
    }
    return CAMERA_OK;
}

void HStreamOperator::GetOutputStatus(int32_t &status)
{
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& stream : repeatStreams) {
        if (stream == nullptr) {
            continue;
        }
        auto streamRepeat = CastStream<HStreamRepeat>(stream);
        if (streamRepeat->GetRepeatStreamType() == RepeatStreamType::VIDEO) {
            if (streamRepeat->GetPreparedCaptureId() != CAPTURE_ID_UNSET) {
                const int32_t videoStartStatus = 2;
                status = videoStartStatus;
            }
        }
    }
}


#ifdef CAMERA_USE_SENSOR
void HStreamOperator::RegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    if (isRegisterSensorSuccess_) {
        MEDIA_INFO_LOG("HCaptureSession::RegisterSensorCallback isRegisterSensorSuccess return");
        return;
    }
    MEDIA_INFO_LOG("HCaptureSession::RegisterSensorCallback start");
    user.callback = GravityDataCallbackImpl;
    int32_t subscribeRet = SubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, subscribeRet: %{public}d", subscribeRet);
    int32_t setBatchRet = SetBatch(SENSOR_TYPE_ID_GRAVITY, &user, POSTURE_INTERVAL, 0);
    MEDIA_INFO_LOG("RegisterSensorCallback, setBatchRet: %{public}d", setBatchRet);
    int32_t activateRet = ActivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    MEDIA_INFO_LOG("RegisterSensorCallback, activateRet: %{public}d", activateRet);
    if (subscribeRet != CAMERA_OK || setBatchRet != CAMERA_OK || activateRet != CAMERA_OK) {
        isRegisterSensorSuccess_ = false;
        MEDIA_INFO_LOG("RegisterSensorCallback failed.");
    } else {
        isRegisterSensorSuccess_ = true;
    }
}

void HStreamOperator::UnRegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    int32_t deactivateRet = DeactivateSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    int32_t unsubscribeRet = UnsubscribeSensor(SENSOR_TYPE_ID_GRAVITY, &user);
    if (deactivateRet == CAMERA_OK && unsubscribeRet == CAMERA_OK) {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback success.");
        isRegisterSensorSuccess_ = false;
    } else {
        MEDIA_INFO_LOG("HCameraService.UnRegisterSensorCallback failed.");
    }
}

void HStreamOperator::GravityDataCallbackImpl(SensorEvent* event)
{
    MEDIA_DEBUG_LOG("GravityDataCallbackImpl prepare execute");
    CHECK_ERROR_RETURN_LOG(event == nullptr, "SensorEvent is nullptr.");
    CHECK_ERROR_RETURN_LOG(event[0].data == nullptr, "SensorEvent[0].data is nullptr.");
    CHECK_ERROR_RETURN_LOG(event->sensorTypeId != SENSOR_TYPE_ID_GRAVITY, "SensorCallback error type.");
    // this data will be delete when callback execute finish
    GravityData* nowGravityData = reinterpret_cast<GravityData*>(event->data);
    gravityData = { nowGravityData->x, nowGravityData->y, nowGravityData->z };
    sensorRotation = CalcSensorRotation(CalcRotationDegree(gravityData));
}

int32_t HStreamOperator::CalcSensorRotation(int32_t sensorDegree)
{
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
}

int32_t HStreamOperator::CalcRotationDegree(GravityData data)
{
    float x = data.x;
    float y = data.y;
    float z = data.z;
    int degree = -1;
    if ((x * x + y * y) * VALID_INCLINATION_ANGLE_THRESHOLD_COEFFICIENT < z * z) {
        return degree;
    }
    // arccotx = pi / 2 - arctanx, 90 is used to calculate acot(in degree); degree = rad / pi * 180
    degree = 90 - static_cast<int>(round(atan2(y, -x) / M_PI * 180));
    // Normalize the degree to the range of 0~360
    return degree >= 0 ? degree % 360 : degree % 360 + 360;
}
#endif

void HStreamOperator::SetSensorRotation(int32_t rotationValue, int32_t sensorOrientation, int32_t cameraPosition)
{
    MEDIA_INFO_LOG("SetSensorRotation rotationValue : %{public}d, sensorOrientation : %{public}d",
        rotationValue, sensorOrientation);
    // 获取当前重力传感器角度
    if (cameraPosition == OHOS_CAMERA_POSITION_BACK) {
        sensorRotation_ = rotationValue - sensorOrientation;
    } else if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        sensorRotation_ = sensorOrientation - rotationValue;
    }
}

void HStreamOperator::StartMovingPhotoEncode(int32_t rotation, uint64_t timestamp, int32_t format, int32_t captureId)
{
    if (!isSetMotionPhoto_) {
        return;
    }
    int32_t addMirrorRotation = 0;
    MEDIA_INFO_LOG("sensorRotation is : %{public}d", sensorRotation_);
    if ((sensorRotation_ == STREAM_ROTATE_0 || sensorRotation_ == STREAM_ROTATE_180) && isMovingPhotoMirror_) {
        addMirrorRotation = STREAM_ROTATE_180;
    }
    int32_t realRotation = rotation + addMirrorRotation;
    realRotation = realRotation % ROTATION_360;
    StartRecord(timestamp, realRotation, captureId);
}

std::string HStreamOperator::CreateDisplayName()
{
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) {
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1) << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_mday << connector << std::setw(otherWidth)
           << std::setfill(placeholder) << currentTime.tm_hour << std::setw(otherWidth) << std::setfill(placeholder)
           << currentTime.tm_min << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    if (lastDisplayName_ == formattedTime) {
        saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(saveIndex);
        MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
        return formattedTime;
    }
    lastDisplayName_ = formattedTime;
    saveIndex = 0;
    MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

std::string HStreamOperator::CreateBurstDisplayName(int32_t imageSeqId, int32_t seqId)
{
    struct tm currentTime;
    std::string formattedTime = "";
    std::stringstream ss;
    // a group of burst capture use the same prefix
    if (imageSeqId == 1) {
        CHECK_ERROR_RETURN_RET_LOG(!GetSystemCurrentTime(&currentTime), formattedTime, "Failed to get current time.");
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

    if (seqId == 1) {
        ss << coverTag;
    }
    formattedTime = ss.str();
    MEDIA_INFO_LOG("CreateBurstDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

void HStreamOperator::SetCameraPhotoProxyInfo(sptr<CameraServerPhotoProxy> cameraPhotoProxy, int32_t &cameraShotType,
    bool &isBursting, std::string &burstKey)
{
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
        CHECK_WARNING_CONTINUE_LOG(stream == nullptr, "stream is null");
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
            int32_t burstShotType = 3;
            cameraShotType = burstShotType;
            cameraPhotoProxy->SetBurstInfo(burstKey, isCoverPhoto);
            break;
        }
        MEDIA_INFO_LOG("CreateMediaLibrary not Bursting");
    }
}

void HStreamOperator::ConfigPayload(uint32_t pid, uint32_t tid, const char *bundleName, int32_t qosLevel,
    std::unordered_map<std::string, std::string> &mapPayload)
{
    std::string strBundleName = bundleName;
    std::string strPid = std::to_string(pid);
    std::string strTid = std::to_string(tid);
    std::string strQos = std::to_string(qosLevel);
    mapPayload["pid"] = strPid;
    mapPayload[strTid] = strQos;
    mapPayload["bundleName"] = strBundleName;
    MEDIA_INFO_LOG("mapPayload pid: %{public}s. tid: %{public}s. Qos: %{public}s",
        strPid.c_str(), strTid.c_str(), strQos.c_str());
}

int32_t HStreamOperator::CreateMediaLibrary(sptr<CameraPhotoProxy>& photoProxy, std::string& uri,
    int32_t& cameraShotType, std::string& burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    constexpr int32_t movingPhotoShotType = 2;
    constexpr int32_t imageShotType = 0;
    cameraShotType = isSetMotionPhoto_ ? movingPhotoShotType : imageShotType;
    MessageParcel data;
    photoProxy->WriteToParcel(data);
    photoProxy->CameraFreeBufferHandle();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->ReadFromParcel(data);
    cameraPhotoProxy->SetDisplayName(CreateDisplayName());
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    bool isBursting = false;
    string pictureId = cameraPhotoProxy->GetTitle() + "." + cameraPhotoProxy->GetExtension();
    CameraReportDfxUtils::GetInstance()->SetPictureId(captureId, pictureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, IPCSkeleton::GetCallingUid());
    CHECK_ERROR_RETURN_RET_LOG(
        photoAssetProxy == nullptr, CAMERA_ALLOC_ERROR, "HCaptureSession::CreateMediaLibrary get photoAssetProxy fail");
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && isSetMotionPhoto_ && taskManager_) {
        MEDIA_INFO_LOG("taskManager setVideoFd start");
        taskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    } else {
        photoAssetProxy.reset();
    }
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    return CAMERA_OK;
}

void RotatePicture(std::weak_ptr<PictureIntf> picture)
{
    CAMERA_SYNC_TRACE;
    auto ptr = picture.lock();
    if (ptr) {
        ptr->RotatePicture();
    }
}

std::shared_ptr<PhotoAssetIntf> HStreamOperator::ProcessPhotoProxy(int32_t captureId,
    std::shared_ptr<PictureIntf> picturePtr, bool isBursting, sptr<CameraServerPhotoProxy> cameraPhotoProxy,
    std::string& uri)
{
    MEDIA_INFO_LOG("enter ProcessPhotoProxy");
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(picturePtr == nullptr, nullptr, "picturePtr is null");
    sptr<HStreamCapture> captureStream = nullptr;
    std::list<sptr<HStreamCommon>> captureStreams = streamContainer_.GetStreams(StreamType::CAPTURE);
    std::list<sptr<HStreamCommon>> captureStreamsOffline = streamContainerOffline_.GetStreams(StreamType::CAPTURE);
    captureStreams.insert(captureStreams.end(), captureStreamsOffline.begin(), captureStreamsOffline.end());
    for (auto& stream : captureStreams) {
        captureStream = CastStream<HStreamCapture>(stream);
        if (captureStream != nullptr) {
            break;
        }
    }
    CHECK_ERROR_RETURN_RET_LOG(captureStream == nullptr, nullptr, "stream is null");
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy = nullptr;
    std::thread taskThread;
    if (isBursting) {
        int32_t cameraShotType = 3;
        photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(cameraShotType, IPCSkeleton::GetCallingUid());
    } else {
        photoAssetProxy = captureStream->GetPhotoAssetInstance(captureId);
    }
    CHECK_ERROR_RETURN_RET_LOG(photoAssetProxy == nullptr, nullptr, "photoAssetProxy is null");
    if (!isBursting && picturePtr) {
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture E");
        taskThread = std::thread(RotatePicture, picturePtr);
    }
    bool isProfessionalPhoto = (opMode_ == static_cast<int32_t>(HDI::Camera::V1_3::OperationMode::PROFESSIONAL_PHOTO));
    if (isBursting || captureStream->GetAddPhotoProxyEnabled() == false || isProfessionalPhoto) {
        MEDIA_INFO_LOG("CreateMediaLibrary AddPhotoProxy E");
        string pictureId = cameraPhotoProxy->GetTitle() + "." + cameraPhotoProxy->GetExtension();
        CameraReportDfxUtils::GetInstance()->SetPictureId(captureId, pictureId);
        photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
        MEDIA_INFO_LOG("CreateMediaLibrary AddPhotoProxy X");
    }
    uri = photoAssetProxy->GetPhotoAssetUri();
    if (!isBursting && taskThread.joinable()) {
        taskThread.join();
        MEDIA_DEBUG_LOG("CreateMediaLibrary RotatePicture X");
    }
    MEDIA_INFO_LOG("CreateMediaLibrary NotifyLowQualityImage E");
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyLowQualityImage(
        photoAssetProxy->GetUserId(), uri, picturePtr);
    MEDIA_INFO_LOG("CreateMediaLibrary NotifyLowQualityImage X");
    return photoAssetProxy;
}

int32_t HStreamOperator::CreateMediaLibrary(std::shared_ptr<PictureIntf> picture, sptr<CameraPhotoProxy>& photoProxy,
    std::string& uri, int32_t& cameraShotType, std::string& burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    const int MAX_RETRIES = 7;
    int32_t tempPid = getpid();
    int32_t tempTid = gettid();
    std::unordered_map<std::string, std::string> mapPayload;
    ConfigPayload(tempPid, tempTid, "camera_service", MAX_RETRIES, mapPayload);
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        OHOS::ResourceSchedule::ResType::RES_TYPE_THREAD_QOS_CHANGE, 0, mapPayload);

    constexpr int32_t movingPhotoShotType = 2;
    constexpr int32_t imageShotType = 0;
    cameraShotType = isSetMotionPhoto_ ? movingPhotoShotType : imageShotType;
    MessageParcel data;
    photoProxy->WriteToParcel(data);
    photoProxy->CameraFreeBufferHandle();
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->ReadFromParcel(data);
    cameraPhotoProxy->SetDisplayName(CreateDisplayName());
    int32_t captureId = cameraPhotoProxy->GetCaptureId();
    bool isBursting = false;
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetAddProxyStartInfo(captureId);
    SetCameraPhotoProxyInfo(cameraPhotoProxy, cameraShotType, isBursting, burstKey);
    std::shared_ptr<PhotoAssetIntf> photoAssetProxy =
        ProcessPhotoProxy(captureId, picture, isBursting, cameraPhotoProxy, uri);
    CHECK_ERROR_RETURN_RET_LOG(photoAssetProxy == nullptr, CAMERA_INVALID_ARG, "photoAssetProxy is null");
    if (!isBursting && isSetMotionPhoto_ && taskManager_) {
        MEDIA_INFO_LOG("CreateMediaLibrary captureId :%{public}d", captureId);
        if (taskManager_) {
            taskManager_->SetVideoFd(timestamp, photoAssetProxy, captureId);
        }
    } else {
        photoAssetProxy.reset();
    }
    CameraReportDfxUtils::GetInstance()->SetAddProxyEndInfo(captureId);
    return CAMERA_OK;
}

int32_t HStreamOperator::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureStarted captureId:%{public}d, streamIds:%{public}s", captureId,
        Container2String(streamIds.begin(), streamIds.end()).c_str());
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& streamId : streamIds) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(streamId);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureStarted StreamId: %{public}d not found", streamId);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameStarted();
            CameraReportUtils::GetInstance().SetOpenCamPerfEndInfo();
            CameraReportUtils::GetInstance().SetModeChangePerfEndInfo();
            CameraReportUtils::GetInstance().SetSwitchCamPerfEndInfo();
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId);
        }
    }
    return CAMERA_OK;
}

void HStreamOperator::StartRecord(uint64_t timestamp, int32_t rotation, int32_t captureId)
{
    if (isSetMotionPhoto_) {
        taskManager_->SubmitTask([this, timestamp, rotation, captureId]() {
            this->StartOnceRecord(timestamp, rotation, captureId);
        });
    }
}

SessionDrainImageCallback::SessionDrainImageCallback(std::vector<sptr<FrameRecord>>& frameCacheList,
                                                     wptr<MovingPhotoListener> listener,
                                                     wptr<MovingPhotoVideoCache> cache,
                                                     uint64_t timestamp,
                                                     int32_t rotation,
                                                     int32_t captureId)
    : frameCacheList_(frameCacheList), listener_(listener), videoCache_(cache), timestamp_(timestamp),
      rotation_(rotation), captureId_(captureId)
{
}

SessionDrainImageCallback::~SessionDrainImageCallback()
{
    MEDIA_INFO_LOG("~SessionDrainImageCallback enter");
}

void SessionDrainImageCallback::OnDrainImage(sptr<FrameRecord> frame)
{
    MEDIA_INFO_LOG("OnDrainImage enter");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        frameCacheList_.push_back(frame);
    }
    auto videoCache = videoCache_.promote();
    if (frame->IsIdle() && videoCache) {
        videoCache->CacheFrame(frame);
    } else if (frame->IsFinishCache() && videoCache) {
        videoCache->OnImageEncoded(frame, frame->IsEncoded());
    } else if (frame->IsReadyConvert()) {
        MEDIA_DEBUG_LOG("frame is ready convert");
    } else {
        MEDIA_INFO_LOG("videoCache and frame is not useful");
    }
}

void SessionDrainImageCallback::OnDrainImageFinish(bool isFinished)
{
    MEDIA_INFO_LOG("OnDrainImageFinish enter");
    auto videoCache = videoCache_.promote();
    if (videoCache) {
        std::lock_guard<std::mutex> lock(mutex_);
        videoCache_->GetFrameCachedResult(
            frameCacheList_,
            [videoCache](const std::vector<sptr<FrameRecord>>& frameRecords,
                         uint64_t timestamp,
                         int32_t rotation,
                         int32_t captureId) { videoCache->DoMuxerVideo(frameRecords, timestamp, rotation, captureId); },
            timestamp_,
            rotation_,
            captureId_);
    }
    auto listener = listener_.promote();
    CHECK_EXECUTE(listener && isFinished, listener->RemoveDrainImageManager(this));
}

void HStreamOperator::StartOnceRecord(uint64_t timestamp, int32_t rotation, int32_t captureId)
{
    MEDIA_INFO_LOG("StartOnceRecord enter");
    // frameCacheList only used by now thread
    std::lock_guard<std::mutex> lock(movingPhotoStatusLock_);
    std::vector<sptr<FrameRecord>> frameCacheList;
    sptr<SessionDrainImageCallback> imageCallback = new SessionDrainImageCallback(frameCacheList,
        livephotoListener_, videoCache_, timestamp, rotation, captureId);
    livephotoListener_->ClearCache(timestamp);
    livephotoListener_->DrainOutImage(imageCallback);
    MEDIA_INFO_LOG("StartOnceRecord end");
}

int32_t HStreamOperator::CreateStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    uint32_t major;
    uint32_t minor;
    CHECK_ERROR_RETURN_RET_LOG(streamInfos.empty(), CAMERA_OK, "HStreamOperator::CreateStreams streamInfos is empty!");
    std::lock_guard<std::mutex> lock(opMutex_);
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = streamOperator_;
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamOperator::CreateStreams GetStreamOperator is null!");
    // get higher streamOperator version
    streamOperator_->GetVersion(major, minor);
    MEDIA_INFO_LOG("streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_1) {
        streamOperatorV1_1 = OHOS::HDI::Camera::V1_1::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_1 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::CreateStreams IStreamOperator cast to V1_1 error");
            streamOperatorV1_1 = static_cast<OHOS::HDI::Camera::V1_1::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }
    if (streamOperatorV1_1 != nullptr) {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_1");
        for (auto streamInfo : streamInfos) {
            if (streamInfo.extendedStreamInfos.size() > 0) {
                MEDIA_INFO_LOG("HCameraDevice::CreateStreams streamId:%{public}d width:%{public}d height:%{public}d"
                    "format:%{public}d dataspace:%{public}d", streamInfo.v1_0.streamId_, streamInfo.v1_0.width_,
                    streamInfo.v1_0.height_, streamInfo.v1_0.format_, streamInfo.v1_0.dataspace_);
                MEDIA_INFO_LOG("HStreamOperator::CreateStreams streamOperator V1_1 type %{public}d",
                    streamInfo.extendedStreamInfos[0].type);
            }
        }
        hdiRc = (CamRetCode)(streamOperatorV1_1->CreateStreams_V1_1(streamInfos));
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
        CHECK_ERROR_PRINT_LOG(!streamIds.empty() &&
            streamOperator->ReleaseStreams(streamIds) != HDI::Camera::V1_0::NO_ERROR,
            "HStreamOperator::CreateStreams(), Failed to release streams");
    }
    for (auto& info : streamInfos) {
        MEDIA_INFO_LOG("HStreamOperator::CreateStreams stream id is:%{public}d", info.v1_0.streamId_);
    }
    return HdiToServiceError(hdiRc);
}

int32_t HStreamOperator::UpdateStreams(std::vector<StreamInfo_V1_1>& streamInfos)
{
    sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperatorV1_2;
    CHECK_ERROR_RETURN_RET_LOG(streamOperator_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamOperator::UpdateStreams GetStreamOperator is null!");
    uint32_t major;
    uint32_t minor;
    streamOperator_->GetVersion(major, minor);
    MEDIA_INFO_LOG("UpdateStreams::UpdateStreams GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_2) {
        streamOperatorV1_2 = OHOS::HDI::Camera::V1_2::IStreamOperator::CastFrom(streamOperator_);
        if (streamOperatorV1_2 == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::UpdateStreams IStreamOperator cast to V1_2 error");
            streamOperatorV1_2 = static_cast<OHOS::HDI::Camera::V1_2::IStreamOperator*>(streamOperator_.GetRefPtr());
        }
    }
    CamRetCode hdiRc = HDI::Camera::V1_0::CamRetCode::NO_ERROR;
    if (streamOperatorV1_2 != nullptr) {
        MEDIA_DEBUG_LOG("HStreamOperator::UpdateStreams streamOperator V1_2");
        hdiRc = (CamRetCode)(streamOperatorV1_2->UpdateStreams(streamInfos));
    } else {
        MEDIA_DEBUG_LOG("HStreamOperator::UpdateStreams failed, streamOperator V1_2 is null.");
        return CAMERA_UNKNOWN_ERROR;
    }
    return HdiToServiceError(hdiRc);
}

int32_t HStreamOperator::OnCaptureStarted_V1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureStarted_V1_2 captureId:%{public}d", captureId);
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& captureInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(captureInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureStarted_V1_2 StreamId: %{public}d not found."
                          " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            MEDIA_DEBUG_LOG("HStreamOperator::OnCaptureStarted_V1_2 StreamId: %{public}d."
                            " exposureTime: %{public}u",
                captureInfo.streamId_, captureInfo.exposureTime_);
            CastStream<HStreamCapture>(curStream)->OnCaptureStarted(captureId, captureInfo.exposureTime_);
        }
    }
    return CAMERA_OK;
}

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

int32_t HStreamOperator::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    MEDIA_INFO_LOG("HStreamOperator::OnCaptureError");
    std::lock_guard<std::mutex> lock(cbMutex_);
    for (auto& errInfo : infos) {
        sptr<HStreamCommon> curStream = GetHdiStreamByStreamID(errInfo.streamId_);
        if (curStream == nullptr) {
            MEDIA_ERR_LOG("HStreamOperator::OnCaptureError StreamId: %{public}d not found."
                          " Error: %{public}d",
                errInfo.streamId_, errInfo.error_);
            return CAMERA_INVALID_ARG;
        } else if (curStream->GetStreamType() == StreamType::REPEAT) {
            CastStream<HStreamRepeat>(curStream)->OnFrameError(errInfo.error_);
        } else if (curStream->GetStreamType() == StreamType::CAPTURE) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnCaptureError(captureId, errInfo.error_);
        }
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
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            int32_t rotation = 0;
            captureStream->rotationMap_.Find(captureId, rotation);
            StartMovingPhotoEncode(rotation, timestamp, captureStream->format_, captureId);
            captureStream->OnFrameShutter(captureId, timestamp);
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
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
            auto captureStream = CastStream<HStreamCapture>(curStream);
            captureStream->rotationMap_.Erase(captureId);
            captureStream->OnFrameShutterEnd(captureId, timestamp);
            mlastCaptureId = captureId;
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
        if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::CAPTURE)) {
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
    MEDIA_DEBUG_LOG("HStreamOperator::OnResult");
    sptr<HStreamCommon> curStream;
    const int32_t metaStreamId = -1;
    if (streamId == metaStreamId) {
        curStream = GetStreamByStreamID(streamId);
    } else {
        curStream = GetHdiStreamByStreamID(streamId);
    }
    if ((curStream != nullptr) && (curStream->GetStreamType() == StreamType::METADATA)) {
        CastStream<HStreamMetadata>(curStream)->OnMetaResult(streamId, result);
    } else {
        MEDIA_ERR_LOG("HStreamOperator::OnResult StreamId: %{public}d is null or not Not adapted", streamId);
        return CAMERA_INVALID_ARG;
    }
    return CAMERA_OK;
}

std::vector<int32_t> HStreamOperator::GetFrameRateRange()
{
    auto repeatStreams = streamContainer_.GetStreams(StreamType::REPEAT);
    for (auto& item : repeatStreams) {
        auto curStreamRepeat = CastStream<HStreamRepeat>(item);
        auto repeatType = curStreamRepeat->GetRepeatStreamType();
        if (repeatType == RepeatStreamType::PREVIEW) {
            return curStreamRepeat->GetFrameRateRange();
        }
    }
    return {};
}

bool StreamContainer::AddStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    if (it == list.end()) {
        list.emplace_back(stream);
        return true;
    }
    return false;
}

bool StreamContainer::RemoveStream(sptr<HStreamCommon> stream)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    auto& list = streams_[stream->GetStreamType()];
    auto it = std::find_if(list.begin(), list.end(), [stream](auto item) { return item == stream; });
    CHECK_ERROR_RETURN_RET(it == list.end(), false);
    list.erase(it);
    return true;
}

sptr<HStreamCommon> StreamContainer::GetStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            CHECK_ERROR_RETURN_RET(stream->GetFwkStreamId() == streamId, stream);
        }
    }
    return nullptr;
}

sptr<HStreamCommon> StreamContainer::GetHdiStream(int32_t streamId)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            CHECK_ERROR_RETURN_RET(stream->GetHdiStreamId() == streamId, stream);
        }
    }
    return nullptr;
}

void StreamContainer::Clear()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    streams_.clear();
}

size_t StreamContainer::Size()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    size_t totalSize = 0;
    for (auto& pair : streams_) {
        totalSize += pair.second.size();
    }
    return totalSize;
}

std::list<sptr<HStreamCommon>> StreamContainer::GetStreams(const StreamType streamType)
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& stream : streams_[streamType]) {
        auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
            [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
        totalOrderedStreams.emplace(insertPos, stream);
    }
    return totalOrderedStreams;
}

std::list<sptr<HStreamCommon>> StreamContainer::GetAllStreams()
{
    std::lock_guard<std::mutex> lock(streamsLock_);
    std::list<sptr<HStreamCommon>> totalOrderedStreams;
    for (auto& pair : streams_) {
        for (auto& stream : pair.second) {
            auto insertPos = std::find_if(totalOrderedStreams.begin(), totalOrderedStreams.end(),
                [&stream](auto& it) { return stream->GetFwkStreamId() <= it->GetFwkStreamId(); });
            totalOrderedStreams.emplace(insertPos, stream);
        }
    }
    return totalOrderedStreams;
}

MovingPhotoListener::MovingPhotoListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper, sptr<Surface> metaSurface,
    shared_ptr<FixedSizeList<MetaElementType>> metaCache, uint32_t preCacheFrameCount, uint32_t postCacheFrameCount)
    : movingPhotoSurfaceWrapper_(surfaceWrapper),
      metaSurface_(metaSurface),
      metaCache_(metaCache),
      recorderBufferQueue_("videoBuffer", preCacheFrameCount),
      postCacheFrameCount_(postCacheFrameCount)
{
    shutterTime_ = 0;
}

MovingPhotoListener::~MovingPhotoListener()
{
    recorderBufferQueue_.SetActive(false);
    metaCache_->clear();
    recorderBufferQueue_.Clear();
    MEDIA_ERR_LOG("HStreamRepeat::LivePhotoListener ~ end");
}

void MovingPhotoListener::RemoveDrainImageManager(sptr<SessionDrainImageCallback> callback)
{
    callbackMap_.Erase(callback);
    MEDIA_INFO_LOG("RemoveDrainImageManager drainImageManagerVec_ Start %d", callbackMap_.Size());
}

void MovingPhotoListener::ClearCache(uint64_t timestamp)
{
    CHECK_ERROR_RETURN(!isNeededClear_.load());
    MEDIA_INFO_LOG("ClearCache enter");
    shutterTime_ = static_cast<int64_t>(timestamp);
    while (!recorderBufferQueue_.Empty()) {
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Front();
        MEDIA_DEBUG_LOG("surface_ release surface buffer %{public}llu, timestamp %{public}llu",
            (long long unsigned)popFrame->GetTimeStamp(), (long long unsigned)timestamp);
        if (popFrame->GetTimeStamp() > shutterTime_) {
            isNeededClear_ = false;
            MEDIA_INFO_LOG("ClearCache end");
            return;
        }
        recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
        popFrame->ReleaseMetaBuffer(metaSurface_, true);
    }
}

void MovingPhotoListener::SetClearFlag()
{
    MEDIA_INFO_LOG("need clear cache!");
    isNeededClear_ = true;
}

void MovingPhotoListener::StopDrainOut()
{
    MEDIA_INFO_LOG("StopDrainOut drainImageManagerVec_ Start %d", callbackMap_.Size());
    callbackMap_.Iterate([](const sptr<SessionDrainImageCallback> callback, sptr<DrainImageManager> manager) {
        manager->DrainFinish(false);
    });
    callbackMap_.Clear();
}

void MovingPhotoListener::OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform)
{
    MEDIA_DEBUG_LOG("OnBufferArrival timestamp %{public}llu", (long long unsigned)timestamp);
    if (recorderBufferQueue_.Full()) {
        MEDIA_DEBUG_LOG("surface_ release surface buffer");
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
        popFrame->ReleaseMetaBuffer(metaSurface_, true);
        MEDIA_DEBUG_LOG("surface_ release surface buffer: %{public}s, refCount: %{public}d",
            popFrame->GetFrameId().c_str(), popFrame->GetSptrRefCount());
    }
    MEDIA_DEBUG_LOG("surface_ push buffer %{public}d x %{public}d, stride is %{public}d",
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), buffer->GetStride());
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(buffer, timestamp, transform);
    CHECK_ERROR_RETURN_LOG(frameRecord == nullptr, "MovingPhotoListener::OnBufferAvailable create FrameRecord fail!");
    if (isNeededClear_ && isNeededPop_) {
        if (timestamp < shutterTime_) {
            frameRecord->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
            MEDIA_INFO_LOG("Drop this frame in cache");
            return;
        } else {
            isNeededClear_ = false;
            isNeededPop_ = false;
            MEDIA_INFO_LOG("ClearCache end");
        }
    }
    recorderBufferQueue_.Push(frameRecord);
    auto metaPair = metaCache_->find_if([timestamp](const MetaElementType& value) {
        return value.first == timestamp;
    });
    if (metaPair.has_value()) {
        MEDIA_DEBUG_LOG("frame has meta");
        frameRecord->SetMetaBuffer(metaPair.value().second);
    }
    vector<sptr<SessionDrainImageCallback>> callbacks;
    callbackMap_.Iterate([frameRecord, &callbacks](const sptr<SessionDrainImageCallback> callback,
        sptr<DrainImageManager> manager) {
        callbacks.push_back(callback);
    });
    for (sptr<SessionDrainImageCallback> drainImageCallback : callbacks) {
        sptr<DrainImageManager> drainImageManager;
        if (callbackMap_.Find(drainImageCallback, drainImageManager)) {
            std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
            drainImageManager->DrainImage(frameRecord);
        }
    }
}

void MovingPhotoListener::DrainOutImage(sptr<SessionDrainImageCallback> drainImageCallback)
{
    sptr<DrainImageManager> drainImageManager =
        new DrainImageManager(drainImageCallback, recorderBufferQueue_.Size() + postCacheFrameCount_);
    {
        MEDIA_INFO_LOG("DrainOutImage enter %{public}zu", recorderBufferQueue_.Size());
        callbackMap_.Insert(drainImageCallback, drainImageManager);
    }
    // Convert recorderBufferQueue_ to a vector
    std::vector<sptr<FrameRecord>> frameList = recorderBufferQueue_.GetAllElements();
    CHECK_EXECUTE(!frameList.empty(), frameList.back()->SetCoverFrame());
    std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
    for (const auto& frame : frameList) {
        MEDIA_DEBUG_LOG("DrainOutImage enter DrainImage");
        drainImageManager->DrainImage(frame);
    }
}

void MovingPhotoMetaListener::OnBufferAvailable()
{
    CHECK_ERROR_RETURN_LOG(!surface_, "streamRepeat surface is null");
    MEDIA_DEBUG_LOG("metaSurface_ OnBufferAvailable %{public}u", surface_->GetQueueSize());
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = surface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire meta surface buffer");
    surfaceRet = surface_->DetachBufferFromQueue(buffer);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "Failed to detach meta buffer. %{public}d", surfaceRet);
    metaCache_->add({timestamp, buffer});
}

MovingPhotoMetaListener::MovingPhotoMetaListener(sptr<Surface> surface,
    shared_ptr<FixedSizeList<MetaElementType>> metaCache)
    : surface_(surface), metaCache_(metaCache)
{
}

MovingPhotoMetaListener::~MovingPhotoMetaListener()
{
    MEDIA_ERR_LOG("HStreamRepeat::MovingPhotoMetaListener ~ end");
}

} // namespace CameraStandard
} // namespace OHOS
