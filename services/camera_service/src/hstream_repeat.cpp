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

#include "hstream_repeat.h"

#include <cstdint>
#include <mutex>

#ifdef NOTIFICATION_ENABLE
#include "camera_beauty_notification.h"
#endif
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "display_manager.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "istream_repeat_callback.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"
#include "parameters.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
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
}

int32_t HStreamRepeat::LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG(
        "HStreamRepeat::LinkInput streamId:%{public}d ,repeatStreamType:%{public}d",
        GetFwkStreamId(), repeatStreamType_);
    int32_t ret = HStreamCommon::LinkInput(streamOperator, cameraAbility);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret,
        "HStreamRepeat::LinkInput err, streamId:%{public}d ,err:%{public}d", GetFwkStreamId(), ret);
    CHECK_EXECUTE(repeatStreamType_ != RepeatStreamType::VIDEO, SetStreamTransform());
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
    return CAMERA_OK;
}

void HStreamRepeat::SetVideoStreamInfo(StreamInfo_V1_1& streamInfo)
{
    streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
    MEDIA_INFO_LOG("HStreamRepeat::SetVideoStreamInfo Enter");
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
            HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO),
        .width = 0, .height = 0, .format = 0, .dataspace = 0, .bufferQueue = nullptr
    };
    extendedStreamInfo.bufferQueue = metaSurfaceBufferQueue_;
    MEDIA_INFO_LOG("HStreamRepeat::SetVideoStreamInfo end");
    streamInfo.extendedStreamInfos = { extendedStreamInfo };
}

void HStreamRepeat::SetStreamInfo(StreamInfo_V1_1& streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    auto metaProducerSequenceable = metaProducer_ == nullptr ? nullptr : new BufferProducerSequenceable(metaProducer_);
    HDI::Camera::V1_1::ExtendedStreamInfo metaExtendedStreamInfo {
        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(4), .width = 0, .height = 0, .format = 0,
        .dataspace = 0, .bufferQueue = metaProducerSequenceable
    };
    switch (repeatStreamType_) {
        case RepeatStreamType::LIVEPHOTO:
            streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
            streamInfo.extendedStreamInfos = { metaExtendedStreamInfo };
            break;
        case RepeatStreamType::VIDEO:
            SetVideoStreamInfo(streamInfo);
            break;
        case RepeatStreamType::PREVIEW:
            streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
            if (mEnableSecure) {
                MEDIA_INFO_LOG("HStreamRepeat::SetStreamInfo Enter");
                HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
                    .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                        HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_SECURE),
                    .width = 0, .height = 0, .format = 0, .dataspace = 0, .bufferQueue = nullptr
                };
                MEDIA_INFO_LOG("HStreamRepeat::SetStreamInfo end");
                streamInfo.extendedStreamInfos = { extendedStreamInfo };
            }
            break;
        case RepeatStreamType::SKETCH:
            streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
            HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
                .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                    HDI::Camera::V1_2::EXTENDED_STREAM_INFO_SKETCH),
                .width = 0, .height = 0, .format = 0, .dataspace = 0, .bufferQueue = nullptr
            };
            streamInfo.extendedStreamInfos = { extendedStreamInfo };
            break;
    }
}

void HStreamRepeat::SetMetaProducer(sptr<OHOS::IBufferProducer> metaProducer)
{
    std::lock_guard<std::mutex> lock(producerLock_);
    metaProducer_ = metaProducer;
}

void HStreamRepeat::SetMovingPhotoStartCallback(std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(movingPhotoCallbackLock_);
    startMovingPhotoCallback_ = callback;
}

void HStreamRepeat::UpdateSketchStatus(SketchStatus status)
{
    CHECK_ERROR_RETURN(repeatStreamType_ != RepeatStreamType::SKETCH);
    auto parent = parentStreamRepeat_.promote();
    CHECK_ERROR_RETURN(parent == nullptr);
    CHECK_ERROR_RETURN(sketchStatus_ == status);
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
        if (sketchStreamRepeat_ == nullptr || sketchStreamRepeat_->sketchRatio_ <= 0) {
            MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream sketchStreamRepeat_ is null or ratio is illegal");
            return;
        }
        sketchStreamRepeat = sketchStreamRepeat_;
    }
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream get OHOS_CONTROL_ZOOM_RATIO fail");
        return;
    }
    float tagRatio = *item.data.f;
    MEDIA_DEBUG_LOG("HStreamRepeat::StartSketchStream OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        tagRatio, sketchStreamRepeat->sketchRatio_);
    if (sketchStreamRepeat->sketchRatio_ > 0 &&
        tagRatio - sketchStreamRepeat->sketchRatio_ >= -std::numeric_limits<float>::epsilon()) {
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
    CHECK_ERROR_RETURN_RET(streamOperator == nullptr, CAMERA_INVALID_STATE);
    auto preparedCaptureId = GetPreparedCaptureId();
    CHECK_ERROR_RETURN_RET_LOG(!isUpdateSeetings && preparedCaptureId != CAPTURE_ID_UNSET, CAMERA_INVALID_STATE,
        "HStreamRepeat::Start, Already started with captureID: %{public}d", preparedCaptureId);
    // If current is sketch stream, check parent is start or not.
    if (repeatStreamType_ == RepeatStreamType::SKETCH) {
        auto parentRepeat = parentStreamRepeat_.promote();
        CHECK_ERROR_RETURN_RET_LOG(parentRepeat == nullptr || parentRepeat->GetPreparedCaptureId() == CAPTURE_ID_UNSET,
            CAMERA_INVALID_STATE, "HStreamRepeat::Start sketch parent state is illegal");
    }
    if (!isUpdateSeetings) {
        int32_t ret = PrepareCaptureId();
        preparedCaptureId = GetPreparedCaptureId();
        CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET, ret,
            "HStreamRepeat::Start Failed to allocate a captureId");
    }
    UpdateSketchStatus(SketchStatus::STARTING);

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
    if (repeatStreamType_ == RepeatStreamType::VIDEO || repeatStreamType_ == RepeatStreamType::LIVEPHOTO) {
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
    }
#ifdef NOTIFICATION_ENABLE
    bool isNeedBeautyNotification = IsNeedBeautyNotification();
    if (isNeedBeautyNotification && CameraBeautyNotification::GetInstance()->GetBeautyStatus() == BEAUTY_STATUS_ON) {
        UpdateBeautySettings(dynamicSetting);
    }
#endif
    
    std::vector<uint8_t> captureSetting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(dynamicSetting, captureSetting);

    CaptureInfo captureInfo;
    captureInfo.streamIds_ = { GetHdiStreamId() };
    captureInfo.captureSetting_ = captureSetting;
    captureInfo.enableShutterCallback_ = false;
    MEDIA_INFO_LOG("HStreamRepeat::Start streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d, "
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
            MEDIA_ERR_LOG("HStreamRepeat::Start Failed with error Code:%{public}d", rc);
            CameraReportUtils::ReportCameraError(
                "HStreamRepeat::Start", rc, true, CameraReportUtils::GetCallerInfo());
            ret = HdiToServiceError(rc);
            UpdateSketchStatus(SketchStatus::STOPED);
        } else {
            repeatStreamStatus_ = RepeatStreamStatus::STARTED;
        }
    }
    CHECK_EXECUTE(settings != nullptr, StartSketchStream(settings));
#ifdef NOTIFICATION_ENABLE
    if (isNeedBeautyNotification) {
        CameraBeautyNotification::GetInstance()->PublishNotification(true);
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
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamRepeat::Stop streamOperator is null");
    auto preparedCaptureId = GetPreparedCaptureId();
    MEDIA_INFO_LOG("HStreamRepeat::Stop streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d, "
                   "repeatStreamType:%{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId, repeatStreamType_);
    CHECK_ERROR_RETURN_RET_LOG(preparedCaptureId == CAPTURE_ID_UNSET, CAMERA_INVALID_STATE,
        "HStreamRepeat::Stop, Stream not started yet");
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
        CHECK_EXECUTE(sketchStreamRepeat_ != nullptr, sketchStreamRepeat_->Stop());
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
        CHECK_EXECUTE(sketchStreamRepeat_ != nullptr, sketchStreamRepeat_->Release());
    }
    return HStreamCommon::ReleaseStream(isDelay);
}

int32_t HStreamRepeat::SetCallback(const sptr<IStreamRepeatCallback>& callback)
{
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamRepeat::SetCallback callback is null");
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
        CHECK_EXECUTE(streamRepeatCallback_ != nullptr, streamRepeatCallback_->OnFrameStarted());
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
        CHECK_EXECUTE(streamRepeatCallback_ != nullptr, streamRepeatCallback_->OnFrameEnded(frameCount));
    }
    // report video end dfx
    CHECK_EXECUTE(repeatStreamType_ == RepeatStreamType::VIDEO, CameraReportUtils::GetInstance().SetVideoEndInfo(1));
    UpdateSketchStatus(SketchStatus::STOPED);
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnDeferredVideoEnhancementInfo(CaptureEndedInfoExt captureEndedInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamRepeat::OnDeferredVideoEnhancementInfo");
    if (repeatStreamType_ == RepeatStreamType::VIDEO) {
        // report video end dfx
        CameraReportUtils::GetInstance().SetVideoEndInfo(1);
        std::lock_guard<std::mutex> lock(callbackLock_);
        CHECK_EXECUTE(streamRepeatCallback_ != nullptr,
            streamRepeatCallback_->OnDeferredVideoEnhancementInfo(captureEndedInfo));
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::OnFrameError(int32_t errorType)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_DEBUG_LOG("HStreamRepeat::OnFrameError %{public}d  %{public}d", errorType, streamRepeatCallback_ == nullptr);
    CHECK_EXECUTE(errorType == HDI::Camera::V1_3::HIGH_TEMPERATURE_ERROR, UpdateSketchStatus(SketchStatus::STOPED));
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
    CHECK_EXECUTE(streamRepeatCallback_ != nullptr, streamRepeatCallback_->OnSketchStatusChanged(status));
    return CAMERA_OK;
}

int32_t HStreamRepeat::AddDeferredSurface(const sptr<OHOS::IBufferProducer>& producer)
{
    MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface called");
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, CAMERA_INVALID_ARG,
            "HStreamRepeat::AddDeferredSurface producer is null");
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
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
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
    CHECK_ERROR_PRINT_LOG(rc != HDI::Camera::V1_0::NO_ERROR,
        "HStreamRepeat::AttachBufferQueue(), Failed to AttachBufferQueue %{public}d", rc);
    MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface end %{public}d", rc);
    std::lock_guard<std::mutex> lock(movingPhotoCallbackLock_);
    if (startMovingPhotoCallback_) {
        startMovingPhotoCallback_();
        startMovingPhotoCallback_ = nullptr;
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::ForkSketchStreamRepeat(
    int32_t width, int32_t height, sptr<IRemoteObject>& sketchStream, float sketchRatio)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    CHECK_ERROR_RETURN_RET_LOG(width <= 0 || height <= 0, CAMERA_INVALID_ARG,
        "HCameraService::ForkSketchStreamRepeat args is illegal");
    CHECK_EXECUTE(sketchStreamRepeat_ != nullptr, sketchStreamRepeat_->Release());

    auto streamRepeat = new (std::nothrow) HStreamRepeat(nullptr, format_, width, height, RepeatStreamType::SKETCH);
    CHECK_ERROR_RETURN_RET_LOG(streamRepeat == nullptr, CAMERA_ALLOC_ERROR,
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
    CHECK_ERROR_RETURN_RET(sketchStreamRepeat_ == nullptr, CAMERA_OK);
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
    CHECK_ERROR_RETURN_RET_LOG(cameraAbility_ == nullptr, CAMERA_OK,
        "HStreamRepeat::SetFrameRate cameraAbility_ is null");
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
        std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = nullptr;
        OHOS::Camera::MetadataUtils::ConvertVecToMetadata(ability, dynamicSetting);
        if (dynamicSetting == nullptr) {
            dynamicSetting = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
        }
        CHECK_ERROR_RETURN_RET_LOG(dynamicSetting == nullptr, CAMERA_INVALID_ARG,
            "HStreamRepeat::SetFrameRate dynamicSetting is nullptr.");
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(dynamicSetting->get(), OHOS_CONTROL_FPS_RANGES, &item);
        bool status = false;
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            MEDIA_DEBUG_LOG("HStreamRepeat::SetFrameRate Failed to find frame range");
            status = dynamicSetting->addEntry(
                OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
        } else if (ret == CAM_META_SUCCESS) {
            MEDIA_DEBUG_LOG("HStreamRepeat::SetFrameRate success to find frame range");
            status = dynamicSetting->updateEntry(
                OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
        }
        CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::SetFrameRate Failed to set frame range");
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
        CHECK_ERROR_PRINT_LOG(rc != HDI::Camera::V1_0::NO_ERROR,
            "HStreamRepeat::SetFrameRate Failed with error Code:%{public}d", rc);
    }
    return rc;
}

int32_t HStreamRepeat::SetMirror(bool isEnable)
{
    enableMirror_ = isEnable;
    return CAMERA_OK;
}
 
bool HStreamRepeat::SetMirrorForLivePhoto(bool isEnable, int32_t mode)
{
    camera_metadata_item_t item;
    const int32_t canMirrorVideoAndPhoto = 2;
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_ERROR_RETURN_RET(cameraAbility_ == nullptr, false);
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

int32_t HStreamRepeat::SetCameraRotation(bool isEnable, int32_t rotation)
{
    enableCameraRotation_ = isEnable;
    CHECK_ERROR_RETURN_RET(rotation > STREAM_ROTATE_360, CAMERA_INVALID_ARG);
    setCameraRotation_ = STREAM_ROTATE_360 - rotation;
    SetStreamTransform();
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetCameraApi(uint32_t apiCompatibleVersion)
{
    apiCompatibleVersion_ = apiCompatibleVersion;
    return CAMERA_OK;
}

int32_t HStreamRepeat::GetMirror(bool& isEnable)
{
    isEnable = enableMirror_;
    return CAMERA_OK;
}

int32_t HStreamRepeat::SetPreviewRotation(std::string &deviceClass)
{
    enableStreamRotate_ = true;
    deviceClass_ = deviceClass;
    return CAMERA_OK;
}

int32_t HStreamRepeat::UpdateSketchRatio(float sketchRatio)
{
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    CHECK_ERROR_RETURN_RET_LOG(sketchStreamRepeat_ == nullptr, CAMERA_INVALID_STATE,
        "HCameraService::UpdateSketchRatio sketch stream not create!");
    sketchStreamRepeat_->sketchRatio_ = sketchRatio;
    return CAMERA_OK;
}

sptr<HStreamRepeat> HStreamRepeat::GetSketchStream()
{
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    return sketchStreamRepeat_;
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
    CHECK_ERROR_RETURN_LOG(producer_ == nullptr, "HStreamRepeat::SyncTransformToSketch producer_ is null");
    GraphicTransformType previewTransform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    int ret = producer_->GetTransform(previewTransform);
    MEDIA_INFO_LOG("HStreamRepeat::SyncTransformToSketch previewTransform is %{public}d", previewTransform);
    CHECK_ERROR_RETURN_LOG(ret != GSERROR_OK, "HStreamRepeat::SyncTransformToSketch GetTransform fail %{public}d", ret);
    auto sketchStream = GetSketchStream();
    CHECK_ERROR_RETURN_LOG(sketchStream == nullptr, "HStreamRepeat::SyncTransformToSketch sketchStream is null");
    std::lock_guard<std::mutex> lock(sketchStream->producerLock_);
    CHECK_ERROR_RETURN_LOG(
        sketchStream->producer_ == nullptr, "HStreamRepeat::SyncTransformToSketch sketchStream->producer_ is null");
    ret = sketchStream->producer_->SetTransform(previewTransform);
    CHECK_ERROR_RETURN_LOG(ret != GSERROR_OK, "HStreamRepeat::SyncTransformToSketch SetTransform fail %{public}d", ret);
}

void HStreamRepeat::SetStreamTransform(int disPlayRotation)
{
    camera_metadata_item_t item;
    int32_t sensorOrientation;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    CHECK_ERROR_RETURN_LOG(display == nullptr,
        "HStreamRepeat::SetStreamTransform GetDefaultDisplay failed");
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        CHECK_ERROR_RETURN(cameraAbility_ == nullptr);
        int ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
        CHECK_ERROR_RETURN_LOG(ret != CAM_META_SUCCESS,
            "HStreamRepeat::SetStreamTransform get sensor orientation failed");
        sensorOrientation = item.data.i32[0];
        MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform sensor orientation %{public}d", sensorOrientation);

        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        CHECK_ERROR_RETURN_LOG(ret != CAM_META_SUCCESS,
            "HStreamRepeat::SetStreamTransform get camera position failed");
        cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform camera position: %{public}d", cameraPosition);
    }
    std::lock_guard<std::mutex> lock(producerLock_);
    CHECK_ERROR_RETURN_LOG(producer_ == nullptr,
        "HStreamRepeat::SetStreamTransform failed, producer is null or GetDefaultDisplay failed");
    if (cameraUsedAsPosition_ != OHOS_CAMERA_POSITION_OTHER) {
        cameraPosition = cameraUsedAsPosition_;
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform used camera position: %{public}d", cameraPosition);
    }
    if (enableCameraRotation_ && sensorOrientation != 0) {
        ProcessCameraSetRotation(sensorOrientation, cameraPosition);
    }
    if (apiCompatibleVersion_ >= CAMERA_API_VERSION_BASE) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    int mOritation = disPlayRotation;
    if (enableStreamRotate_) {
        if (mOritation == -1) {
            CHECK_ERROR_RETURN_LOG(producer_ == nullptr || display == nullptr,
                "HStreamRepeat::SetStreamTransform failed, producer is null or GetDefaultDisplay failed");
            mOritation = static_cast<int>(display->GetRotation());
        }
        int32_t streamRotation = GetStreamRotation(sensorOrientation, cameraPosition, mOritation, deviceClass_);
        ProcessCameraPosition(streamRotation, cameraPosition);
    } else {
        ProcessFixedTransform(sensorOrientation, cameraPosition);
    }
    SyncTransformToSketch();
}

void HStreamRepeat::ProcessFixedTransform(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    if (enableCameraRotation_) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    bool isTableFlag = system::GetBoolParameter("const.multimedia.enable_camera_rotation_compensation", 0);
    bool isNeedChangeRotation = system::GetBoolParameter("const.multimedia.enable_camera_rotation_change", 0);
    if (isTableFlag) {
        ProcessFixedDiffDeviceTransform(cameraPosition);
        return;
    }
    if (isNeedChangeRotation) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
        return;
    }
    if (IsVerticalDevice()) {
        ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    } else {
        ProcessFixedDiffDeviceTransform(cameraPosition);
    }
}

void HStreamRepeat::ProcessFixedDiffDeviceTransform(camera_position_enum_t& cameraPosition)
{
    int ret = SurfaceError::SURFACE_ERROR_OK;
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        ret = producer_->SetTransform(GRAPHIC_FLIP_H);
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform filp for wide side devices");
    } else {
        ret = producer_->SetTransform(GRAPHIC_ROTATE_NONE);
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform none rotate");
    }
    CHECK_ERROR_PRINT_LOG(ret != SurfaceError::SURFACE_ERROR_OK,
        "HStreamRepeat::ProcessFixedTransform failed %{public}d", ret);
}

void HStreamRepeat::ProcessCameraSetRotation(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    sensorOrientation = STREAM_ROTATE_360 - setCameraRotation_;
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        sensorOrientation = (sensorOrientation == STREAM_ROTATE_180) ? STREAM_ROTATE_0 :
            (sensorOrientation == STREAM_ROTATE_0) ? STREAM_ROTATE_180 : sensorOrientation;
    }
    if (sensorOrientation == STREAM_ROTATE_0) {
        int ret = producer_->SetTransform(GRAPHIC_ROTATE_NONE);
        MEDIA_ERR_LOG("HStreamRepeat::ProcessCameraSetRotation %{public}d", ret);
    }
}

void HStreamRepeat::ProcessVerticalCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    int ret = SurfaceError::SURFACE_ERROR_OK;
#ifdef HOOK_CAMERA_OPERATOR
    int32_t cameraPositionTemp = static_cast<int32_t>(cameraPosition);
    if (!CameraRotatePlugin::GetInstance()->HookPreviewTransform(GetBasicInfo(), producer_,
        sensorOrientation, cameraPositionTemp)) {
        MEDIA_ERR_LOG("HStreamRepeat::ProcessVerticalCameraPosition  HookPreviewTransform is failed");
    }
    cameraPosition = static_cast<camera_position_enum_t>(cameraPositionTemp);
#endif
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        ret = HandleCameraTransform(sensorOrientation, true);
    } else {
        ret = HandleCameraTransform(sensorOrientation, false);
    }
    CHECK_ERROR_PRINT_LOG(ret != SurfaceError::SURFACE_ERROR_OK,
        "HStreamRepeat::ProcessVerticalCameraPosition failed %{public}d", ret);
}

int32_t HStreamRepeat::HandleCameraTransform(int32_t& sensorOrientation, bool isFrontCamera)
{
    int32_t streamRotation = isFrontCamera ? sensorOrientation : STREAM_ROTATE_360 - sensorOrientation;
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
            break;
        }
    }
    if (isFrontCamera) {
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform filp rotate %{public}d", streamRotation);
    } else {
        MEDIA_INFO_LOG("HStreamRepeat::ProcessVerticalCameraPosition not flip rotate %{public}d", streamRotation);
    }

    return ret;
}

void HStreamRepeat::ProcessCameraPosition(int32_t& streamRotation, camera_position_enum_t& cameraPosition)
{
    int ret = SurfaceError::SURFACE_ERROR_OK;
#ifdef HOOK_CAMERA_OPERATOR
    int32_t cameraPositionTemp = static_cast<int32_t>(cameraPosition);
    if (!CameraRotatePlugin::GetInstance()->HookPreviewTransform(GetBasicInfo(), producer_,
        streamRotation, cameraPositionTemp)) {
        MEDIA_ERR_LOG("HStreamRepeat::ProcessCameraPosition HookPreviewTransform is failed");
    }
    cameraPosition = static_cast<camera_position_enum_t>(cameraPositionTemp);
#endif
    ApplyTransformBasedOnRotation(streamRotation, producer_, cameraPosition == OHOS_CAMERA_POSITION_FRONT);

    CHECK_ERROR_PRINT_LOG(ret != SurfaceError::SURFACE_ERROR_OK,
        "HStreamRepeat::ProcessCameraPosition failed %{public}d", ret);
}

void HStreamRepeat::ApplyTransformBasedOnRotation(int32_t streamRotation, const sptr<OHOS::IBufferProducer>& producer,
    bool isFrontCamera)
{
    switch (streamRotation) {
        case STREAM_ROTATE_0: {
            producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H : GRAPHIC_ROTATE_NONE);
            break;
        }
        case STREAM_ROTATE_90: {
            producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT90 : GRAPHIC_ROTATE_90);
            break;
        }
        case STREAM_ROTATE_180: {
            producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT180 : GRAPHIC_ROTATE_180);
            break;
        }
        case STREAM_ROTATE_270: {
            producer_->SetTransform(isFrontCamera ? GRAPHIC_FLIP_H_ROT270 : GRAPHIC_ROTATE_270);
            break;
        }
        default: {
            break;
        }
    }
}

int32_t HStreamRepeat::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IStreamRepeatIpcCode>(interfaceCode)) {
        case IStreamRepeatIpcCode::COMMAND_START:
        case IStreamRepeatIpcCode::COMMAND_FORK_SKETCH_STREAM_REPEAT: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_ERROR_RETURN_RET_LOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HStreamRepeat::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                "is %{public}d", callerToken_, callerToken);
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_INFO_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_ERROR_RETURN_RET_LOG(errCode != CAMERA_OK, errCode, "HStreamRepeat::OperatePermissionCheck fail");
    switch (static_cast<IStreamRepeatIpcCode>(code)) {
        case IStreamRepeatIpcCode::COMMAND_ADD_DEFERRED_SURFACE:
        case IStreamRepeatIpcCode::COMMAND_FORK_SKETCH_STREAM_REPEAT:
        case IStreamRepeatIpcCode::COMMAND_UPDATE_SKETCH_RATIO: {
            CHECK_ERROR_RETURN_RET_LOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamRepeat::CheckSystemApp fail");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamRepeat::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_INFO_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

void HStreamRepeat::OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    bool status = false;
    camera_metadata_item_t item;
    uint8_t dfxSwitch = true;
    CHECK_ERROR_RETURN_LOG(settings == nullptr, "HStreamRepeat::OpenVideoDfxSwitch fail, setting is null!");
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &dfxSwitch, 1);
        MEDIA_INFO_LOG("HStreamRepeat::OpenVideoDfxSwitch success!");
    } else {
        status = true;
    }
    CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::OpenVideoDfxSwitch fail!");
}

int32_t HStreamRepeat::EnableSecure(bool isEnabled)
{
    mEnableSecure = isEnabled;
    return CAMERA_OK;
}

void HStreamRepeat::UpdateVideoSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings, uint8_t mirror)
{
    CHECK_ERROR_RETURN_LOG(settings == nullptr, "HStreamRepeat::UpdateVideoSettings settings is nullptr");
    bool status = false;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("HStreamRepeat::UpdateVideoSettings set Mirror %{public}d", mirror);
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = settings->updateEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    }
    CHECK_ERROR_PRINT_LOG(!status, "UpdateVideoSettings Failed to set mirroring in VideoSettings");
}

void HStreamRepeat::UpdateFrameRateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    CHECK_ERROR_RETURN(settings == nullptr);
    bool status = false;
    camera_metadata_item_t item;

    CHECK_ERROR_RETURN(streamFrameRateRange_.size() == 0);
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FPS_RANGES, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        MEDIA_DEBUG_LOG("HStreamRepeat::SetFrameRate Failed to find frame range");
        status =
            settings->addEntry(OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
    } else if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamRepeat::SetFrameRate success to find frame range");
        status =
            settings->updateEntry(OHOS_CONTROL_FPS_RANGES, streamFrameRateRange_.data(), streamFrameRateRange_.size());
    }
    CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::SetFrameRate Failed to set frame range");
}

void HStreamRepeat::UpdateFrameMuteSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                            std::shared_ptr<OHOS::Camera::CameraMetadata> &dynamicSetting)
{
    CHECK_ERROR_RETURN(settings == nullptr);
    bool status = false;
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_MUTE_MODE, &item);
    CHECK_ERROR_RETURN(ret == CAM_META_ITEM_NOT_FOUND);
    auto mode = item.data.u8[0];
    int32_t count = 1;
    CHECK_ERROR_RETURN_LOG(dynamicSetting == nullptr, "dynamicSetting is nullptr");
    ret = OHOS::Camera::FindCameraMetadataItem(dynamicSetting->get(), OHOS_CONTROL_MUTE_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        status = dynamicSetting->updateEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    } else {
        status = dynamicSetting->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::UpdateFrameMuteSettings Failed to set frame mute");
}

#ifdef NOTIFICATION_ENABLE
void HStreamRepeat::UpdateBeautySettings(std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    CHECK_ERROR_RETURN_LOG(settings == nullptr, "HStreamRepeat::UpdateBeautySettings settings is nullptr");
    MEDIA_INFO_LOG("HStreamRepeat::UpdateBeautySettings enter");
    bool status = false;
    camera_metadata_item_t item;
    int32_t count = 1;
    uint8_t beautyType = OHOS_CAMERA_BEAUTY_TYPE_AUTO;
    uint8_t beautyLevel = BEAUTY_LEVEL;

    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_BEAUTY_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &beautyType, count);
    } else if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamRepeat::SetFrameRate success to find frame range");
        status = settings->updateEntry(OHOS_CONTROL_BEAUTY_TYPE, &beautyType, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::SetFrameRate Failed to set beauty type");

    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_BEAUTY_AUTO_VALUE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &beautyLevel, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = settings->updateEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &beautyLevel, count);
    }
    CHECK_ERROR_PRINT_LOG(!status, "HStreamRepeat::SetFrameRate Failed to set beauty level");
}

void HStreamRepeat::CancelNotification()
{
    CameraBeautyNotification::GetInstance()->CancelNotification();
}

bool HStreamRepeat::IsNeedBeautyNotification()
{
    bool ret = false;
    int uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundle(uid);

    if (streamFrameRateRange_.size() == 0) {
        return ret;
    }
    std::string notificationInfo = system::GetParameter("const.camera.notification_info", "");
    if (notificationInfo.empty()) {
        return ret;
    }
    const int32_t CONFIG_SIZE = 3;
    const int32_t INT32_ZERO = 0;
    const int32_t INT32_ONE = 1;
    const int32_t INT32_TWO = 2;
    std::vector<std::string> configInfos = SplitString(notificationInfo, '#');
    for (int i = 0; i < configInfos.size(); ++i) {
        std::vector<std::string> configInfo = SplitString(configInfos[i], '|');
        if (configInfo.size() < CONFIG_SIZE) {
            continue;
        }
        if (!isIntegerRegex(configInfo[INT32_ONE]) || !isIntegerRegex(configInfo[INT32_TWO])) {
            continue;
        }
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
#endif

int32_t HStreamRepeat::AttachMetaSurface(const sptr<OHOS::IBufferProducer>& producer, int32_t videoMetaType)
{
    MEDIA_INFO_LOG("HStreamRepeat::AttachMetaSurface called");
    CHECK_ERROR_RETURN_RET_LOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamRepeat::AttachMetaSurface:SystemApi is called");
    {
        CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, CAMERA_INVALID_ARG,
            "HStreamRepeat::AttachMetaSurface producer is null");
        metaSurfaceBufferQueue_ = new BufferProducerSequenceable(producer);
    }
    return CAMERA_OK;
}

std::vector<int32_t> HStreamRepeat::GetFrameRateRange()
{
    return streamFrameRateRange_;
}

void HStreamRepeat::UpdateHalRoateSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
#ifdef HOOK_CAMERA_OPERATOR
    int32_t rotateAngle = -1;
    if (CameraRotatePlugin::GetInstance()->
        HookPreviewStreamStart(GetBasicInfo(), GetStreamProducer(), rotateAngle) && rotateAngle >= 0) {
        CHECK_ERROR_PRINT_LOG(settings == nullptr, "HStreamRepeat::UpdateHalRoateSettings settings is nullptr");
        bool status = false;
        camera_metadata_item_t item;

        MEDIA_DEBUG_LOG("HStreamRepeat::UpdateHalRoateSettings rotateAngle is %{public}d", rotateAngle);
        int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_ROTATE_ANGLE, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateAngle, 1);
        } else if (ret == CAM_META_SUCCESS) {
            status = settings->updateEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateAngle, 1);
        }
        CHECK_ERROR_PRINT_LOG(!status, "UpdateHalRoateSettings Failed");
        if (rotateAngle & 0x1FFF) {  // Bit0~12 for angle and mirror
            enableCameraRotation_ = true;
        }
    }
#endif
}
} // namespace CameraStandard
} // namespace OHOS
