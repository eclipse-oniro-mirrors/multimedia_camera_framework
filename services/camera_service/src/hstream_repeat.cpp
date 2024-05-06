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

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_service_ipc_interface_code.h"
#include "display_manager.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "istream_repeat_callback.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static const int32_t STREAM_ROTATE_90 = 90;
static const int32_t STREAM_ROTATE_180 = 180;
static const int32_t STREAM_ROTATE_270 = 270;
static const int32_t STREAM_ROTATE_360 = 360;

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
}

int32_t HStreamRepeat::LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG(
        "HStreamRepeat::LinkInput streamId:%{public}d ,repeatStreamType:%{public}d",
        GetFwkStreamId(), repeatStreamType_);
    int32_t ret = HStreamCommon::LinkInput(streamOperator, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HStreamRepeat::LinkInput err, streamId:%{public}d ,err:%{public}d", GetFwkStreamId(), ret);
        return ret;
    }
    if (repeatStreamType_ != RepeatStreamType::VIDEO) {
        SetStreamTransform();
    }
    return CAMERA_OK;
}

void HStreamRepeat::SetStreamInfo(StreamInfo_V1_1& streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    switch (repeatStreamType_) {
        case RepeatStreamType::VIDEO:
            streamInfo.v1_0.intent_ = StreamIntent::VIDEO;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_H264;
            break;
        case RepeatStreamType::PREVIEW:
            streamInfo.v1_0.intent_ = StreamIntent::PREVIEW;
            streamInfo.v1_0.encodeType_ = ENCODE_TYPE_NULL;
            if (mEnableSecure) {
                MEDIA_INFO_LOG("HStreamRepeat::SetStreamInfo Enter");
                HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
                        .type = static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(
                            HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_SECURE),
                        .width = 0,
                        .height = 0,
                        .format = 0,
                        .dataspace = 0,
                        .bufferQueue = nullptr
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
                .width = 0,
                .height = 0,
                .format = 0,
                .dataspace = 0,
                .bufferQueue = nullptr
            };
            streamInfo.extendedStreamInfos = { extendedStreamInfo };
            break;
    }
}

void HStreamRepeat::UpdateSketchStatus(SketchStatus status)
{
    if (repeatStreamType_ != RepeatStreamType::SKETCH) {
        return;
    }
    auto parent = parentStreamRepeat_.promote();
    if (parent == nullptr) {
        return;
    }
    if (sketchStatus_ != status) {
        sketchStatus_ = status;
        parent->OnSketchStatusChanged(sketchStatus_);
    }
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

int32_t HStreamRepeat::Start(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }

    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamRepeat::Start, Already started with captureID: %{public}d", preparedCaptureId);
        return CAMERA_INVALID_STATE;
    }

    // If current is sketch stream, check parent is start or not.
    if (repeatStreamType_ == RepeatStreamType::SKETCH) {
        auto parentRepeat = parentStreamRepeat_.promote();
        if (parentRepeat == nullptr || parentRepeat->GetPreparedCaptureId() == CAPTURE_ID_UNSET) {
            MEDIA_ERR_LOG("HStreamRepeat::Start sketch parent state is illegal");
            return CAMERA_INVALID_STATE;
        }
    }

    int32_t ret = PrepareCaptureId();
    preparedCaptureId = GetPreparedCaptureId();
    if (ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamRepeat::Start Failed to allocate a captureId");
        return ret;
    }
    UpdateSketchStatus(SketchStatus::STARTING);

    std::vector<uint8_t> ability;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(ability, dynamicSetting);
    // open video dfx switch for hal, no need close
    if (repeatStreamType_ == RepeatStreamType::PREVIEW) {
        OpenVideoDfxSwitch(dynamicSetting);
    }
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
    if (settings != nullptr) {
        StartSketchStream(settings);
    }
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
    if (streamOperator == nullptr) {
        MEDIA_INFO_LOG("HStreamRepeat::Stop streamOperator is null");
        return CAMERA_INVALID_STATE;
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    MEDIA_INFO_LOG("HStreamRepeat::Start streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d, "
                   "repeatStreamType:%{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId, repeatStreamType_);
    if (preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamRepeat::Stop, Stream not started yet");
        return CAMERA_INVALID_STATE;
    }
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
    return HStreamCommon::ReleaseStream(isDelay);
}

int32_t HStreamRepeat::SetCallback(sptr<IStreamRepeatCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamRepeat::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamRepeatCallback_ = callback;
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

int32_t HStreamRepeat::OnFrameError(int32_t errorType)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
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
        if (producer == nullptr) {
            MEDIA_ERR_LOG("HStreamRepeat::AddDeferredSurface producer is null");
            return CAMERA_INVALID_ARG;
        }
        producer_ = producer;
    }
    SetStreamTransform();
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        MEDIA_ERR_LOG("HStreamRepeat::CreateAndHandleDeferredStreams(), streamOperator_ == null");
        return CAMERA_INVALID_STATE;
    }
    MEDIA_INFO_LOG("HStreamRepeat::AttachBufferQueue start streamId:%{public}d, hdiStreamId:%{public}d",
        GetFwkStreamId(), GetHdiStreamId());
    sptr<BufferProducerSequenceable> bufferProducerSequenceable;
    CamRetCode rc;
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        bufferProducerSequenceable = new BufferProducerSequenceable(producer_);
    }
    rc = (CamRetCode)(streamOperator->AttachBufferQueue(GetHdiStreamId(), bufferProducerSequenceable));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamRepeat::AttachBufferQueue(), Failed to AttachBufferQueue %{public}d", rc);
    }
    MEDIA_INFO_LOG("HStreamRepeat::AddDeferredSurface end %{public}d", rc);
    return CAMERA_OK;
}

int32_t HStreamRepeat::ForkSketchStreamRepeat(
    int32_t width, int32_t height, sptr<IStreamRepeat>& sketchStream, float sketchRatio)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    if (width <= 0 || height <= 0) {
        MEDIA_ERR_LOG("HCameraService::ForkSketchStreamRepeat args is illegal");
        return CAMERA_INVALID_ARG;
    }

    if (sketchStreamRepeat_ != nullptr) {
        sketchStreamRepeat_->Release();
    }

    auto streamRepeat = new (std::nothrow) HStreamRepeat(nullptr, format_, width, height, RepeatStreamType::SKETCH);
    CHECK_AND_RETURN_RET_LOG(streamRepeat != nullptr, CAMERA_ALLOC_ERROR,
        "HStreamRepeat::ForkSketchStreamRepeat HStreamRepeat allocation failed");
    MEDIA_DEBUG_LOG(
        "HStreamRepeat::ForkSketchStreamRepeat para is:%{public}dx%{public}d,%{public}f", width, height, sketchRatio);
    sketchStream = streamRepeat;
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
    if (sketchStreamRepeat_ == nullptr) {
        return CAMERA_OK;
    }
    sketchStreamRepeat_->Release();
    sketchStreamRepeat_->parentStreamRepeat_ = nullptr;
    sketchStreamRepeat_ = nullptr;

    return CAMERA_OK;
}

int32_t HStreamRepeat::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    std::vector<uint8_t> repeatSettings;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        std::vector<int32_t> streamFrameRateRange = {minFrameRate, maxFrameRate};
        std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = cameraAbility_;
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(dynamicSetting->get(), OHOS_CONTROL_FPS_RANGES, &item);
        bool status = false;
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            MEDIA_DEBUG_LOG("CaptureSession::SetFrameRate Failed to find frame range");
            status = dynamicSetting->addEntry(OHOS_CONTROL_FPS_RANGES, streamFrameRateRange.data(),
                                              streamFrameRateRange.size());
        } else if (ret == CAM_META_SUCCESS) {
            MEDIA_DEBUG_LOG("CaptureSession::SetFrameRate success to find frame range");
            status = dynamicSetting->updateEntry(
                OHOS_CONTROL_FPS_RANGES, streamFrameRateRange.data(), streamFrameRateRange.size());
        }
        if (!status) {
            MEDIA_ERR_LOG("CaptureSession::SetFrameRate Failed to set frame range");
        }
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
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HStreamRepeat::SetFrameRate Failed with error Code:%{public}d", rc);
        }
    }
    return rc;
}

int32_t HStreamRepeat::UpdateSketchRatio(float sketchRatio)
{
    std::lock_guard<std::mutex> lock(sketchStreamLock_);
    if (sketchStreamRepeat_ == nullptr) {
        MEDIA_ERR_LOG("HCameraService::UpdateSketchRatio sketch stream not create!");
        return CAMERA_INVALID_STATE;
    }
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

void HStreamRepeat::DumpStreamInfo(std::string& dumpString)
{
    dumpString += "repeat stream:\n";
    HStreamCommon::DumpStreamInfo(dumpString);
}

void HStreamRepeat::SetStreamTransform()
{
    camera_metadata_item_t item;
    int ret;
    int32_t sensorOrientation;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        if (cameraAbility_ == nullptr) {
            return;
        }
        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("HStreamRepeat::SetStreamTransform get sensor orientation failed");
            return;
        }
        sensorOrientation = item.data.i32[0];
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform sensor orientation %{public}d", sensorOrientation);

        ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("HStreamRepeat::SetStreamTransform get camera position failed");
            return;
        }
        cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform camera position %{public}d", cameraPosition);
    }

    std::lock_guard<std::mutex> lock(producerLock_);
    if (producer_ == nullptr || OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay() == nullptr) {
        MEDIA_ERR_LOG("HStreamRepeat::SetStreamTransform failed, producer is null or GetDefaultDisplay failed");
        return;
    }

    if (IsVerticalDevice()) {
        ProcessCameraPosition(sensorOrientation, cameraPosition);
    } else {
        ret = SurfaceError::SURFACE_ERROR_OK;
        if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
            ret = producer_->SetTransform(GRAPHIC_FLIP_H);
            MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform filp for wide side devices");
        } else {
            ret = producer_->SetTransform(GRAPHIC_ROTATE_NONE);
            MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform none rotate");
        }
    }
}

void HStreamRepeat::ProcessCameraPosition(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition)
{
    int ret = SurfaceError::SURFACE_ERROR_OK;
    int32_t streamRotation = sensorOrientation;
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        switch (streamRotation) {
            case STREAM_ROTATE_90: {
                ret = producer_->SetTransform(GRAPHIC_FLIP_H_ROT90);
                break;
            }
            case STREAM_ROTATE_180: {
                ret = producer_->SetTransform(GRAPHIC_FLIP_H_ROT180);
                break;
            }
            case STREAM_ROTATE_270: {
                ret = producer_->SetTransform(GRAPHIC_FLIP_H_ROT270);
                break;
            }
            default: {
                break;
            }
        }
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform filp rotate %{public}d", streamRotation);
    } else {
        streamRotation = STREAM_ROTATE_360 - sensorOrientation;
        switch (streamRotation) {
            case STREAM_ROTATE_90: {
                ret = producer_->SetTransform(GRAPHIC_ROTATE_90);
                break;
            }
            case STREAM_ROTATE_180: {
                ret = producer_->SetTransform(GRAPHIC_ROTATE_180);
                break;
            }
            case STREAM_ROTATE_270: {
                ret = producer_->SetTransform(GRAPHIC_ROTATE_270);
                break;
            }
            default: {
                break;
            }
        }
        MEDIA_INFO_LOG("HStreamRepeat::SetStreamTransform not flip rotate %{public}d", streamRotation);
    }
    if (ret != SurfaceError::SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("HStreamRepeat::SetStreamTransform failed %{public}d", ret);
    }
}

int32_t HStreamRepeat::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<StreamRepeatInterfaceCode>(interfaceCode)) {
        case CAMERA_START_VIDEO_RECORDING:
        case CAMERA_FORK_SKETCH_STREAM_REPEAT: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HStreamRepeat::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                              "is %{public}d",
                    callerToken_, callerToken);
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

void HStreamRepeat::OpenVideoDfxSwitch(std::shared_ptr<OHOS::Camera::CameraMetadata> settings)
{
    bool status = false;
    camera_metadata_item_t item;
    uint8_t dfxSwitch = true;
    if (settings == nullptr) {
        MEDIA_ERR_LOG("HStreamRepeat::OpenVideoDfxSwitch fail, setting is null!");
        return;
    }
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = settings->addEntry(OHOS_CONTROL_VIDEO_DEBUG_SWITCH, &dfxSwitch, 1);
        MEDIA_INFO_LOG("HStreamRepeat::OpenVideoDfxSwitch success!");
    } else {
        status = true;
    }
    if (!status) {
        MEDIA_ERR_LOG("HStreamRepeat::OpenVideoDfxSwitch fail!");
    }
}

int32_t HStreamRepeat::EnableSecure(bool isEnabled)
{
    mEnableSecure = isEnabled;
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
