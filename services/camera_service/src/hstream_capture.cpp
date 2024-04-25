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

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static const int32_t CAPTURE_ROTATE_360 = 360;
HStreamCapture::HStreamCapture(sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::CAPTURE, producer, format, width, height)
{
    MEDIA_INFO_LOG(
        "HStreamCapture::HStreamCapture construct, format:%{public}d size:%{public}dx%{public}d streamId:%{public}d",
        format, width, height, GetFwkStreamId());
    thumbnailSwitch_ = 0;
    modeName_ = 0;
    deferredPhotoSwitch_ = 0;
    deferredVideoSwitch_ = 0;
}

HStreamCapture::~HStreamCapture()
{
    MEDIA_INFO_LOG(
        "HStreamCapture::~HStreamCapture deconstruct, format:%{public}d size:%{public}dx%{public}d streamId:%{public}d",
        format_, width_, height_, GetFwkStreamId());
}

int32_t HStreamCapture::LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG("HStreamCapture::LinkInput streamId:%{public}d", GetFwkStreamId());
    return HStreamCommon::LinkInput(streamOperator, cameraAbility);
}

void HStreamCapture::SetStreamInfo(StreamInfo_V1_1 &streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    streamInfo.v1_0.intent_ = STILL_CAPTURE;
    streamInfo.v1_0.encodeType_ = ENCODE_TYPE_JPEG;
    HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;
    // quickThumbnial do not need these param
    extendedStreamInfo.width = 0;
    extendedStreamInfo.height = 0;
    extendedStreamInfo.format = 0;
    extendedStreamInfo.dataspace = 0;
    if (format_ == OHOS_CAMERA_FORMAT_DNG) {
        MEDIA_INFO_LOG("HStreamCapture::SetStreamInfo Set DNG info, streamId:%{public}d", GetFwkStreamId());
        extendedStreamInfo.type =
            static_cast<HDI::Camera::V1_1::ExtendedStreamInfoType>(HDI::Camera::V1_3::EXTENDED_STREAM_INFO_RAW);
        extendedStreamInfo.bufferQueue = rawBufferQueue_;
        extendedStreamInfo.width = width_;
        extendedStreamInfo.height = height_;
        extendedStreamInfo.format = format_;
    } else {
        extendedStreamInfo.type = HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
        extendedStreamInfo.bufferQueue = thumbnailBufferQueue_;
    }
    streamInfo.extendedStreamInfos = {extendedStreamInfo};
}

int32_t HStreamCapture::SetThumbnail(bool isEnabled, const sptr<OHOS::IBufferProducer> &producer)
{
    if (isEnabled && producer != nullptr) {
        thumbnailSwitch_ = 1;
        thumbnailBufferQueue_ = new BufferProducerSequenceable(producer);
    } else {
        thumbnailSwitch_ = 0;
        thumbnailBufferQueue_ = nullptr;
    }
    return CAMERA_OK;
}


int32_t HStreamCapture::SetRawPhotoStreamInfo(const sptr<OHOS::IBufferProducer> &producer)
{
    if (producer != nullptr) {
        rawBufferQueue_ = new BufferProducerSequenceable(producer);
    } else {
        rawBufferQueue_ = nullptr;
    }
    MEDIA_DEBUG_LOG("HStreamCapture::SetRawPhotoStreamInfo rawBufferQueue whether is nullptr: %{public}d",
        rawBufferQueue_ == nullptr);
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

int32_t HStreamCapture::Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapture::Capture Entry, streamId:%{public}d", GetFwkStreamId());
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }

    if (isCaptureReady_ == false) {
        MEDIA_ERR_LOG("HStreamCapture::Capture failed due to capture not ready");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }

    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamCapture::Capture, Already started with captureID: %{public}d", preparedCaptureId);
        return CAMERA_INVALID_STATE;
    }

    int32_t ret = PrepareCaptureId();
    preparedCaptureId = GetPreparedCaptureId();
    if (ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamCapture::Capture Failed to allocate a captureId");
        return ret;
    }
    CaptureInfo captureInfoPhoto;
    captureInfoPhoto.streamIds_ = { GetHdiStreamId() };
    ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings);
    
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    const std::string permissionName = "ohos.permission.CAMERA";
    AddCameraPermissionUsedRecord(callingTokenId, permissionName);

    // report capture performance dfx
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureMetadataSetting_ = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(captureInfoPhoto.captureSetting_, captureMetadataSetting_);
    DfxCaptureInfo captureInfo;
    captureInfo.captureId = preparedCaptureId;
    captureInfo.caller = CameraReportUtils::GetCallerInfo();
    CameraReportUtils::GetInstance().SetCapturePerfStartInfo(captureInfo);
    MEDIA_INFO_LOG("HStreamCapture::Capture Starting photo capture with capture ID: %{public}d", preparedCaptureId);
    HStreamCommon::PrintCaptureDebugLog(captureMetadataSetting_);
    CamRetCode rc = (CamRetCode)(streamOperator->Capture(preparedCaptureId, captureInfoPhoto, false));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        ResetCaptureId();
        MEDIA_ERR_LOG("HStreamCapture::Capture failed with error Code: %{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HStreamCapture::Capture", rc, true, CameraReportUtils::GetCallerInfo());
        ret = HdiToServiceError(rc);
    }
    camera_metadata_item_t item;
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        if (cameraAbility_ == nullptr) {
            MEDIA_ERR_LOG("HStreamCapture::cameraAbility_ is null");
            return CAMERA_INVALID_STATE;
        }
        int32_t result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION,
                                                              &item);
        if (result == CAM_META_SUCCESS && item.count > 0) {
            cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        }
    }

    int32_t NightMode = 4;
    if (GetMode() == NightMode && cameraPosition == OHOS_CAMERA_POSITION_BACK) {
        return ret;
    }
    ResetCaptureId();

    uint32_t major;
    uint32_t minor;
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    // intercept when streamOperatorCallback support onCaptureReady
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_2) {
        MEDIA_INFO_LOG("HStreamCapture::Capture set capture not ready");
        isCaptureReady_ = false;
    }
    return ret;
}

void HStreamCapture::ProcessCaptureInfoPhoto(CaptureInfo& captureInfoPhoto,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings)
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
        SetRotation(captureMetadataSetting_);

        // update settings
        std::vector<uint8_t> finalSetting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureMetadataSetting_, finalSetting);
        captureInfoPhoto.captureSetting_ = finalSetting;
    }
}

void HStreamCapture::SetRotation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_)
{
    // set orientation for capture
    // sensor orientation, counter-clockwise rotation
    int32_t sensorOrientation = 0;
    int result;
    camera_metadata_item_t item;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        if (cameraAbility_ == nullptr) {
            return;
        }
        result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
        if (result == CAM_META_SUCCESS && item.count > 0) {
            sensorOrientation = item.data.i32[0];
        }
        MEDIA_INFO_LOG("set rotation sensor orientation %{public}d", sensorOrientation);

        camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_BACK;
        result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
        if (result == CAM_META_SUCCESS && item.count > 0) {
            cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
        }
        MEDIA_INFO_LOG("set rotation camera position %{public}d", cameraPosition);
    }

    // rotation from application
    int32_t rotationValue = 0;
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result == CAM_META_SUCCESS && item.count > 0) {
        rotationValue = item.data.i32[0];
    }
    MEDIA_INFO_LOG("set rotation app rotationValue %{public}d", rotationValue);

    // real rotation
    int32_t rotation = sensorOrientation + rotationValue;
    if (rotation >= CAPTURE_ROTATE_360) {
        rotation = rotation - CAPTURE_ROTATE_360;
    }
    uint8_t connectType = 0;
    int ret = OHOS::Camera::FindCameraMetadataItem(
        cameraAbility_->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        connectType = item.data.u8[0];
    }
    if (connectType == OHOS_CAMERA_CONNECTION_TYPE_REMOTE) {
        rotation = rotationValue;
    }
    MEDIA_INFO_LOG("set rotation camera real rotation %{public}d", rotation);

    bool status = false;
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    } else if (result == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    }
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("set rotation Failed to find OHOS_JPEG_ORIENTATION tag");
    }
    if (!status) {
        MEDIA_ERR_LOG("set rotation Failed to set Rotation");
    }
}

int32_t HStreamCapture::CancelCapture()
{
    CAMERA_SYNC_TRACE;
    // Cancel capture is dummy till continuous/burst mode is supported
    StopStream();
    return CAMERA_OK;
}

void HStreamCapture::SetMode(int32_t modeName)
{
    modeName_ = modeName;
    MEDIA_INFO_LOG("HStreamCapture SetMode modeName = %{public}d", modeName);
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
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    MEDIA_INFO_LOG("HStreamCapture::ConfirmCapture with capture ID: %{public}d", preparedCaptureId);
    sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperatorV1_2 =
        OHOS::HDI::Camera::V1_2::IStreamOperator::CastFrom(streamOperator);
    if (streamOperatorV1_2 == nullptr) {
        MEDIA_ERR_LOG("HStreamCapture::ConfirmCapture streamOperatorV1_2 castFrom failed!");
        return CAMERA_UNKNOWN_ERROR;
    }
    OHOS::HDI::Camera::V1_2::CamRetCode rc =
        (OHOS::HDI::Camera::V1_2::CamRetCode)(streamOperatorV1_2->ConfirmCapture(preparedCaptureId));
    int32_t ret = 0;
    if (rc != HDI::Camera::V1_2::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamCapture::ConfirmCapture failed with error Code: %{public}d", rc);
        ret = HdiToServiceErrorV1_2(rc);
    }
    ResetCaptureId();
    return ret;
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
    return HStreamCommon::ReleaseStream(isDelay);
}

int32_t HStreamCapture::SetCallback(sptr<IStreamCaptureCallback> &callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCapture::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamCaptureCallback_ = callback;
    return CAMERA_OK;
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
    CameraReportUtils::GetInstance().SetCapturePerfEndInfo(captureId);
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_INFO_LOG("HStreamCapture::OnCaptureEnded capturId = %{public}d already used, need release",
                       preparedCaptureId);
        ResetCaptureId();
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureError(int32_t captureId, int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        int32_t captureErrorCode;
        if (errorCode == BUFFER_LOST) {
            captureErrorCode = CAMERA_STREAM_BUFFER_LOST;
        } else {
            captureErrorCode = CAMERA_UNKNOWN_ERROR;
        }
        CAMERA_SYSEVENT_FAULT(CreateMsg("Photo OnCaptureError! captureId:%d & "
                                        "errorCode:%{public}d", captureId, captureErrorCode));
        streamCaptureCallback_->OnCaptureError(captureId, captureErrorCode);
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_INFO_LOG("HStreamCapture::OnCaptureError capturId = %{public}d already used, need release",
                       preparedCaptureId);
        ResetCaptureId();
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
    return CAMERA_OK;
}


int32_t HStreamCapture::OnCaptureReady(int32_t captureId, uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    MEDIA_INFO_LOG("HStreamCapture::Capture, notify OnCaptureReady with capture ID: %{public}d", captureId);
    isCaptureReady_ = true;
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureReady(captureId, timestamp);
    }
    return CAMERA_OK;
}

void HStreamCapture::DumpStreamInfo(std::string& dumpString)
{
    dumpString += "capture stream:\n";
    dumpString += "ThumbnailSwitch:[" + std::to_string(thumbnailSwitch_);
    if (thumbnailBufferQueue_) {
        dumpString += "] ThumbnailBuffer producer Id:["
            + std::to_string(thumbnailBufferQueue_->producer_->GetUniqueId());
    }
    dumpString += "]\n";
    HStreamCommon::DumpStreamInfo(dumpString);
}

int32_t HStreamCapture::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<StreamCaptureInterfaceCode>(interfaceCode)) {
        case CAMERA_STREAM_CAPTURE_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HStreamCapture::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
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

int32_t HStreamCapture::IsDeferredPhotoEnabled()
{
    MEDIA_INFO_LOG("HStreamCapture IsDeferredPhotoEnabled  deferredPhotoSwitch_: %{public}d", deferredPhotoSwitch_);
    if (deferredPhotoSwitch_ == 1) {
        return 1;
    }
    MEDIA_INFO_LOG("HStreamCapture IsDeferredPhotoEnabled return 0");
    return 0;
}

int32_t HStreamCapture::IsDeferredVideoEnabled()
{
    MEDIA_INFO_LOG("HStreamCapture IsDeferredVideoEnabled  deferredVideoSwitch_: %{public}d", deferredVideoSwitch_);
    if (deferredVideoSwitch_ == 1) {
        return 1;
    }
    return 0;
}
} // namespace CameraStandard
} // namespace OHOS
