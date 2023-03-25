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

#include "camera_util.h"
#include "camera_log.h"
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
static const int32_t CAPTURE_ROTATE_360 = 360;
HStreamCapture::HStreamCapture(sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::CAPTURE, producer, format, width, height)
{}

HStreamCapture::~HStreamCapture()
{}

int32_t HStreamCapture::LinkInput(sptr<IStreamOperator> streamOperator,
                                  std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility, int32_t streamId)
{
    return HStreamCommon::LinkInput(streamOperator, cameraAbility, streamId);
}

void HStreamCapture::SetStreamInfo(StreamInfo &streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    streamInfo.intent_ = STILL_CAPTURE;
    streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
}

int32_t HStreamCapture::Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings)
{
    CAMERA_SYNC_TRACE;
    if (streamOperator_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    int32_t ret = AllocateCaptureId(curCaptureID_);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HStreamCapture::Capture Failed to allocate a captureId");
        return ret;
    }
    CaptureInfo captureInfoPhoto;
    captureInfoPhoto.streamIds_ = {streamId_};
    std::vector<uint8_t> setting;
    if (!OHOS::Camera::GetCameraMetadataItemCount(captureSettings->get())) {
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, setting);
        captureInfoPhoto.captureSetting_ = setting;
    } else {
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureSettings, setting);
        captureInfoPhoto.captureSetting_ = setting;
    }
    captureInfoPhoto.enableShutterCallback_ = true;

    // debug log for jpeg quality
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureMetadataSetting_ = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(captureInfoPhoto.captureSetting_, captureMetadataSetting_);
    if (captureMetadataSetting_ != nullptr) {
        // print quality, mirror log
        PrintDebugLog(captureMetadataSetting_);
        // convert rotation with application set rotation
        SetRotation(captureMetadataSetting_);

        // update settings
        std::vector<uint8_t> finalSetting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureMetadataSetting_, finalSetting);
        captureInfoPhoto.captureSetting_ = finalSetting;
    }
    MEDIA_INFO_LOG("HStreamCapture::Capture Starting photo capture with capture ID: %{public}d", curCaptureID_);
    CamRetCode rc = (CamRetCode)(streamOperator_->Capture(curCaptureID_, captureInfoPhoto, false));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamCapture::Capture failed with error Code: %{public}d", rc);
        ret = HdiToServiceError(rc);
    }
    ReleaseCaptureId(curCaptureID_);
    curCaptureID_ = 0;
    return ret;
}

void HStreamCapture::PrintDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_)
{
    camera_metadata_item_t item;
    int result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_QUALITY, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Failed to find OHOS_JPEG_QUALITY tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::find OHOS_JPEG_QUALITY value = %{public}d", item.data.u8[0]);
    }

    // debug log for capture mirror
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(),
                                                   OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Failed to find OHOS_CONTROL_CAPTURE_MIRROR tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::find OHOS_CONTROL_CAPTURE_MIRROR value = %{public}d", item.data.u8[0]);
    }
}

void HStreamCapture::SetRotation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_)
{
    // set orientation for capture
    // sensor orientation, counter-clockwise rotation
    camera_metadata_item_t item;
    int result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("HStreamCapture::Capture set rotation get sensor orientation failed");
    }
    int32_t sensorOrientation = item.data.i32[0];
    MEDIA_INFO_LOG("HStreamCapture::Capture Capture set rotation sensor orientation %{public}d", sensorOrientation);

    result = OHOS::Camera::FindCameraMetadataItem(cameraAbility_->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("HStreamCapture::Capture Capture set rotation get camera position failed");
    }
    camera_position_enum_t cameraPosition = static_cast<camera_position_enum_t>(item.data.u8[0]);
    MEDIA_INFO_LOG("HStreamCapture::Capture Capture set rotation camera position %{public}d", cameraPosition);

    // rotation from application
    int32_t rotationValue = 0;
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result == CAM_META_SUCCESS) {
        rotationValue = item.data.i32[0];
    }
    MEDIA_INFO_LOG("HStreamCapture::Capture set rotation app rotationValue %{public}d", rotationValue);

    // real rotation
    int32_t rotation = sensorOrientation + rotationValue;
    if (rotation >= CAPTURE_ROTATE_360) {
        rotation = rotation - CAPTURE_ROTATE_360;
    }
    MEDIA_INFO_LOG("HStreamCapture::Capture set rotation camera real rotation %{public}d", rotation);

    bool status = false;
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    } else if (result == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    }
    result = OHOS::Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (result != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HStreamCapture::Capture set rotation Failed to find OHOS_JPEG_ORIENTATION tag");
    } else {
        MEDIA_DEBUG_LOG("HStreamCapture::Capture set rotation find OHOS_JPEG_ORIENTATION value = %{public}d",
                        item.data.i32[0]);
    }
    if (!status) {
        MEDIA_ERR_LOG("HStreamCapture::Capture set rotation Failed to set Rotation");
    }
}

int32_t HStreamCapture::CancelCapture()
{
    // Cancel cature is dummy till continuous/burst mode is supported
    return CAMERA_OK;
}

int32_t HStreamCapture::Release()
{
    if (curCaptureID_) {
        ReleaseCaptureId(curCaptureID_);
    }
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamCaptureCallback_ = nullptr;
    return HStreamCommon::Release();
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

int32_t HStreamCapture::OnCaptureEnded(int32_t captureId, int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureEnded(captureId, frameCount);
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

void HStreamCapture::DumpStreamInfo(std::string& dumpString)
{
    dumpString += "capture stream:\n";
    HStreamCommon::DumpStreamInfo(dumpString);
}
} // namespace CameraStandard
} // namespace OHOS
