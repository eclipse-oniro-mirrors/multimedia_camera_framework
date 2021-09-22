/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "camera_util.h"
#include "hstream_capture.h"
#include "media_log.h"

#include <iostream>

namespace OHOS {
namespace CameraStandard {
HStreamCapture::HStreamCapture(sptr<OHOS::IBufferProducer> producer)
{
    producer_ = producer;
    photoStreamId_ = 0;
    photoCaptureId_ = 0;
}

HStreamCapture::~HStreamCapture()
{}

int32_t HStreamCapture::LinkInput(sptr<Camera::IStreamOperator> &streamOperator,
    std::shared_ptr<CameraMetadata> cameraAbility, int32_t streamId)
{
    if (streamOperator == nullptr || cameraAbility == nullptr) {
        MEDIA_ERR_LOG("HStreamCapture::LinkInput streamOperator is null");
        return CAMERA_INVALID_ARG;
    }
    if (!IsValidSize(producer_->GetDefaultWidth(), producer_->GetDefaultHeight(), validSizes_)) {
        return CAMERA_INVALID_OUTPUT_CFG;
    }
    streamOperator_ = streamOperator;
    photoStreamId_ = streamId;
    cameraAbility_ = cameraAbility;
    photoCaptureId_ = PHOTO_CAPTURE_ID_START;
    return CAMERA_OK;
}

void HStreamCapture::SetStreamInfo(std::shared_ptr<Camera::StreamInfo> streamInfoPhoto)
{
    streamInfoPhoto->streamId_ = photoStreamId_;
    streamInfoPhoto->width_ = producer_->GetDefaultWidth();
    streamInfoPhoto->height_ = producer_->GetDefaultHeight();
    streamInfoPhoto->format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfoPhoto->datasapce_ = CAMERA_PHOTO_COLOR_SPACE;
    streamInfoPhoto->intent_ = Camera::STILL_CAPTURE;
    streamInfoPhoto->tunneledMode_ = true;
    streamInfoPhoto->bufferQueue_ = producer_;
    streamInfoPhoto->encodeType_ = Camera::ENCODE_TYPE_JPEG;
}

bool HStreamCapture::IsValidCaptureID()
{
    return (photoCaptureId_ >= PHOTO_CAPTURE_ID_START && photoCaptureId_ <= PHOTO_CAPTURE_ID_END);
}

int32_t HStreamCapture::Capture()
{
    Camera::CamRetCode rc = Camera::NO_ERROR;
    int32_t CurCaptureId = 0;

    if (!IsValidCaptureID()) {
        MEDIA_ERR_LOG("HStreamCapture::Capture crossed the allowed limit, CurCaptureId: %{public}d", photoCaptureId_);
        return CAMERA_CAPTURE_LIMIT_EXCEED;
    }
    CurCaptureId = photoCaptureId_;
    photoCaptureId_++;
    std::shared_ptr<Camera::CaptureInfo> captureInfoPhoto = std::make_shared<Camera::CaptureInfo>();
    captureInfoPhoto->streamIds_ = {photoStreamId_};
    captureInfoPhoto->captureSetting_ = cameraAbility_;
    captureInfoPhoto->enableShutterCallback_ = true;

    MEDIA_INFO_LOG("HStreamCapture::Capture() Starting photo capture with capture ID: %{public}d", CurCaptureId);
    rc = streamOperator_->Capture(CurCaptureId, captureInfoPhoto, false);
    if (rc != Camera::NO_ERROR) {
        MEDIA_ERR_LOG("HStreamCapture::Capture failed with error Code: %{public}d", rc);
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::CancelCapture()
{
    // Cancel cature is dummy till continuous/burst mode is supported
    return CAMERA_OK;
}

int32_t HStreamCapture::Release()
{
    streamCaptureCallback_ = nullptr;
    photoCaptureId_ = 0;
    return CAMERA_OK;
}

int32_t HStreamCapture::SetCallback(sptr<IStreamCaptureCallback> &callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCapture::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    streamCaptureCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureStarted(int32_t captureId)
{
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureStarted(captureId);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureEnded(int32_t captureId)
{
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnCaptureEnded(captureId);
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnCaptureError(int32_t captureId, int32_t errorCode)
{
    if (streamCaptureCallback_ != nullptr) {
        if (errorCode == Camera::BUFFER_LOST) {
            streamCaptureCallback_->OnCaptureError(captureId, CAMERA_STREAM_BUFFER_LOST);
        } else {
            streamCaptureCallback_->OnCaptureError(captureId, CAMERA_UNKNOWN_ERROR);
        }
    }
    return CAMERA_OK;
}

int32_t HStreamCapture::OnFrameShutter(int32_t captureId, uint64_t timestamp)
{
    if (streamCaptureCallback_ != nullptr) {
        streamCaptureCallback_->OnFrameShutter(captureId, timestamp);
    }
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
