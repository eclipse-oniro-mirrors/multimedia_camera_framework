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

#ifndef OHOS_CAMERA_H_STREAM_CAPTURE_H
#define OHOS_CAMERA_H_STREAM_CAPTURE_H

#include <atomic>
#include <cstdint>
#include <iostream>
#include <refbase.h>

#include "camera_metadata_info.h"
#include "hstream_capture_stub.h"
#include "hstream_common.h"
#include "v1_0/istream_operator.h"
#include "v1_2/istream_operator.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::BufferProducerSequenceable;
using namespace OHOS::HDI::Camera::V1_0;
class HStreamCapture : public HStreamCaptureStub, public HStreamCommon {
public:
    HStreamCapture(sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height);
    ~HStreamCapture();

    int32_t LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1 &streamInfo) override;
    int32_t SetThumbnail(bool isEnabled, const sptr<OHOS::IBufferProducer> &producer) override;
    int32_t SetRawPhotoStreamInfo(const sptr<OHOS::IBufferProducer> &producer) override;
    int32_t DeferImageDeliveryFor(int32_t type) override;
    int32_t Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings) override;
    int32_t CancelCapture() override;
    int32_t ConfirmCapture() override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t SetCallback(sptr<IStreamCaptureCallback> &callback) override;
    int32_t OnCaptureStarted(int32_t captureId);
    int32_t OnCaptureStarted(int32_t captureId, uint32_t exposureTime);
    int32_t OnCaptureEnded(int32_t captureId, int32_t frameCount);
    int32_t OnCaptureError(int32_t captureId, int32_t errorType);
    int32_t OnFrameShutter(int32_t captureId, uint64_t timestamp);
    int32_t OnFrameShutterEnd(int32_t captureId, uint64_t timestamp);
    int32_t OnCaptureReady(int32_t captureId, uint64_t timestamp);
    void DumpStreamInfo(std::string& dumpString) override;
    void SetRotation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_);
    void SetMode(int32_t modeName);
    int32_t GetMode();
    int32_t IsDeferredPhotoEnabled() override;
    int32_t IsDeferredVideoEnabled() override;

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;

private:
    void ProcessCaptureInfoPhoto(CaptureInfo& captureInfoPhoto,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& captureSettings);

    sptr<IStreamCaptureCallback> streamCaptureCallback_;
    std::mutex callbackLock_;
    int32_t thumbnailSwitch_;
    sptr<BufferProducerSequenceable> thumbnailBufferQueue_;
    sptr<BufferProducerSequenceable> rawBufferQueue_;
    int32_t modeName_;
    int32_t deferredPhotoSwitch_;
    int32_t deferredVideoSwitch_;
    std::atomic<bool> isCaptureReady_ = true;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_CAPTURE_H
