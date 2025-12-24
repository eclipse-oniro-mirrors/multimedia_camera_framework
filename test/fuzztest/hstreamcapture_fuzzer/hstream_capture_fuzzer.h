/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HSTREAM_CAPTURE_FUZZER_H
#define HSTREAM_CAPTURE_FUZZER_H

#include "stream_capture_stub.h"
#include "hstream_capture.h"
#include "hcamera_device.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "stream_capture_callback_stub.h"
#include "hstream_capture_photo_callback_stub.h"
#include "stream_capture_photo_asset_callback_stub.h"
#include "hstream_capture_thumbnail_callback_stub.h"
namespace OHOS {
namespace CameraStandard {

class MockStreamCaptureCallback : public StreamCaptureCallbackStub {
public:
    ErrCode OnCaptureStarted(int32_t captureId) override
    {
        return 0;
    }

    ErrCode OnCaptureEnded(int32_t captureId, int32_t frameCount) override
    {
        return 0;
    }

    ErrCode OnCaptureError(int32_t captureId, int32_t errorType) override
    {
        return 0;
    }

    ErrCode OnFrameShutter(int32_t captureId, uint64_t timestamp) override
    {
        return 0;
    }

    ErrCode OnCaptureStarted(int32_t captureId, uint32_t exposureTime) override
    {
        return 0;
    }

    ErrCode OnFrameShutterEnd(int32_t captureId, uint64_t timestamp) override
    {
        return 0;
    }

    ErrCode OnCaptureReady(int32_t captureId, uint64_t timestamp) override
    {
        return 0;
    }

    ErrCode OnOfflineDeliveryFinished(int32_t captureId) override
    {
        return 0;
    }
};

class MockStreamCapturePhotoCallback : public HStreamCapturePhotoCallbackStub {
public:
    int32_t OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw) override
    {
        return 0;
    }
};

class MockStreamCapturePhotoAssetCallback : public StreamCapturePhotoAssetCallbackStub {
public:
    ErrCode OnPhotoAssetAvailable(
        int32_t captureId, const std::string& uri, int32_t cameraShotType, const std::string& burstKey) override
    {
        return 0;
    }
};

class MockStreamCaptureThumbnailCallback : public HStreamCaptureThumbnailCallbackStub {
public:
    int32_t OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) override
    {
        return 0;
    }
};

class IStreamOperatorMock : public IStreamOperator {
public:
    explicit IStreamOperatorMock() = default;
    inline int32_t IsStreamsSupported(OHOS::HDI::Camera::V1_0::OperationMode mode,
        const std::vector<uint8_t>& modeSetting, const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& infos,
        OHOS::HDI::Camera::V1_0::StreamSupportType& type) override
    {
        return 0;
    }
    inline int32_t CreateStreams(const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& streamInfos) override
    {
        return 0;
    }
    inline int32_t ReleaseStreams(const std::vector<int32_t>& streamIds) override
    {
        return 0;
    }
    inline int32_t CommitStreams(
        OHOS::HDI::Camera::V1_0::OperationMode mode, const std::vector<uint8_t>& modeSetting) override
    {
        return 0;
    }
    inline int32_t GetStreamAttributes(std::vector<OHOS::HDI::Camera::V1_0::StreamAttribute>& attributes) override
    {
        return 0;
    }
    inline int32_t AttachBufferQueue(
        int32_t streamId, const sptr<OHOS::HDI::Camera::V1_0::BufferProducerSequenceable>& bufferProducer) override
    {
        return 0;
    }
    inline int32_t DetachBufferQueue(int32_t streamId) override
    {
        return 0;
    }
    inline int32_t Capture(
        int32_t captureId, const OHOS::HDI::Camera::V1_0::CaptureInfo& info, bool isStreaming) override
    {
        return 0;
    }
    inline int32_t CancelCapture(int32_t captureId) override
    {
        return 0;
    }
    inline int32_t ChangeToOfflineStream(const std::vector<int32_t>& streamIds,
        const sptr<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback>& callbackObj,
        sptr<OHOS::HDI::Camera::V1_0::IOfflineStreamOperator>& offlineOperator) override
    {
        return 0;
    }
    inline int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override
    {
        majorVer = 1;
        minorVer = 0;
        return HDF_SUCCESS;
    }
    inline bool IsProxy() override
    {
        return false;
    }
    inline const std::u16string GetDesc() override
    {
        return metaDescriptor_;
    }
};

} // namespace CameraStandard
} // namespace OHOS
#endif // HSTREAM_CAPTURE_FUZZER_H