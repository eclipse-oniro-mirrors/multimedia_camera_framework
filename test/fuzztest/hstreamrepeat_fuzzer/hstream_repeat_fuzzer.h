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

#ifndef HSTREAM_REPEAT_FUZZER_H
#define HSTREAM_REPEAT_FUZZER_H

#include "hstream_capture_stub.h"
#include "hstream_repeat.h"
#include "hcamera_device.h"
#include "hstream_repeat_callback_stub.h"

namespace OHOS {
namespace CameraStandard {
class HStreamRepeatCallbackStubDemo : public HStreamRepeatCallbackStub {
public:
    int32_t OnFrameStarted() override
    {
        return 0;
    }
    int32_t OnFrameEnded(int32_t frameCount) override
    {
        return 0;
    }
    int32_t OnFrameError(int32_t errorCode) override
    {
        return 0;
    }
    int32_t OnSketchStatusChanged(SketchStatus status) override
    {
        return 0;
    }
    int32_t OnDeferredVideoEnhancementInfo(CaptureEndedInfoExt captureEndedInfo) override
    {
        return 0;
    }
};

class IStreamOperatorMock : public IStreamOperator {
public:
    explicit IStreamOperatorMock() = default;
    inline int32_t IsStreamsSupported(OHOS::HDI::Camera::V1_0::OperationMode mode,
        const std::vector<uint8_t>& modeSetting,
        const std::vector<OHOS::HDI::Camera::V1_0::StreamInfo>& infos,
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
    inline int32_t CommitStreams(OHOS::HDI::Camera::V1_0::OperationMode mode,
        const std::vector<uint8_t>& modeSetting) override
    {
        return 0;
    }
    inline int32_t GetStreamAttributes(std::vector<OHOS::HDI::Camera::V1_0::StreamAttribute>& attributes) override
    {
        return 0;
    }
    inline int32_t AttachBufferQueue(int32_t streamId,
        const sptr<OHOS::HDI::Camera::V1_0::BufferProducerSequenceable>& bufferProducer) override
    {
        return 0;
    }
    inline int32_t DetachBufferQueue(int32_t streamId) override
    {
        return 0;
    }
    inline int32_t Capture(int32_t captureId, const OHOS::HDI::Camera::V1_0::CaptureInfo& info,
        bool isStreaming) override
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

class HStreamRepeatFuzzer {
public:
static bool hasPermission;
static HStreamRepeat *fuzz_;
static void HStreamRepeatFuzzTest1();
static void HStreamRepeatFuzzTest2();
static void HStreamRepeatFuzzTest3();
};
} //CameraStandard
} //OHOS
#endif //HSTREAM_REPEAT_FUZZER_H