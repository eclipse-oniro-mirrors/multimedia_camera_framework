 /*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PHOTO_OUTPUT_FUZZER_H
#define PHOTO_OUTPUT_FUZZER_H

#include "output/photo_output.h"

namespace OHOS {
namespace CameraStandard {
namespace PhotoOutputFuzzer {

class PhotoStateCallbackMock : public PhotoStateCallback {
public:
    void OnCaptureStarted(const int32_t captureID) const override {}
    void OnCaptureStarted(const int32_t captureID, uint32_t exposureTime) const override {}
    void OnCaptureEnded(const int32_t captureID, const int32_t frameCount) const override {}
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override {}
    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override {}
    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override {}
    void OnEstimatedCaptureDuration(const int32_t duration) const override {}
    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override {}
    void OnOfflineDeliveryFinished(const int32_t captureId) const override {}
    void OnConstellationDrawingState(const int32_t drawingState) const override {};
};

class IBufferConsumerListenerMock : public IBufferConsumerListener {
public:
    void OnBufferAvailable() override {}
};

void Test(uint8_t *rawData, size_t size);
void TestOutput1(sptr<PhotoOutput> output, uint8_t *rawData, size_t size);
void TestOutput2(sptr<PhotoOutput> output, uint8_t *rawData, size_t size);
void CaptureSetting(std::shared_ptr<PhotoCaptureSetting> setting, uint8_t *rawData, size_t size);
void CaptureCallback(sptr<HStreamCaptureCallbackImpl> callback, uint8_t *rawData, size_t size);

} //PhotoOutputFuzzer
} //CameraStandard
} //OHOS
#endif //PHOTO_OUTPUT_FUZZER_H
