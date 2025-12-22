/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_PHOTO_BUFFER_CONSUMER_H
#define OHOS_CAMERA_PHOTO_BUFFER_CONSUMER_H

#include "ibuffer_consumer_listener.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
class HStreamCapture;

class PhotoBufferConsumer : public IBufferConsumerListener {
public:
    explicit PhotoBufferConsumer(wptr<HStreamCapture> streamCapture, bool isRaw);
    ~PhotoBufferConsumer() override;
    void OnBufferAvailable() override;

private:
    void ExecuteOnBufferAvailable();
    void StartWaitAuxiliaryTask(
        const int32_t captureId, const int32_t auxiliaryCount, int64_t timestamp, sptr<SurfaceBuffer> &surfaceBuffer);
    void AssembleDeferredPicture(int64_t timestamp, int32_t captureId);
    void CleanAfterTransPicture(int32_t captureId);

    wptr<HStreamCapture> streamCapture_ = nullptr;
    bool isRaw_ = false;
};

}  // namespace CameraStandard
}  // namespace OHOS
#endif
