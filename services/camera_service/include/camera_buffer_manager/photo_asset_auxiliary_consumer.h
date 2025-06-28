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

#ifndef OHOS_CAMERA_AUXILIARY_BUFFER_CONSUMER_H
#define OHOS_CAMERA_AUXILIARY_BUFFER_CONSUMER_H

#include "ibuffer_consumer_listener.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
class HStreamCapture;
namespace DeferredProcessing {
class TaskManager;
}
static const std::string S_GAINMAP = "gainmap";
static const std::string S_DEEP = "deep";
static const std::string S_EXIF = "exif";
static const std::string S_DEBUG = "debug";

class AuxiliaryBufferConsumer : public IBufferConsumerListener {
public:
    AuxiliaryBufferConsumer(const std::string surfaceName, wptr<HStreamCapture> streamCapture);
    ~AuxiliaryBufferConsumer() override;

    void OnBufferAvailable() override;
private:
    void ExecuteOnBufferAvailable();

    std::string surfaceName_;
    wptr<HStreamCapture> streamCapture_ = nullptr;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif