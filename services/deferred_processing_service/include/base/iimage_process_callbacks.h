/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_I_IMAGE_PROCESS_CALLBACKS_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_I_IMAGE_PROCESS_CALLBACKS_H

#include <cstdint>
#include <string>
#include "buffer_info.h"
#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class IImageProcessCallbacks {
public:
    virtual ~IImageProcessCallbacks() = default;
    virtual void OnProcessDone(int userId, const std::string& imageId, std::shared_ptr<BufferInfo> bufferInfo) = 0;
    virtual void OnError(int userId, const std::string& imageId, DpsError errorCode) = 0;
    virtual void OnStateChanged(int userId, DpsStatus statusCode) = 0;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_I_IMAGE_PROCESS_CALLBACKS_H
