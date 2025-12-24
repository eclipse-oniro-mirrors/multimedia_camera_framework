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

#ifndef OHOS_CAMERA_MEDIA_STREAM_ENGINE_CONTEXT_EXT_H
#define OHOS_CAMERA_MEDIA_STREAM_ENGINE_CONTEXT_EXT_H

#include "refbase.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
class MovingPhotoRecorderEngineContext;
class EngineContextExt {
public:
    void SetEngineContext(wptr<MovingPhotoRecorderEngineContext> engineContext);
    sptr<MovingPhotoRecorderEngineContext> GetEngineContext();
private:
    std::mutex engineContextMutex_{};
    wptr<MovingPhotoRecorderEngineContext> engineContext_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MEDIA_STREAM_ENGINE_CONTEXT_EXT_H
