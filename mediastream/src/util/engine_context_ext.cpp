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

#include "engine_context_ext.h"
#include "camera_log.h"
#include "moving_photo_engine_context.h"

namespace OHOS {
namespace CameraStandard {

void EngineContextExt::SetEngineContext(wptr<MovingPhotoRecorderEngineContext> engineContext)
{
    std::lock_guard<std::mutex> lock(engineContextMutex_);
    engineContext_ = engineContext;
}

sptr<MovingPhotoRecorderEngineContext> EngineContextExt::GetEngineContext()
{
    std::lock_guard<std::mutex> lock(engineContextMutex_);
    return engineContext_.promote();
}
} // namespace CameraStandard
} // namespace OHOS