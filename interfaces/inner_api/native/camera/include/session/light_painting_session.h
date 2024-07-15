/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_LIGHT_PAINTING_SESSION_H
#define OHOS_CAMERA_LIGHT_PAINTING_SESSION_H
 
#include "capture_session.h"
#include "icapture_session.h"
#include <stdint.h>
#include <vector>
 
namespace OHOS {
namespace CameraStandard {
class LightPaintingSession : public CaptureSession {
public:
    explicit LightPaintingSession(sptr<ICaptureSession> &lightPaintingSession): CaptureSession(lightPaintingSession) {}
    ~LightPaintingSession();
 
    /**
     * @brief Get the supported LightPaintingType.
     *
     * @return Returns the array of LightPaintingType.
     */
    int32_t GetSupportedLightPaintings(std::vector<LightPaintingType>& lightPaintings);
 
    int32_t GetLightPainting(LightPaintingType& lightPaintingType);
 
    int32_t SetLightPainting(const LightPaintingType type);
 
    int32_t TriggerLighting();
 
private:
    LightPaintingType currentLightPaintingType_ = LightPaintingType::CAR;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_LIGHT_PAINTING_SESSION_H