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

#ifndef OHOS_CAMERA_PORTRAIT_SESSION_H
#define OHOS_CAMERA_PORTRAIT_SESSION_H

#include <iostream>
#include <set>
#include <vector>
#include "camera_error_code.h"
#include "input/capture_input.h"
#include "output/capture_output.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
enum FilterType {
    NONE = 0,
    CLASSIC = 1,
    DAWN = 2,
    PURE = 3,
    GREY = 4,
    NATURAL = 5,
    MORI = 6,
    FAIR = 7,
    PINK = 8,
};

enum PortraitEffect {
    OFF_EFFECT = 0,
    CIRCLES = 1,
};

enum BeautyType {
    AUTO_TYPE = 0,
    SKIN_SMOOTH = 1,
    FACE_SLENDER = 2,
    SKIN_TONE = 3,
};


class CaptureOutput;
class PortraitSession : public CaptureSession {
public:
    explicit PortraitSession(sptr<ICaptureSession> &PortraitSession);
    PortraitSession() {};
    ~PortraitSession();

    /**
     * @brief Get the supported filters.
     *
     * @return Returns the array of filter.
     */
    std::vector<FilterType> getSupportedFilters();

    /**
     * @brief Get the current filter.
     *
     * @return Returns the array of filter.
     */
    FilterType getFilter();

    /**
     * @brief Set the filter.
     */
    void setFilter(FilterType filter);

    /**
     * @brief Get the supported portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    std::vector<PortraitEffect> getSupportedPortraitEffects();

    /**
     * @brief Get the portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    PortraitEffect getPortraitEffect();

    /**
     * @brief Set the portrait effects.
     */
    void setPortraitEffect(PortraitEffect effect);

    /**
     * @brief Get the supported beauty type.
     *
     * @return Returns the array of beautytype.
     */
    std::vector<BeautyType> getSupportedBeautyTypes();
    
    /**
     * @brief Get the supported beauty range.
     *
     * @return Returns the array of beauty range.
     */
    std::vector<int32_t> getSupportedBeautyRange(BeautyType type);
    
    /**
     * @brief Set the beauty.
     */
    void setBeauty(BeautyType type, int value);
    /**
     * @brief according type to get the strength.
     */
    int32_t getBeauty(BeautyType type);
    
private:
    sptr<ICaptureSession> portraitSession_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PORTRAIT_SESSION_H
