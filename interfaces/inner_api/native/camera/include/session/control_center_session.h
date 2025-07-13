/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CONTROL_CENTER_SESSION_H
#define OHOS_CONTROL_CENTER_SESSION_H

#include "ability/camera_ability_const.h"
#include "refbase.h"
#include "video_session.h"
#include <cstdint>
namespace OHOS {
namespace CameraStandard {

class ControlCenterSession : public RefBase {
public:
    ControlCenterSession();
    ~ControlCenterSession();

    int32_t Release();

    /**
     * @brief Get the supported virtual apertures.
     * @param apertures returns the array of virtual aperture.
     * @return Error code.
     */
    int32_t GetSupportedVirtualApertures(std::vector<float>& apertures);

     /**
     * @brief Get the virtual aperture.
     * @param aperture returns the current virtual aperture.
     * @return Error code.
     */
    int32_t GetVirtualAperture(float& aperture);

    /**
     * @brief Set the virtual aperture.
     * @param virtualAperture set virtual aperture value.
     * @return Error code.
     */
    int32_t SetVirtualAperture(const float virtualAperture);

    /**
     * @brief Get the supported physical apertures.
     * @param apertures returns the array of physical aperture.
     * @return Error code.
     */
    int32_t GetSupportedPhysicalApertures(std::vector<std::vector<float>>& apertures);

    /**
     * @brief Get the physical aperture.
     * @param aperture returns current physical aperture.
     * @return Error code.
     */
    int32_t GetPhysicalAperture(float& aperture);

    /**
     * @brief Set the physical aperture.
     * @param physicalAperture set physical aperture value.
     * @return Error code.
     */
    int32_t SetPhysicalAperture(float physicalAperture);

    /**
     * @brief Get the supported beauty type.
     *
     * @return Returns the array of beautytype.
     */
    std::vector<int32_t> GetSupportedBeautyTypes();

    /**
     * @brief Get the supported beauty range.
     *
     * @return Returns the array of beauty range.
     */
    std::vector<int32_t> GetSupportedBeautyRange(BeautyType type);

    /**
     * @brief Set the beauty.
     */
    void SetBeauty(BeautyType type, int value);

    /**
     * @brief according type to get the strength.
     */
    int32_t GetBeauty(BeautyType type);

    /**
     * @brief Gets supported portrait theme type.
     * @param vector of PortraitThemeType supported portraitTheme type.
     * @return Returns errCode.
     */
    int32_t GetSupportedPortraitThemeTypes(std::vector<PortraitThemeType>& types);

    /**
     * @brief Checks whether portrait theme is supported.
     * @param isSupported True if supported false otherwise.
     * @return Returns errCode.
     */
    int32_t IsPortraitThemeSupported(bool &isSupported);

    /**
     * @brief Checks whether portrait theme is supported.
     *
     * @return True if supported false otherwise.
     */
    bool IsPortraitThemeSupported();

    /**
     * @brief Sets a portrait theme type for a camera device.
     * @param type PortraitTheme type to be sety.
     * @return Returns errCode.
     */
    int32_t SetPortraitThemeType(PortraitThemeType type);
private:
    bool CheckIsSupportControlCenter();
};

} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_CONTROL_CENTER_SESSION_H