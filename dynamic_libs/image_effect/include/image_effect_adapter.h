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

#ifndef OHOS_CAMERA_IMAGE_EFFECT_ADAPTER_H
#define OHOS_CAMERA_IMAGE_EFFECT_ADAPTER_H

#include <string>
#include "image_effect_interface.h"

namespace OHOS::Media {
    namespace Effect {
        class ImageEffect;
        class EFilter;
    }
}

namespace OHOS::CameraStandard {
class ImageEffectAdapter : public ImageEffectIntf {
public:
    ImageEffectAdapter();
    virtual ~ImageEffectAdapter() = default;

    void GetSupportedFilters(std::vector<std::string>& filterNames) override;
    int32_t Init() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Reset() override;
    sptr<Surface> GetInputSurface() override;
    int32_t SetOutputSurface(sptr<Surface> surface) override;
    int32_t SetImageEffect(const std::string& filter, const std::string& filterParam) override;
private:
    bool HasFilterSetted();
    bool IsColorFilter(std::string filter);
    void AddColorFilter(const std::string& filter);
    void AddWaterMark(const std::string& filter, const std::string& filterParam);
    void RemoveColorFilter();
    void RemoveWaterMark();

    std::unique_ptr<Media::Effect::ImageEffect> imageEffect_ {nullptr};
    sptr<Surface> effectSurface_ {nullptr};
    std::atomic_bool effectRunning_ {false};
    std::shared_ptr<Media::Effect::EFilter> colorEFilter_ {nullptr};
    std::shared_ptr<Media::Effect::EFilter> waterMarkEFilter_ {nullptr};

    std::string colorEffect_ { COLOR_FILTER_ORIGIN };
    std::mutex filterLock_;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_IMAGE_EFFECT_ADAPTER_H