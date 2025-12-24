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

#ifndef OHOS_CAMERA_WATERMARK_UTIL_H
#define OHOS_CAMERA_WATERMARK_UTIL_H

#include "avbuffer.h"
#include "meta.h"
#include "pixel_map.h"

namespace OHOS {
namespace CameraStandard {
// water mark
inline constexpr char INPLACE_STICKER_NAME[] = "InplaceSticker";
inline constexpr char WATER_MARK_INFO_KEY[] = "com.openharmony.water_mark_info";
using namespace Media;
struct WatermarkXmlInfo {
    int32_t width {0};
    int32_t height {0};
    int32_t paramA {0};
    int32_t paramB {0};
    int32_t paramC {0};
    int32_t paramD {0};
};

struct WatermarkEncodeConfig {
    std::string imagePath;
    std::string xmlPath;
    int32_t cameraPosition {0};
    int32_t rotation {0};
    int32_t x {0};
    int32_t y {0};
    int32_t width {0};
    int32_t height {0};
    float scaleFactor {0};
    WatermarkXmlInfo xmlInfo {};
};

void ParseWatermarkConfigFromJson(WatermarkEncodeConfig& config, const std::string& filterParam);
void ParseWatermarkInfoFromXml(WatermarkXmlInfo& xmlInfo, const std::string& xmlPath);
void CreatePixelMapFromPath(std::shared_ptr<PixelMap>& pixelMap, const std::string& imagePath);
void ScalePixelMap(std::shared_ptr<PixelMap>& pixelMap, WatermarkEncodeConfig& config,   
    int32_t videoWidth, int32_t videoHeight);
void RotatePixelMap(std::shared_ptr<PixelMap>& pixelMap, WatermarkEncodeConfig& config);
std::shared_ptr<Meta> GetAvBufferMeta(WatermarkEncodeConfig& config, int32_t videoWidth, int32_t videoHeight);
std::shared_ptr<AVBuffer> CreateWatermarkBuffer(std::shared_ptr<PixelMap>& pixelMap, std::shared_ptr<Meta>& meta);
std::string CoverWatermarkConfigToJson(WatermarkEncodeConfig& config);
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_WATERMARK_UTIL_H
