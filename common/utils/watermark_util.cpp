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

#include "watermark_util.h"

#include <fcntl.h>

#include "camera_log.h"
#include "camera_xml_parser.h"
#include "image_source.h"
#include "nlohmann/json.hpp"
#include "string_ex.h"
#include "surface_buffer.h"

namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr char WATER_MARK_PATH_KEY[] = "RESOURCE_DIRECTORY";
    constexpr char WATER_MARK_DIRECTION[] = "FILTER_WATER_DIRECTION";
    constexpr char WATER_MARK_CAMERA_POSITION[] = "cameraPosition";
    constexpr char WATERMARK_XML_WIDTH_KEY[] = "watermark_width";
    constexpr char WATERMARK_XML_HEIGHT_KEY[] = "watermark_height";
    constexpr char WATERMARK_XML_PARAM_A_KEY[] = "param_A";
    constexpr char WATERMARK_XML_PARAM_B_KEY[] = "param_B";
    constexpr char WATERMARK_XML_PARAM_C_KEY[] = "param_C";
    constexpr char WATERMARK_XML_PARAM_D_KEY[] = "param_D";
    constexpr char WATERMARK_XML_VALUE[] = "value";
    constexpr char WATERMARK_XML_CONFIG[] = "Config";
    constexpr int32_t ROTATION_360 = 360;
    constexpr char IMAGE_PATH[] = "IMAGE_PATH";
    constexpr char ROTATION[] = "ROTATION";
    constexpr char SCALE_FACTOR[] = "SCALE_FACTOR";
    constexpr char COORDINATE_X[] = "COORDINATE_X";
    constexpr char COORDINATE_Y[] = "COORDINATE_Y";
    constexpr char COORDINATE_W[] = "COORDINATE_W";
    constexpr char COORDINATE_H[] = "COORDINATE_H";
}

void ParseWatermarkInfoFromXml(WatermarkXmlInfo& xmlInfo, const std::string& xmlPath)
{
    MEDIA_INFO_LOG("ParseWatermarkInfoFromXml is called");
    auto curNode = CameraXmlNode::Create();
    int32_t ret = curNode->Config(xmlPath.c_str(), nullptr, 0);
    CHECK_RETURN_ELOG(ret != 0 || !curNode->IsElementNode(), "Not found %{public}s!", xmlPath.c_str());
    if (curNode->CompareName(WATERMARK_XML_CONFIG)) {
        std::string pVal;
        for (auto childNode = curNode->GetChildrenNode(); childNode->IsNodeValid(); childNode->MoveToNext()) {
            CHECK_CONTINUE(!childNode->IsElementNode());
            childNode->GetProp(WATERMARK_XML_VALUE, pVal);
            if (childNode->GetName() == WATERMARK_XML_WIDTH_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.width));
            } else if (childNode->GetName() == WATERMARK_XML_HEIGHT_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.height));
            } else if (childNode->GetName() == WATERMARK_XML_PARAM_A_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.paramA));
            } else if (childNode->GetName() == WATERMARK_XML_PARAM_B_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.paramB));
            } else if (childNode->GetName() == WATERMARK_XML_PARAM_C_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.paramC));
            } else if (childNode->GetName() == WATERMARK_XML_PARAM_D_KEY) {
                CHECK_RETURN(!StrToInt(pVal, xmlInfo.paramD));
            }
        }
    }
    MEDIA_INFO_LOG("[WMDB] XmlInfo: width: %{public}d, height: %{public}d, paramA: %{public}d, paramB: %{public}d, "
        "paramC: %{public}d, paramD: %{public}d",
        xmlInfo.width, xmlInfo.height, xmlInfo.paramA, xmlInfo.paramB, xmlInfo.paramC, xmlInfo.paramD);
    curNode->FreeDoc();
    curNode->CleanUpParser();
}

void ParseWatermarkConfigFromJson(WatermarkEncodeConfig& config, const std::string& filterParam)
{
    MEDIA_INFO_LOG("ParseWatermarkConfigFromJson is called");
    CHECK_RETURN_ELOG(filterParam.empty() || !nlohmann::json::accept(filterParam),
        "filterParam is Illegal.");
    nlohmann::json watermarkInfo = nlohmann::json::parse(filterParam);
    CHECK_RETURN_ELOG(watermarkInfo.empty(), "invalid watermark description, input is empty");
    CHECK_RETURN_ELOG(!watermarkInfo.contains(WATER_MARK_PATH_KEY) || !watermarkInfo.contains(WATER_MARK_DIRECTION) ||
                          !watermarkInfo.contains(WATER_MARK_CAMERA_POSITION),
                      "invalid watermark description, missing necessary property");
    CHECK_RETURN_ELOG(!watermarkInfo[WATER_MARK_CAMERA_POSITION].is_number_integer() ||
                          !watermarkInfo[WATER_MARK_DIRECTION].is_number_integer() ||
                          !watermarkInfo[WATER_MARK_PATH_KEY].is_string(),
                      "invalid field type, missing necessary property");
    std::string path = watermarkInfo[WATER_MARK_PATH_KEY];
    config.rotation = watermarkInfo[WATER_MARK_DIRECTION];
    config.cameraPosition = watermarkInfo[WATER_MARK_CAMERA_POSITION];
    config.imagePath = path + "/watermark/dm.png";
    config.xmlPath = path + "/watermark/param.xml";
    // get image width, image height, left margin and right margin from config xml
    ParseWatermarkInfoFromXml(config.xmlInfo, config.xmlPath);
}

void CreatePixelMapFromPath(std::shared_ptr<PixelMap>& pixelMap, const std::string& imagePath)
{
    MEDIA_INFO_LOG("CreatePixelMapFromPath is called");
    char canonicalPath[PATH_MAX] = {0};
    CHECK_RETURN(realpath(imagePath.c_str(), canonicalPath) == nullptr);
    int fd = open(canonicalPath, O_RDONLY);
    CHECK_RETURN_ELOG(fd < 0, "open watermark file error.");

    SourceOptions info { .formatHint = "image/png" };
    uint32_t error;
    auto imageSource = ImageSource::CreateImageSource(fd, info, error);
    CHECK_EXECUTE(fd >= 0, (void)::close(fd));
    CHECK_RETURN_ELOG(!imageSource, "CreateImageSource error: %{public}u.", error);
    DecodeOptions decodeOptions { .allocatorType = AllocatorType::DMA_ALLOC, .editable = true };
    pixelMap = imageSource->CreatePixelMap(decodeOptions, error);
    CHECK_RETURN_ELOG(!pixelMap, "Create pixelMap error: %{public}u.", error);
    error = pixelMap->ConvertAlphaFormat(*pixelMap.get(), false);
    CHECK_RETURN_ELOG(error != 0, "ConvertAlphaFormat error: %{public}u.", error);
}

void ScalePixelMap(std::shared_ptr<PixelMap>& pixelMap, WatermarkEncodeConfig& config, int32_t width, int32_t height)
{
    CHECK_RETURN(pixelMap == nullptr);
    int32_t standBench = std::min(width, height);
    CHECK_RETURN(config.xmlInfo.paramD == 0 || config.xmlInfo.width == 0);
    auto maxWidth = config.xmlInfo.paramC * standBench / config.xmlInfo.paramD;
    auto watermarkWidth = maxWidth > config.xmlInfo.width ? config.xmlInfo.width : maxWidth;
    config.scaleFactor = (float)watermarkWidth / config.xmlInfo.width;
    MEDIA_INFO_LOG("ScalePixelMap scaleFactor: %{public}f", config.scaleFactor);
    pixelMap->scale(config.scaleFactor, config.scaleFactor);
    CHECK_RETURN_ELOG(pixelMap->GetPixelFormat() != PixelFormat::RGBA_8888, "Invalid pixel format");
}

void RotatePixelMap(std::shared_ptr<PixelMap>& pixelMap, WatermarkEncodeConfig& config)
{
    CHECK_RETURN(pixelMap == nullptr);
    pixelMap->rotate(ROTATION_360 - config.rotation);
    config.width = pixelMap->GetWidth();
    config.height = pixelMap->GetHeight();
    MEDIA_INFO_LOG("PixelMap .width: %{public}d, .height: %{public}d", config.width, config.height);
}

std::shared_ptr<Meta> GetAvBufferMeta(WatermarkEncodeConfig& config, int32_t width, int32_t height)
{
    auto rotation = config.rotation;
    int32_t subWidth = width - config.width;
    int32_t subHeight = height - config.height;
    int32_t standBench = std::min(width, height);
    CHECK_RETURN_RET(config.xmlInfo.paramD == 0, nullptr);
    int32_t marginLeft = config.xmlInfo.paramA * standBench / config.xmlInfo.paramD;
    int32_t marginBottom = config.xmlInfo.paramB * standBench / config.xmlInfo.paramD;
    switch (rotation) {
        case Plugins::VideoRotation::VIDEO_ROTATION_0:
            config.x = marginLeft;
            config.y = subHeight - marginBottom;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_90:
            config.x = subWidth - marginBottom;
            config.y = subHeight - marginLeft;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_180:
            config.x = subWidth - marginLeft;
            config.y = marginBottom;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_270:
            config.x = marginBottom;
            config.y = marginLeft;
            break;
        default:
            break;
    }
    CHECK_RETURN_RET_ELOG(config.x < 0 || config.x > subWidth, nullptr, "config.x is invalid");
    CHECK_RETURN_RET_ELOG(config.y < 0 || config.y > subHeight, nullptr, "config.y is invalid");
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->Set<Tag::VIDEO_ENCODER_ENABLE_WATERMARK>(true);
    meta->Set<Tag::VIDEO_COORDINATE_X>(config.x);
    meta->Set<Tag::VIDEO_COORDINATE_Y>(config.y);
    meta->Set<Tag::VIDEO_COORDINATE_W>(config.width);
    meta->Set<Tag::VIDEO_COORDINATE_H>(config.height);
    MEDIA_INFO_LOG("config .x: %{public}d, .y: %{public}d, .width: %{public}d, .height: %{public}d", config.x, config.y,
        config.width, config.height);
    return meta;
}

std::shared_ptr<AVBuffer> CreateWatermarkBuffer(std::shared_ptr<PixelMap>& pixelMap, std::shared_ptr<Meta>& meta)
{
    CHECK_RETURN_RET(pixelMap == nullptr, nullptr);
    sptr<SurfaceBuffer> surfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
    CHECK_RETURN_RET_ELOG(surfaceBuffer == nullptr, nullptr, "SurfaceBuffer is nullptr");
    MEDIA_INFO_LOG(
        "SurfaceBuffer size: %{public}d, stride: %{public}d", surfaceBuffer->GetSize(), surfaceBuffer->GetStride());
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    CHECK_RETURN_RET_ELOG(waterMarkBuffer == nullptr, nullptr, "AVBuffer is nullptr");
    waterMarkBuffer->meta_ = meta;
    return waterMarkBuffer;
}

std::string CoverWatermarkConfigToJson(WatermarkEncodeConfig& config)
{
    nlohmann::json json {
        {IMAGE_PATH, config.imagePath},
        {ROTATION, config.rotation},
        {SCALE_FACTOR, config.scaleFactor},
        {COORDINATE_X, config.x},
        {COORDINATE_Y, config.y},
        {COORDINATE_W, config.width},
        {COORDINATE_H, config.height},
    };
    auto info = json.dump();
    MEDIA_INFO_LOG("Watermark config info: %{public}s", info.c_str());
    return info;
}
} // namespace CameraStandard
} // namespace OHOS
