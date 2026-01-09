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

#include "watermark_exif_metadata_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
WatermarkExifMetadataProxy::WatermarkExifMetadataProxy(std::shared_ptr<Dynamiclib> lib,
    std::shared_ptr<WatermarkExifMetadataIntf> intf)
    : watermarkExifMetadataProxyLib_ (lib), watermarkExifMetadataIntf_ (intf)
{
    MEDIA_DEBUG_LOG("WatermarkExifMetadataProxy constructor");
    CHECK_RETURN_ELOG(watermarkExifMetadataProxyLib_  == nullptr, "watermarkExifMetadataProxyLib_  is nullptr");
    CHECK_RETURN_ELOG(watermarkExifMetadataIntf_  == nullptr, "watermarkExifMetadataIntf_ is nullptr");
}

WatermarkExifMetadataProxy::~WatermarkExifMetadataProxy()
{
    MEDIA_DEBUG_LOG("WatermarkExifMetadataProxy destructor");
}

typedef WatermarkExifMetadataIntf* (*CreateWatermarkExifMetadataIntf)();
std::shared_ptr<WatermarkExifMetadataProxy> WatermarkExifMetadataProxy::CreateWatermarkExifMetadataProxy()
{
    MEDIA_DEBUG_LOG("CreateWatermarkExifMetadataProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(WATERMARK_EXIF_METADATA_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateWatermarkExifMetadataIntf createWatermarkExifMetadataIntf =
        (CreateWatermarkExifMetadataIntf)dynamiclib->GetFunction("createWatermarkExifMetadataIntf");
    CHECK_RETURN_RET_ELOG(createWatermarkExifMetadataIntf == nullptr, nullptr, "createWatermarkExifMetadataIntf fail");
    WatermarkExifMetadataIntf* watermarkExifMetadataIntf = createWatermarkExifMetadataIntf();
    CHECK_RETURN_RET_ELOG(watermarkExifMetadataIntf == nullptr, nullptr, "get watermarkExifMetadataIntf fail");
    auto watermarkExifMetadataProxy = std::make_shared<WatermarkExifMetadataProxy>(
        dynamiclib, std::shared_ptr<WatermarkExifMetadataIntf>(watermarkExifMetadataIntf));
    return watermarkExifMetadataProxy;
}

void WatermarkExifMetadataProxy::SetWatermarkExifMetadata(
    std::unique_ptr<Media::PixelMap> &pixelMap, const WatermarkInfo &info)
{
    MEDIA_DEBUG_LOG("WatermarkExifMetadataProxy::SetWatermarkExifMetadata");
    CHECK_RETURN_ELOG(watermarkExifMetadataIntf_ == nullptr, "watermarkExifMetadataIntf_ is nullptr");
    watermarkExifMetadataIntf_->SetWatermarkExifMetadata(pixelMap, info);
}

void WatermarkExifMetadataProxy::FreeWatermarkExifMetadataDynamiclib()
{
    auto delayMs = 300;
    CameraDynamicLoader::FreeDynamicLibDelayed(WATERMARK_EXIF_METADATA_SO, delayMs);
}
}  // namespace CameraStandard
}  // namespace OHOS