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

#include "image_effect_proxy.h"
#include "camera_log.h"

namespace OHOS::CameraStandard {
ImageEffectProxy::ImageEffectProxy(std::shared_ptr<Dynamiclib> lib,
    std::shared_ptr<ImageEffectIntf> intf) : imageEffectLib_ (lib), imageEffectIntf_ (intf)
{
    MEDIA_DEBUG_LOG("ImageEffectProxy constructor");
    CHECK_RETURN_ELOG(imageEffectLib_  == nullptr, "imageEffectLib_ is nullptr");
    CHECK_RETURN_ELOG(imageEffectIntf_  == nullptr, "imageEffectIntf_ is nullptr");
}

ImageEffectProxy::~ImageEffectProxy()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy destructor");
}

using CreateImageEffectIntf = ImageEffectIntf*(*)();

std::shared_ptr<ImageEffectProxy> ImageEffectProxy::CreateImageEffectProxy()
{
    MEDIA_DEBUG_LOG("CreateImageEffectProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(IMAGE_EFFECT_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateImageEffectIntf createImageEffectIntf =
        (CreateImageEffectIntf)dynamiclib->GetFunction("createImageEffectIntf");
    CHECK_RETURN_RET_ELOG(createImageEffectIntf == nullptr, nullptr, "createImageEffectIntf fail");
    ImageEffectIntf* imageEffectIntf = createImageEffectIntf();
    CHECK_RETURN_RET_ELOG(imageEffectIntf == nullptr, nullptr, "get imageEffectIntf fail");
    auto imageEffectProxy = std::make_shared<ImageEffectProxy>(
        dynamiclib, std::shared_ptr<ImageEffectIntf>(imageEffectIntf));
    return imageEffectProxy;
}

void ImageEffectProxy::FreeImageEffectDynamiclib()
{
    auto delayMs = 300;
    CameraDynamicLoader::FreeDynamicLibDelayed(IMAGE_EFFECT_SO, delayMs);
}

void ImageEffectProxy::GetSupportedFilters(std::vector<std::string>& filterNames)
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::GetSupportedFilters is called");
    CHECK_RETURN_ELOG(imageEffectIntf_ == nullptr, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->GetSupportedFilters(filterNames);
}

int32_t ImageEffectProxy::Init()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::Init is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->Init();
}
int32_t ImageEffectProxy::Start()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::Start is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->Start();
}
int32_t ImageEffectProxy::Stop()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::Stop is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->Stop();
}
int32_t ImageEffectProxy::Reset()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::Reset is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->Reset();
}
sptr<Surface> ImageEffectProxy::GetInputSurface()
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::GetInputSurface is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, nullptr, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->GetInputSurface();
}
int32_t ImageEffectProxy::SetOutputSurface(sptr<Surface> surface)
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::SetOutputSurface is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->SetOutputSurface(surface);
}
int32_t ImageEffectProxy::SetImageEffect(const std::string& filter, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("ImageEffectProxy::SetImageEffect is called");
    CHECK_RETURN_RET_ELOG(imageEffectIntf_ == nullptr, MEDIA_ERR, "imageEffectIntf_ is nullptr");
    return imageEffectIntf_->SetImageEffect(filter, filterParam);
}
}  // namespace OHOS::CameraStandard