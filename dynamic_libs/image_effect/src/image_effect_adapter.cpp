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

#include "image_effect_adapter.h"

#include "any.h"
#include "efilter_factory.h"
#include "image_effect_inner.h"
#include "camera_log.h"
#include "surface_type.h"
#include <cstdint>

// LCOV_EXCL_START
namespace OHOS::CameraStandard {
using namespace OHOS::Media;
namespace {
const static std::string INPLACE_STICKER_NAME = "InplaceSticker";
const static std::string WATER_MARK_PATH_KEY = "RESOURCE_DIRECTORY";
const static std::string WATER_MARK_DIRECTION = "FILTER_WATER_DIRECTION";
const static std::string WATER_MARK_CAMERA_POSITION = "cameraPosition";
const static std::vector<std::string> COLOR_FILTERS = {COLOR_FILTER_CLASSIC, COLOR_FILTER_MOODY, COLOR_FILTER_NATURAL,
                                                       COLOR_FILTER_BLOSSOM, COLOR_FILTER_FAIR, COLOR_FILTER_PINK };
template<typename Iter>
using return_container_iter_string_value =
    typename std::enable_if<std::is_convertible<typename std::iterator_traits<Iter>::value_type,
                                typename std::iterator_traits<Iter>::value_type>::value,
        std::string>::type;

template<typename Iter>
return_container_iter_string_value<Iter> Container2String(Iter first, Iter last)
{
    std::stringstream stringStream;
    stringStream << "[";
    bool isFirstElement = true;
    while (first != last) {
        if (isFirstElement) {
            stringStream << *first;
            isFirstElement = false;
        } else {
            stringStream << "," << *first;
        }
        first++;
    }
    stringStream << "]";
    return stringStream.str();
}
}

ImageEffectAdapter::ImageEffectAdapter()
{
    MEDIA_DEBUG_LOG("ImageEffectAdapter ctor");
}

int32_t ImageEffectAdapter::Init()
{
    MEDIA_INFO_LOG("ImageEffectAdapter::InitEffect is called");
    CHECK_EXECUTE(!imageEffect_,
        imageEffect_ = std::make_unique<OHOS::Media::Effect::ImageEffect>("CameraService"));
    return MEDIA_OK;
}

void ImageEffectAdapter::GetSupportedFilters(std::vector<std::string>& filters)
{
    std::vector<const char *> names;
    Media::Effect::EFilterFactory::Instance()->GetAllEffectNames(names);
    for (auto name : names) {
        filters.emplace_back(name);
    }
    std::string vecStr = Container2String(filters.begin(), filters.end());
    MEDIA_INFO_LOG("ImageEffectAdapter::GetSupportedFilters %{public}s", vecStr.c_str());
}

int32_t ImageEffectAdapter::Start()
{
    MEDIA_INFO_LOG("ImageEffectAdapter::Start");
    // if no effect is set, return OK and do not start image effect adapter
    CHECK_RETURN_RET(!HasFilterSetted(), MEDIA_OK);
    // stop before start to enhance robust
    CHECK_RETURN_RET_ELOG(effectRunning_.load(), MEDIA_ERR, "ImageEffect is running");

    if (imageEffect_) {
        imageEffect_->Start();
    }
    effectRunning_.store(true);
    return MEDIA_OK;
}

int32_t ImageEffectAdapter::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("ImageEffectAdapter::Stop");
    // if no effect is set, return OK and do not stop image effect adapter
    CHECK_RETURN_RET(!HasFilterSetted(), MEDIA_OK);
    CHECK_RETURN_RET_ELOG(!effectRunning_.load(), MEDIA_ERR, "Stop failed, ImageEffect is not running");

    if (imageEffect_) {
        imageEffect_->Stop();
    }
    effectRunning_.store(false);
    return MEDIA_OK;
}

int32_t ImageEffectAdapter::Reset()
{
    MEDIA_INFO_LOG("ImageEffectAdapter::Reset");
    return MEDIA_OK;
}

sptr<Surface> ImageEffectAdapter::GetInputSurface()
{
    CHECK_RETURN_RET_ELOG(imageEffect_ == nullptr, nullptr, "codecServer_ is nullptr");
    sptr<Surface> surface = imageEffect_->GetInputSurface();
    return surface;
}

int32_t ImageEffectAdapter::SetOutputSurface(sptr<Surface> surface)
{
    MEDIA_INFO_LOG("SetOutputSurface");
    CHECK_RETURN_RET_ELOG(imageEffect_ == nullptr, MEDIA_ERR, "imageEffect_ is null");
    imageEffect_->SetOutputSurface(surface);
    return MEDIA_OK;
}

bool ImageEffectAdapter::HasFilterSetted()
{
    return waterMarkEFilter_ != nullptr || colorEFilter_ != nullptr;
}

int32_t ImageEffectAdapter::SetImageEffect(const std::string& filter, const std::string& filterParam)
{
    MEDIA_INFO_LOG("ImageEffectAdapter::SetImageEffect filter:%{public}s filterParam:%{public}s",
        filter.c_str(), filterParam.c_str());
    CHECK_RETURN_RET_ILOG(
        colorEffect_ == filter, MEDIA_OK, "ImageEffectAdapter::SetVideoFilter not need add same filter color");
    bool isNeedRestart = effectRunning_.load();
    if (isNeedRestart) {
        Stop();
    }
    {
        std::lock_guard<std::mutex> lock(filterLock_);
        if (filter == INPLACE_STICKER_NAME) {
            if (filterParam.empty()) {
                RemoveWaterMark();
            } else {
                AddWaterMark(filter, filterParam);
            }
        } else if (filter == COLOR_FILTER_ORIGIN) {
            RemoveColorFilter();
        } else if (IsColorFilter(filter)) {
            AddColorFilter(filter);
        } else {
            MEDIA_ERR_LOG("ImageEffectAdapter::SetVideoFilter NOT SUPPORT");
        }
    }
    if (isNeedRestart) {
        Start();
    }
    return MEDIA_OK;
}

void ImageEffectAdapter::RemoveColorFilter()
{
    if (imageEffect_ && colorEFilter_) {
        imageEffect_->RemoveEFilter(colorEFilter_);
        colorEFilter_ = nullptr;
        MEDIA_INFO_LOG("ImageEffectWrapper::RemoveColorFilter remove colorFilter");
    }
}

void ImageEffectAdapter::RemoveWaterMark()
{
    if (imageEffect_ && waterMarkEFilter_) {
        imageEffect_->RemoveEFilter(waterMarkEFilter_);
        waterMarkEFilter_ = nullptr;
        MEDIA_INFO_LOG("ImageEffectAdapter::RemoveWaterMark remove waterMark");
    }
}

bool ImageEffectAdapter::IsColorFilter(std::string filter)
{
    auto it = std::find(COLOR_FILTERS.begin(), COLOR_FILTERS.end(), filter);
    return it != COLOR_FILTERS.end();
}

void ImageEffectAdapter::AddWaterMark(const std::string& filter, const std::string& filterParam)
{
    if (imageEffect_ && waterMarkEFilter_) {
        imageEffect_->RemoveEFilter(waterMarkEFilter_);
        waterMarkEFilter_ = nullptr;
        MEDIA_INFO_LOG("ImageEffectAdapter::AddWaterMark remove old waterMark");
    }

    CHECK_RETURN_ELOG(imageEffect_ == nullptr, "ImageEffectAdapter::AddWaterMark failed imageEffect is null");
    const Media::Effect::EffectJsonPtr root = Media::Effect::EffectJsonHelper::ParseJsonData(filterParam);
    int32_t orientation = root->GetInt(WATER_MARK_DIRECTION);
    int32_t cameraPosition = root->GetInt(WATER_MARK_CAMERA_POSITION);
    std::string waterMarkDirString = root->GetString(WATER_MARK_PATH_KEY);
    MEDIA_INFO_LOG("ImageEffectAdapter::AddWaterMark orientation:%{public}d cameraPosition:%{public}d "
        "waterMarkDir:%{public}s", orientation, cameraPosition, waterMarkDirString.c_str());
    waterMarkEFilter_ = Media::Effect::EFilterFactory::Instance()->Create(INPLACE_STICKER_NAME);
    CHECK_RETURN_ELOG(waterMarkEFilter_ == nullptr, "ImageEffectAdapter::AddWaterMark create filter failed");
    OHOS::Media::Effect::ErrorCode result = waterMarkEFilter_->Restore(root);
    CHECK_PRINT_ELOG(
        result != OHOS::Media::Effect::ErrorCode::SUCCESS, "ImageEffectAdapter::AddWaterMark Restore failed");
    imageEffect_->AddEFilter(waterMarkEFilter_);
}

void ImageEffectAdapter::AddColorFilter(const std::string& filter)
{
    if (imageEffect_ && colorEFilter_) {
        imageEffect_->RemoveEFilter(colorEFilter_);
        colorEFilter_ = nullptr;
        colorEffect_ = COLOR_FILTER_ORIGIN;
        MEDIA_INFO_LOG("ImageEffectAdapter::AddColorFilter remove old colorFilter");
    }

    CHECK_RETURN_ELOG(imageEffect_ == nullptr, "ImageEffectAdapter::AddColorFilter failed imageEffect is null");
    MEDIA_INFO_LOG("ImageEffectAdapter::SetVideoFilter Create filter:%{public}s", filter.c_str());
    colorEFilter_ = Media::Effect::EFilterFactory::Instance()->Create(filter);
    colorEffect_ = filter;
    CHECK_RETURN_ELOG(colorEFilter_ == nullptr, "ImageEffectAdapter::AddColorFilter create filter failed");
    imageEffect_->AddEFilter(colorEFilter_);
}

extern "C" ImageEffectIntf *createImageEffectIntf()
{
    return new ImageEffectAdapter();
}
}
// LCOV_EXCL_STOP