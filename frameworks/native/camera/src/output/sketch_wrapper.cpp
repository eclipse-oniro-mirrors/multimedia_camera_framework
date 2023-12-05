/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "sketch_wrapper.h"

#include <cstdint>
#include <mutex>

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_util.h"
#include "image_format.h"
#include "image_source.h"
#include "image_type.h"
#include "istream_repeat_callback.h"
#include "surface_type.h"

namespace OHOS {
namespace CameraStandard {
std::mutex SketchWrapper::g_sketchReferenceFovRatioMutex_;
std::map<int32_t, std::vector<SketchWrapper::SketchReferenceFovRange>> SketchWrapper::g_sketchReferenceFovRatioMap_;
std::mutex SketchWrapper::g_sketchEnableRatioMutex_;
std::map<int32_t, float> SketchWrapper::g_sketchEnableRatioMap_;

SketchWrapper::SketchWrapper(sptr<IStreamCommon> hostStream, const Size size)
    : hostStream_(hostStream), sketchSize_(size)
{}

int32_t SketchWrapper::Init(std::shared_ptr<Camera::CameraMetadata>& deviceMetadata, int32_t modeName)
{
    sptr<IStreamCommon> hostStream = hostStream_.promote();
    if (hostStream == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    UpdateSketchStaticInfo(deviceMetadata);
    sketchEnableRatio_ = GetSketchEnableRatio(modeName);
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(hostStream.GetRefPtr());
    return repeatStream->ForkSketchStreamRepeat(
        sketchSize_.width, sketchSize_.height, sketchStream_, sketchEnableRatio_);
}

int32_t SketchWrapper::AttachSketchSurface(sptr<Surface> sketchSurface)
{
    if (sketchStream_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    if (sketchSurface == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    return sketchStream_->AddDeferredSurface(sketchSurface->GetProducer());
}

int32_t SketchWrapper::UpdateSketchRatio(float sketchRatio)
{
    MEDIA_DEBUG_LOG("Enter Into SketchWrapper::UpdateSketchRatio");
    if (sketchStream_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    if (sketchRatio <= 0) {
        MEDIA_WARNING_LOG("SketchWrapper::UpdateSketchRatio arg is illegal:%{public}f", sketchRatio);
        return CAMERA_INVALID_ARG;
    }
    sptr<IStreamCommon> hostStream = hostStream_.promote();
    if (hostStream == nullptr) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchRatio hostStream is null");
        return CAMERA_INVALID_STATE;
    }
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(hostStream.GetRefPtr());
    int32_t ret = repeatStream->UpdateSketchRatio(sketchRatio);
    if (ret == CAMERA_OK) {
        sketchEnableRatio_ = sketchRatio;
    }
    AutoStream();
    return ret;
}

int32_t SketchWrapper::Destroy()
{
    if (sketchStream_ != nullptr) {
        sketchStream_->Stop();
        sketchStream_->Release();
        sketchStream_ = nullptr;
    }
    sptr<IStreamCommon> hostStream = hostStream_.promote();
    if (hostStream == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(hostStream.GetRefPtr());
    return repeatStream->RemoveSketchStreamRepeat();
}

SketchWrapper::~SketchWrapper()
{
    Destroy();
}

int32_t SketchWrapper::StartSketchStream()
{
    if (sketchStream_ != nullptr) {
        MEDIA_DEBUG_LOG("Enter Into SketchWrapper::SketchWrapper::StartSketchStream");
        int retCode = sketchStream_->Start();
        return retCode;
    }
    return CAMERA_UNKNOWN_ERROR;
}

int32_t SketchWrapper::StopSketchStream()
{
    if (sketchStream_ != nullptr) {
        MEDIA_DEBUG_LOG("Enter Into SketchWrapper::SketchWrapper::StopSketchStream");
        int retCode = sketchStream_->Stop();
        return retCode;
    }
    return CAMERA_UNKNOWN_ERROR;
}

void SketchWrapper::SetPreviewStateCallback(std::shared_ptr<PreviewStateCallback> callback)
{
    previewStateCallback_ = callback;
}

void SketchWrapper::OnSketchStatusChanged(int32_t modeName)
{
    auto callback = previewStateCallback_.lock();
    if (callback == nullptr) {
        return;
    }
    float sketchReferenceRatio = GetSketchReferenceFovRatio(modeName, currentZoomRatio_);
    std::lock_guard<std::mutex> lock(sketchStatusChangeMutex_);
    if (currentSketchStatusData_.sketchRatio != sketchReferenceRatio) {
        SketchStatusData statusData;
        statusData.status = currentSketchStatusData_.status;
        statusData.sketchRatio = sketchReferenceRatio;
        MEDIA_DEBUG_LOG("SketchWrapper::OnSketchStatusDataChanged-:%{public}d->%{public}d,%{public}f->%{public}f",
            currentSketchStatusData_.status, statusData.status, currentSketchStatusData_.sketchRatio,
            statusData.sketchRatio);
        currentSketchStatusData_ = statusData;
        callback->OnSketchStatusDataChanged(currentSketchStatusData_);
    }
}

void SketchWrapper::OnSketchStatusChanged(SketchStatus sketchStatus, int32_t modeName)
{
    auto callback = previewStateCallback_.lock();
    if (callback == nullptr) {
        return;
    }
    float sketchReferenceRatio = GetSketchReferenceFovRatio(modeName, currentZoomRatio_);
    std::lock_guard<std::mutex> lock(sketchStatusChangeMutex_);
    if (currentSketchStatusData_.status != sketchStatus ||
        currentSketchStatusData_.sketchRatio != sketchReferenceRatio) {
        SketchStatusData statusData;
        statusData.status = sketchStatus;
        statusData.sketchRatio = sketchReferenceRatio;
        MEDIA_DEBUG_LOG("SketchWrapper::OnSketchStatusDataChanged:%{public}d->%{public}d,%{public}f->%{public}f",
            currentSketchStatusData_.status, statusData.status, currentSketchStatusData_.sketchRatio,
            statusData.sketchRatio);
        currentSketchStatusData_ = statusData;
        callback->OnSketchStatusDataChanged(currentSketchStatusData_);
    }
}

void SketchWrapper::UpdateSketchStaticInfo(std::shared_ptr<Camera::CameraMetadata> deviceMetadata)
{
    UpdateSketchEnableRatio(deviceMetadata);
    UpdateSketchReferenceFovRatio(deviceMetadata);
}

void SketchWrapper::UpdateSketchEnableRatio(std::shared_ptr<Camera::CameraMetadata>& deviceMetadata)
{
    std::lock_guard<std::mutex> lock(g_sketchEnableRatioMutex_);
    g_sketchEnableRatioMap_.clear();
    if (deviceMetadata == nullptr) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchEnableRatio deviceMetadata is null");
        return;
    }
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_ABILITY_SKETCH_ENABLE_RATIO, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchEnableRatio get sketch enable ratio failed");
        return;
    }
    if (item.count <= 0) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchEnableRatio sketch enable ratio count <= 0");
        return;
    }
    uint32_t groupCount = item.count / 2; // 2 data as a group: key,value
    float* dataEntry = item.data.f;
    for (uint32_t i = 0; i < groupCount; i++) {
        float key = dataEntry[i * 2];       // 2 data as a group: key,value
        float value = dataEntry[i * 2 + 1]; // 2 data as a group: key,value
        MEDIA_DEBUG_LOG("SketchWrapper::UpdateSketchEnableRatio get sketch enable ratio "
                        "%{public}f:%{public}f",
            key, value);
        g_sketchEnableRatioMap_[(int32_t)key] = value;
    }
}

void SketchWrapper::UpdateSketchReferenceFovRatio(std::shared_ptr<Camera::CameraMetadata>& deviceMetadata)
{
    std::lock_guard<std::mutex> lock(g_sketchReferenceFovRatioMutex_);
    g_sketchReferenceFovRatioMap_.clear();
    if (deviceMetadata == nullptr) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchReferenceFovRatio deviceMetadata is null");
        return;
    }
    camera_metadata_item_t item;
    int ret =
        OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_ERR_LOG("SketchWrapper::UpdateSketchReferenceFovRatio get sketch reference fov ratio failed");
        return;
    }
    UpdateSketchReferenceFovRatio(item, g_sketchReferenceFovRatioMap_);
}

void SketchWrapper::UpdateSketchReferenceFovRatio(camera_metadata_item_t& metadataItem,
    std::map<int32_t, std::vector<SketchWrapper::SketchReferenceFovRange>>& referenceMap)
{
    int32_t dataCount = metadataItem.count;
    float currentMode = -1.0f;
    float currentMinRatio = -1.0f;
    float currentMaxRatio = -1.0f;
    for (int32_t i = 0; i < dataCount; i++) {
        if (currentMode < 0) {
            currentMode = metadataItem.data.f[i];
            continue;
        }
        if (currentMinRatio < 0) {
            currentMinRatio = metadataItem.data.f[i];
            continue;
        }
        if (currentMaxRatio < 0) {
            currentMaxRatio = metadataItem.data.f[i];
            continue;
        }
        SketchReferenceFovRange fovRange;
        fovRange.zoomMin = metadataItem.data.f[i];
        fovRange.zoomMax = metadataItem.data.f[i + 1];        // Offset 1 data
        fovRange.referenceValue = metadataItem.data.f[i + 2]; // Offset 2 data
        i = i + 2;                                            // Offset 2 data
        auto it = referenceMap.find((int32_t)currentMode);
        std::vector<SketchReferenceFovRange> rangeFov;
        if (it != referenceMap.end()) {
            rangeFov = std::move(it->second);
        }
        rangeFov.emplace_back(fovRange);
        referenceMap[(int32_t)currentMode] = rangeFov;
        MEDIA_DEBUG_LOG("SketchWrapper::UpdateSketchReferenceFovRatio get sketch reference fov ratio:mode->%{public}f "
                        "%{public}f-%{public}f value->%{public}f",
            currentMode, fovRange.zoomMin, fovRange.zoomMax, fovRange.referenceValue);
        if (fovRange.zoomMax - currentMaxRatio >= -std::numeric_limits<float>::epsilon()) {
            currentMode = -1.0f;
            currentMinRatio = -1.0f;
            currentMaxRatio = -1.0f;
        }
    }
}

float SketchWrapper::GetSketchReferenceFovRatio(int32_t modeName, float zoomRatio)
{
    float currentZoomRatio = zoomRatio;
    std::lock_guard<std::mutex> lock(g_sketchReferenceFovRatioMutex_);
    auto it = g_sketchReferenceFovRatioMap_.find(modeName);
    if (it != g_sketchReferenceFovRatioMap_.end()) {
        if (it->second.size() == 1) { // only 1 element, just return result;
            return it->second[0].referenceValue;
        }
        // If zoom ratio out of range, try return min or max range value.
        const auto& minRange = it->second.front();
        if (currentZoomRatio - minRange.zoomMin <= std::numeric_limits<float>::epsilon()) {
            return minRange.referenceValue;
        }
        const auto& maxRange = it->second.back();
        if (currentZoomRatio - maxRange.zoomMax >= -std::numeric_limits<float>::epsilon()) {
            return maxRange.referenceValue;
        }

        std::vector<SketchReferenceFovRange>::iterator itRange = std::find_if(it->second.begin(),it->second.end()
            [&currentZoomRatio,std::numeric_limits<float>::epsilon()](const auto& range){
            return currentZoomRatio - range.zoomMin >= -std::numeric_limits<float>::epsilon() &&
            currentZoomRatio - range.zoomMax < -std::numeric_limits<float>::epsilon()
        });
        if(itRange != it->second.end()) {
            return itRange->referenceValue;
        }
    }
    return -1.0f;
}

float SketchWrapper::GetSketchEnableRatio(int32_t modeName)
{
    std::lock_guard<std::mutex> lock(g_sketchEnableRatioMutex_);
    auto it = g_sketchEnableRatioMap_.find(modeName);
    if (it != g_sketchEnableRatioMap_.end()) {
        return it->second;
    }
    return -1.0f;
}

void SketchWrapper::UpdateZoomRatio(float zoomRatio)
{
    currentZoomRatio_ = zoomRatio;
    AutoStream();
}

void SketchWrapper::AutoStream()
{
    if (currentZoomRatio_ > 0 && sketchEnableRatio_ > 0 &&
        currentZoomRatio_ - sketchEnableRatio_ >= -std::numeric_limits<float>::epsilon()) {
        StartSketchStream();
    } else {
        StopSketchStream();
    }
}

int32_t SketchWrapper::OnControlMetadataDispatch(
    int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    if (tag == OHOS_CONTROL_ZOOM_RATIO) {
        return OnMetadataChangedZoomRatio(modeName, tag, metadataItem);
    } else if (tag == OHOS_CONTROL_CAMERA_MACRO) {
        return OnMetadataChangedMacro(modeName, tag, metadataItem);
    } else {
        MEDIA_DEBUG_LOG(
            "SketchWrapper::OnControlMetadataDispatch get unhandled tag:%{public}d", static_cast<int32_t>(tag));
    }
    return CAM_META_SUCCESS;
}

int32_t SketchWrapper::OnMetadataChangedZoomRatio(
    int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    float tagRatio = *metadataItem.data.f;
    MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataChangedZoomRatio OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        tagRatio, sketchEnableRatio_);
    UpdateZoomRatio(tagRatio);
    OnSketchStatusChanged(modeName);
    return CAM_META_SUCCESS;
}

int32_t SketchWrapper::OnMetadataChangedMacro(
    int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    float sketchRatio = GetSketchEnableRatio(modeName);
    float currentZoomRatio = currentZoomRatio_;
    MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataChangedMacro OHOS_CONTROL_ZOOM_RATIO >>> currentZoomRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        currentZoomRatio, sketchRatio);
    UpdateSketchRatio(sketchRatio);
    OnSketchStatusChanged(modeName);
    return CAM_META_SUCCESS;
}
} // namespace CameraStandard
} // namespace OHOS