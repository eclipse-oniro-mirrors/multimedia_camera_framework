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

#include "abilities/sketch_ability.h"
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "image_format.h"
#include "image_source.h"
#include "image_type.h"
#include "istream_repeat_callback.h"
#include "surface_type.h"

namespace OHOS {
namespace CameraStandard {
constexpr uint32_t INVALID_MODE = 0xffffffff;
constexpr float INVALID_MODE_FLOAT = -1.0f;
constexpr float INVALID_ZOOM_RATIO = -1.0f;
constexpr float SKETCH_DIV = 100.0f;
std::mutex SketchWrapper::g_sketchReferenceFovRatioMutex_;
std::map<SceneFeaturesMode, std::vector<SketchReferenceFovRange>> SketchWrapper::g_sketchReferenceFovRatioMap_;
std::mutex SketchWrapper::g_sketchEnableRatioMutex_;
std::map<SceneFeaturesMode, float> SketchWrapper::g_sketchEnableRatioMap_;

SketchWrapper::SketchWrapper(sptr<IStreamCommon> hostStream, const Size size)
    : hostStream_(hostStream), sketchSize_(size)
{}

int32_t SketchWrapper::Init(
    std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata, const SceneFeaturesMode& sceneFeaturesMode)
{
    sptr<IStreamCommon> hostStream = hostStream_.promote();
    if (hostStream == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    UpdateSketchStaticInfo(deviceMetadata);
    sketchEnableRatio_ = GetSketchEnableRatio(sceneFeaturesMode);
        SceneFeaturesMode dumpSceneFeaturesMode = sceneFeaturesMode;
        MEDIA_DEBUG_LOG("SketchWrapper::Init sceneFeaturesMode:%{public}s, sketchEnableRatio_:%{public}f",
            dumpSceneFeaturesMode.Dump().c_str(), sketchEnableRatio_);
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
    // SketchRatio value could be negative value
    MEDIA_DEBUG_LOG("Enter Into SketchWrapper::UpdateSketchRatio");
    if (sketchStream_ == nullptr) {
        return CAMERA_INVALID_STATE;
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

void SketchWrapper::OnSketchStatusChanged(const SceneFeaturesMode& sceneFeaturesMode)
{
    auto callback = previewStateCallback_.lock();
    if (callback == nullptr) {
        return;
    }
    float sketchReferenceRatio = GetSketchReferenceFovRatio(sceneFeaturesMode, currentZoomRatio_);
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

void SketchWrapper::OnSketchStatusChanged(SketchStatus sketchStatus, const SceneFeaturesMode& sceneFeaturesMode)
{
    auto callback = previewStateCallback_.lock();
    if (callback == nullptr) {
        return;
    }
    float sketchReferenceRatio = GetSketchReferenceFovRatio(sceneFeaturesMode, currentZoomRatio_);
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
    {
        std::lock_guard<std::mutex> lock(g_sketchEnableRatioMutex_);
        g_sketchEnableRatioMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_sketchReferenceFovRatioMutex_);
        g_sketchReferenceFovRatioMap_.clear();
    }
    UpdateSketchEnableRatio(deviceMetadata);
    UpdateSketchReferenceFovRatio(deviceMetadata);
    UpdateSketchConfigFromMoonCaptureBoostConfig(deviceMetadata);
}

SceneFeaturesMode SketchWrapper::GetSceneFeaturesModeFromModeData(float modeFloatData)
{
    SceneFeaturesMode currentSceneFeaturesMode {};
    auto sceneMode = static_cast<SceneMode>(round(modeFloatData));
    currentSceneFeaturesMode.SetSceneMode(sceneMode);
    return currentSceneFeaturesMode;
}

void SketchWrapper::UpdateSketchEnableRatio(std::shared_ptr<Camera::CameraMetadata>& deviceMetadata)
{
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
    constexpr int32_t dataGroupSize = 2; // 2 data as a group: key,value
    constexpr int32_t valueOffset = 1;   // 1 is value offset
    uint32_t groupCount = item.count / dataGroupSize;
    float* dataEntry = item.data.f;
    for (uint32_t i = 0; i < groupCount; i++) {
        float key = dataEntry[i * dataGroupSize];
        float value = dataEntry[i * dataGroupSize + valueOffset];
        MEDIA_DEBUG_LOG("SketchWrapper::UpdateSketchEnableRatio get sketch enable ratio "
                        "%{public}f:%{public}f",
            key, value);
        auto sceneFeaturesMode = GetSceneFeaturesModeFromModeData(key);
        InsertSketchEnableRatioMapValue(sceneFeaturesMode, value);
    }
}

void SketchWrapper::InsertSketchReferenceFovRatioMapValue(
    SceneFeaturesMode& sceneFeaturesMode, SketchReferenceFovRange& sketchReferenceFovRange)
{
    std::lock_guard<std::mutex> lock(g_sketchReferenceFovRatioMutex_);
    auto it = g_sketchReferenceFovRatioMap_.find(sceneFeaturesMode);
    std::vector<SketchReferenceFovRange> rangeFov;
    if (it != g_sketchReferenceFovRatioMap_.end()) {
        rangeFov = std::move(it->second);
    }
    rangeFov.emplace_back(sketchReferenceFovRange);
    g_sketchReferenceFovRatioMap_[sceneFeaturesMode] = rangeFov;
    if (sceneFeaturesMode.GetSceneMode() == CAPTURE_MACRO) {
        g_sketchReferenceFovRatioMap_[{ CAPTURE, { FEATURE_MACRO } }] = rangeFov;
        g_sketchReferenceFovRatioMap_[{ CAPTURE_MACRO, { FEATURE_MACRO } }] = rangeFov;
    } else if (sceneFeaturesMode.GetSceneMode() == VIDEO_MACRO) {
        g_sketchReferenceFovRatioMap_[{ VIDEO, { FEATURE_MACRO } }] = rangeFov;
        g_sketchReferenceFovRatioMap_[{ VIDEO_MACRO, { FEATURE_MACRO } }] = rangeFov;
    }
}

void SketchWrapper::InsertSketchEnableRatioMapValue(SceneFeaturesMode& sceneFeaturesMode, float ratioValue)
{
    MEDIA_DEBUG_LOG("SketchWrapper::InsertSketchEnableRatioMapValue %{public}s : %{public}f",
        sceneFeaturesMode.Dump().c_str(), ratioValue);
    std::lock_guard<std::mutex> lock(g_sketchEnableRatioMutex_);
    g_sketchEnableRatioMap_[sceneFeaturesMode] = ratioValue;
    if (sceneFeaturesMode.GetSceneMode() == CAPTURE_MACRO) {
        g_sketchEnableRatioMap_[{ CAPTURE, { FEATURE_MACRO } }] = ratioValue;
        g_sketchEnableRatioMap_[{ CAPTURE_MACRO, { FEATURE_MACRO } }] = ratioValue;
    } else if (sceneFeaturesMode.GetSceneMode() == VIDEO_MACRO) {
        g_sketchEnableRatioMap_[{ VIDEO, { FEATURE_MACRO } }] = ratioValue;
        g_sketchEnableRatioMap_[{ VIDEO_MACRO, { FEATURE_MACRO } }] = ratioValue;
    }
}

void SketchWrapper::UpdateSketchReferenceFovRatio(std::shared_ptr<Camera::CameraMetadata>& deviceMetadata)
{
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
    UpdateSketchReferenceFovRatio(item);
}

void SketchWrapper::UpdateSketchReferenceFovRatio(camera_metadata_item_t& metadataItem)
{
    uint32_t dataCount = metadataItem.count;
    float currentMode = INVALID_MODE_FLOAT;
    float currentMinRatio = INVALID_ZOOM_RATIO;
    float currentMaxRatio = INVALID_ZOOM_RATIO;
    SceneFeaturesMode currentSceneFeaturesMode;
    for (uint32_t i = 0; i < dataCount; i++) {
        if (currentMode == INVALID_MODE_FLOAT) {
            currentMode = metadataItem.data.f[i];
            currentSceneFeaturesMode = GetSceneFeaturesModeFromModeData(metadataItem.data.f[i]);
            continue;
        }
        if (currentMinRatio == INVALID_ZOOM_RATIO) {
            currentMinRatio = metadataItem.data.f[i];
            continue;
        }
        if (currentMaxRatio == INVALID_ZOOM_RATIO) {
            currentMaxRatio = metadataItem.data.f[i];
            continue;
        }
        SketchReferenceFovRange fovRange;
        fovRange.zoomMin = metadataItem.data.f[i];
        fovRange.zoomMax = metadataItem.data.f[i + 1];        // Offset 1 data
        fovRange.referenceValue = metadataItem.data.f[i + 2]; // Offset 2 data
        i = i + 2;                                            // Offset 2 data
        InsertSketchReferenceFovRatioMapValue(currentSceneFeaturesMode, fovRange);
        MEDIA_DEBUG_LOG("SketchWrapper::UpdateSketchReferenceFovRatio get sketch reference fov ratio:mode->%{public}f "
                        "%{public}f-%{public}f value->%{public}f",
            currentMode, fovRange.zoomMin, fovRange.zoomMax, fovRange.referenceValue);
        if (fovRange.zoomMax - currentMaxRatio >= -std::numeric_limits<float>::epsilon()) {
            currentMode = INVALID_MODE_FLOAT;
            currentMinRatio = INVALID_ZOOM_RATIO;
            currentMaxRatio = INVALID_ZOOM_RATIO;
        }
    }
}

bool SketchWrapper::GetMoonCaptureBoostAbilityItem(
    std::shared_ptr<Camera::CameraMetadata>& deviceMetadata, camera_metadata_item_t& metadataItem)
{
    if (deviceMetadata == nullptr) {
        MEDIA_ERR_LOG("SketchWrapper::GetMoonCaptureBoostAbilityItem deviceMetadata is null");
        return false;
    }
    int ret =
        OHOS::Camera::FindCameraMetadataItem(deviceMetadata->get(), OHOS_ABILITY_MOON_CAPTURE_BOOST, &metadataItem);
    if (ret != CAM_META_SUCCESS || metadataItem.count <= 0) {
        MEDIA_ERR_LOG("SketchWrapper::GetMoonCaptureBoostAbilityItem get OHOS_ABILITY_MOON_CAPTURE_BOOST failed");
        return false;
    }
    return true;
}

void SketchWrapper::UpdateSketchConfigFromMoonCaptureBoostConfig(
    std::shared_ptr<Camera::CameraMetadata>& deviceMetadata)
{
    camera_metadata_item_t item;
    if (!GetMoonCaptureBoostAbilityItem(deviceMetadata, item)) {
        MEDIA_ERR_LOG(
            "SketchWrapper::UpdateSketchConfigFromMoonCaptureBoostConfig get GetMoonCaptureBoostAbilityItem failed");
        return;
    }
    uint32_t currentMode = INVALID_MODE;
    float currentMinRatio = INVALID_ZOOM_RATIO;
    float currentMaxRatio = INVALID_ZOOM_RATIO;
    SceneFeaturesMode currentSceneFeaturesMode;
    for (uint32_t i = 0; i < item.count; i++) {
        if (currentMode == INVALID_MODE) {
            currentMode = static_cast<SceneMode>(item.data.ui32[i]);
            currentSceneFeaturesMode =
                SceneFeaturesMode(static_cast<SceneMode>(currentMode), { FEATURE_MOON_CAPTURE_BOOST });
            continue;
        }
        if (currentMinRatio == INVALID_ZOOM_RATIO) {
            currentMinRatio = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
            continue;
        }
        if (currentMaxRatio == INVALID_ZOOM_RATIO) {
            currentMaxRatio = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
            continue;
        }
        SketchReferenceFovRange fovRange;
        fovRange.zoomMin = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
        fovRange.zoomMax = static_cast<float>(item.data.ui32[i + 1]) / SKETCH_DIV;        // Offset 1 data
        fovRange.referenceValue = static_cast<float>(item.data.ui32[i + 2]) / SKETCH_DIV; // Offset 2 data
        i = i + 2;                                                                        // Offset 2 data
        InsertSketchReferenceFovRatioMapValue(currentSceneFeaturesMode, fovRange);
        MEDIA_DEBUG_LOG("SketchWrapper::UpdateSketchConfigFromMoonCaptureBoostConfig get sketch reference fov "
                        "ratio:mode->%{public}d %{public}f-%{public}f value->%{public}f",
            currentMode, fovRange.zoomMin, fovRange.zoomMax, fovRange.referenceValue);
        if (fovRange.zoomMax - currentMaxRatio >= -std::numeric_limits<float>::epsilon()) {
            InsertSketchEnableRatioMapValue(currentSceneFeaturesMode, currentMinRatio);
            currentMode = INVALID_MODE;
            currentMinRatio = INVALID_ZOOM_RATIO;
            currentMaxRatio = INVALID_ZOOM_RATIO;
        }
    }
}

float SketchWrapper::GetSketchReferenceFovRatio(const SceneFeaturesMode& sceneFeaturesMode, float zoomRatio)
{
    float currentZoomRatio = zoomRatio;
    std::lock_guard<std::mutex> lock(g_sketchReferenceFovRatioMutex_);
    auto it = g_sketchReferenceFovRatioMap_.find(sceneFeaturesMode);
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
        auto itRange = std::find_if(it->second.begin(), it->second.end(), [currentZoomRatio](const auto& range) {
            return currentZoomRatio - range.zoomMin >= -std::numeric_limits<float>::epsilon() &&
                   currentZoomRatio - range.zoomMax < -std::numeric_limits<float>::epsilon();
        });
        if (itRange != it->second.end()) {
            return itRange->referenceValue;
        }
    }
    return INVALID_ZOOM_RATIO;
}

float SketchWrapper::GetSketchEnableRatio(const SceneFeaturesMode& sceneFeaturesMode)
{
    std::lock_guard<std::mutex> lock(g_sketchEnableRatioMutex_);
    auto it = g_sketchEnableRatioMap_.find(sceneFeaturesMode);
    if (it != g_sketchEnableRatioMap_.end()) {
        return it->second;
    }
    return INVALID_ZOOM_RATIO;
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

int32_t SketchWrapper::OnMetadataDispatch(const SceneFeaturesMode& sceneFeaturesMode,
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    if (tag == OHOS_CONTROL_ZOOM_RATIO) {
        MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataDispatch get tag:OHOS_CONTROL_ZOOM_RATIO");
        return OnMetadataChangedZoomRatio(sceneFeaturesMode, tag, metadataItem);
    } else if (tag == OHOS_CONTROL_SMOOTH_ZOOM_RATIOS) {
        MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataDispatch get tag:OHOS_CONTROL_SMOOTH_ZOOM_RATIOS");
        return OnMetadataChangedZoomRatio(sceneFeaturesMode, tag, metadataItem);
    } else if (tag == OHOS_CONTROL_CAMERA_MACRO) {
        return OnMetadataChangedMacro(sceneFeaturesMode, tag, metadataItem);
    } else if (tag == OHOS_CONTROL_MOON_CAPTURE_BOOST) {
        return OnMetadataChangedMoonCaptureBoost(sceneFeaturesMode, tag, metadataItem);
    } else {
        MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataDispatch get unhandled tag:%{public}d", static_cast<int32_t>(tag));
    }
    return CAM_META_SUCCESS;
}

int32_t SketchWrapper::OnMetadataChangedZoomRatio(const SceneFeaturesMode& sceneFeaturesMode,
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    float tagRatio = *metadataItem.data.f;
    MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataChangedZoomRatio OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        tagRatio, sketchEnableRatio_);
    UpdateZoomRatio(tagRatio);
    OnSketchStatusChanged(sceneFeaturesMode);
    return CAM_META_SUCCESS;
}

int32_t SketchWrapper::OnMetadataChangedMacro(const SceneFeaturesMode& sceneFeaturesMode,
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    float sketchRatio = GetSketchEnableRatio(sceneFeaturesMode);
    float currentZoomRatio = currentZoomRatio_;
    MEDIA_DEBUG_LOG("SketchWrapper::OnMetadataChangedMacro OHOS_CONTROL_ZOOM_RATIO >>> currentZoomRatio:%{public}f -- "
                    "sketchRatio:%{public}f",
        currentZoomRatio, sketchRatio);
    UpdateSketchRatio(sketchRatio);
    OnSketchStatusChanged(sceneFeaturesMode);
    return CAM_META_SUCCESS;
}

int32_t SketchWrapper::OnMetadataChangedMoonCaptureBoost(const SceneFeaturesMode& sceneFeaturesMode,
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    float sketchRatio = GetSketchEnableRatio(sceneFeaturesMode);
    float currentZoomRatio = currentZoomRatio_;
    MEDIA_DEBUG_LOG(
        "SketchWrapper::OnMetadataChangedMoonCaptureBoost OHOS_CONTROL_ZOOM_RATIO >>> currentZoomRatio:%{public}f -- "
        "sketchRatio:%{public}f",
        currentZoomRatio, sketchRatio);
    UpdateSketchRatio(sketchRatio);
    OnSketchStatusChanged(sceneFeaturesMode);
    return CAM_META_SUCCESS;
}
} // namespace CameraStandard
} // namespace OHOS