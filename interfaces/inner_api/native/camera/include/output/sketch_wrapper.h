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

#ifndef OHOS_CAMERA_SKETCH_WRAPPER_H
#define OHOS_CAMERA_SKETCH_WRAPPER_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "abilities/sketch_ability.h"
#include "capture_scene_const.h"
#include "image_receiver.h"
#include "preview_output.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
class SketchWrapper {
public:
    static float GetSketchReferenceFovRatio(const SceneFeaturesMode& sceneFeaturesMode, float zoomRatio);
    static float GetSketchEnableRatio(const SceneFeaturesMode& sceneFeaturesMode);
    static void UpdateSketchStaticInfo(std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata);

    explicit SketchWrapper(sptr<IStreamCommon> hostStream, const Size size);
    virtual ~SketchWrapper();
    int32_t Init(
        std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata, const SceneFeaturesMode& sceneFeaturesMode);
    int32_t AttachSketchSurface(sptr<Surface> sketchSurface);
    int32_t StartSketchStream();
    int32_t StopSketchStream();
    int32_t Destroy();

    void OnSketchStatusChanged(SketchStatus sketchStatus, const SceneFeaturesMode& sceneFeaturesMode);
    void SetPreviewStateCallback(std::shared_ptr<PreviewStateCallback> callback);
    int32_t UpdateSketchRatio(float sketchRatio);
    void UpdateZoomRatio(float zoomRatio);

    int32_t OnMetadataDispatch(const SceneFeaturesMode& sceneFeaturesMode, const camera_device_metadata_tag_t tag,
        const camera_metadata_item_t& metadataItem);

private:
    // Cache device info
    static std::mutex g_sketchReferenceFovRatioMutex_;
    static std::map<SceneFeaturesMode, std::vector<SketchReferenceFovRange>> g_sketchReferenceFovRatioMap_;
    static std::mutex g_sketchEnableRatioMutex_;
    static std::map<SceneFeaturesMode, float> g_sketchEnableRatioMap_;

    wptr<IStreamCommon> hostStream_;
    Size sketchSize_;
    sptr<Surface> sketchSurface_ = nullptr;
    sptr<IStreamRepeat> sketchStream_;
    std::mutex sketchStatusChangeMutex_;

    std::weak_ptr<PreviewStateCallback> previewStateCallback_;

    volatile float sketchEnableRatio_ = -1.0f;
    volatile float currentZoomRatio_ = 1.0f;
    SketchStatusData currentSketchStatusData_ = { .status = SketchStatus::STOPED, .sketchRatio = -1.0f };

    static SceneFeaturesMode GetSceneFeaturesModeFromModeData(float floatModeData);
    static void InsertSketchReferenceFovRatioMapValue(
        SceneFeaturesMode& sceneFeaturesMode, SketchReferenceFovRange& sketchReferenceFovRange);
    static void InsertSketchEnableRatioMapValue(SceneFeaturesMode& sceneFeaturesMode, float ratioValue);
    static void UpdateSketchEnableRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    static void UpdateSketchReferenceFovRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    static void UpdateSketchReferenceFovRatio(camera_metadata_item_t& metadataItem);
    static bool GetMoonCaptureBoostAbilityItem(
        std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata, camera_metadata_item_t& metadataItem);
    static void UpdateSketchConfigFromMoonCaptureBoostConfig(
        std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    void OnSketchStatusChanged(const SceneFeaturesMode& sceneFeaturesMode);
    int32_t OnMetadataChangedZoomRatio(const SceneFeaturesMode& sceneFeaturesMode,
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);
    int32_t OnMetadataChangedMacro(const SceneFeaturesMode& sceneFeaturesMode, const camera_device_metadata_tag_t tag,
        const camera_metadata_item_t& metadataItem);
    int32_t OnMetadataChangedMoonCaptureBoost(const SceneFeaturesMode& sceneFeaturesMode,
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);

    void AutoStream();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SKETCH_WRAPPER_H