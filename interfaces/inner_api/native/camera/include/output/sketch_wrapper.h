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

#include "image_receiver.h"
#include "preview_output.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
class SketchWrapper {
public:
    static float GetSketchReferenceFovRatio(int32_t modeName, float zoomRatio);
    static float GetSketchEnableRatio(int32_t modeName);
    static void UpdateSketchStaticInfo(std::shared_ptr<OHOS::Camera::CameraMetadata> deviceMetadata);

    explicit SketchWrapper(sptr<IStreamCommon> hostStream, const Size size);
    virtual ~SketchWrapper();
    int32_t Init(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata, int32_t modeName);
    int32_t AttachSketchSurface(sptr<Surface> sketchSurface);
    int32_t StartSketchStream();
    int32_t StopSketchStream();
    int32_t Destroy();

    void OnSketchStatusChanged(SketchStatus sketchStatus, int32_t modeName);
    void SetPreviewStateCallback(std::shared_ptr<PreviewStateCallback> callback);
    int32_t UpdateSketchRatio(float sketchRatio);
    void UpdateZoomRatio(float zoomRatio);

    int32_t OnMetadataDispatch(
        int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);

private:
    struct SketchReferenceFovRange {
        float zoomMin = -1.0f;
        float zoomMax = -1.0f;
        float referenceValue = -1.0f;
    };

    // Cache device info
    static std::mutex g_sketchReferenceFovRatioMutex_;
    static std::map<int32_t, std::vector<SketchReferenceFovRange>> g_sketchReferenceFovRatioMap_;
    static std::mutex g_sketchEnableRatioMutex_;
    static std::map<int32_t, float> g_sketchEnableRatioMap_;

    wptr<IStreamCommon> hostStream_;
    Size sketchSize_;
    sptr<Surface> sketchSurface_ = nullptr;
    sptr<IStreamRepeat> sketchStream_;
    std::mutex sketchStatusChangeMutex_;

    std::weak_ptr<PreviewStateCallback> previewStateCallback_;

    volatile float sketchEnableRatio_;
    volatile float currentZoomRatio_ = 1.0f;
    SketchStatusData currentSketchStatusData_ = { .status = SketchStatus::STOPED, .sketchRatio = -1.0f };

    static void UpdateSketchEnableRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    static void UpdateSketchReferenceFovRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    static void UpdateSketchReferenceFovRatio(camera_metadata_item_t& metadataItem,
        std::map<int32_t, std::vector<SketchWrapper::SketchReferenceFovRange>>& referenceMap);
    void OnSketchStatusChanged(int32_t modeName);
    int32_t OnMetadataChangedZoomRatio(
        int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);
    int32_t OnMetadataChangedMacro(
        int32_t modeName, const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);

    void AutoStream();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SKETCH_WRAPPER_H