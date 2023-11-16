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

#ifndef OHOS_CAMERA_PREVIEW_OUTPUT_H
#define OHOS_CAMERA_PREVIEW_OUTPUT_H

#include "camera_output_capability.h"
#include "capture_output.h"
#include "hstream_repeat_callback_stub.h"
#include "icamera_service.h"
#include "istream_repeat.h"
#include "istream_repeat_callback.h"

namespace OHOS {
namespace CameraStandard {
class PreviewStateCallback {
public:
    PreviewStateCallback() = default;
    virtual ~PreviewStateCallback() = default;

    /**
     * @brief Called when preview frame is started rendering.
     */
    virtual void OnFrameStarted() const = 0;

    /**
     * @brief Called when preview frame is ended.
     *
     * @param frameCount Indicates number of frames captured.
     */
    virtual void OnFrameEnded(const int32_t frameCount) const = 0;

    /**
     * @brief Called when error occured during preview rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for preview callback error.
     */
    virtual void OnError(const int32_t errorCode) const = 0;

    /**
     * @brief Called when sketch data available.
     *
     * @param SketchData Indicates a {@link SketchData}.
     */
    virtual void OnSketchAvailable(SketchData& SketchData) const = 0;
};

class PreviewOutput : public CaptureOutput {
public:
    explicit PreviewOutput(sptr<IStreamRepeat>& streamRepeat);
    virtual ~PreviewOutput();

    /**
     * @brief Set the preview callback for the preview output.
     *
     * @param PreviewStateCallback to be triggered.
     */
    void SetCallback(std::shared_ptr<PreviewStateCallback> callback);

    /**
     * @brief Releases a instance of the preview output.
     */
    int32_t Release() override;

    /**
     * @brief Add delayed preview surface.
     *
     * @param surface to add.
     */
    void AddDeferredSurface(sptr<Surface> surface);

    /**
     * @brief Start preview stream.
     */
    int32_t Start();

    /**
     * @brief stop preview stream.
     */
    int32_t Stop();

    /**
     * @brief Check whether the current preview mode supports sketch.
     *
     * @return Return the supported result.
     */
    bool IsSketchSupported();

    /**
     * @brief Get the scaling ratio threshold for sketch callback data.
     *
     * @return Return the threshold value.
     */
    float GetSketchRatio();

    /**
     * @brief Enable sketch
     *
     * @param isEnable True for enable, false otherwise.
     *
     */
    int32_t EnableSketch(bool isEnable);

    /**
     * @brief Start sketch.
     */
    int32_t StartSketch();

    /**
     * @brief Stop sketch.
     */
    int32_t StopSketch();

    /**
     * @brief Get the application callback information.
     *
     * @return Returns the pointer application callback.
     */
    std::shared_ptr<PreviewStateCallback> GetApplicationCallback();

    /**
     * @brief Get sketch reference FOV ratio.
     *
     * @param modeName Mode name.
     * @param currentZoomRatio Current zoom ratio.
     *
     */
    float GetSketchReferenceFovRatio(int32_t modeName, float currentZoomRatio);

    /**
     * @brief Get sketch enable ratio.
     *
     * @param modeName Mode name.
     *
     */
    float GetSketchEnableRatio(int32_t modeName);

    /**
     * @brief Get Observed matadata tags
     *        Register tags into capture session. If the tags data changes,{@link OnMetadataChanged} will be called.
     * @return Observed tags
     */
    std::set<camera_device_metadata_tag_t> GetObserverTags() const override;

    /**
     * @brief Callback of metadata change.
     * @return Operate result
     */
    int32_t OnMetadataChanged(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem) override;

    void OnNativeRegisterCallback(const std::string& eventString);
    void OnNativeUnregisterCallback(const std::string& eventString);

private:
    struct SketchReferenceFovRange {
        float zoomMin = -1.0f;
        float zoomMax = -1.0f;
        float referenceValue = -1.0f;
    };

    std::shared_ptr<PreviewStateCallback> appCallback_;
    sptr<IStreamRepeatCallback> svcCallback_;
    std::shared_ptr<void> sketchWrapper_;
    std::mutex sketchReferenceFovRatioMutex_;
    std::map<int32_t, std::vector<SketchReferenceFovRange>> sketchReferenceFovRatioMap_;
    std::mutex sketchEnableRatioMutex_;
    std::map<int32_t, float> sketchEnableRatioMap_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetDeviceMetadata();
    void UpdateSketchStaticInfo();
    void UpdateSketchEnableRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    void UpdateSketchReferenceFovRatio(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceMetadata);
    std::shared_ptr<Size> FindSketchSize();
    int32_t OnMetadataChangedMacro(const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);
    int32_t OnMetadataChangedZoomRatio(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem);
    int32_t CreateSketchWrapper(Size sketchSize, int32_t imageFormat);
    void CameraServerDied(pid_t pid) override;
};

class PreviewOutputCallbackImpl : public HStreamRepeatCallbackStub {
public:
    wptr<PreviewOutput> previewOutput_ = nullptr;
    PreviewOutputCallbackImpl() : previewOutput_(nullptr) {}

    explicit PreviewOutputCallbackImpl(PreviewOutput* previewOutput) : previewOutput_(previewOutput) {}

    ~PreviewOutputCallbackImpl()
    {
        previewOutput_ = nullptr;
    }

    /**
     * @brief Called when preview frame is started rendering.
     */
    int32_t OnFrameStarted() override;

    /**
     * @brief Called when preview frame is ended.
     *
     * @param frameCount Indicates number of frames captured.
     */
    int32_t OnFrameEnded(int32_t frameCount) override;

    /**
     * @brief Called when error occured during preview rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for preview callback error.
     */
    int32_t OnFrameError(int32_t errorCode) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PREVIEW_OUTPUT_H
