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

#include <cstdint>
#include <memory>
#include <mutex>

#include "camera_listener_manager.h"
#include "camera_output_capability.h"
#include "capture_output.h"
#include "stream_repeat_callback_stub.h"
#include "icamera_service.h"
#include "input/camera_device.h"
#include "istream_repeat.h"
#include "istream_repeat_callback.h"

namespace OHOS {
namespace CameraStandard {
static const std::string CONST_PREVIEW_FRAME_START = "frameStart";
static const std::string CONST_PREVIEW_FRAME_END = "frameEnd";
static const std::string CONST_PREVIEW_FRAME_ERROR = "error";
static const std::string CONST_SKETCH_STATUS_CHANGED = "sketchStatusChanged";
class SketchWrapper;
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
     * @brief Called when sketch status changed.
     *
     * @param statusData Indicates a {@link SketchStatusData}.
     */
    virtual void OnSketchStatusDataChanged(const SketchStatusData& statusData) const = 0;
};

class PreviewOutputListenerManager;
class PreviewOutput : public CaptureOutput {
public:
    explicit PreviewOutput(sptr<IBufferProducer> bufferProducer);
    explicit PreviewOutput();
    virtual ~PreviewOutput();

    /**
     * @brief Set the preview callback for the preview output.
     *
     * @param PreviewStateCallback to be triggered.
     */
    void SetCallback(std::shared_ptr<PreviewStateCallback> callback);

    /**
     * @brief Remove the preview callback for the preview output.
     *
     * @param PreviewStateCallback to be triggered.
     */
    void RemoveCallback(std::shared_ptr<PreviewStateCallback> callback);

    int32_t CreateStream() override;

    void SetStream(sptr<IStreamCommon> stream) override;

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
     * @brief get the preview rotation angle.
     *
     * @return result of the photo rotation angle.
     */
    int32_t GetPreviewRotation(int32_t imageRotation);

    /**
     * @brief set the preview rotation angle.
     */
    int32_t SetPreviewRotation(int32_t imageRotation, bool isDisplayLocked);

    /**
     * @brief Check whether the current preview mode supports sketch.
     *
     * @return Return the supported result.
     */
    bool IsSketchSupported();

    bool IsDynamicSketchNotifySupported();

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
     * @brief Attach sketch surface
     *
     * @param sketchSurface Sketch surface
     *
     */
    int32_t AttachSketchSurface(sptr<Surface> sketchSurface);

    /**
     * @brief Set the preview fps.
     *
     * @param frameRate value of frame rate.
     */
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate);
 
    /**
     * @brief Get the active preview frame rate range.
     *
     * @return Returns vector<int32_t> of active exposure compensation range.
     */
    const std::vector<int32_t>& GetFrameRateRange();
 
    /**
     * @brief Set the preview fps range. If fixed frame rate
     * to be set the both min and max framerate should be same.
     *
     * @param minFrameRate min frame rate value of range.
     * @param maxFrameRate max frame rate value of range.
     */
    void SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate);
 
    /**
     * @brief Set the format
     *
     * @param format format of the previewOutput.
     */
    void SetOutputFormat(int32_t format);
 
    /**
     * @brief Set the size
     *
     * @param size size of the previewOutput.
     */
    void SetSize(Size size);
 
    /**
     * @brief Get the supported preview frame rate range.
     *
     * @return Returns vector<int32_t> of supported exposure compensation range.
     */
    std::vector<std::vector<int32_t>> GetSupportedFrameRates();

    /**
     * @brief Get the preview-output listener.
     *
     * @return Returns the pointer preview-output listener.
     */
    sptr<PreviewOutputListenerManager> GetPreviewOutputListenerManager();

    /**
     * @brief Get Observed matadata tags
     *        Register tags into capture session. If the tags data changes,{@link OnControlMetadataChanged} will be
     *        called.
     * @return Observed tags
     */
    virtual const std::set<camera_device_metadata_tag_t>& GetObserverControlTags() override;

    /**
     * @brief Get Observed matadata tags
     *        Register tags into capture session. If the tags data changes,{@link OnResultMetadataChanged} will be
     *        called.
     * @return Observed tags
     */
    virtual const std::set<camera_device_metadata_tag_t>& GetObserverResultTags() override;

    /**
     * @brief Callback of request metadata change.
     * @return Operate result
     */
    int32_t OnControlMetadataChanged(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem) override;

    /**
     * @brief Callback of result metadata change.
     * @return Operate result
     */
    int32_t OnResultMetadataChanged(
        const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem) override;

    int32_t OnSketchStatusChanged(SketchStatus status);

    void OnNativeRegisterCallback(const std::string& eventString);
    void OnNativeUnregisterCallback(const std::string& eventString);
    void AdjustRenderFit();
    bool IsXComponentSwap();
    int32_t GetCameraDeviceRotationAngle(uint32_t &cameraRotation);
    void SetSurfaceId(const std::string& surfaceId);
    std::string GetSurfaceId();
private:
    int32_t PreviewFormat_;
    std::mutex surfaceIdMutex_;
    std::string surfaceId_ = "";
    Size PreviewSize_ = {0, 0};
    sptr<PreviewOutputListenerManager> previewOutputListenerManager_ = sptr<PreviewOutputListenerManager>::MakeSptr();

    std::shared_ptr<SketchWrapper> sketchWrapper_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetDeviceMetadata();
    std::shared_ptr<Size> FindSketchSize();
    std::vector<int32_t> previewFrameRateRange_{0, 0};
    int32_t CreateSketchWrapper(Size sketchSize);
    int32_t StartSketch();
    int32_t StopSketch();
    void CameraServerDied(pid_t pid) override;
    int32_t canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate);
    int32_t JudegRotationFunc(int32_t imageRotation);
};

class PreviewOutputListenerManager : public StreamRepeatCallbackStub,
                                     public CameraListenerManager<PreviewStateCallback> {
public:
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

    /**
     * @brief Called when sketch status changed.
     *
     * @param status Indicates a {@link SketchStatus} which will give information for preview callback error.
     */
    int32_t OnSketchStatusChanged(SketchStatus status) override;

    int32_t OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt &captureEndedInfo) override;

    void SetPreviewOutput(wptr<PreviewOutput> previewOutput);
    sptr<PreviewOutput> GetPreviewOutput();

private:
    wptr<PreviewOutput> previewOutput_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PREVIEW_OUTPUT_H
