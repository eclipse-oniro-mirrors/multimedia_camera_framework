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

#ifndef OHOS_CAMERA_VIDEO_OUTPUT_H
#define OHOS_CAMERA_VIDEO_OUTPUT_H

#include <iostream>
#include <vector>

#include "camera_metadata_info.h"
#include "hstream_repeat_callback_stub.h"
#include "istream_repeat.h"
#include "istream_repeat_callback.h"
#include "output/capture_output.h"
#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {

enum VideoMetaType {
    VIDEO_META_MAKER_INFO = 0,
};

class VideoStateCallback {
public:
    VideoStateCallback() = default;
    virtual ~VideoStateCallback() = default;

    /**
     * @brief Called when video frame is started rendering.
     */
    virtual void OnFrameStarted() const = 0;

    /**
     * @brief Called when video frame is ended.
     *
     * @param frameCount Indicates number of frames captured.
     */
    virtual void OnFrameEnded(const int32_t frameCount) const = 0;

    /**
     * @brief Called when error occured during video rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for video callback error.
     */
    virtual void OnError(const int32_t errorCode) const = 0;

    virtual void OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const = 0;
};

class VideoOutput : public CaptureOutput {
public:
    explicit VideoOutput(sptr<IBufferProducer> bufferProducer);
    virtual ~VideoOutput();

    int32_t CreateStream() override;

    /**
     * @brief Releases a instance of the VideoOutput.
     */
    int32_t Release() override;

    /**
     * @brief Set the video callback for the video output.
     *
     * @param VideoStateCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<VideoStateCallback> callback);

    /**
     * @brief Start the video capture.
     */
    int32_t Start();

    /**
     * @brief Stop the video capture.
     */
    int32_t Stop();

    /**
     * @brief get the video rotation angle.
     */
    int32_t GetVideoRotation(int32_t imageRotation);

    /**
     * @brief Pause the video capture.
     */
    int32_t Pause();

    /**
     * @brief Resume the paused video capture.
     */
    int32_t Resume();

    /**
     * @brief Get the application callback information.
     *
     * @return VideoStateCallback pointer set by application.
     */
    std::shared_ptr<VideoStateCallback> GetApplicationCallback();

    /**
     * @brief Get the active video frame rate range.
     *
     * @return Returns vector<int32_t> of active exposure compensation range.
     */
    const std::vector<int32_t>& GetFrameRateRange();

    /**
     * @brief Set the Video fps range. If fixed frame rate
     * to be set the both min and max framerate should be same.
     *
     * @param min frame rate value of range.
     * @param max frame rate value of range.
     */
    void SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate);

    /**
     * @brief Set the format
     *
     * @param format format of the videoOutput.
     */
    void SetOutputFormat(int32_t format);
 
    /**
     * @brief Set the size
     *
     * @param size size of the videoOutput.
     */
    void SetSize(Size size);
 
    /**
     * @brief Set the Video fps.
     *
     * @param frameRate value of frame rate.
     */
    int32_t SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate);
 
    /**
     * @brief Get supported frame rate ranges from device.
     *
     * @return Returns vector<int32_t> supported frame rate ranges.
     */
    std::vector<std::vector<int32_t>> GetSupportedFrameRates();

    /**
     * @brief Set the mirror option for the video output.
     *
     * @param boolean true/false to set/unset mirror respectively.
     */
    int32_t enableMirror(bool enabled);
 
    /**
     * @brief To check the video output support mirror or not.
     *
     * @return Returns true/false if the video output is support mirro or not.
     */
    bool IsMirrorSupported();

        /**
     * @brief Querying the supported video auxiliary stream types.
     *
     * @return Returns the supported video auxiliary stream types.
     */
    std::vector<VideoMetaType> GetSupportedVideoMetaTypes();
 
    /**
     * @brief Check whether the tag is supported.
     *
     * @return Returns true/false if the tag is support or not.
     */
    bool IsTagSupported(camera_device_metadata_tag tag);
 
    /**
     * @brief Sets the surface of the presentation.
     *
     */
    void AttachMetaSurface(sptr<Surface> surface, VideoMetaType videoMetaType);
    /**
     * @brief To check the autoDeferredVideoEnhance capability is supported or not.
     *
     * @return Returns true/false if the autoDeferredVideoEnhance is supported/not-supported respectively.
     */
    int32_t IsAutoDeferredVideoEnhancementSupported();

    /**
     * @brief To check the autoDeferredVideoEnhance capability is supported or not.
     *
     * @return Returns true/false if the autoDeferredVideoEnhance is supported/not-supported respectively.
     */
    int32_t IsAutoDeferredVideoEnhancementEnabled();

    /**
     * @brief Enable or not enable for autoDeferredVideoEnhance capability.
     *
     */
    int32_t EnableAutoDeferredVideoEnhancement(bool enabled);

    /**
    * @brief Checks if the video has started.
    *
    * @return true if the video is currently running; false otherwise.
    */
    bool IsVideoStarted();

    /**
     * @brief Get supported rotations.
     *
     */
    int32_t GetSupportedRotations(std::vector<int32_t> &supportedRotations);

    /**
     * @brief Check whether the rotation is supported.
     *
     */
    int32_t IsRotationSupported(bool &isSupported);

    /**
     * @brief Set the rotation.
     *
     */
    int32_t SetRotation(int32_t rotation);

private:
    int32_t videoFormat_;
    Size videoSize_;
    std::shared_ptr<VideoStateCallback> appCallback_;
    sptr<IStreamRepeatCallback> svcCallback_;
    std::vector<int32_t> videoFrameRateRange_{0, 0};
    std::atomic_bool isVideoStarted_ = false;
    void CameraServerDied(pid_t pid) override;
    int32_t canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate);
};

class VideoOutputCallbackImpl : public HStreamRepeatCallbackStub {
public:
    wptr<VideoOutput> videoOutput_ = nullptr;
    VideoOutputCallbackImpl() : videoOutput_(nullptr) {}

    explicit VideoOutputCallbackImpl(VideoOutput* videoOutput) : videoOutput_(videoOutput) {}

    ~VideoOutputCallbackImpl()
    {
        videoOutput_ = nullptr;
    }

    /**
     * @brief Called when video frame is started rendering.
     */
    int32_t OnFrameStarted() override;

    /**
     * @brief Called when video frame is ended.
     *
     * @param frameCount Indicates number of frames captured.
     */
    int32_t OnFrameEnded(const int32_t frameCount) override;

    /**
     * @brief Called when error occured during video rendering.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for video callback error.
     */
    int32_t OnFrameError(const int32_t errorCode) override;

    /**
     * @brief Empty function.
     *
     * @param status sketch status.
     */
    int32_t OnSketchStatusChanged(SketchStatus status) override;

    int32_t OnDeferredVideoEnhancementInfo(CaptureEndedInfoExt captureEndedInfo) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_VIDEO_OUTPUT_H
