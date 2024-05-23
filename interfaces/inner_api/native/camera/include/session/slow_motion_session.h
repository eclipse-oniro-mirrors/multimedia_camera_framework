/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_SLOW_MOTION_SESSION_H
#define OHOS_CAMERA_SLOW_MOTION_SESSION_H

#include "capture_session.h"
#include "icapture_session.h"
#include "input/capture_input.h"
#include "output/metadata_output.h"

namespace OHOS {
namespace CameraStandard {
enum SlowMotionState {
    DEFAULT = -1,
    DISABLE = 0,
    READY,
    START,
    RECORDING,
    FINISH
};

class SlowMotionStateCallback {
public:
    SlowMotionStateCallback() = default;
    virtual ~SlowMotionStateCallback() = default;
    virtual void OnSlowMotionState(const SlowMotionState state) = 0;

    void SetSlowMotionState(const SlowMotionState state)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        currentState_ = state;
    }
    SlowMotionState GetSlowMotionState()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return currentState_;
    }

private:
    SlowMotionState currentState_;
    std::mutex mutex_;
};

class SlowMotionSession : public CaptureSession {
public:
    class SlowMotionSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit SlowMotionSessionMetadataResultProcessor(wptr<SlowMotionSession> session) : session_(session) {}
        void ProcessCallbacks(
            const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<SlowMotionSession> session_;
    };
    explicit SlowMotionSession(sptr<ICaptureSession> &slowMotionSession): CaptureSession(slowMotionSession)
    {
        metadataResultProcessor_ = std::make_shared<SlowMotionSessionMetadataResultProcessor>(this);
    }
    ~SlowMotionSession();

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;

    /**
     * @brief Checks if motion detection is supported.
     *
     * @return true if motion detection is supported, false otherwise.
     */
    bool IsSlowMotionDetectionSupported();

    /**
     * @brief Starts motion monitoring within the specified rectangle.
     *
     * @param rect The rectangle defining the area where motion monitoring will be started.
     *             It consists of the coordinates of the top-left corner (topLeftX, topLeftY),
     *             width, and height.
     */
    void SetSlowMotionDetectionArea(Rect rect);

    /**
     * @brief Callback function invoked when there is a change in slow motion state.
     *
     * @param state The new state of slow motion.
     */
    void OnSlowMotionStateChange(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);

    /**
     * @brief Sets the callback function for handling changes in slow motion state.
     *
     * @param callback A shared pointer to the callback function object.
     */
    void SetCallback(std::shared_ptr<SlowMotionStateCallback> callback);

    /**
     * @brief Normalizes the values of a Rect object, setting values greater than 1 to 1
     * and values less than 0 to 0.
     *
     * @param rect The Rect object to be normalized.
     */
    void NormalizeRect(Rect& rect);

    /**
     * @brief Enables or disables motion detection.
     *
     * @param isEnable true to enable motion detection, false to disable.
     *
     * @return If the operation is successful, returns 0; otherwise, returns the corresponding error code.
     */
    int32_t EnableMotionDetection(bool isEnable);

    /**
     * @brief Retrieves the application callback for slow motion state changes.
     *
     * @return A shared pointer to the application callback for slow motion state changes.
     */
    std::shared_ptr<SlowMotionStateCallback> GetApplicationCallback();

private:
    std::mutex stateCallbackMutex_;
    std::shared_ptr<SlowMotionStateCallback> slowMotionStateCallback_;
    static const std::unordered_map<camera_slow_motion_status_type_t, SlowMotionState> metaMotionStateMap_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SLOW_MOTION_SESSION_H