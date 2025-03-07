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
 
#ifndef OHOS_CAMERA_VIDEO_SESSION_H
#define OHOS_CAMERA_VIDEO_SESSION_H
 
#include "camera_output_capability.h"
#include "capture_input.h"
#include "capture_session.h"
#include "icapture_session.h"
#include "metadata_output.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {

class LightStatusCallback;

enum FocusTrackingMode : int32_t {
    FOCUS_TRACKING_MODE_AUTO = 0,
};

typedef struct {
    int32_t status;
} LightStatus;

struct FocusTrackingInfoParms {
    FocusTrackingMode trackingMode = FOCUS_TRACKING_MODE_AUTO;
    Rect trackingRegion = {0.0, 0.0, 0.0, 0.0};
};

class FocusTrackingInfo : public RefBase {
public:
    FocusTrackingInfo(const FocusTrackingMode mode, const Rect rect);
    FocusTrackingInfo(const FocusTrackingInfoParms& parms);
    virtual ~FocusTrackingInfo() = default;

    inline FocusTrackingMode GetMode()
    {
        return mode_;
    }

    inline Rect GetRegion()
    {
        return region_;
    }

    inline void SetRegion(Rect& region)
    {
        region_ = region;
    }

    inline void SetMode(FocusTrackingMode mode)
    {
        mode_ = mode;
    }
private:
    FocusTrackingMode mode_;
    Rect region_;
};

class FocusTrackingCallback {
public:
    FocusTrackingCallback() = default;
    virtual ~FocusTrackingCallback() = default;
    virtual void OnFocusTrackingInfoAvailable(FocusTrackingInfo &focusTrackingInfo) const = 0;
};

class VideoSession : public CaptureSession {
public:
    class VideoSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit VideoSessionMetadataResultProcessor(wptr<VideoSession> session) : session_(session) {}
        void ProcessCallbacks(const uint64_t timestamp,
            const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<VideoSession> session_;
    };

    explicit VideoSession(sptr<ICaptureSession> &videoSession): CaptureSession(videoSession)
    {
        metadataResultProcessor_ = std::make_shared<VideoSessionMetadataResultProcessor>(this);
    }
    ~VideoSession();

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;

    /**
     * @brief Video-Session can set frame rate range.
     *
     * @param minFps Min frame rate of range.
     * @param minFps Max frame rate of range.
     */
    bool CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput) override;

    /**
     * @brief Check the preconfig type is supported or not.
     *
     * @param preconfigType The target preconfig type.
     * @param preconfigRatio The target ratio enum
     *
     * @return True if the preconfig type is supported, false otherwise.
     */
    bool CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio) override;

    /**
     * @brief Set the preconfig type.
     *
     * @param preconfigType The target preconfig type.
     * @param preconfigRatio The target ratio enum
     *
     * @return Camera error code.
     */
    int32_t Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio) override;

    /**
     * @brief Set focus tracking info callback for the video session.
     *
     * @param focusTrackingInfoCallback callback to be set.
     */
    void SetFocusTrackingInfoCallback(std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback);

    /**
     * @brief Get focus tracking info callback pointer.
     *
     * @return Focus tracking info callback pointer.
     */
    std::shared_ptr<FocusTrackingCallback> GetFocusTrackingCallback();

    /**
     * @brief Process focus tracking info.
     *
     * @param result Metadata result reported by HDI.
     */
    void ProcessFocusTrackingInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief Set the exposure hint callback.
     * which will be called when there is exposure hint change.
     *
     * @param The LightStatusCallback pointer.
     */
    void SetLightStatusCallback(std::shared_ptr<LightStatusCallback> callback);

    /**
     * @brief Get light status callback pointer.
     *
     * @return Focus light status callback pointer.
     */
    std::shared_ptr<LightStatusCallback> GetLightStatusCallback();

    /**
     * @brief This function is called when there is LightStatus change
     * and process the LightStatus callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessLightStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    void SetLightStatus(uint8_t status)
    {
        lightStatus_ = status;
    }
    uint8_t GetLightStatus()
    {
        return lightStatus_;
    }

protected:
    std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles(
        PreconfigType preconfigType, ProfileSizeRatio preconfigRatio) override;

private:
    bool IsPreconfigProfilesLegal(std::shared_ptr<PreconfigProfiles> configs);
    bool IsPhotoProfileLegal(sptr<CameraDevice>& device, Profile& photoProfile);
    bool IsPreviewProfileLegal(sptr<CameraDevice>& device, Profile& previewProfile);
    bool IsVideoProfileLegal(sptr<CameraDevice>& device, VideoProfile& videoProfile);
    bool ProcessFocusTrackingModeInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
        FocusTrackingMode& mode);
    bool ProcessRectInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata, Rect& rect);
    std::shared_ptr<LightStatusCallback> lightStatusCallback_ = nullptr;

    std::mutex videoSessionCallbackMutex_;
    std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback_ = nullptr;
    static const std::unordered_map<camera_focus_tracking_mode_t, FocusTrackingMode> metaToFwFocusTrackingMode_;
    int32_t lightStatus_ = 0;
};

class LightStatusCallback {
public:
    LightStatusCallback() = default;
    virtual ~LightStatusCallback() = default;
    virtual void OnLightStatusChanged(LightStatus &status) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_VIDEO_SESSION_H