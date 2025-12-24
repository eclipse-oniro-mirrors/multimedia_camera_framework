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

#ifndef OHOS_CAMERA_STITCHING_PHOTO_SESSION_H
#define OHOS_CAMERA_STITCHING_PHOTO_SESSION_H

#include "capture_session_for_sys.h"
#include "image_receiver.h"
#include "image_source.h"
#include "sp_holder.h"

namespace OHOS {
namespace CameraStandard {

class StitchingTargetInfo;
class StitchingCaptureInfo;
class StitchingHintInfo;
class StitchingCaptureStateInfo;

template<typename InfoTp>
class NativeInfoCallback;
using StitchingTargetInfoCallback = NativeInfoCallback<StitchingTargetInfo>;
using StitchingCaptureInfoCallback = NativeInfoCallback<StitchingCaptureInfo>;
using StitchingHintInfoCallback = NativeInfoCallback<StitchingHintInfo>;
using StitchingCaptureStateCallback = NativeInfoCallback<StitchingCaptureStateInfo>;

class StitchingPhotoSession : public CaptureSessionForSys {
    friend class StitchingSurfaceListener;

public:
    class StitchingPhotoSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit StitchingPhotoSessionMetadataResultProcessor(wptr<StitchingPhotoSession> session)
            : session_(session)
        {}
        void ProcessCallbacks(
            const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<StitchingPhotoSession> session_;
    };

    explicit StitchingPhotoSession(sptr<ICaptureSession>& session);

    ~StitchingPhotoSession();

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;

    int32_t AddOutput(sptr<CaptureOutput>& output) override;

    int32_t SetStitchingType(StitchingType stitchingType);
    int32_t GetStitchingType(StitchingType& stitchingType);

    int32_t SetStitchingDirection(StitchingDirection StitchingDirection);
    int32_t GetStitchingDirection(StitchingDirection& stitchingType);
    int32_t SetMovingClockwise(bool enable);
    int32_t GetMovingClockwise(bool& enable);

    /**
     * @brief Set the stitching target positions callback.
     * which will be called when stitching target change.
     *
     * @param The StitchingTargetInfo pointer.
     */
    int32_t SetStitchingTargetInfoCallback(std::shared_ptr<StitchingTargetInfoCallback> callback);

    /**
     * @brief Set the stitching capture callback.
     * which will be called when stitching capture.
     *
     * @param callback the StitchingCaptureInfo pointer.
     */
    int32_t SetStitchingCaptureInfoCallback(std::shared_ptr<StitchingCaptureInfoCallback> callback);

    /**
     * @brief Set the stitching hint callback.
     * which will be called when stitching hint change.
     *
     * @param callback the StitchingHintInfo pointer.
     */
    int32_t SetStitchingHintInfoCallback(std::shared_ptr<StitchingHintInfoCallback> callback);

    /**
     * @brief Set the stitching capture state callback.
     * which will be called when stitching capture state change.
     *
     * @param callback the StitchingCaptureStateCallback pointer.
     */
    int32_t SetStitchingCaptureStateCallback(std::shared_ptr<StitchingCaptureStateCallback> callback);

    /**
     * @brief This function is called when stitching target changes
     * and process the stitching target callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessStitchingTargetChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when stitching hint changes
     * and process the stitching hint callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessStitchingHintChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when stitching capture state changes
     * and process the stitching capture state callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessStitchingCaptureStateChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

protected:
    bool CreateStitchingPreviewOutput(
        wptr<StitchingPhotoSession> pStitchingPhotoSession, const Size& size, const CameraFormat& profileFormat);
    static const std::unordered_map<StitchingType, PhotoStitchingType> fwkStitchingTypeMap_;
    static const std::unordered_map<PhotoStitchingType, StitchingType> metaStitchingTypeMap_;
    static const std::unordered_map<StitchingDirection, PhotoStitchingDirection> fwkStitchingDirectionMap_;
    static const std::unordered_map<PhotoStitchingDirection, StitchingDirection> metaStitchingDirectionMap_;
    static const std::unordered_set<PhotoStitchingCaptureState> metaStitchingCaptureStateSet_;

private:
    std::mutex sessionCallbackMutex_;
    std::shared_ptr<StitchingTargetInfoCallback> stitchingTargetInfoCallback_ = nullptr;
    std::shared_ptr<StitchingCaptureInfoCallback> stitchingCaptureInfoCallback_ = nullptr;
    std::shared_ptr<StitchingHintInfoCallback> stitchingHintInfoCallback_ = nullptr;
    SpHolder<std::shared_ptr<StitchingCaptureStateCallback>> stitchingCaptureStateCallback_;
    std::shared_ptr<StitchingCaptureInfo> stitchingCaptureInfoRecord_ = nullptr;
    std::shared_ptr<StitchingTargetInfo> stitchingTargetInfoRecord_ = nullptr;
    std::shared_ptr<StitchingHintInfo> stitchingHintInfoRecord_ = nullptr;

    sptr<IConsumerSurface> stitchingSurface_;
};

class StitchingTargetInfo {
public:
    StitchingTargetInfo() = default;
    bool operator!=(const StitchingTargetInfo& rhs)
    {
        return positions_ != rhs.positions_ || angle_ != rhs.angle_;
    }

    std::vector<float> positions_;
    float angle_;
};

class StitchingCaptureInfo {
public:
    StitchingCaptureInfo() = default;

    int32_t captureNumber_;
    std::shared_ptr<OHOS::Media::PixelMap> previewStitching_;
};

class StitchingHintInfo {
public:
    enum StitchingHint { DARK_LIGHT = 0, KEEP_H, SPINNING, TOO_FAST, OUT_OF_RANGE, TOO_CLOSE };
    StitchingHintInfo() = default;

    bool operator!=(const StitchingHintInfo& rhs)
    {
        return hint_ != rhs.hint_;
    }

    StitchingHint hint_;
};

class StitchingCaptureStateInfo {
public:
    StitchingCaptureStateInfo() = default;
    bool operator!=(const StitchingCaptureStateInfo& rhs)
    {
        return state_ != rhs.state_;
    }
    int32_t state_;
};

class StitchingSurfaceListener : public IBufferConsumerListener {
public:
    static std::unique_ptr<OHOS::Media::PixelMap> Buffer2PixelMap(OHOS::sptr<OHOS::SurfaceBuffer> buffer);
    StitchingSurfaceListener(wptr<StitchingPhotoSession> pStitchingPhotoSession, wptr<IConsumerSurface> surface);
    virtual ~StitchingSurfaceListener() = default;
    void OnBufferAvailable() override;

private:
    wptr<StitchingPhotoSession> pStitchingPhotoSession_;
    wptr<IConsumerSurface> surface_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_STITCHING_PHOTO_SESSION_H