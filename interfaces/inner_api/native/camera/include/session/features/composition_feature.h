/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_COMPOSITION_FEATURE_H
#define OHOS_CAMERA_COMPOSITION_FEATURE_H

#include "abilities/sketch_ability.h"
#include "camera_metadata_info.h"
#include "capture_scene_const.h"
#include "native_info_callback.h"
#include "iconsumer_surface.h"
#include "capture_output.h"
#include "camera_device.h"
#include "istream_repeat.h"

namespace OHOS {
namespace Media {
class PixelMap;
}
namespace CameraStandard {
class CaptureSession;
class CompositionEffectInfo;
struct CompositionPositionCalibrationInfo;
class CompositionFeature : public std::enable_shared_from_this<CompositionFeature> {
    friend class CompositionEffectListener;

public:
    explicit CompositionFeature(wptr<CaptureSession> captureSession) : captureSession_(captureSession) {};
    ~CompositionFeature();

    int32_t IsCompositionEffectPreviewSupported(bool& isSupported);
    int32_t EnableCompositionEffectPreview(bool isEnable);
    int32_t GetSupportedRecommendedInfoLanguage(std::vector<std::string>& supportedLanguages);
    int32_t SetRecommendedInfoLanguage(const std::string& language);
    int32_t SetCompositionEffectReceiveCallback(std::shared_ptr<NativeInfoCallback<CompositionEffectInfo>> callback);

private:
    enum class StreamStatus {
        STARTED,
        STOPPED,
    } compositionStreamStatus_ = StreamStatus::STOPPED;
    static constexpr CameraFormat COMPOSITION_FORMAT = CameraFormat::CAMERA_FORMAT_YUV_420_SP;
    int32_t StartCompositionStream();
    int32_t StopCompositionStream();
    inline static const std::unordered_map<uint8_t, std::string> INT_TO_STR_LANGUAGE_MAP { { 1, "zh-Hans" },
        { 2, "en-Latn-US" } };
    inline static const std::unordered_map<std::string, uint8_t> STR_TO_INT_LANGUAGE_MAP { { "zh-Hans", 1 },
        { "en-Latn-US", 2 } };
    static const std::unordered_set<SceneMode> SUPPORTED_MODES;
    int32_t CheckCommonPreconditions();
    int32_t CheckMode();
    wptr<CaptureSession> captureSession_ = nullptr;
    std::mutex compositionEffectReceiveCallbackMutex_;
    std::shared_ptr<NativeInfoCallback<CompositionEffectInfo>> compositionEffectReceiveCallback_;
    sptr<IStreamRepeat> compositionStream_;
    sptr<IConsumerSurface> compositionSurface_;
};

class CompositionEffectInfo {
public:
    int64_t compositionId_ = -1;
    int32_t compositionPointIndex_ = -1;
    std::string compositionReasons_ = "";
    std::shared_ptr<OHOS::Media::PixelMap> compositionImage_ = nullptr;
};

class PreviewOutput;
class CompositionEffectListener : public IBufferConsumerListener {
public:
    CompositionEffectListener(std::weak_ptr<CompositionFeature> compositionFeature, wptr<IConsumerSurface> surface)
        : compositionFeature_(compositionFeature), surface_(surface)
    {}
    void OnBufferAvailable() override;

private:
    static std::unique_ptr<Media::PixelMap> Buffer2PixelMap(sptr<SurfaceBuffer> buffer);
    std::weak_ptr<CompositionFeature> compositionFeature_;
    wptr<IConsumerSurface> surface_;
};

} // namespace CameraStandard
} // namespace OHOS

#endif