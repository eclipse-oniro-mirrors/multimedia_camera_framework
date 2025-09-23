/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_QUERY_CAMERA_QUERY_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_QUERY_CAMERA_QUERY_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "session/capture_session.h"
#include "capture_session_for_sys.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;
using namespace taihe;

class SessionBase {
public:
    SessionBase() = default;
    virtual ~SessionBase() = default;
protected:
    sptr<OHOS::CameraStandard::CaptureSession> captureSession_ = nullptr;
    sptr<OHOS::CameraStandard::CaptureSessionForSys> captureSessionForSys_ = nullptr;
    bool isSessionBase_ = false;
};

class FunctionBase {
public:
    FunctionBase() = default;
    virtual ~FunctionBase() = default;
protected:
    sptr<OHOS::CameraStandard::CameraAbility> cameraAbility_ = nullptr;
    bool isFunctionBase_ = false;
};

class FlashQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit FlashQueryImpl() {}
    virtual ~FlashQueryImpl() = default;
    bool HasFlash();
    bool IsFlashModeSupported(FlashMode flashMode);
    bool IsLcdFlashSupported();
};

class FlashImpl : public FlashQueryImpl {
public:
    explicit FlashImpl() {}
    virtual ~FlashImpl() = default;
    void EnableLcdFlash(bool enabled);
    void SetFlashMode(FlashMode flashMode);
    FlashMode GetFlashMode();
};

class ZoomQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit ZoomQueryImpl() {}
    virtual ~ZoomQueryImpl() = default;
    array<double> GetZoomRatioRange();
    array<ZoomPointInfo> GetZoomPointInfos();
};

class ZoomImpl : public ZoomQueryImpl {
public:
    explicit ZoomImpl() {}
    virtual ~ZoomImpl() = default;
    double GetZoomRatio();
    void SetZoomRatio(double zoomRatio);
    void PrepareZoom();
    void UnprepareZoom();
    void SetSmoothZoom(double targetRatio, optional_view<SmoothZoomMode> mode);
};

class ColorReservationQueryImpl : virtual public SessionBase {
public:
    explicit ColorReservationQueryImpl() {}
    virtual ~ColorReservationQueryImpl() = default;
    virtual array<ColorReservationType> GetSupportedColorReservationTypes();
};

class ColorReservationImpl : public ColorReservationQueryImpl {
public:
    explicit ColorReservationImpl() {}
    virtual ~ColorReservationImpl() = default;
    void SetColorReservation(ColorReservationType type);
    ColorReservationType GetColorReservation();
};

class FocusQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit FocusQueryImpl() {}
    virtual ~FocusQueryImpl() = default;
    bool IsFocusRangeTypeSupported(FocusRangeType type);
    bool IsFocusDrivenTypeSupported(FocusDrivenType type);
    bool IsFocusModeSupported(FocusMode afMode);
    virtual bool IsFocusAssistSupported();
};

class FocusImpl : public FocusQueryImpl {
public:
    explicit FocusImpl() {}
    virtual ~FocusImpl() = default;
    void SetFocusDriven(FocusDrivenType type);
    FocusDrivenType GetFocusDriven();
    void SetFocusRange(FocusRangeType type);
    FocusRangeType GetFocusRange();
    virtual void SetFocusAssist(bool enabled);
    Point GetFocusPoint();
    void SetFocusPoint(Point const& point);
    double GetFocalLength();
    FocusMode GetFocusMode();
    void SetFocusMode(FocusMode afMode);
};

class StabilizationQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit StabilizationQueryImpl() {}
    virtual ~StabilizationQueryImpl() = default;
    bool IsVideoStabilizationModeSupported(VideoStabilizationMode vsMode);
};

class StabilizationImpl : public StabilizationQueryImpl {
public:
    explicit StabilizationImpl() {}
    virtual ~StabilizationImpl() = default;
    VideoStabilizationMode GetActiveVideoStabilizationMode();
    void SetVideoStabilizationMode(VideoStabilizationMode mode);
};

class BeautyQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit BeautyQueryImpl() {}
    virtual ~BeautyQueryImpl() = default;
    array<PortraitThemeType> GetSupportedPortraitThemeTypes();
    array<BeautyType> GetSupportedBeautyTypes();
    array<int32_t> GetSupportedBeautyRange(BeautyType type);
    bool IsPortraitThemeSupported();
};

class BeautyImpl : public BeautyQueryImpl {
public:
    explicit BeautyImpl() {}
    virtual ~BeautyImpl() = default;
    void SetPortraitThemeType(PortraitThemeType type);
    int32_t GetBeauty(BeautyType type);
    void SetBeauty(BeautyType type, int32_t value);
};

class AutoExposureQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit AutoExposureQueryImpl() {}
    virtual ~AutoExposureQueryImpl() = default;
    array<double> GetExposureBiasRange();
    bool IsExposureModeSupported(ExposureMode aeMode);
    virtual bool IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode);
};

class AutoExposureImpl : public AutoExposureQueryImpl {
public:
    explicit AutoExposureImpl() {}
    virtual ~AutoExposureImpl() = default;
    void SetExposureBias(double exposureBias);
    virtual void SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode);
    virtual ExposureMeteringMode GetExposureMeteringMode();
    double GetExposureValue();
    Point GetMeteringPoint();
    void SetMeteringPoint(Point const& point);
    ExposureMode GetExposureMode();
    void SetExposureMode(ExposureMode aeMode);
};

class ColorManagementQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit ColorManagementQueryImpl() {}
    virtual ~ColorManagementQueryImpl() = default;
    array<uintptr_t> GetSupportedColorSpaces();
};

class ColorManagementImpl : public ColorManagementQueryImpl {
public:
    explicit ColorManagementImpl() {}
    virtual ~ColorManagementImpl() = default;
    void SetColorSpace(uintptr_t colorSpace);
    uintptr_t GetActiveColorSpace();
};

class SceneDetectionQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit SceneDetectionQueryImpl() {}
    virtual ~SceneDetectionQueryImpl() = default;
    bool IsSceneFeatureSupported(SceneFeatureType type);
};

class SceneDetectionImpl : public SceneDetectionQueryImpl {
public:
    explicit SceneDetectionImpl() {}
    virtual ~SceneDetectionImpl() = default;
    void EnableSceneFeature(SceneFeatureType type, bool enabled);
};

class WhiteBalanceQueryImpl : virtual public SessionBase {
public:
    explicit WhiteBalanceQueryImpl() {}
    virtual ~WhiteBalanceQueryImpl() = default;
    virtual bool IsWhiteBalanceModeSupported(WhiteBalanceMode mode);
    virtual array<int32_t> GetWhiteBalanceRange();
};

class WhiteBalanceImpl : public WhiteBalanceQueryImpl {
public:
    explicit WhiteBalanceImpl() {}
    virtual ~WhiteBalanceImpl() = default;
    virtual void SetWhiteBalance(int32_t whiteBalance);
    virtual int32_t GetWhiteBalance();
    virtual void SetWhiteBalanceMode(WhiteBalanceMode mode);
    virtual WhiteBalanceMode GetWhiteBalanceMode();
};

class ManualExposureQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit ManualExposureQueryImpl() {}
    virtual ~ManualExposureQueryImpl() = default;
    virtual array<int32_t> GetSupportedExposureRange();
};

class ManualExposureImpl : public ManualExposureQueryImpl {
public:
    explicit ManualExposureImpl() {}
    virtual ~ManualExposureImpl() = default;
    virtual int32_t GetExposure();
    virtual void SetExposure(int32_t exposure);
};

class ColorEffectQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit ColorEffectQueryImpl() {}
    virtual ~ColorEffectQueryImpl() = default;
    array<ColorEffectType> GetSupportedColorEffects();
};

class ColorEffectImpl : public ColorEffectQueryImpl {
public:
    explicit ColorEffectImpl() {}
    virtual ~ColorEffectImpl() = default;
    void SetColorEffect(ColorEffectType type);
    ColorEffectType GetColorEffect();
};

class ManualIsoQueryImpl : virtual public SessionBase {
public:
    explicit ManualIsoQueryImpl() {}
    virtual ~ManualIsoQueryImpl() = default;
    virtual array<int32_t> GetIsoRange();
    virtual bool IsManualIsoSupported();
};

class ManualIsoImpl : public ManualIsoQueryImpl {
public:
   explicit ManualIsoImpl() {}
    virtual ~ManualIsoImpl() = default;
    virtual void SetIso(int32_t iso);
    virtual int32_t GetIso();
};

class ApertureQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit ApertureQueryImpl() {}
    virtual ~ApertureQueryImpl() = default;
    array<PhysicalAperture> GetSupportedPhysicalApertures();
    array<double> GetSupportedVirtualApertures();
};

class ApertureImpl : public ApertureQueryImpl {
public:
    explicit ApertureImpl() {}
    virtual ~ApertureImpl() = default;
    void SetVirtualAperture(double aperture);
    double GetVirtualAperture();
    void SetPhysicalAperture(double aperture);
    double GetPhysicalAperture();
};

class EffectSuggestionImpl : virtual public SessionBase {
public:
    explicit EffectSuggestionImpl() {}
    virtual ~EffectSuggestionImpl() = default;
    void SetEffectSuggestionStatus(array_view<EffectSuggestionStatus> status);
    void UpdateEffectSuggestion(EffectSuggestionType type, bool enabled);
    void EnableEffectSuggestion(bool enabled);
    bool IsEffectSuggestionSupported();
    array<EffectSuggestionType> GetSupportedEffectSuggestionTypes();
};

class MacroQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit MacroQueryImpl() {}
    virtual ~MacroQueryImpl() = default;
    bool IsMacroSupported();
};

class MacroImpl : public MacroQueryImpl {
public:
    explicit MacroImpl() {}
    virtual ~MacroImpl() = default;
    void EnableMacro(bool enabled);
};

class ManualFocusImpl : virtual public SessionBase {
public:
    explicit ManualFocusImpl() {}
    virtual ~ManualFocusImpl() = default;
    double GetFocusDistance();
    void SetFocusDistance(double distance);
};

class PortraitQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit PortraitQueryImpl() {}
    virtual ~PortraitQueryImpl() = default;
    virtual array<PortraitEffect> GetSupportedPortraitEffects();
};

class PortraitImpl : public PortraitQueryImpl {
public:
    explicit PortraitImpl() {}
    virtual ~PortraitImpl() = default;
    virtual void SetPortraitEffect(PortraitEffect effect);
    virtual PortraitEffect GetPortraitEffect();
};

class DepthFusionQueryImpl : virtual public SessionBase, virtual public FunctionBase {
public:
    explicit DepthFusionQueryImpl() {}
    virtual ~DepthFusionQueryImpl() = default;
    bool IsDepthFusionSupported();
    array<double> GetDepthFusionThreshold();
};

class DepthFusionImpl : public DepthFusionQueryImpl {
public:
    explicit DepthFusionImpl() {}
    virtual ~DepthFusionImpl() = default;
    void EnableDepthFusion(bool enabled);
    bool IsDepthFusionEnabled();
};

class AutoDeviceSwitchQueryImpl : virtual public SessionBase {
public:
    explicit AutoDeviceSwitchQueryImpl() {}
    virtual ~AutoDeviceSwitchQueryImpl() = default;
    bool IsAutoDeviceSwitchSupported();
};

class AutoDeviceSwitchImpl : public AutoDeviceSwitchQueryImpl {
public:
    explicit AutoDeviceSwitchImpl() {}
    virtual ~AutoDeviceSwitchImpl() = default;
    void EnableAutoDeviceSwitch(bool enabled);
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_QUERY_CAMERA_QUERY_TAIHE_H