/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef TIME_LAPSE_PHOTO_SESSION_NAPI_H
#define TIME_LAPSE_PHOTO_SESSION_NAPI_H

#include "time_lapse_photo_session.h"
#include "mode/profession_session_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char TIME_LAPSE_PHOTO_SESSION_NAPI_CLASS_NAME[] = "TimeLapsePhotoSessionNapi";
static const char TRY_AE_INFO_NAPI_CLASS_NAME[] = "TryAEInfo";

class TryAEInfoCallbackListener : public TryAEInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<TryAEInfoCallbackListener> {
public:
    TryAEInfoCallbackListener(napi_env env) : ListenerBase(env) {}
    ~TryAEInfoCallbackListener() = default;
    void OnTryAEInfoChanged(TryAEInfo info) override;

private:
    void OnTryAEInfoChangedCallback(TryAEInfo info) const;
    void OnTryAEInfoChangedCallbackAsync(TryAEInfo info) const;
};

struct TryAEInfoChangedCallback {
    TryAEInfo info_;
    weak_ptr<const TryAEInfoCallbackListener> listener_;
    TryAEInfoChangedCallback(TryAEInfo info, shared_ptr<const TryAEInfoCallbackListener> listener)
        : info_(info), listener_(listener) {}
};

class TryAEInfoNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env);
    TryAEInfoNapi();
    virtual ~TryAEInfoNapi();

    static napi_value IsTryAEDone(napi_env env, napi_callback_info info);
    static napi_value IsTryAEHintNeeded(napi_env env, napi_callback_info info);
    static napi_value GetPreviewType(napi_env env, napi_callback_info info);
    static napi_value GetCaptureInterval(napi_env env, napi_callback_info info);

    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);

    unique_ptr<TryAEInfo> tryAEInfo_;
private:
    static thread_local napi_ref sConstructor_;
};

class TimeLapsePhotoSessionNapi : public CameraSessionNapi {
public:
    static const vector<napi_property_descriptor> time_lapse_photo_props;
    static const vector<napi_property_descriptor> manual_exposure_props;
    static const vector<napi_property_descriptor> manual_iso_props;
    static const vector<napi_property_descriptor> white_balance_props;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    TimeLapsePhotoSessionNapi();
    virtual ~TimeLapsePhotoSessionNapi();
    // TimeLapsePhotoSession
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value IsTryAENeeded(napi_env env, napi_callback_info info);
    static napi_value StartTryAE(napi_env env, napi_callback_info info);
    static napi_value StopTryAE(napi_env env, napi_callback_info info);
    static napi_value GetSupportedTimeLapseIntervalRange(napi_env env, napi_callback_info info);
    static napi_value GetTimeLapseInterval(napi_env env, napi_callback_info info);
    static napi_value SetTimeLapseInterval(napi_env env, napi_callback_info info);
    static napi_value SetTimeLapseRecordState(napi_env env, napi_callback_info info);
    static napi_value SetTimeLapsePreviewType(napi_env env, napi_callback_info info);
    // ManualExposure
    static napi_value GetExposure(napi_env env, napi_callback_info info);
    static napi_value SetExposure(napi_env env, napi_callback_info info);
    static napi_value GetSupportedExposureRange(napi_env env, napi_callback_info info);
    static napi_value GetSupportedMeteringModes(napi_env env, napi_callback_info info);
    static napi_value IsExposureMeteringModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetExposureMeteringMode(napi_env env, napi_callback_info info);
    static napi_value SetExposureMeteringMode(napi_env env, napi_callback_info info);
    // ManualIso
    static napi_value GetIso(napi_env env, napi_callback_info info);
    static napi_value SetIso(napi_env env, napi_callback_info info);
    static napi_value IsManualIsoSupported(napi_env env, napi_callback_info info);
    static napi_value GetIsoRange(napi_env env, napi_callback_info info);
    // WhiteBalance
    static napi_value IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalanceRange(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalanceMode(napi_env env, napi_callback_info info);
    static napi_value SetWhiteBalanceMode(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalance(napi_env env, napi_callback_info info);
    static napi_value SetWhiteBalance(napi_env env, napi_callback_info info);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);
    static thread_local napi_ref sConstructor_;

    sptr<TimeLapsePhotoSession> timeLapsePhotoSession_;

    shared_ptr<IsoInfoCallbackListener> isoInfoCallback_ = nullptr;
    shared_ptr<ExposureInfoCallbackListener> exposureInfoCallback_ = nullptr;
    shared_ptr<LuminationInfoCallbackListener> luminationInfoCallback_ = nullptr;
    shared_ptr<TryAEInfoCallbackListener> tryAEInfoCallback_ = nullptr;

protected:
    void RegisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
};

}
}
#endif