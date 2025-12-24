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

#ifndef STITCHING_PHOTO_SESSION_NAPI_H
#define STITCHING_PHOTO_SESSION_NAPI_H

#include "output/preview_output.h"
#include "session/camera_session_for_sys_napi.h"
#include "session/stitching_photo_session.h"

namespace OHOS {
namespace CameraStandard {
static const char STITCHING_PHOTO_SESSION_NAPI_CLASS_NAME[] = "StitchingPhotoSession";

template<typename InfoTp>
class NapiInfoCallback;

using StitchingTargetInfoCallbackListener = NapiInfoCallback<StitchingTargetInfo>;
using StitchingCaptureInfoCallbackListener = NapiInfoCallback<StitchingCaptureInfo>;
using StitchingHintInfoCallbackListener = NapiInfoCallback<StitchingHintInfo>;
using StitchingCaptureStateCallbackListener = NapiInfoCallback<StitchingCaptureStateInfo>;
class StitchingSurfaceListener;

class StitchingPhotoSessionNapi : public CameraSessionForSysNapi {
private:
    sptr<StitchingPhotoSession> GetSession()
    {
        return stitchingPhotoSession_;
    }
    using Adaptor =
        CameraNapiAdaptor<StitchingPhotoSessionNapi, StitchingPhotoSession, &StitchingPhotoSessionNapi::GetSession>;
    friend Adaptor;

public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    StitchingPhotoSessionNapi();
    ~StitchingPhotoSessionNapi() override;

    static napi_value StitchingPhotoSessionNapiConstructor(napi_env env, napi_callback_info info);
    static void StitchingPhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    static napi_value SetStitchingType(napi_env env, napi_callback_info info);
    static napi_value GetStitchingType(napi_env env, napi_callback_info info);
    static napi_value SetStitchingDirection(napi_env env, napi_callback_info info);
    static napi_value GetStitchingDirection(napi_env env, napi_callback_info info);
    static napi_value SetMovingClockwise(napi_env env, napi_callback_info info);
    static napi_value GetMovingClockwise(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    sptr<StitchingPhotoSession> stitchingPhotoSession_;
    std::shared_ptr<StitchingTargetInfoCallbackListener> stitchingTargetInfoCallbackListener_ = nullptr;
    std::shared_ptr<StitchingCaptureInfoCallbackListener> stitchingCaptureInfoCallbackListener_ = nullptr;
    std::shared_ptr<StitchingHintInfoCallbackListener> stitchingHintInfoCallbackListener_ = nullptr;
    std::shared_ptr<StitchingCaptureStateCallbackListener> stitchingCaptureStateCallbackListener_ = nullptr;
    std::shared_ptr<StitchingSurfaceListener> stitchingSurfaceLister_ = nullptr;
    static const std::vector<napi_property_descriptor> manual_stitching_funcs_;

protected:
    void RegisterStitchingTargetInfoCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterStitchingTargetInfoCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterStitchingCaptureInfoCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterStitchingCaptureInfoCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterStitchingHintInfoCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterStitchingHintInfoCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterStitchingCaptureStateCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterStitchingCaptureStateCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;

private:
    static thread_local sptr<StitchingPhotoSession> sStitchingPhotoSession_;
    static thread_local napi_ref sConstructor_;
    static thread_local sptr<PreviewOutput> sPreviewOutput_;
    static thread_local uint32_t previewOutputTaskId;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* STITCHING_PHOTO_SESSION_NAPI_H */
