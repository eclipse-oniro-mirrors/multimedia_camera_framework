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

#ifndef CAMERA_SESSION_NAPI_H_
#define CAMERA_SESSION_NAPI_H_

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"

#include "input/camera_manager.h"
#include "input/camera_device.h"
#include "session/capture_session.h"

#include "input/camera_input_napi.h"
#include "output/photo_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "output/metadata_output_napi.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_SESSION_NAPI_CLASS_NAME[] = "CaptureSession";

enum SessionAsyncCallbackModes {
    COMMIT_CONFIG_ASYNC_CALLBACK,
    SESSION_START_ASYNC_CALLBACK,
    SESSION_STOP_ASYNC_CALLBACK,
    SESSION_RELEASE_ASYNC_CALLBACK,
};

class ExposureCallbackListener : public ExposureCallback {
public:
    ExposureCallbackListener(napi_env env, napi_ref ref) : env_(env), callbackRef_(ref) {}
    ~ExposureCallbackListener() = default;
    void OnExposureState(const ExposureState state) override;

private:
    void OnExposureStateCallback(ExposureState state) const;
    void OnExposureStateCallbackAsync(ExposureState state) const;

    napi_env env_;
    napi_ref callbackRef_ = nullptr;
};

struct ExposureCallbackInfo {
    ExposureCallback::ExposureState state_;
    const ExposureCallbackListener* listener_;
    ExposureCallbackInfo(ExposureCallback::ExposureState state, const ExposureCallbackListener* listener)
        : state_(state), listener_(listener) {}
};

class FocusCallbackListener : public FocusCallback {
public:
    FocusCallbackListener(napi_env env, napi_ref ref) : env_(env), callbackRef_(ref) {}
    ~FocusCallbackListener() = default;
    void OnFocusState(FocusState state) override;

private:
    void OnFocusStateCallback(FocusState state) const;
    void OnFocusStateCallbackAsync(FocusState state) const;

    napi_env env_;
    napi_ref callbackRef_ = nullptr;
};

struct FocusCallbackInfo {
    FocusCallback::FocusState state_;
    const FocusCallbackListener* listener_;
    FocusCallbackInfo(FocusCallback::FocusState state, const FocusCallbackListener* listener)
        : state_(state), listener_(listener) {}
};

class SessionCallbackListener : public SessionCallback {
public:
    SessionCallbackListener(napi_env env, napi_ref ref) : env_(env), callbackRef_(ref) {}
    ~SessionCallbackListener() = default;
    void OnError(int32_t errorCode) override;

private:
    void OnErrorCallback(int32_t errorCode) const;
    void OnErrorCallbackAsync(int32_t errorCode) const;

    napi_env env_;
    napi_ref callbackRef_ = nullptr;
};

struct SessionCallbackInfo {
    int32_t errorCode_;
    const SessionCallbackListener* listener_;
    SessionCallbackInfo(int32_t errorCode, const SessionCallbackListener* listener)
        : errorCode_(errorCode), listener_(listener) {}
};

class CameraSessionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    CameraSessionNapi();
    ~CameraSessionNapi();

    static void CameraSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraSessionNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value HasFlash(napi_env env, napi_callback_info info);
    static napi_value IsFlashModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFlashMode(napi_env env, napi_callback_info info);
    static napi_value SetFlashMode(napi_env env, napi_callback_info info);
    static napi_value IsExposureModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetExposureMode(napi_env env, napi_callback_info info);
    static napi_value SetExposureMode(napi_env env, napi_callback_info info);
    static napi_value SetMeteringPoint(napi_env env, napi_callback_info info);
    static napi_value GetMeteringPoint(napi_env env, napi_callback_info info);
    static napi_value GetExposureBiasRange(napi_env env, napi_callback_info info);
    static napi_value SetExposureBias(napi_env env, napi_callback_info info);
    static napi_value GetExposureValue(napi_env env, napi_callback_info info);
    static napi_value IsFocusModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusMode(napi_env env, napi_callback_info info);
    static napi_value SetFocusMode(napi_env env, napi_callback_info info);
    static napi_value SetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocalLength(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatioRange(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatio(napi_env env, napi_callback_info info);
    static napi_value SetZoomRatio(napi_env env, napi_callback_info info);

    static napi_value BeginConfig(napi_env env, napi_callback_info info);
    static napi_value CommitConfig(napi_env env, napi_callback_info info);

    static napi_value AddInput(napi_env env, napi_callback_info info);
    static napi_value CanAddInput(napi_env env, napi_callback_info info);
    static napi_value RemoveInput(napi_env env, napi_callback_info info);

    static napi_value AddOutput(napi_env env, napi_callback_info info);
    static napi_value CanAddOutput(napi_env env, napi_callback_info info);
    static napi_value RemoveOutput(napi_env env, napi_callback_info info);

    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetActiveVideoStabilizationMode(napi_env env, napi_callback_info info);
    static napi_value SetVideoStabilizationMode(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);

    static napi_value LockForControl(napi_env env, napi_callback_info info);
    static napi_value UnlockForControl(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    sptr<CaptureSession> cameraSession_;

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<CaptureSession> sCameraSession_;
    static thread_local uint32_t cameraSessionTaskId;
};

struct CameraSessionAsyncContext : public AsyncContext {
    CameraSessionNapi* objectInfo;

    SessionAsyncCallbackModes modeForAsync;
    std::string errorMsg;
    bool bRetBool;
    ~CameraSessionAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_SESSION_NAPI_H_ */
