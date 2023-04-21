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

#ifndef CAMERA_INPUT_NAPI_H_
#define CAMERA_INPUT_NAPI_H_

#include <securec.h>

#include "display_type.h"
#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hilog/log.h"
#include "camera_napi_utils.h"

#include "input/camera_manager.h"
#include "input/camera_input.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "input/camera_size_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_INPUT_NAPI_CLASS_NAME[] = "CameraInput";

enum InputAsyncCallbackModes {
    DEEAULT_ASYNC_CALLBACK = -1,
    OPEN_ASYNC_CALLBACK = 1,
    CLOSE_ASYNC_CALLBACK = 2,
    RELEASE_ASYNC_CALLBACK = 3,
};

struct CameraInputAsyncContext;

class ErrorCallbackListener : public ErrorCallback {
public:
    ErrorCallbackListener(napi_env env, napi_ref ref) : env_(env), callbackRef_(ref) {}
    ~ErrorCallbackListener() = default;
    void OnError(const int32_t errorType, const int32_t errorMsg) const override;

private:
    void OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const;
    void OnErrorCallbackAsync(const int32_t errorType, const int32_t errorMsg) const;

    napi_env env_;
    napi_ref callbackRef_ = nullptr;
};

struct ErrorCallbackInfo {
    int32_t errorType_;
    int32_t errorMsg_;
    const ErrorCallbackListener* listener_;
    ErrorCallbackInfo(int32_t errorType, int32_t errorMsg, const ErrorCallbackListener* listener)
        : errorType_(errorType), errorMsg_(errorMsg), listener_(listener) {}
};

class CameraInputNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraInput(napi_env env, sptr<CameraInput> cameraInput);
    CameraInputNapi();
    ~CameraInputNapi();

    static void NapiCreateInt32Logs(
        napi_env env, int32_t contextMode, std::unique_ptr<JSAsyncContextOutput> &jsContext);
    static void NapiCreateDoubleLogs(
        napi_env env, double contextMode, std::unique_ptr<JSAsyncContextOutput> &jsContext);

    static napi_value Open(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);

    sptr<CameraInput> GetCameraInput();
private:
    static void CameraInputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraInputNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    std::string cameraId_;
    sptr<CameraInput> cameraInput_;

    void RegisterCallback(napi_env env, const std::string &eventType, napi_ref callbackRef);

    static thread_local napi_ref sConstructor_;
    static thread_local std::string sCameraId_;
    static thread_local sptr<CameraInput> sCameraInput_;
    static thread_local uint32_t cameraInputTaskId;
};

struct CameraInputAsyncContext :public AsyncContext {
    CameraInputNapi* objectInfo;
    bool bRetBool;
    bool isSupported;
    InputAsyncCallbackModes modeForAsync;
    std::string cameraId;
    std::string enumType;
    std::vector<CameraFormat> vecList;
    ~CameraInputAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_INPUT_NAPI_H_ */
