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

#ifndef CAMERA_PICKER_NAPI_H
#define CAMERA_PICKER_NAPI_H
#include "camera_log.h"
#include "camera_napi_utils.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace CameraStandard {

typedef struct {
    string saveUri;
    CameraPosition cameraPosition;
    int videoDuration;
} VideoProfileForPicker;

typedef struct {
    string saveUri;
    CameraPosition cameraPosition;
} PhotoProfileForPicker;

static const char CAMERA_PICKER_NAPI_CLASS_NAME[] = "CameraPicker";

class CameraPickerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value TakePhoto(napi_env env, napi_callback_info info);
    static napi_value RecordVideo(napi_env env, napi_callback_info info);
    static napi_value CreateCameraPicker(napi_env env);
    static napi_value CameraPickerNapiConstructor(napi_env env, napi_callback_info info);
    static void CameraPickerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    CameraPickerNapi();
    ~CameraPickerNapi();
    static VideoProfileForPicker videoProfile_;
    static PhotoProfileForPicker photoProfile_;

private:
    napi_env env_;
    napi_ref wrapper_;
    static thread_local napi_ref sConstructor_;
};

} // namespace CameraStandard
} // namespace OHOS

#endif /* CAMERA_PICKER_NAPI_H */
