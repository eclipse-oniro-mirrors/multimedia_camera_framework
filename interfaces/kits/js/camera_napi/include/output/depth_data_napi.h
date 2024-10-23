/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef DEPTH_DATA_NAPI_H_
#define DEPTH_DATA_NAPI_H_

#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
static const char DEPTH_DATA_NAPI_CLASS_NAME[] = "DepthData";

class DepthDataNapi {
public:
    DepthDataNapi();
    ~DepthDataNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateDepthData(napi_env env, napi_value format, napi_value depthMap, napi_value qualityLevel,
                                      napi_value accuracy);

    static napi_value GetFormat(napi_env env, napi_callback_info info);
    static napi_value GetDepthMap(napi_env env, napi_callback_info info);
    static napi_value GetQualityLevel(napi_env env, napi_callback_info info);
    static napi_value GetAccuracy(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

private:
    static napi_value DepthDataNapiConstructor(napi_env env, napi_callback_info info);
    static void DepthDataNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    static thread_local napi_ref sConstructor_;
    static thread_local napi_value sFormat_;
    static thread_local napi_value sDepthMap_;
    static thread_local napi_value sQualityLevel_;
    static thread_local napi_value sAccuracy_;
    static thread_local uint32_t depthDataTaskId;

    napi_env env_;
    napi_value format_;
    napi_value depthMap_;
    napi_value qualityLevel_;
    napi_value accuracy_;
};

struct DepthDataAsyncContext : public AsyncContext {
    DepthDataNapi* objectInfo;

    ~DepthDataAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif // DEPTH_DATA_NAPI_H_