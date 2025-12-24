/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_EX_PROXY_H_
#define CAMERA_NAPI_EX_PROXY_H_

#include "camera_dynamic_loader.h"
#include "napi/native_node_api.h"
#include "output/capture_output.h"

namespace OHOS {
namespace CameraStandard {
class CameraNapiExProxy {
public:
    static std::shared_ptr<CameraNapiExProxy> GetCameraNapiExProxy();

    explicit CameraNapiExProxy(std::shared_ptr<Dynamiclib> napiExLib);
    ~CameraNapiExProxy();
    napi_value CreateSessionForSys(napi_env env, int32_t jsModeName);
    napi_value CreateDeprecatedSessionForSys(napi_env env);
    napi_value CreateDepthDataOutput(napi_env env, DepthProfile& depthProfile);
    napi_value CreateMovieFileOutput(napi_env env, VideoProfile& videoProfile);
    napi_value CreateModeManager(napi_env env);

    bool CheckAndGetOutput(napi_env env, napi_value obj, sptr<CaptureOutput> &output);

private:
    std::shared_ptr<Dynamiclib> napiExLib_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_NAPI_EX_PROXY_H_