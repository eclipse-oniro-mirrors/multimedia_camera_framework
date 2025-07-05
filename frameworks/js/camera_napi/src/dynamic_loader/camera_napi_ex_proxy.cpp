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

#include "dynamic_loader/camera_napi_ex_proxy.h"

#include "camera_log.h"


namespace OHOS {
namespace CameraStandard {
std::shared_ptr<CameraNapiExProxy> CameraNapiExProxy::GetCameraNapiExProxy()
{
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(NAPI_EXT_SO);
    CHECK_ERROR_RETURN_RET_LOG(
        dynamiclib == nullptr, nullptr, "get extension lib fail");
    std::shared_ptr<CameraNapiExProxy> sessionForSysProxy = std::make_shared<CameraNapiExProxy>(dynamiclib);
    return sessionForSysProxy;
}
CameraNapiExProxy::CameraNapiExProxy(std::shared_ptr<Dynamiclib> napiExLib) : napiExLib_(
    napiExLib)
{
    MEDIA_DEBUG_LOG("CameraNapiExProxy construct");
    CHECK_ERROR_RETURN_LOG(napiExLib_ == nullptr, "napiExLib is null");
}

CameraNapiExProxy::~CameraNapiExProxy()
{
    MEDIA_DEBUG_LOG("CameraNapiExProxy destruct");
    CameraDynamicLoader::FreeDynamicLibDelayed(NAPI_EXT_SO);
    napiExLib_ = nullptr;
}

typedef napi_value (*CreateSessionInstanceForSys)(napi_env, int32_t);
napi_value CameraNapiExProxy::CreateSessionForSys(napi_env env, int32_t jsModeName)
{
    MEDIA_DEBUG_LOG("CameraNapiExManager::CreateSessionForSys is called");
    napi_value result = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(napiExLib_ == nullptr, result, "napiExLib_ is null");
    CreateSessionInstanceForSys createSessionInstanceForSys =
        (CreateSessionInstanceForSys)napiExLib_->GetFunction("createSessionInstanceForSys");
    CHECK_ERROR_RETURN_RET_LOG(
        createSessionInstanceForSys == nullptr, result, "get function createSessionInstanceForSys fail");
    result = createSessionInstanceForSys(env, jsModeName);
    CHECK_ERROR_RETURN_RET_LOG(
        result == nullptr, result, "createSessionInstanceForSys fail");
    return result;
}

typedef napi_value (*CreateDeprecatedSessionInstanceForSys)(napi_env);
napi_value CameraNapiExProxy::CreateDeprecatedSessionForSys(napi_env env)
{
    napi_value result = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(napiExLib_ == nullptr, result, "napiExLib_ is null");
    CreateDeprecatedSessionInstanceForSys createDeprecatedSessionInstanceForSys =
        (CreateDeprecatedSessionInstanceForSys)napiExLib_->GetFunction("createDeprecatedSessionInstanceForSys");
    CHECK_ERROR_RETURN_RET_LOG(createDeprecatedSessionInstanceForSys == nullptr, result,
        "get function createDeprecatedSessionInstanceForSys fail");
    result = createDeprecatedSessionInstanceForSys(env);
    CHECK_ERROR_RETURN_RET_LOG(
        result == nullptr, result, "createDeprecatedSessionInstanceForSys fail");
    return result;
}

typedef napi_value (*CreateDepthDataOutputInstance)(napi_env, DepthProfile&);
napi_value CameraNapiExProxy::CreateDepthDataOutput(napi_env env, DepthProfile& depthProfile)
{
    MEDIA_DEBUG_LOG("CameraNapiExManager::CreateDepthDataOutput is called");
    napi_value result = nullptr;
    CHECK_ERROR_RETURN_RET_LOG(napiExLib_ == nullptr, result, "napiExLib_ is null");
    CreateDepthDataOutputInstance createDepthDataOutputInstance =
        (CreateDepthDataOutputInstance)napiExLib_->GetFunction("createDepthDataOutputInstance");
    CHECK_ERROR_RETURN_RET_LOG(
        createDepthDataOutputInstance == nullptr, result, "get function createDepthDataOutputInstance fail");
    result = createDepthDataOutputInstance(env, depthProfile);
    CHECK_ERROR_RETURN_RET_LOG(
        result == nullptr, result, "createDepthDataOutputInstance fail");
    return result;
}

typedef bool (*CheckAndGetSysOutput)(napi_env, napi_value, sptr<CaptureOutput>&);
bool CameraNapiExProxy::CheckAndGetOutput(napi_env env, napi_value obj, sptr<CaptureOutput> &output)
{
    MEDIA_DEBUG_LOG("CameraNapiExManager::CheckAndGetOutput is called");
    bool result = false;
    CHECK_ERROR_RETURN_RET_LOG(napiExLib_ == nullptr, result, "napiExLib_ is null");
    CheckAndGetSysOutput checkAndGetOutput =
        (CheckAndGetSysOutput)napiExLib_->GetFunction("checkAndGetOutput");
    CHECK_ERROR_RETURN_RET_LOG(
        checkAndGetOutput == nullptr, result, "get function checkAndGetOutput fail");
    result = checkAndGetOutput(env, obj, output);
    return result;
}
} // namespace CameraStandard
} // namespace OHOS