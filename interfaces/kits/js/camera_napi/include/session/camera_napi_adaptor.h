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
#ifndef CAMERA_NAPI_BASE_OP_H
#define CAMERA_NAPI_BASE_OP_H

#include "refbase.h"
#include "napi_info_callback.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
class CaptureSession;

template<typename TSessionNapi, typename TSession, sptr<TSession> (TSessionNapi::*GetSession)()>
class CameraNapiAdaptor {
public:
    template<typename T,
        typename = std::enable_if_t<std::is_same_v<T, bool> || std::is_same_v<T, int32_t> ||
            std::is_same_v<T, int64_t> || std::is_same_v<T, uint32_t> || std::is_same_v<T, int8_t> ||
            std::is_same_v<T, uint8_t> || std::is_same_v<T, double> || std::is_same_v<T, std::string> ||
            std::is_enum_v<T> || std::is_same_v<T, Size>>>
    static napi_value SetArg(napi_env env, napi_callback_info info, int32_t (TSession::*setFunc)(T))
    {
        return SetArgImpl(env, info, setFunc);
    }

    template<typename T,
        typename = std::enable_if_t<std::is_same_v<T, bool> || std::is_same_v<T, int32_t> ||
            std::is_same_v<T, int64_t> || std::is_same_v<T, uint32_t> || std::is_same_v<T, int8_t> ||
            std::is_same_v<T, uint8_t> || std::is_same_v<T, double> || std::is_same_v<T, std::string> ||
            std::is_enum_v<T> || std::is_same_v<T, Size>>>
    static napi_value SetArg(napi_env env, napi_callback_info info, int32_t (TSession::*setFunc)(const T&))
    {
        return SetArgImpl(env, info, setFunc);
    }

private:
    template<typename U>
    static napi_value SetArgImpl(napi_env env, napi_callback_info info, int32_t (TSession::*setFunc)(U))
    {
        using T = typename std::remove_const<typename std::remove_reference<U>::type>::type;
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        if constexpr (std::is_same_v<T, Size>) {
            uint32_t height;
            uint32_t width;
            CameraNapiObject napiSize { { { "height", &height }, { "width", &width } } };
            auto napiObjToNative = [](const CameraNapiObject& napiObj) -> Size {
                uint32_t height;
                uint32_t width;
                napiObj.GetFieldMapValueByKey("height", height);
                napiObj.GetFieldMapValueByKey("width", width);
                return { width, height };
            };
            return SetArg<Size>(env, info, setFunc, napiObjToNative, napiSize);
        }
        auto result = CameraNapiUtils::GetUndefinedValue(env);
        TSessionNapi* sessionNapi = nullptr;
        T arg;
        bool parseStatus;
        if constexpr (std::is_same_v<T, bool> || std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t> ||
            std::is_same_v<T, uint32_t> || std::is_same_v<T, int8_t> || std::is_same_v<T, uint8_t> ||
            std::is_same_v<T, double> || std::is_same_v<T, std::string>) {
            CameraNapiParamParser jsParamParser(env, info, sessionNapi, arg);
            parseStatus = jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error");
        } else if constexpr (std::is_enum_v<T>) {
            using UnderlyingTp = std::underlying_type_t<T>;
            UnderlyingTp uArg;
            CameraNapiParamParser jsParamParser(env, info, sessionNapi, uArg);
            parseStatus = jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error");
            arg = static_cast<T>(uArg);
        } else {
            MEDIA_ERR_LOG("Wrong type");
            return nullptr;
        }
        CHECK_RETURN_RET_ELOG(!parseStatus, result, "%{public}s parse parameter occur error", __PRETTY_FUNCTION__);

        sptr<TSession> sessionNative = sessionNapi->GetSession();
        if (sessionNative == nullptr) {
            MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
            CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
            return nullptr;
        }
        int retCode = (sessionNative->*setFunc)(arg);
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), result, "%{public}s fail! %{public}d",
            __PRETTY_FUNCTION__, retCode);
        return result;
    }

    template<typename NativeStructTp>
    static napi_value SetArg(napi_env env, napi_callback_info info, int32_t (TSession::*setFunc)(NativeStructTp),
        std::function<NativeStructTp(const CameraNapiObject&)> napiObjToNativeFunc, CameraNapiObject napiObj)
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        auto result = CameraNapiUtils::GetUndefinedValue(env);
        TSessionNapi* sessionNapi = nullptr;
        CameraNapiParamParser jsParamParser(env, info, sessionNapi, napiObj);
        bool parseStatus = jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error");
        CHECK_RETURN_RET_ELOG(!parseStatus, result, "%{public}s parse parameter occur error", __PRETTY_FUNCTION__);

        sptr<TSession> sessionNative = sessionNapi->GetSession();
        if (sessionNative == nullptr) {
            MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
            CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
            return nullptr;
        }
        int retCode = (sessionNative->*setFunc)(napiObjToNativeFunc(napiObj));
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), result, "%{public}s fail! %{public}d",
            __PRETTY_FUNCTION__, retCode);
        return result;
    }

public:
    template<typename T,
        typename = std::enable_if_t<std::is_same_v<T, bool> || std::is_same_v<T, int32_t> ||
            std::is_same_v<T, int64_t> || std::is_same_v<T, uint32_t> || std::is_same_v<T, uint8_t> ||
            std::is_same_v<T, int8_t> || std::is_same_v<T, double> || std::is_same_v<T, std::string> ||
            std::is_enum_v<T> || std::is_same_v<T, std::vector<bool>> || std::is_same_v<T, std::vector<int32_t>> ||
            std::is_same_v<T, std::vector<int64_t>> || std::is_same_v<T, std::vector<uint32_t>> ||
            std::is_same_v<T, std::vector<int8_t>> || std::is_same_v<T, std::vector<uint8_t>> ||
            std::is_same_v<T, std::vector<double>> || std::is_same_v<T, std::vector<std::string>> ||
            std::is_same_v<T, std::vector<Size>>>>
    static napi_value GetArg(napi_env env, napi_callback_info info, int32_t (TSession::*getFunc)(T&))
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        auto result = CameraNapiUtils::GetUndefinedValue(env);
        TSessionNapi* sessionNapi = nullptr;
        CameraNapiParamParser jsParamParser(env, info, sessionNapi);
        CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), result,
            "%{public}s parse parameter occur error", __PRETTY_FUNCTION__);
        sptr<TSession> sessionNative = sessionNapi->GetSession();
        if (sessionNative == nullptr) {
            MEDIA_ERR_LOG("%{public}s get native object fail", __PRETTY_FUNCTION__);
            CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
            return nullptr;
        }
        T arg;
        int32_t retCode = (sessionNative->*getFunc)(arg);

        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), result, "%{public}s fail! %{public}d",
            __PRETTY_FUNCTION__, retCode);
        result = CameraNapiUtils::ToNapiValue(env, arg);
        return result;
    }

    template<typename T>
    static void RegCallback(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce, std::shared_ptr<NapiInfoCallback<T>>& NapiInfoCb,
        int32_t (TSession::*setCbFunc)(std::shared_ptr<NativeInfoCallback<T>>), sptr<TSession> sessionNative)
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        if (sessionNative == nullptr) {
            CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
            return;
        }
        if (NapiInfoCb == nullptr && setCbFunc) {
            MEDIA_INFO_LOG("%{public}s NapiInfoCb is empty, to reg", __PRETTY_FUNCTION__);
            auto napiCallback = std::make_shared<NapiInfoCallback<T>>(env);
            auto ret = (sessionNative->*setCbFunc)(napiCallback);
            if (ret != SUCCESS) {
                MEDIA_INFO_LOG("%{public}s setCbFunc fail", __PRETTY_FUNCTION__);
                CameraNapiUtils::ThrowError(env, ret, "setCbFunc fail");
                return;
            }
            NapiInfoCb = napiCallback;
        }
        NapiInfoCb->SaveCallbackReference(eventName, callback, isOnce);
        MEDIA_INFO_LOG("%{public}s success", __PRETTY_FUNCTION__);
    }

    template<typename T>
    static void UnregCallback(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, std::shared_ptr<NapiInfoCallback<T>>& NapiInfoCb,
        int32_t (TSession::*unSetCbFunc)(), sptr<TSession> sessionNative)
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        if (NapiInfoCb == nullptr) {
            MEDIA_ERR_LOG("%{public}s listener is nullptr", __PRETTY_FUNCTION__);
            return;
        }
        if (sessionNative && unSetCbFunc) {
            auto ret = (sessionNative->*unSetCbFunc)();
            if (ret != SUCCESS) {
                CameraNapiUtils::ThrowError(env, ret, "unset callback fail");
                return;
            }
        } else {
            MEDIA_WARNING_LOG("%{public}s unSetCbFunc or sessionNative is nullptr", __PRETTY_FUNCTION__);
        }
        NapiInfoCb->RemoveCallbackRef(eventName, callback);
        NapiInfoCb = nullptr;
        MEDIA_INFO_LOG("%{public}s success", __PRETTY_FUNCTION__);
    }

    template<typename T>
    static void UnregCallback(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, std::shared_ptr<NapiInfoCallback<T>>& NapiInfoCb)
    {
        MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
        UnregCallback(eventName, env, callback, args, NapiInfoCb, nullptr, nullptr);
    }
};
} // namespace CameraStandard
} // namespace OHOS

#endif