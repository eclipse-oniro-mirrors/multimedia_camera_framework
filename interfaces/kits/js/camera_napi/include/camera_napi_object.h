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

#ifndef CAMERA_NAPI_OBJECT_H
#define CAMERA_NAPI_OBJECT_H

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
struct CameraNapiObject {
public:
    typedef std::variant<bool*, int32_t*, uint32_t*, int64_t*, float*, double*, std::string*, CameraNapiObject*,
        napi_value, std::vector<int32_t>*, std::list<CameraNapiObject>*>
        NapiVariantBindAddr;

    typedef std::unordered_map<std::string, NapiVariantBindAddr> CameraNapiObjFieldMap;

    CameraNapiObject(CameraNapiObjFieldMap fieldMap) : fieldMap_(fieldMap) {}

    napi_status ParseNapiObjectToMap(napi_env env, napi_value napiObject)
    {
        napi_valuetype type = napi_undefined;
        napi_typeof(env, napiObject, &type);
        if (type != napi_object) {
            return napi_invalid_arg;
        }
        for (auto& it : fieldMap_) {
            NapiVariantBindAddr& bindAddr = it.second;
            napi_value napiObjValue = nullptr;
            napi_status res = napi_get_named_property(env, napiObject, it.first.c_str(), &napiObjValue);
            if (res != napi_ok) {
                return res;
            }
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, napiObjValue, &valueType);
            if (valueType == napi_undefined && optionalKeys_.find(it.first) != optionalKeys_.end()) {
                continue;
            }
            if (std::holds_alternative<bool*>(bindAddr)) {
                res = GetVariantBoolFromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<int32_t*>(bindAddr)) {
                res = GetVariantInt32FromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<uint32_t*>(bindAddr)) {
                res = GetVariantUint32FromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<int64_t*>(bindAddr)) {
                res = GetVariantInt64FromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<float*>(bindAddr)) {
                res = GetVariantFloatFromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<double*>(bindAddr)) {
                res = GetVariantDoubleFromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<std::string*>(bindAddr)) {
                res = GetVariantStringFromNapiValue(env, napiObjValue, bindAddr);
            } else if (std::holds_alternative<CameraNapiObject*>(bindAddr)) {
                res = GetVariantCameraNapiObjectFromNapiValue(env, napiObjValue, bindAddr);
            } else {
                res = napi_invalid_arg;
            }
            if (res != napi_ok) {
                return res;
            }
            settedKeys_.emplace(it.first);
        }
        return napi_ok;
    };

    void SetOptionalKeys(std::unordered_set<std::string>& keys)
    {
        optionalKeys_ = keys;
    }

    bool IsKeySetted(const std::string& key)
    {
        return settedKeys_.find(key) != settedKeys_.end();
    }

    napi_value CreateNapiObjFromMap(napi_env env)
    {
        napi_value result = nullptr;
        if (fieldMap_.empty()) {
            napi_get_undefined(env, &result);
            return result;
        }
        napi_create_object(env, &result);
        for (auto& it : fieldMap_) {
            NapiVariantBindAddr& bindAddr = it.second;
            napi_value fieldValue = std::visit(CreateNapiObjVisitor(env), bindAddr);
            napi_set_named_property(env, result, it.first.c_str(), fieldValue);
        }
        return result;
    }

private:
    class CreateNapiObjVisitor {
    public:
        explicit CreateNapiObjVisitor(napi_env& env) : env_(env) {}
        napi_value operator()(bool*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_get_boolean(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(int32_t*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_int32(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(uint32_t*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_uint32(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(int64_t*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_int64(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(float*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_double(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(double*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_double(env_, *variantAddr, &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(std::string*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_string_utf8(env_, variantAddr->c_str(), variantAddr->size(), &result);
            return status == napi_ok ? result : nullptr;
        }
        napi_value operator()(CameraNapiObject*& variantAddr)
        {
            return variantAddr->CreateNapiObjFromMap(env_);
        }
        napi_value operator()(napi_value& variantAddr)
        {
            return variantAddr;
        }
        napi_value operator()(std::vector<int32_t>*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_array(env_, &result);
            if (status != napi_ok) {
                return nullptr;
            }
            auto& nativeArray = *variantAddr;
            for (size_t i = 0; i < nativeArray.size(); i++) {
                napi_value item = nullptr;
                napi_create_int32(env_, nativeArray[i], &item);
                if (napi_set_element(env_, result, i, item) != napi_ok) {
                    return nullptr;
                }
            }
            return result;
        }
        napi_value operator()(std::list<CameraNapiObject>*& variantAddr)
        {
            napi_value result = nullptr;
            napi_status status = napi_create_array(env_, &result);
            if (status != napi_ok) {
                return nullptr;
            }
            auto& nativeArray = *variantAddr;
            size_t index = 0;
            for (auto& obj : nativeArray) {
                if (napi_set_element(env_, result, index, obj.CreateNapiObjFromMap(env_)) != napi_ok) {
                    return nullptr;
                }
                index++;
            }
            return result;
        }

    private:
        napi_env& env_;
    };

    napi_status GetVariantBoolFromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_boolean)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<bool*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return napi_get_value_bool(env, napiValue, *variantAddrPointer);
    };

    napi_status GetVariantInt32FromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_number)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<int32_t*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return napi_get_value_int32(env, napiValue, *variantAddrPointer);
    };

    napi_status GetVariantUint32FromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_number)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<uint32_t*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return napi_get_value_uint32(env, napiValue, *variantAddrPointer);
    };

    napi_status GetVariantInt64FromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_number)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<int64_t*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return napi_get_value_int64(env, napiValue, *variantAddrPointer);
    };

    napi_status GetVariantFloatFromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_number)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<float*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        double tmpData = 0;
        napi_status res = napi_get_value_double(env, napiValue, &tmpData);
        **variantAddrPointer = tmpData;
        return res;
    };

    napi_status GetVariantDoubleFromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_number)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<double*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return napi_get_value_double(env, napiValue, *variantAddrPointer);
    };

    napi_status GetVariantStringFromNapiValue(napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_string)) {
            return napi_invalid_arg;
        }

        auto variantAddrPointer = std::get_if<std::string*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }

        size_t stringSize = 0;
        napi_status res = napi_get_value_string_utf8(env, napiValue, nullptr, 0, &stringSize);
        if (res != napi_ok) {
            return res;
        }
        auto& stringValue = **variantAddrPointer;
        stringValue.resize(stringSize);
        res = napi_get_value_string_utf8(env, napiValue, stringValue.data(), stringSize + 1, &stringSize);
        return res;
    };

    napi_status GetVariantCameraNapiObjectFromNapiValue(
        napi_env env, napi_value napiValue, NapiVariantBindAddr& variantAddr)
    {
        if (!ValidNapiType(env, napiValue, napi_object)) {
            return napi_invalid_arg;
        }
        auto variantAddrPointer = std::get_if<CameraNapiObject*>(&variantAddr);
        if (variantAddrPointer == nullptr) {
            return napi_invalid_arg;
        }
        return (*variantAddrPointer)->ParseNapiObjectToMap(env, napiValue);
    }

    bool ValidNapiType(napi_env env, napi_value napiObjValue, napi_valuetype valueType)
    {
        napi_valuetype objValueType = napi_undefined;
        napi_status res = napi_typeof(env, napiObjValue, &objValueType);
        if (res != napi_ok) {
            return false;
        }
        return objValueType == valueType;
    }

    CameraNapiObjFieldMap fieldMap_;
    std::unordered_set<std::string> optionalKeys_;
    std::unordered_set<std::string> settedKeys_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_OBJECT_H */
