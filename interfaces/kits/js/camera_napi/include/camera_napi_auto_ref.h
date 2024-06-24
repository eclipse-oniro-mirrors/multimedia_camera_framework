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

#ifndef CAMERA_NAPI_AUTO_REF_H
#define CAMERA_NAPI_AUTO_REF_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
struct AutoRef {
public:
    AutoRef(napi_env env, napi_value callback, bool isOnce) : isOnce_(isOnce), env_(env)
    {
        (void)napi_create_reference(env_, callback, 1, &callbackRef_);
    }

    AutoRef(const AutoRef& other)
    {
        isOnce_ = other.isOnce_;
        env_ = other.env_;
        callbackRef_ = other.callbackRef_;
        if (env_ != nullptr && callbackRef_ != nullptr) {
            (void)napi_reference_ref(env_, callbackRef_, nullptr);
        }
    }

    AutoRef& operator=(const AutoRef& other)
    {
        AutoRef tmp(other);
        std::swap(isOnce_, tmp.isOnce_);
        std::swap(env_, tmp.env_);
        std::swap(callbackRef_, tmp.callbackRef_);
        return *this;
    }

    ~AutoRef()
    {
        if (env_ != nullptr && callbackRef_ != nullptr) {
            (void)napi_reference_unref(env_, callbackRef_, nullptr);
        }
    }

    napi_value GetCallbackFunction()
    {
        if (env_ == nullptr || callbackRef_ == nullptr) {
            return nullptr;
        }
        napi_value callback = nullptr;
        if (napi_get_reference_value(env_, callbackRef_, &callback) == napi_ok) {
            return callback;
        }
        return nullptr;
    }

    bool isOnce_ = false;

private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif