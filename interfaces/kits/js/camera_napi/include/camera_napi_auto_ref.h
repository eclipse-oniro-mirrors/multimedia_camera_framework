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
#include "node_api.h"
#include "node_api_types.h"

namespace OHOS {
namespace CameraStandard {
struct AutoRef {
public:
    AutoRef(napi_env env, napi_value callback, bool isOnce) : isOnce_(isOnce), env_(env)
    {
        (void)napi_create_reference(env_, callback, 1, &callbackRef_);
        napi_create_string_utf8(env, "~AutoRef", NAPI_AUTO_LENGTH, &tsfnName_);
    }

    AutoRef(const AutoRef& other)
    {
        isOnce_ = other.isOnce_;
        env_ = other.env_;
        callbackRef_ = other.callbackRef_;
        tsfnName_ = other.tsfnName_;
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
        std::swap(tsfnName_, tmp.tsfnName_);
        return *this;
    }

    ~AutoRef()
    {
        if (callbackRef_ == nullptr) {
            return;
        }
        napi_threadsafe_function tsfn = nullptr;
        napi_status status = napi_create_threadsafe_function(
            env_, nullptr, nullptr, tsfnName_, 0, 1, nullptr, nullptr, nullptr,
            [](napi_env env, napi_value js_cb, void* context, void* data) {
                if (data == nullptr) {
                    return;
                }
                napi_ref callbackRef = static_cast<napi_ref>(data);
                (void)napi_reference_unref(env, callbackRef, nullptr);
            },
            &tsfn);
        if (status != napi_ok) {
            return;
        }
        napi_call_threadsafe_function(tsfn, callbackRef_, napi_tsfn_nonblocking);
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
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
    napi_value tsfnName_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif