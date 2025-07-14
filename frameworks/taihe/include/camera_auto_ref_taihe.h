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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_AUTO_REF_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_AUTO_REF_TAIHE_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "taihe/runtime.hpp"
#include "camera_utils_taihe.h"
#include "camera_log.h"

namespace Ani::Camera {
struct AutoRef {
public:
    AutoRef(ani_env* env, std::shared_ptr<uintptr_t> callback, bool isOnce) : isOnce_(isOnce), env_(env)
    {
        if (callback != nullptr) {
            callbackRef_ = callback;
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
        env_ = nullptr;
        callbackRef_ = nullptr;
    }

    std::shared_ptr<uintptr_t> GetCallbackFunction()
    {
        if (env_ == nullptr || callbackRef_ == nullptr) {
            MEDIA_ERR_LOG("env_ and callbackRef_ is nullptr");
            return nullptr;
        }
        return callbackRef_;
    }

    bool isOnce_ = false;

private:
    ani_env* env_ = nullptr;
    std::shared_ptr<uintptr_t> callbackRef_;
};
} // namespace Ani::Camera
#endif //FRAMEWORKS_TAIHE_INCLUDE_CAMERA_AUTO_REF_TAIHE_H