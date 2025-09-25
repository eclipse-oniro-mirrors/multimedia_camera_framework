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

#ifndef OHOS_CAMERA_SP_HOLDER_H
#define OHOS_CAMERA_SP_HOLDER_H

#include <mutex>

#include "memory.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
template<typename>
struct is_shared_ptr : std::false_type {};

template<typename U>
struct is_shared_ptr<std::shared_ptr<U>> : std::true_type {};

template<typename>
struct is_ohos_sptr : std::false_type {};

template<typename U>
struct is_ohos_sptr<OHOS::sptr<U>> : std::true_type {};

// 组合类型检查：T 必须是 shared_ptr 或 sptr
template<typename T>
struct is_valid_smart_ptr {
    static constexpr bool value = is_shared_ptr<T>::value || is_ohos_sptr<T>::value;
};

// ===== 模板类实现 =====
template<typename T>
class SpHolder {
    static_assert(is_valid_smart_ptr<T>::value, "T must be either std::shared_ptr or OHOS::sptr");

public:
    SpHolder() = default;

    void Set(T ptr)
    {
        std::lock_guard<std::mutex> lock(objPtrMutex_);
        objPtr_ = ptr;
    }

    T Get()
    {
        std::lock_guard<std::mutex> lock(objPtrMutex_);
        return objPtr_;
    }

private:
    std::mutex objPtrMutex_;
    T objPtr_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif