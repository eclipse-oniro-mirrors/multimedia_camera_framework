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

#ifndef OHOS_CAMERA_DPS_UTILS_H
#define OHOS_CAMERA_DPS_UTILS_H

#include <memory>
#include "watch_dog.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
template <typename U>
constexpr U AlignUp(U num, U alignment)
{
    return alignment ? ((num + alignment - 1) & (~(alignment - 1))) : num;
}

template <typename T, typename... Args>
struct MakeSharedHelper : public T {
    explicit MakeSharedHelper(Args&&... args) : T(std::forward<Args>(args)...)
    {
    }
};

template <typename T, typename... Args>
std::shared_ptr<T> CreateShared(Args&&... args)
{
    return std::move(std::make_shared<MakeSharedHelper<T, Args &&...>>(std::forward<Args>(args)...));
}

template <typename T, typename... Args>
struct MakeUniqueHelper : public T {
    explicit MakeUniqueHelper(Args&&... args) : T(std::forward<Args>(args)...)
    {
    }
};

template <typename T, typename... Args>
std::unique_ptr<T> CreateUnique(Args&&... args)
{
    return std::move(std::make_unique<MakeUniqueHelper<T, Args &&...>>(std::forward<Args>(args)...));
}

Watchdog& GetGlobalWatchdog();
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_UTILS_H