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

#include <unistd.h>

#include "watch_dog.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using SteadyTimePoint = std::chrono::steady_clock::time_point;
using Nano = std::chrono::nanoseconds;
using Micro = std::chrono::microseconds;
using Milli = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;

inline SteadyTimePoint GetSteadyNow()
{
    return SteadyTimePoint::clock::now();
}

template <typename Duration, typename TimePoint>
inline auto GetDiffTime(TimePoint begin, TimePoint end)
{
    if (begin > end) {
        return static_cast<typename Duration::rep>(0);
    }
    return std::chrono::duration_cast<Duration>(end - begin).count();
}

template <typename Duration, typename TimePoint>
inline auto GetDiffTime(TimePoint begin)
{
    return GetDiffTime<Duration>(begin, TimePoint::clock::now());
}

inline bool IsFileEmpty(int fd)
{
    off_t fileSize = lseek(fd, 0, SEEK_END);
    if (fileSize == (off_t)-1) {
        return false;
    }
    return fileSize == 0;
}

inline bool ClearFileContent(int fd)
{
    if (ftruncate(fd, 0) != 0) {
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        return false;
    }
    return true;
}

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
    return std::make_shared<MakeSharedHelper<T, Args &&...>>(std::forward<Args>(args)...);
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
    return std::make_unique<MakeUniqueHelper<T, Args &&...>>(std::forward<Args>(args)...);
}

inline int32_t GetVersionId(uint32_t major, uint32_t minor)
{
    const uint32_t offset = 8;
    return static_cast<int32_t>((major << offset) | minor);
}

Watchdog& GetGlobalWatchdog();
float TransExifOrientationToDegree(const std::string& orientation);

struct DpsCallerInfo {
    int32_t pid;
    int32_t uid;
    uint32_t tokenID;
    std::string bundleName;
    std::string version;
};

DpsCallerInfo GetDpsCallerInfo();
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_UTILS_H