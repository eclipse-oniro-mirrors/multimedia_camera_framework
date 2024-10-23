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
#ifndef CAMERA_FRAMEWORK_FIXED_SIZE_LIST
#define CAMERA_FRAMEWORK_FIXED_SIZE_LIST
#include <vector>
#include <mutex>
#include <thread>
#include <functional>
#include <optional>

namespace OHOS {
namespace CameraStandard {
template <typename T>
class FixedSizeList {
public:
    FixedSizeList(size_t size) : maxSize(size), currentSize(0), index(0)
    {
        data.resize(size);
    }

    void add(T value)
    {
        std::lock_guard<std::mutex> lock(mtx);
        data[index] = value;
        index = (index + 1) % maxSize;
        if (currentSize < maxSize) {
            ++currentSize;
        }
    }

    std::optional<T> find_if(const std::function<bool(const T&)>& predicate)
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (size_t i = 0; i < currentSize; ++i) {
            if (predicate(data[i])) {
                T result = data[i];
                remove_at(i);
                return result;
            }
        }
        return std::nullopt;
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(mtx);
        data.clear();
        data.resize(maxSize);
        currentSize = 0;
        index = 0;
    }

private:
    void remove_at(size_t position)
    {
        if (position < currentSize) {
            for (size_t i = position; i < currentSize - 1; ++i) {
                data[i] = data[i + 1];
            }
            --currentSize;
            index = (index - 1 + maxSize) % maxSize;
        }
    }

    std::vector<T> data;
    size_t maxSize;
    size_t currentSize;
    size_t index;
    mutable std::mutex mtx;  // mutable to allow const methods to lock the mutex
};
} // namespace CameraStandard
} // namespace OHOS
#endif //CAMERA_FRAMEWORK_FIXED_SIZE_LIST