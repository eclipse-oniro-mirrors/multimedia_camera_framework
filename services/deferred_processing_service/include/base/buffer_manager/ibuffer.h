/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_I_BUFFER_H
#define OHOS_CAMERA_DPS_I_BUFFER_H

#include <cstdint>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr int INVALID_FD = -1;

class IBuffer {
public:
    IBuffer() = default;
    virtual ~IBuffer() = default;

private:
    virtual int64_t GetSize() = 0;
    virtual int32_t CopyFrom(uint8_t* address, int64_t bytes) = 0;
    virtual void Reset() = 0;
    virtual int GetFd() const = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_I_BUFFER_H
