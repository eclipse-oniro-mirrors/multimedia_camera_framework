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

#ifndef OHOS_CAMERA_DPS_SHARED_BUFFER_H
#define OHOS_CAMERA_DPS_SHARED_BUFFER_H

#include <ashmem.h>

#include "ibuffer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SharedBuffer : public IBuffer {
public:
    explicit SharedBuffer(int64_t capacity);
    ~SharedBuffer();

    int32_t Initialize();
    int64_t GetSize() override;
    int32_t CopyFrom(uint8_t* address, int64_t bytes) override;
    void Reset() override;
    int GetFd() const override;

private:
    int32_t AllocateAshmemUnlocked();
    void DeallocAshmem();

    const int64_t capacity_;
    sptr<Ashmem> ashmem_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SHARED_BUFFER_H
