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

#include "image_info_fuzzer.h"
#include "shared_buffer.h"
#include <cstdint>
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

// covers: default ctor + parametrized ctor, SetError/SetPicture/SetBuffer (->SetType with 3 values),
// all getters, GetPicture, and GetIPCFileDescriptor (null buffer / fd==-1 / valid fd branches)
void ImageInfoFuzzTest1(FuzzedDataProvider& fdp)
{
    auto info = std::make_unique<ImageInfo>();
    info->SetError(static_cast<DpsError>(fdp.ConsumeIntegral<int32_t>() % 13));
    info->SetPicture(nullptr);
    info->GetPicture();
    info->GetErrorCode();
    info->GetType();
    auto fdNull = info->GetIPCFileDescriptor();
    auto info2 = std::make_unique<ImageInfo>(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool(),
        fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>(), DpsMetadata {});
    info2->GetDataSize();
    info2->IsHighQuality();
    info2->GetCloudFlag();
    info2->GetCaptureFlag();
    info2->GetMetaData();
    auto bufInvalid = std::make_unique<SharedBuffer>(1024);
    info2->SetBuffer(std::move(bufInvalid));
    auto fdInvalid = info2->GetIPCFileDescriptor();
    auto bufValid = std::make_unique<SharedBuffer>(1024);
    bufValid->Initialize();
    info2->SetBuffer(std::move(bufValid));
    auto fdValid = info2->GetIPCFileDescriptor();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CameraStandard::DeferredProcessing::ImageInfoFuzzTest1(fdp);
    return 0;
}
