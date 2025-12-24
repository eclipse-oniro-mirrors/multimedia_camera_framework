/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_server_photo_proxy_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 10;
static constexpr int32_t BUFFER_HANDLE_RESERVE_TEST_SIZE = 16;
const size_t THRESHOLD = 10;
std::shared_ptr<CameraServerPhotoProxy> CameraServerPhotoProxyFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void CameraServerPhotoProxyFuzzer::CameraServerPhotoProxyFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<CameraServerPhotoProxy>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (BUFFER_HANDLE_RESERVE_TEST_SIZE * 2));
    fuzz_->bufferHandle_ = static_cast<BufferHandle *>(malloc(handleSize));
    fuzz_->imageFormat_ = fdp.ConsumeIntegral<int32_t>();
    fuzz_->isMmaped_ = fdp.ConsumeBool();
    fuzz_->GetFileDataAddr();
    fuzz_->GetFormat();
    fuzz_->deferredProcType_ = 0;
    fuzz_->GetDeferredProcType();
    fuzz_->deferredProcType_ = 1;
    fuzz_->GetDeferredProcType();
    fuzz_->mode_ = fdp.ConsumeIntegral<int32_t>();
    fuzz_->isMmaped_ = fdp.ConsumeBool();
    fuzz_->GetShootingMode();
    free(fuzz_->bufferHandle_);
    fuzz_->bufferHandle_ = nullptr;
}

void Test(uint8_t* data, size_t size)
{
    auto cameraServerPhotoProxy = std::make_unique<CameraServerPhotoProxyFuzzer>();
    if (cameraServerPhotoProxy == nullptr) {
        MEDIA_INFO_LOG("cameraServerPhotoProxy is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraServerPhotoProxy->CameraServerPhotoProxyFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}