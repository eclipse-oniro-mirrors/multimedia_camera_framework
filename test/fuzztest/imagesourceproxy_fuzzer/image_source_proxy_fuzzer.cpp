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

#include "image_source_proxy_fuzzer.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;

std::shared_ptr<ImageSourceProxy> ImageSourceProxyFuzzer::imageSourceProxyFuzz_{nullptr};

void ImageSourceProxyFuzzer::ImageSourceProxyFuzzerTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_EXECUTE(imageSourceProxyFuzz_ == nullptr,
        imageSourceProxyFuzz_ = ImageSourceProxy::CreateImageSourceProxy());
    CHECK_RETURN_ELOG(!imageSourceProxyFuzz_, "CreateImageSourceProxy Error");
    size_t width = 256;
    size_t height = 256;
    size_t blockNum = ((width + 4 - 1) / 4) * ((height + 4 - 1) / 4);
    size_t dataSize = blockNum * 16 + 16;
    uint8_t* data = (uint8_t*)malloc(dataSize);
    uint32_t size = fdp.ConsumeIntegral<uint32_t>();
    if (size > dataSize) {
        size = static_cast<uint32_t>(dataSize);
    }
    Media::SourceOptions opts;
    uint32_t errorCode = fdp.ConsumeIntegral<uint32_t>();
    imageSourceProxyFuzz_->CreateImageSource(data, size, opts, errorCode);

    Media::DecodeOptions decodeOpts;
    imageSourceProxyFuzz_->CreatePixelMap(decodeOpts, errorCode);
    if (data != nullptr) {
        free(data);
        data = nullptr;
    }
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto imageSourceProxyFuzzer = std::make_unique<ImageSourceProxyFuzzer>();
    if (imageSourceProxyFuzzer == nullptr) {
        MEDIA_INFO_LOG("imageSourceProxyFuzzer is null");
        return;
    }
    imageSourceProxyFuzzer->ImageSourceProxyFuzzerTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}