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

#include "media_manager_proxy_fuzzer.h"
#include "camera_log.h"
#include "ipc_file_descriptor.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr size_t MAX_LENGTH_STRING = 64;
constexpr int REQUEST_FD_ID = 1;

std::shared_ptr<MediaManagerProxy> MediaManagerProxyFuzzer::mediaManagerProxyFuzz_{nullptr};

void MediaManagerProxyFuzzer::MediaManagerProxyFuzzerTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    mediaManagerProxyFuzz_ = MediaManagerProxy::CreateMediaManagerProxy();
    CHECK_RETURN_ELOG(!mediaManagerProxyFuzz_, "CreateMediaManagerProxy Error");
    std::string requestId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    sptr<IPCFileDescriptor> inputFd = sptr<IPCFileDescriptor>::MakeSptr(dup(REQUEST_FD_ID));
    mediaManagerProxyFuzz_->MpegAcquire(requestId, inputFd);
    mediaManagerProxyFuzz_->MpegGetResultFd();
    std::unique_ptr<MediaUserInfo> userInfo = std::make_unique<MediaUserInfo>();
    mediaManagerProxyFuzz_->MpegAddUserMeta(std::move(userInfo));
    mediaManagerProxyFuzz_->MpegGetProcessTimeStamp();
    mediaManagerProxyFuzz_->MpegGetSurface();
    mediaManagerProxyFuzz_->MpegGetMakerSurface();
    int32_t size = fdp.ConsumeIntegral<int32_t>();
    mediaManagerProxyFuzz_->MpegSetMarkSize(size);
    int32_t result = fdp.ConsumeIntegral<int32_t>();
    mediaManagerProxyFuzz_->MpegUnInit(result);
    mediaManagerProxyFuzz_->MpegRelease();
}

void MediaManagerProxyFuzzer::MpegGetDurationFuzzerTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    mediaManagerProxyFuzz_ = MediaManagerProxy::CreateMediaManagerProxy();
    CHECK_RETURN_ELOG(!mediaManagerProxyFuzz_, "CreateMediaManagerProxy Error");
    mediaManagerProxyFuzz_->MpegGetDuration();
    int32_t result = fdp.ConsumeIntegral<int32_t>();
    mediaManagerProxyFuzz_->MpegUnInit(result);
    mediaManagerProxyFuzz_->MpegRelease();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto mediaManagerProxyFuzzer = std::make_unique<MediaManagerProxyFuzzer>();
    if (mediaManagerProxyFuzzer == nullptr) {
        MEDIA_INFO_LOG("avCodecProxyFuzzer is null");
        return;
    }
    mediaManagerProxyFuzzer->MediaManagerProxyFuzzerTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}