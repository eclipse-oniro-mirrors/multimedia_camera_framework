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

#include "mpeg_manager_fuzzer.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 128;
const size_t MAX_LENGTH_STRING = 64;
std::shared_ptr<MpegManager> MpegManagerFuzzer::fuzz_{nullptr};

void MpegManagerFuzzer::MpegManagerFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<MpegManager>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    MediaResult result1 = MediaResult::FAIL;
    MediaResult result2 = MediaResult::PAUSE;
    fuzz_->UnInit(result1);
    fuzz_->UnInit(result2);
    fuzz_->GetSurface();
    fuzz_->GetMakerSurface();
    fuzz_->GetProcessTimeStamp();
    fuzz_->GetResultFd();
    int64_t width = fdp.ConsumeIntegralInRange<int32_t>(0, 8960);
    int64_t height = fdp.ConsumeIntegralInRange<int32_t>(0, 8960);
    fuzz_->InitVideoCodec(width, height);
    fuzz_->UnInitVideoCodec();
    fuzz_->InitVideoMakerSurface();
    fuzz_->UnInitVideoMaker();
    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    uint8_t randomIndex = fdp.ConsumeIntegral<uint8_t>() % memoryFlags.size();
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    std::shared_ptr<AVAllocator> avAllocator = AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    fuzz_->OnMakerBufferAvailable();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    fuzz_->AcquireMakerBuffer(timestamp);
    int flags = 1;
    std::string requestId(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    fuzz_->GetFileFd(requestId, flags, "_vid_temp");
    fuzz_->GetFileFd(requestId, flags, "_vid");
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto mpegManager = std::make_unique<MpegManagerFuzzer>();
    if (mpegManager == nullptr) {
        MEDIA_INFO_LOG("mpegManager is null");
        return;
    }
    mpegManager->MpegManagerFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}