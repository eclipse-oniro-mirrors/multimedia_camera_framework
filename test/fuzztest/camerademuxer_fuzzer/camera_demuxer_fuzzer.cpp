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

#include "camera_demuxer_fuzzer.h"
#include "message_parcel.h"
#include "camera_log.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;

std::shared_ptr<Demuxer> CameraDemuxerFuzzer::fuzz_ {nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void CameraDemuxerFuzzer::CameraDemuxerFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<Demuxer>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    std::shared_ptr<AVSourceTest> source = std::make_shared<AVSourceTest>();
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks;
    fuzz_->Create(source, tracks);

    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(Media::MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(Media::MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(Media::MemoryFlag::MEMORY_READ_WRITE)
    };

    uint8_t randomIndex = fdp.ConsumeIntegral<uint8_t>() % memoryFlags.size();
    Media::MemoryFlag selectedFlag = static_cast<Media::MemoryFlag>(memoryFlags[randomIndex]);
    std::shared_ptr<AVAllocator> avAllocator =
        Media::AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = fdp.ConsumeIntegral<int32_t>();
    if (capacity <= 0) {
        MEDIA_INFO_LOG("Invalid capacity: %d", capacity);
        return;
    }
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);

    std::vector<Media::Plugins::MediaType> mediaTypes = {
        Media::Plugins::MediaType::UNKNOWN,
        Media::Plugins::MediaType::AUDIO,
        Media::Plugins::MediaType::VIDEO,
        Media::Plugins::MediaType::SUBTITLE,
        Media::Plugins::MediaType::ATTACHMENT,
        Media::Plugins::MediaType::DATA,
        Media::Plugins::MediaType::TIMEDMETA
    };

    uint8_t mediaTypeIndex = fdp.ConsumeIntegral<uint8_t>() % mediaTypes.size();
    Media::Plugins::MediaType selectedMediaType = mediaTypes[mediaTypeIndex];
    fuzz_->ReadStream(selectedMediaType, buffer);
}

void Test(uint8_t* data, size_t size)
{
    auto cameraDemuxer = std::make_unique<CameraDemuxerFuzzer>();
    if (cameraDemuxer == nullptr) {
        MEDIA_INFO_LOG("cameraDemuxer is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);

    cameraDemuxer->CameraDemuxerFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}