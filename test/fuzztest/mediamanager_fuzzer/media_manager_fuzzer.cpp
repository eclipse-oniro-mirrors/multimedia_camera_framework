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

#include "media_manager_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
MediaManager *MediaManagerFuzzer::fuzz_ = nullptr;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void MediaManagerFuzzer::MediaManagerFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    if (fuzz_ == nullptr) {
        fuzz_ = new MediaManager();
    }
    auto inFd = GetData<int32_t>();
    auto outFd = GetData<int32_t>();
    auto tempFd = GetData<int32_t>();
    fuzz_->Create(inFd, outFd, tempFd);
    fuzz_->Pause();
    fuzz_->Stop();
    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    std::vector<Media::Plugins::MediaType> mediaTypes = {
        Media::Plugins::MediaType::UNKNOWN,
        Media::Plugins::MediaType::AUDIO,
        Media::Plugins::MediaType::VIDEO,
        Media::Plugins::MediaType::SUBTITLE,
        Media::Plugins::MediaType::ATTACHMENT,
        Media::Plugins::MediaType::DATA,
        Media::Plugins::MediaType::TIMEDMETA
    };
    uint8_t randomIndex = GetData<uint8_t>() % memoryFlags.size();
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    uint8_t mediaTypeIndex = GetData<uint8_t>() % mediaTypes.size();
    Media::Plugins::MediaType selectedMediaType = mediaTypes[mediaTypeIndex];
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = GetData<int32_t>();
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    fuzz_->WriteSample(selectedMediaType, buffer);
    fuzz_->ReadSample(selectedMediaType, buffer);
    auto size_ = GetData<int64_t>();
    fuzz_->Recover(size_);
    fuzz_->CopyAudioTrack();
    fuzz_->InitReader();
    fuzz_->InitWriter();
    auto duration = GetData<int64_t>();
    auto bitRate = GetData<int64_t>();
    fuzz_->InitRecoverReader(size_, duration, bitRate);
    fuzz_->GetRecoverInfo(size_);
}

void MediaManagerFuzzer::ReaderFuzzTest()
{
    std::shared_ptr<Reader> inputReader_ {nullptr};
    inputReader_ = std::make_shared<Reader>();
    inputReader_->GetSourceFormat();
}

void MediaManagerFuzzer::TrackFuzzTest()
{
    std::shared_ptr<Track> track {nullptr};
    track = std::make_shared<Track>();
    TrackFormat formatOfIndex;
    Format trackFormat;
    int32_t trackType = GetData<int32_t>();
    int32_t trackIndex = GetData<int32_t>();

    std::vector<Media::Plugins::MediaType> mediaTypes = {
        Media::Plugins::MediaType::UNKNOWN,
        Media::Plugins::MediaType::AUDIO,
        Media::Plugins::MediaType::VIDEO,
        Media::Plugins::MediaType::SUBTITLE,
        Media::Plugins::MediaType::ATTACHMENT,
        Media::Plugins::MediaType::DATA,
        Media::Plugins::MediaType::TIMEDMETA
    };
    uint8_t mediaTypeIndex = GetData<uint8_t>() % mediaTypes.size();
    Media::Plugins::MediaType selectedMediaType = mediaTypes[mediaTypeIndex];

    trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType);
    formatOfIndex.format = std::make_shared<Format>(trackFormat);
    formatOfIndex.trackId = trackIndex;
    track->SetFormat(formatOfIndex, selectedMediaType);
    track->GetFormat();
}

void MediaManagerFuzzer::WriterFuzzTest()
{
    std::shared_ptr<Writer> writer {nullptr};
    writer = std::make_shared<Writer>();
    auto outputFd = GetData<int32_t>();
    std::shared_ptr<AVSourceFuzz> source = std::make_shared<AVSourceFuzz>();
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks;
    writer->Create(outputFd, tracks);

    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    uint8_t randomIndex = GetData<uint8_t>() % memoryFlags.size();
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);

    std::shared_ptr<AVAllocator> avAllocator_ =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity_ = GetData<int32_t>();
    std::shared_ptr<AVBuffer> sample = AVBuffer::CreateAVBuffer(avAllocator_, capacity_);
    writer->Start();
}

void MediaManagerFuzzer::MuxerFuzzTest()
{
    std::shared_ptr<Muxer> muxer {nullptr};
    muxer = std::make_shared<Muxer>();
    auto outputFd = GetData<int32_t>();
    std::vector<Plugins::OutputFormat> outputFormats = {
        Plugins::OutputFormat::DEFAULT,
        Plugins::OutputFormat::MPEG_4,
        Plugins::OutputFormat::M4A,
        Plugins::OutputFormat::AMR,
        Plugins::OutputFormat::MP3,
        Plugins::OutputFormat::WAV
    };
    uint8_t outputFormatIndex = GetData<uint8_t>() % outputFormats.size();
    Plugins::OutputFormat selectedOutputFormat = outputFormats[outputFormatIndex];
    muxer->Create(outputFd, selectedOutputFormat);
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks;
    muxer->AddTracks(tracks);
}

void Test()
{
    auto mediaManager = std::make_unique<MediaManagerFuzzer>();
    if (mediaManager == nullptr) {
        MEDIA_INFO_LOG("mediaManager is null");
        return;
    }
    mediaManager->MediaManagerFuzzTest();
    mediaManager->WriterFuzzTest();
    mediaManager->TrackFuzzTest();
    mediaManager->ReaderFuzzTest();
    mediaManager->MuxerFuzzTest();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}