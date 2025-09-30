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
static constexpr int32_t MIN_SIZE_NUM = 256;
std::shared_ptr<MediaManager> MediaManagerFuzzer::fuzz_{nullptr};

void MediaManagerFuzzer::MediaManagerFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<MediaManager>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
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
    uint8_t randomIndex = fdp.ConsumeIntegral<uint8_t>() % memoryFlags.size();
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);
    uint8_t mediaTypeIndex = fdp.ConsumeIntegral<uint8_t>() % mediaTypes.size();
    Media::Plugins::MediaType selectedMediaType = mediaTypes[mediaTypeIndex];
    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    fuzz_->WriteSample(selectedMediaType, buffer);
    fuzz_->ReadSample(selectedMediaType, buffer);
    auto configSize = fdp.ConsumeIntegral<int64_t>();
    fuzz_->Recover(configSize);
    fuzz_->CopyAudioTrack();
    fuzz_->InitReader();
    fuzz_->InitWriter();
    auto duration = fdp.ConsumeIntegral<int64_t>();
    auto bitRate = fdp.ConsumeIntegral<int64_t>();
    fuzz_->InitRecoverReader(configSize, duration, bitRate);
    fuzz_->GetRecoverInfo(configSize);
    fuzz_->Pause();
    fuzz_->Stop();
}

void MediaManagerFuzzer::ReaderFuzzTest(FuzzedDataProvider& fdp)
{
    std::shared_ptr<Reader> inputReader {nullptr};
    inputReader = std::make_shared<Reader>();
    CHECK_RETURN_ELOG(!inputReader, "Create inputReader Error");
    inputReader->GetSourceFormat();
}

void MediaManagerFuzzer::TrackFuzzTest(FuzzedDataProvider& fdp)
{
    std::shared_ptr<Track> track {nullptr};
    track = std::make_shared<Track>();
    CHECK_RETURN_ELOG(!track, "Create track Error");
    TrackFormat formatOfIndex;
    Format trackFormat;
    int32_t trackType = fdp.ConsumeIntegral<int32_t>();
    int32_t trackIndex = fdp.ConsumeIntegral<int32_t>();

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

    trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType);
    formatOfIndex.format = std::make_shared<Format>(trackFormat);
    formatOfIndex.trackId = trackIndex;
    track->SetFormat(formatOfIndex, selectedMediaType);
    track->GetFormat();
}

void MediaManagerFuzzer::WriterFuzzTest(FuzzedDataProvider& fdp)
{
    std::shared_ptr<Writer> writer {nullptr};
    writer = std::make_shared<Writer>();
    CHECK_RETURN_ELOG(!writer, "Create writer Error");
    auto outputFd = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<AVSourceFuzz> source = std::make_shared<AVSourceFuzz>();
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks;
    writer->Create(outputFd, tracks);

    std::vector<uint8_t> memoryFlags = {
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_WRITE_ONLY),
        static_cast<uint8_t>(MemoryFlag::MEMORY_READ_WRITE)
    };
    uint8_t randomIndex = fdp.ConsumeIntegral<uint8_t>() % memoryFlags.size();
    MemoryFlag selectedFlag = static_cast<MemoryFlag>(memoryFlags[randomIndex]);

    std::shared_ptr<AVAllocator> avAllocator =
        AVAllocatorFactory::CreateSharedAllocator(selectedFlag);
    int32_t capacity = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<AVBuffer> sample = AVBuffer::CreateAVBuffer(avAllocator, capacity);
    writer->Start();
}

void MediaManagerFuzzer::MuxerFuzzTest(FuzzedDataProvider& fdp)
{
    std::shared_ptr<Muxer> muxer {nullptr};
    muxer = std::make_shared<Muxer>();
    CHECK_RETURN_ELOG(!muxer, "Create muxer Error");
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks;
    muxer->AddTracks(tracks);
}

void MediaManagerFuzzer::SetAuxiliaryTypeTest(FuzzedDataProvider& fdp)
{
    std::shared_ptr<Track> track {nullptr};
    int32_t trackType = fdp.ConsumeIntegral<int32_t>();
    int32_t trackIndex = fdp.ConsumeIntegral<int32_t>();

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

    auto format = std::make_unique<Format>();
    format->PutIntValue(Media::Tag::MEDIA_TYPE, trackType);
    track = std::make_shared<Track>(trackIndex, std::move(format), selectedMediaType);
    CHECK_RETURN_ELOG(!track, "Create track Error");
    AuxiliaryType type = static_cast<AuxiliaryType>(fdp.ConsumeIntegral<int32_t>() % 3 - 1);
    track->SetAuxiliaryType(type);
    track->GetAuxiliaryType();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto mediaManager = std::make_unique<MediaManagerFuzzer>();
    if (mediaManager == nullptr) {
        MEDIA_INFO_LOG("mediaManager is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    mediaManager->MediaManagerFuzzTest(fdp);
    mediaManager->WriterFuzzTest(fdp);
    mediaManager->TrackFuzzTest(fdp);
    mediaManager->ReaderFuzzTest(fdp);
    mediaManager->MuxerFuzzTest(fdp);
    mediaManager->SetAuxiliaryTypeTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}