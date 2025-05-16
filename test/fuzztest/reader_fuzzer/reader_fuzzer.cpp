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

#include "reader_fuzzer.h"
#include "message_parcel.h"
#include "ipc_file_descriptor.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "securec.h"
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 10;
const size_t THRESHOLD = 10;

std::shared_ptr<Reader> ReaderFuzzer::fuzz_{nullptr};

void ReaderFuzzer::ReaderFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<Reader>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    int32_t inputFd = GetData<int32_t>();
    fuzz_->Create(inputFd);
    fuzz_->GetSourceFormat();
    Format sourceFormat;
    fuzz_->sourceFormat_ = std::make_shared<Format>(sourceFormat);
    fuzz_->InitTracksAndDemuxer();
    auto mediaInfo = std::make_shared<MediaInfo>();
    fuzz_->GetMediaInfo(mediaInfo);
    fuzz_->GetSourceMediaInfo(mediaInfo);
    
    int32_t trackType = fdp.ConsumeIntegralInRange<int32_t>(0, 300);
    int32_t trackIndex = fdp.ConsumeIntegralInRange<int32_t>(0, 300);
    TrackFormat formatOfIndex;
    Format trackFormat;
    trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType);
    formatOfIndex.format = std::make_shared<Format>(trackFormat);
    formatOfIndex.trackId = trackIndex;
    fuzz_->GetTrackMediaInfo(formatOfIndex, mediaInfo);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto reader = std::make_unique<ReaderFuzzer>();
    if (reader == nullptr) {
        MEDIA_INFO_LOG("mpegManager is null");
        return;
    }
        reader->ReaderFuzzTest(fdp);
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