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

#ifndef AUDIO_VIDEO_MUXER_FUZZER_H
#define AUDIO_VIDEO_MUXER_FUZZER_H

#include "audio_video_muxer.h"
#include <memory>
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace CameraStandard {
class AudioVideoMuxerFuzzer {
public:
static std::shared_ptr<AudioVideoMuxer> fuzz_;
static void AudioVideoMuxerFuzzTest(FuzzedDataProvider& fdp);
static void AudioVideoMuxerFuzzTest1(FuzzedDataProvider& fdp);
};
} //CameraStandard
} //OHOS
#endif //AUDIO_VIDEO_MUXER_FUZZER_H