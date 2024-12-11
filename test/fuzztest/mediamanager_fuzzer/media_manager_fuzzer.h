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

#ifndef MEDIA_MANAGER_FUZZER_H
#define MEDIA_MANAGER_FUZZER_H

#include "media_manager.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
class MediaManagerFuzzer {
public:
static MediaManager *fuzz_;

class AVSourceFuzz : public AVSource {
public:
    int32_t GetSourceFormat(OHOS::Media::Format &format) override
    {
        return 0;
    }
    int32_t GetTrackFormat(OHOS::Media::Format &format, uint32_t trackIndex) override
    {
        return 0;
    }
    int32_t GetUserMeta(OHOS::Media::Format &format) override
    {
        return 0;
    }
};

static void MediaManagerFuzzTest();
static void WriterFuzzTest();
static void TrackFuzzTest();
static void ReaderFuzzTest();
static void MuxerFuzzTest();
};
} //CameraStandard
} //OHOS
#endif //MEDIA_MANAGER_FUZZER_H