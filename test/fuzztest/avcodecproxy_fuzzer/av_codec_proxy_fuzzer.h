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

#ifndef AV_CODEC_PROXY_FUZZER_H
#define AV_CODEC_PROXY_FUZZER_H

#include "av_codec_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {

class CoderCallback : public MediaCodecCallback {
public:
    CoderCallback() {}
    ~CoderCallback() {}
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) {}
    void OnOutputFormatChanged(const Format &format) {}
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) {}
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) {}
};

class AVSourceTest : public AVSource {
public:
    AVSourceTest() {}
    ~AVSourceTest() {}
    int32_t GetSourceFormat(OHOS::Media::Format &format)
    {
        return 0;
    }
    int32_t GetTrackFormat(OHOS::Media::Format &format, uint32_t trackIndex)
    {
        return 0;
    }
    int32_t GetUserMeta(OHOS::Media::Format &format)
    {
        return 0;
    }
};

class AvCodecProxyFuzzer {
public:
    static void AvCodecProxyFuzzerTest1(FuzzedDataProvider& fdp);
    static void AvCodecProxyFuzzerTest2(FuzzedDataProvider& fdp);
    static void AvCodecProxyFuzzerTest3(FuzzedDataProvider& fdp);
    static void AvCodecProxyFuzzerTest4(FuzzedDataProvider& fdp);
    static std::shared_ptr<AVCodecProxy> avCodecProxyFuzz_;
};

} // CameraStandard
} // OHOS
#endif // AV_CODEC_PROXY_FUZZER_H