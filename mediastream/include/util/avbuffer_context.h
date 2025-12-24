/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MEDIA_STREAM_AVBUFFER_CONTEXT_H
#define OHOS_CAMERA_MEDIA_STREAM_AVBUFFER_CONTEXT_H
#include <cstdint>
#include <securec.h>
#include <string>
#include <condition_variable>
#include <queue>
#include "camera_log.h"
#include "native_avcodec_base.h"
#include "native_avbuffer.h"
#include "native_audio_channel_layout.h"
#include <refbase.h>
#include "avcodec_common.h"

namespace OHOS {
namespace CameraStandard {

class AVBufferInfo : public RefBase {
public:
    explicit AVBufferInfo(uint32_t bufferIndex, std::shared_ptr<OHOS::Media::AVBuffer> avBuffer);
    ~AVBufferInfo() = default;
    uint32_t bufferIndex_ = 0;
    std::shared_ptr<OHOS::Media::AVBuffer> avBuffer_ = nullptr;

    std::shared_ptr<OHOS::Media::AVBuffer> GetCopyAVBuffer();
    std::shared_ptr<OHOS::Media::AVBuffer> AddCopyAVBuffer(std::shared_ptr<OHOS::Media::AVBuffer> IDRBuffer);
};

class AVBufferContext : public RefBase {
public:
    AVBufferContext() = default;
    ~AVBufferContext();
    void Release();

    uint32_t inputFrameCount_ = 0;
    std::mutex inputMutex_;
    std::condition_variable inputCond_;
    std::queue<sptr<AVBufferInfo>> inputBufferInfoQueue_;

    uint32_t outputFrameCount_ = 0;
    std::mutex outputMutex_;
    std::condition_variable outputCond_;
    std::queue<sptr<AVBufferInfo>> outputBufferInfoQueue_;
};
} // CameraStandard
} // OHOS
#endif // OHOS_CAMERA_MEDIA_STREAM_AVBUFFER_CONTEXT_H