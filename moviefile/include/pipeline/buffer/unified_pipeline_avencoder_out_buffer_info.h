/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_UNIFIED_PIPELINE_AVENCODER_OUT_BUFFER_INFO_H
#define OHOS_UNIFIED_PIPELINE_AVENCODER_OUT_BUFFER_INFO_H

#include <list>

#include "av_common.h"
#include "avcodec_common.h"
#include "native_avbuffer.h"

namespace OHOS {
namespace CameraStandard {
struct AVEncoderAVBufferInfo {
    uint32_t index = 0;
    std::shared_ptr<MediaAVCodec::AVBuffer> buffer;
    bool isIDRFrame = false;
};

struct AVEncoderPackagedAVBufferInfo {
    std::list<AVEncoderAVBufferInfo> infos {};
};

struct AVEncoderOH_AVBufferInfo {
    uint32_t index = 0;
    OH_AVBuffer* buffer;
    int64_t timestamp = 0;
    size_t size = 0;
};

struct AVEncoderedPackagedOH_AVBufferInfo {
    std::list<AVEncoderOH_AVBufferInfo> infos {};
};
} // namespace CameraStandard
} // namespace OHOS

#endif