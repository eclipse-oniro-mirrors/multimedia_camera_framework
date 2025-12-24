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

#ifndef OHOS_UNIFIED_PIPELINE_BUFFER_TYPES_H
#define OHOS_UNIFIED_PIPELINE_BUFFER_TYPES_H

#include <cstdint>

namespace OHOS {
namespace CameraStandard {
enum class BufferType : int32_t {
    VOID = 0,
    CAMERA_AUDIO_RAW_BUFFER,

    CAMERA_AUDIO_PACKAGED_RAW_BUFFER,
    CAMERA_AUDIO_PACKAGED_ENCODED_RAW_BUFFER,

    CAMERA_AUDIO_PACKAGED_BUFFER,
    CAMERA_AUDIO_PACKAGED_ENCODED_BUFFER,

    CAMERA_VIDEO_SURFACE_BUFFER,
    CAMERA_VIDEO_ENCODED_BUFFER,
    CAMERA_VIDEO_PACKAGED_ENCODED_BUFFER,
    CAMERA_VIDEO_META,
};
} // namespace CameraStandard
} // namespace OHOS

#endif