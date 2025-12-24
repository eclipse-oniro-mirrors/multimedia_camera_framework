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

#include "movie_file_audio_raw_package_node.h"

namespace OHOS {
namespace CameraStandard {

std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> MovieFileAudioRawPackageNode::ProcessBuffer(
    std::unique_ptr<UnifiedPipelineAudioBuffer> bufferIn)
{
    PipelinePackagedAudioBufferData packagedData {};
    auto unwrapData = bufferIn->UnwrapData();
    packagedData.bufferDatas.emplace_back(unwrapData);
    auto packagedAudioBuffer =
        std::make_unique<UnifiedPipelineAudioPackagedBuffer>(BufferType::CAMERA_AUDIO_PACKAGED_RAW_BUFFER);
    packagedData.timestamp = unwrapData.timestamp;
    packagedAudioBuffer->WrapData(packagedData);
    return packagedAudioBuffer;
}
} // namespace CameraStandard
} // namespace OHOS