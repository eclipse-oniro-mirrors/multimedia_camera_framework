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

#include "movie_file_video_encoder_plugin.h"

#include "movie_file_video_encoder_encode_node.h"

namespace OHOS {
namespace CameraStandard {
MovieFileVideoEncoderPlugin::MovieFileVideoEncoderPlugin(VideoEncoderConfig& encoderNodeConfig)
    : currentEncoderNodeConfig_(encoderNodeConfig)
{
    UpdateEncodeNode(currentEncoderNodeConfig_);
}

void MovieFileVideoEncoderPlugin::UpdateEncodeNode(VideoEncoderConfig& config)
{
    auto encoderNode = std::make_shared<MovieFileVideoEncoderEncodeNode>(config);
    AddProcessNode(0, encoderNode);
}

void MovieFileVideoEncoderPlugin::ResetEncodeNode()
{
    UpdateEncodeNode(currentEncoderNodeConfig_);
}

void MovieFileVideoEncoderPlugin::ChangeCodecSettings(const std::string& mineType, int32_t rotation, bool isBFrame,
    int32_t videoBitrate)
{
    if (currentEncoderNodeConfig_.mimeType != mineType || currentEncoderNodeConfig_.rotation != rotation
        || currentEncoderNodeConfig_.isBFrame != isBFrame || currentEncoderNodeConfig_.videoBitrate != videoBitrate) {
        currentEncoderNodeConfig_.mimeType = mineType;
        currentEncoderNodeConfig_.rotation = rotation;
        currentEncoderNodeConfig_.isBFrame = isBFrame;
        currentEncoderNodeConfig_.videoBitrate = videoBitrate;
        UpdateEncodeNode(currentEncoderNodeConfig_);
    }
}
} // namespace CameraStandard
} // namespace OHOS
