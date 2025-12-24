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

#ifndef OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODER_PLUGIN_H
#define OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODER_PLUGIN_H

#include <memory>

#include "camera_util.h"
#include "movie_file_video_encoder_encode_node.h"
#include "unified_pipeline_plugin.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileVideoEncoderPlugin : public UnifiedPipelinePlugin {
public:
    MovieFileVideoEncoderPlugin(VideoEncoderConfig& encoderNodeConfig);
    void ChangeCodecSettings(const std::string& mineType, int32_t rotation, bool isBFrame, int32_t videoBitrate);
    void ResetEncodeNode();

private:
    void UpdateEncodeNode(VideoEncoderConfig& config);
    VideoEncoderConfig currentEncoderNodeConfig_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif