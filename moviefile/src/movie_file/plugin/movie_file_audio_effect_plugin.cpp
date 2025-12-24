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

#include "movie_file_audio_effect_plugin.h"

#include "movie_file_audio_offline_algo_node.h"

namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
MovieFileAudioEffectPlugin::MovieFileAudioEffectPlugin(const AudioStandard::AudioStreamInfo& inputOptions)
{
    outputOptions_ = inputOptions;
    outputOptions_.channels = AudioChannel::MONO;
    outputOptions_.samplingRate = static_cast<AudioSamplingRate>(AudioSamplingRate::SAMPLE_RATE_48000);

    auto algoNode = std::make_shared<MovieFileAudioOfflineAlgoNode>();
    auto selectedChain = algoNode->GetSelectedChain();
    if (selectedChain == MovieFileAudioOfflineAlgoNode::CHAIN_NAME_POST_EDIT) {
        outputOptions_.channels = AudioChannel::STEREO;
    }
    algoNode->InitAudioProcessConfig(inputOptions, outputOptions_);
    AddProcessNode(0, algoNode);
}
} // namespace CameraStandard
} // namespace OHOS