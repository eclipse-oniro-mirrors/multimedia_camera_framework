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

#ifndef OHOS_CAMERA_MOVIE_FILE_AUDIO_OFFLINE_ALGO_NODE_H
#define OHOS_CAMERA_MOVIE_FILE_AUDIO_OFFLINE_ALGO_NODE_H

#include <array>
#include <memory>

#include "audio_stream_info.h"
#include "offline_audio_effect_manager.h"
#include "unified_pipeline_audio_buffer.h"
#include "unified_pipeline_process_node.h"

namespace OHOS {
namespace CameraStandard {

class MovieFileAudioOfflineAlgoNode
    : public UnifiedPiplineProcessNode<UnifiedPipelineAudioBuffer, UnifiedPipelineAudioPackagedBuffer> {
public:
    MovieFileAudioOfflineAlgoNode();
    ~MovieFileAudioOfflineAlgoNode() override;
    std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> ProcessBuffer(
        std::unique_ptr<UnifiedPipelineAudioBuffer> bufferIn) override;

    void ProcessCommand(UnifiedPipelineCommand* command) override;

    void InitAudioProcessConfig(
        const AudioStandard::AudioStreamInfo& inputStreamInfo, const AudioStandard::AudioStreamInfo& outputStreamInfo);

    inline std::string GetSelectedChain()
    {
        return selectedChain_;
    }

    static const std::string CHAIN_NAME_OFFLINE;
    static const std::string CHAIN_NAME_POST_EDIT;

private:
    // 私有的方法，代码处理可以保证 processedPtr 不会踩内存，无需传入数组大小
    std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> MakeUpResultPack(uint8_t* processedPtr, size_t dataSize);

    std::unique_ptr<AudioStandard::OfflineAudioEffectManager> offlineAudioEffectManager_ = nullptr;
    std::unique_ptr<AudioStandard::OfflineAudioEffectChain> offlineEffectChain_ = nullptr;

    uint32_t oneUnprocessedSize_ = 0;
    uint32_t oneProcessedSize_ = 0;

    std::string selectedChain_ = "";
};
} // namespace CameraStandard
} // namespace OHOS

#endif