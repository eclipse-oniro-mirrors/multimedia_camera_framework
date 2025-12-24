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

#ifndef OHOS_CAMERA_MOVIE_FILE_AUDIO_ENCODER_ENCODE_NODE_H
#define OHOS_CAMERA_MOVIE_FILE_AUDIO_ENCODER_ENCODE_NODE_H

#include <memory>
#include <mutex>

#include "movie_file_common_const.h"
#include "native_audio_channel_layout.h"
#include "native_avcodec_audiocodec.h"
#include "unified_pipeline_audio_buffer.h"
#include "unified_pipeline_audio_encoded_buffer.h"
#include "unified_pipeline_process_node.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;
class MovieFileAudioEncoderEncodeNode
    : public UnifiedPiplineProcessNode<UnifiedPipelineAudioPackagedBuffer, UnifiedPipelineAudioPackagedEncodedBuffer> {
public:
    struct EncodeConfig {
        int64_t channelLayout = OH_AudioChannelLayout::CH_LAYOUT_MONO;
        int32_t channelCount = MOVIE_FILE_AUDIO_DEFAULT_CHANNEL_COUNT;
        int32_t sampleFormat = OH_BitsPerSample::SAMPLE_S16LE;
        int32_t sampleRate = MOVIE_FILE_AUDIO_SAMPLE_RATE_32000;
        int64_t bitRate = MOVIE_FILE_AUDIO_DEFAULT_BITRATE;
        int32_t profile = MOVIE_FILE_AUDIO_DEFAULT_PROFILE;
    };

    class MovieFileAudioEncoderEncodeNodeEncoderCallback {
    public:
        MovieFileAudioEncoderEncodeNodeEncoderCallback(MovieFileAudioEncoderEncodeNode* encodeNode);
        void OnInputBufferAvailable(uint32_t index, OH_AVBuffer* buffer);
        void OnOutputBufferAvailable(uint32_t index, OH_AVBuffer* buffer);
        void Release();

    private:
        // MovieFileVideoEncoderEncodeNode
        // 析构的时候调用MovieFileVideoEncoderEncodeNodeEncoderCallback的Release方法，确保回调函数中不会踩内存。因此这个地方使用裸指针是安全的。
        std::mutex encodeNodeMutex_;
        MovieFileAudioEncoderEncodeNode* encodeNode_ = nullptr;
    };

    static void AudioCallbackOnError(OH_AVCodec* codec, int32_t errorCode, void* userData);
    static void AudioCallbackAVCodecOnStreamChanged(OH_AVCodec* codec, OH_AVFormat* format, void* userData);
    static void AudioCallbackAVCodecOnNeedInputBuffer(
        OH_AVCodec* codec, uint32_t index, OH_AVBuffer* buffer, void* userData);
    static void AudioCallbackAVCodecOnNewOutputBuffer(
        OH_AVCodec* codec, uint32_t index, OH_AVBuffer* buffer, void* userData);

public:
    MovieFileAudioEncoderEncodeNode(EncodeConfig& encodeConfig);
    ~MovieFileAudioEncoderEncodeNode() override;

    std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> ProcessBuffer(
        std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> bufferIn) override;
    void ProcessCommand(UnifiedPipelineCommand* command) override;

private:
    static constexpr int64_t INVALID_TIMESTAMP = -1;

    bool EnqueueBuffer(uint8_t* bufferAddr, size_t bufferSize, int64_t timestamp);
    std::list<AVEncoderOH_AVBufferInfo> DequeueBuffer(int64_t timestamp);

    void OnInputBufferAvailable(uint32_t index, OH_AVBuffer* buffer);
    void OnOutputBufferAvailable(uint32_t index, OH_AVBuffer* buffer);

    inline void ResetBaseTimestamp()
    {
        baseTimestamp_ = INVALID_TIMESTAMP;
    }

    inline void UpdateBaseTimestampIfNessary(int64_t timestamp)
    {
        if (baseTimestamp_ == INVALID_TIMESTAMP) {
            baseTimestamp_ = timestamp;
        }
    }

    inline int64_t GetBaseTimestamp()
    {
        return baseTimestamp_;
    }

    OH_AVCodec* encoder_ = nullptr;

    std::mutex inputMutex_; // Lock for inputCond_, avEncoderInBufferInfos_
    std::condition_variable inputCond_;
    std::list<std::shared_ptr<AVEncoderOH_AVBufferInfo>> avEncoderInBufferInfos_;

    std::mutex outputMutex_; // Lock for outputCond_, avEncoderOutBufferInfos_
    std::condition_variable outputCond_;
    std::list<std::shared_ptr<AVEncoderOH_AVBufferInfo>> avEncoderOutBufferInfos_;

    std::shared_ptr<MovieFileAudioEncoderEncodeNodeEncoderCallback> encoderCallback_;

    std::atomic<int64_t> baseTimestamp_ = INVALID_TIMESTAMP;
};
} // namespace CameraStandard
} // namespace OHOS
#endif