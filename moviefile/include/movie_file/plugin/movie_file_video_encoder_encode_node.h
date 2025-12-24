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

#ifndef OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODER_ENCODE_NODE_H
#define OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODER_ENCODE_NODE_H

#include <memory>

#include "avcodec_video_encoder.h"
#include "common/movie_file_video_encode_config.h"
#include "unified_pipeline_process_node.h"
#include "unified_pipeline_surface_buffer.h"
#include "unified_pipeline_video_encoded_buffer.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;
class MovieFileVideoEncoderEncodeNode
    : public UnifiedPiplineProcessNode<UnifiedPipelineSurfaceBuffer, UnifiedPipelineVideoEncodedBuffer> {
public:
    class MovieFileVideoEncoderEncodeNodeEncoderCallback : public MediaCodecCallback {
    public:
        MovieFileVideoEncoderEncodeNodeEncoderCallback(MovieFileVideoEncoderEncodeNode* encodeNode);
        ~MovieFileVideoEncoderEncodeNodeEncoderCallback() override;
        void OnError(AVCodecErrorType errorType, int32_t errorCode) override;
        void OnOutputFormatChanged(const Format& format) override;
        void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override;
        void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override;
        void Release();

    private:
        // MovieFileVideoEncoderEncodeNode
        // 析构的时候调用MovieFileVideoEncoderEncodeNodeEncoderCallback的Release方法，确保回调函数中不会踩内存。因此这个地方使用裸指针是安全的。
        std::mutex encodeNodeMutex_;
        MovieFileVideoEncoderEncodeNode* encodeNode_ = nullptr;
    };

public:
    MovieFileVideoEncoderEncodeNode(VideoEncoderConfig& config);
    ~MovieFileVideoEncoderEncodeNode() override;

    bool AttachBuffer(PipelineSurfaceBufferData data);
    void DetachBuffer(PipelineSurfaceBufferData data);

    std::unique_ptr<UnifiedPipelineVideoEncodedBuffer> ProcessBuffer(
        std::unique_ptr<UnifiedPipelineSurfaceBuffer> bufferIn) override;

private:
    std::shared_ptr<AVEncoderAVBufferInfo> CopyPipelineVideoEncodedBuffer(
        std::shared_ptr<AVEncoderAVBufferInfo> bufferIn);

    void ReleaseAVEncoderAVBuffer(AVEncoderAVBufferInfo& bufferIn);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);

    std::shared_ptr<AVEncoderAVBufferInfo> AddCopyIDRBufferAVBuffer(
        std::shared_ptr<AVEncoderAVBufferInfo> headBuffer, std::shared_ptr<AVEncoderAVBufferInfo> tailBuffer);

    std::shared_ptr<MediaAVCodec::AVBuffer> CopyAVBuffer(std::shared_ptr<MediaAVCodec::AVBuffer> buffer);

    std::list<AVEncoderAVBufferInfo> DequeueBuffer();
    void HandleReceivedOutBuffers(std::list<std::shared_ptr<AVEncoderAVBufferInfo>>& receivedOutBuffers,
        std::list<std::shared_ptr<AVEncoderAVBufferInfo>>& receivedIDRBuffers,
        std::list<AVEncoderAVBufferInfo>& returnBuffers);

    std::shared_ptr<MediaAVCodec::AVCodecVideoEncoder> encoder_;
    sptr<Surface> codecSurface_;

    std::mutex outputMutex_; // Lock for outputCond_, avEncoderOutBufferInfos_
    std::condition_variable outputCond_;
    std::list<std::shared_ptr<AVEncoderAVBufferInfo>> avEncoderOutBufferInfos_;

    std::shared_ptr<MovieFileVideoEncoderEncodeNodeEncoderCallback> encoderCallback_;

    int32_t requestIFrameCount_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif