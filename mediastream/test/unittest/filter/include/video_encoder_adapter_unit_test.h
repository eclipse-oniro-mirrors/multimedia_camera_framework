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

#ifndef VIDEO_ENCODER_ADAPTER_UNIT_TEST_H
#define VIDEO_ENCODER_ADAPTER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "video_encoder_adapter.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;

class VideoEncoderAdapterUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

private:
    std::shared_ptr<VideoEncoderAdapter> videoEncoderAdapter_ {nullptr};
};

class MockAVCodecVideoEncoder : public MediaAVCodec::AVCodecVideoEncoder {
public:

    MOCK_METHOD1(Configure, int32_t(const Format &format));
    MOCK_METHOD0(Prepare, int32_t());
    MOCK_METHOD0(Start, int32_t());
    MOCK_METHOD0(Stop, int32_t());
    MOCK_METHOD0(Flush, int32_t());
    MOCK_METHOD0(NotifyEos, int32_t());
    MOCK_METHOD0(Reset, int32_t());
    MOCK_METHOD0(Release, int32_t());
    MOCK_METHOD0(CreateInputSurface, sptr<Surface>());
    MOCK_METHOD3(QueueInputBuffer,
                 int32_t(uint32_t index, MediaAVCodec::AVCodecBufferInfo info, MediaAVCodec::AVCodecBufferFlag flag));
    MOCK_METHOD1(QueueInputBuffer, int32_t(uint32_t index));
    MOCK_METHOD1(QueueInputParameter, int32_t(uint32_t index));
    MOCK_METHOD1(GetOutputFormat, int32_t(Format &format));
    MOCK_METHOD1(ReleaseOutputBuffer, int32_t(uint32_t index));
    MOCK_METHOD1(SetParameter, int32_t(const Format &format));
    MOCK_METHOD1(SetCallback, int32_t(const std::shared_ptr<MediaAVCodec::AVCodecCallback> &callback));
    MOCK_METHOD1(SetCallback, int32_t(const std::shared_ptr<MediaAVCodec::MediaCodecCallback> &callback));
    MOCK_METHOD1(SetCallback, int32_t(const std::shared_ptr<MediaAVCodec::MediaCodecParameterCallback> &callback));
    MOCK_METHOD1(SetCallback,
                 int32_t(const std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback> &callback));
    MOCK_METHOD1(GetInputFormat, int32_t(Format &format));
    MOCK_METHOD1(SetCustomBuffer, int32_t(std::shared_ptr<AVBuffer> buffer));
};

class MockEncoderAdapterCallback : public EncoderAdapterCallback {
public:
    MOCK_METHOD2(OnError, void(MediaAVCodec::AVCodecErrorType type, int32_t errorCode));
    MOCK_METHOD1(OnOutputFormatChanged, void(const std::shared_ptr<Meta> &format));
};

class MockAVBufferQueueProducer : public IRemoteStub<AVBufferQueueProducer> {
public:
    MOCK_METHOD0(GetQueueSize, uint32_t());
    MOCK_METHOD1(SetQueueSize, Status(uint32_t size));
    MOCK_METHOD3(RequestBuffer,
                 Status(std::shared_ptr<AVBuffer> &outBuffer, const AVBufferConfig &config, int32_t timeoutMs));
    MOCK_METHOD2(PushBuffer, Status(const std::shared_ptr<AVBuffer>& inBuffer, bool available));
    MOCK_METHOD2(ReturnBuffer, Status(const std::shared_ptr<AVBuffer>& inBuffer, bool available));
    MOCK_METHOD2(AttachBuffer, Status(std::shared_ptr<AVBuffer>& inBuffer, bool isFilled));
    MOCK_METHOD1(DetachBuffer, Status(const std::shared_ptr<AVBuffer>& outBuffer));
    MOCK_METHOD1(SetBufferFilledListener, Status(sptr<IBrokerListener>& listener));
    MOCK_METHOD1(RemoveBufferFilledListener, Status(sptr<IBrokerListener>& listener));
    MOCK_METHOD1(SetBufferAvailableListener, Status(sptr<Media::IProducerListener>& listener));
    MOCK_METHOD0(Clear, Status());
    MOCK_METHOD1(ClearBufferIf, Status(std::function<bool(const std::shared_ptr<AVBuffer>&)> pred));
};

class MockEncoderAdapterKeyFramePtsCallback : public EncoderAdapterKeyFramePtsCallback {
public:
    ~MockEncoderAdapterKeyFramePtsCallback() = default;
    MOCK_METHOD1(OnReportKeyFramePts, void(std::string KeyFramePts));
    MOCK_METHOD2(OnFirstFrameArrival, void(std::string name, int64_t& startPts));
    MOCK_METHOD1(OnReportFirstFramePts, void(int64_t firstFramePts));
};

}
}

#endif
