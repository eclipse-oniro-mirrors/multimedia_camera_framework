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

#include "video_encoder_adapter_unit_test.h"
#include <new>

namespace OHOS {
namespace CameraStandard {
void VideoEncoderAdapterUnitTest::SetUpTestCase(void) {}

void VideoEncoderAdapterUnitTest::TearDownTestCase(void) {}

void VideoEncoderAdapterUnitTest::SetUp(void)
{
    videoEncoderAdapter_ = std::make_shared<VideoEncoderAdapter>();
}

void VideoEncoderAdapterUnitTest::TearDown(void)
{
    videoEncoderAdapter_ = nullptr;
}

/**
 * @tc.name: Init_001
 * @tc.desc: Init
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Init_001, TestSize.Level1)
{
    std::string mime = "VideoEncoderAdapterTest";
    videoEncoderAdapter_->codecServer_ = nullptr;
    Status result = videoEncoderAdapter_->Init(mime, true);
    EXPECT_EQ(result, Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: Init_002
 * @tc.desc: Init
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Init_002, TestSize.Level1)
{
    std::string mime = "VideoEncoderAdapterTest";
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    videoEncoderAdapter_->releaseBufferTask_ = nullptr;
    Status result = videoEncoderAdapter_->Init(mime, true);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Init_003
 * @tc.desc: Init
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Init_003, TestSize.Level1)
{
    std::string mime = "VideoEncoderAdapterTest";
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    videoEncoderAdapter_->releaseBufferTask_ = std::make_shared<Task>("test");
    Status result = videoEncoderAdapter_->Init(mime, true);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Configure_001
 * @tc.desc: Configure
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Configure_001, TestSize.Level1)
{
    videoEncoderAdapter_->codecServer_ = nullptr;
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    EXPECT_EQ(videoEncoderAdapter_->Configure(meta), Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: Configure_002
 * @tc.desc: Configure
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Configure_002, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer,
                SetCallback(Matcher<const std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback> &>(_)))
        .WillOnce(Return(0));
    EXPECT_CALL(*codecServer, Configure(_)).WillOnce(Return(0));
    EXPECT_EQ(videoEncoderAdapter_->Configure(meta), Status::OK);
}

/**
 * @tc.name: SetWatermark_001
 * @tc.desc: SetWatermark
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetWatermark_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer();
    EXPECT_EQ(videoEncoderAdapter_->SetWatermark(waterMarkBuffer), Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: SetWatermark_002
 * @tc.desc: SetWatermark
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetWatermark_002, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer();
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, SetCustomBuffer(_)).WillOnce(Return(0));
    EXPECT_EQ(videoEncoderAdapter_->SetWatermark(waterMarkBuffer), Status::OK);
}

/**
 * @tc.name: SetStopTime_001
 * @tc.desc: SetStopTime
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetStopTime_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->SetStopTime();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: SetOutputBufferQueue_001
 * @tc.desc: SetOutputBufferQueue
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetOutputBufferQueue_001, TestSize.Level1)
{
    sptr<MockAVBufferQueueProducer> producer = new (std::nothrow) MockAVBufferQueueProducer();
    Status result = videoEncoderAdapter_->SetOutputBufferQueue(producer);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: SetEncoderAdapterCallback_001
 * @tc.desc: SetEncoderAdapterCallback
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetEncoderAdapterCallback_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    std::shared_ptr<MockEncoderAdapterCallback> encoderAdapterCallback = std::make_shared<MockEncoderAdapterCallback>();
    EXPECT_CALL(*codecServer, SetCallback(Matcher<const std::shared_ptr<MediaAVCodec::MediaCodecCallback> &>(_)))
        .WillOnce(Return(0));
    Status result = videoEncoderAdapter_->SetEncoderAdapterCallback(encoderAdapterCallback);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: SetEncoderAdapterCallback_002
 * @tc.desc: SetEncoderAdapterCallback
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetEncoderAdapterCallback_002, TestSize.Level1)
{
    videoEncoderAdapter_->codecServer_ = nullptr;
    std::shared_ptr<MockEncoderAdapterCallback> encoderAdapterCallback = std::make_shared<MockEncoderAdapterCallback>();
    Status result = videoEncoderAdapter_->SetEncoderAdapterCallback(encoderAdapterCallback);
    EXPECT_EQ(result, Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: SetEncoderAdapterKeyFramePtsCallback_001
 * @tc.desc: SetEncoderAdapterKeyFramePtsCallback
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetEncoderAdapterKeyFramePtsCallback_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->SetEncoderAdapterKeyFramePtsCallback(
        std::make_shared<MockEncoderAdapterKeyFramePtsCallback>());
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: SetTransCoderMode_001
 * @tc.desc: SetTransCoderMode
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetTransCoderMode_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->SetTransCoderMode();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: GetInputSurface_001
 * @tc.desc: GetInputSurface
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, GetInputSurface_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    sptr<Surface> surface;
    EXPECT_CALL(*codecServer, CreateInputSurface()).WillOnce(Return(surface));
    sptr<Surface> result = videoEncoderAdapter_->GetInputSurface();
    EXPECT_EQ(result, surface);
}

/**
 * @tc.name: GetInputSurface_002
 * @tc.desc: GetInputSurface
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, GetInputSurface_002, TestSize.Level1)
{
    sptr<Surface> result = videoEncoderAdapter_->GetInputSurface();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Start_001
 * @tc.desc: Start
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Start_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, Start()).WillOnce(Return(0));
    Status result = videoEncoderAdapter_->Start();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Start_002
 * @tc.desc: Start
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Start_002, TestSize.Level1)
{
    videoEncoderAdapter_->codecServer_ = nullptr;
    Status result = videoEncoderAdapter_->Start();
    EXPECT_EQ(result, Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Stop
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Stop_001, TestSize.Level1)
{
    videoEncoderAdapter_->curState_ = ProcessStateCode::RECORDING;
    videoEncoderAdapter_->isStreamStarted_ = true;
    videoEncoderAdapter_->hasReceivedEOS_ = true;
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, Stop()).WillOnce(Return(0));
    Status result = videoEncoderAdapter_->Stop();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Pause
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Pause_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->Pause();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Resume_001
 * @tc.desc: Resume
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Resume_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->Resume();
    EXPECT_EQ(result, Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: Flush_001
 * @tc.desc: Flush
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Flush_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, Flush()).WillOnce(Return(0));
    Status result = videoEncoderAdapter_->Flush();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Flush_002
 * @tc.desc: Flush
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Flush_002, TestSize.Level1)
{
    videoEncoderAdapter_->codecServer_ = nullptr;
    Status result = videoEncoderAdapter_->Flush();
    EXPECT_EQ(result, Status::ERROR_UNKNOWN);
}

/**
 * @tc.name: Reset_001
 * @tc.desc: Reset
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Reset_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, Reset()).WillOnce(Return(0));
    Status result = videoEncoderAdapter_->Reset();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: Release_001
 * @tc.desc: Release
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, Release_001, TestSize.Level1)
{
    Status result = videoEncoderAdapter_->Release();
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: NotifyEos_001
 * @tc.desc: NotifyEos
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, NotifyEos_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, NotifyEos()).WillOnce(Return(0));
    Status result = videoEncoderAdapter_->NotifyEos(0);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetParameter_001, TestSize.Level1)
{
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, SetParameter(_)).WillOnce(Return(0));
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    Status result = videoEncoderAdapter_->SetParameter(parameter);
    EXPECT_EQ(result, Status::OK);
}

/**
 * @tc.name: ReleaseBuffer_001
 * @tc.desc: ReleaseBuffer
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, ReleaseBuffer_001, TestSize.Level1)
{
    videoEncoderAdapter_->isThreadExit_ = true;
    videoEncoderAdapter_->ReleaseBuffer();
    EXPECT_EQ(videoEncoderAdapter_->startBufferTime_, -1);
}

/**
 * @tc.name: SetCallingInfo_001
 * @tc.desc: SetCallingInfo
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, SetCallingInfo_001, TestSize.Level1)
{
    videoEncoderAdapter_->SetCallingInfo(1, 1, "test", 0);
    EXPECT_EQ(videoEncoderAdapter_->bundleName_, "test");
}

/**
 * @tc.name: OnInputParameterWithAttrAvailablee_100
 * @tc.desc: OnInputParameterWithAttrAvailable
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, OnInputParameterWithAttrAvailablee_100, TestSize.Level1)
{
    uint32_t index = 0;
    std::shared_ptr<Format> attribute = std::make_shared<Format>();
    std::shared_ptr<Format> parameter = std::make_shared<Format>();
    std::shared_ptr<MockAVCodecVideoEncoder> codecServer = std::make_shared<MockAVCodecVideoEncoder>();
    videoEncoderAdapter_->codecServer_ = codecServer;
    EXPECT_CALL(*codecServer, Release()).WillOnce(Return(0));
    EXPECT_CALL(*codecServer, QueueInputParameter(_)).WillOnce(Return(0));
    videoEncoderAdapter_->OnInputParameterWithAttrAvailable(index, attribute, parameter);
    EXPECT_EQ(videoEncoderAdapter_->stopTime_, -1);
}

/**
 * @tc.name: CheckFrames_001
 * @tc.desc: CheckFrames
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, CheckFrames_001, TestSize.Level1)
{
    int64_t currentPts = 50;
    int64_t checkFramesPauseTime = 0;
    videoEncoderAdapter_->pauseResumeQueue_.push_back(std::make_pair(100, StateCode::PAUSE));
    bool result = videoEncoderAdapter_->CheckFrames(currentPts, checkFramesPauseTime);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: CheckFrames_002
 * @tc.desc: CheckFrames
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, CheckFrames_002, TestSize.Level1)
{
    int64_t currentPts = 50;
    int64_t checkFramesPauseTime = 0;
    videoEncoderAdapter_->pauseResumeQueue_.push_back(std::make_pair(100, StateCode::RESUME));
    bool result = videoEncoderAdapter_->CheckFrames(currentPts, checkFramesPauseTime);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: AddStartPts_001
 * @tc.desc: AddStartPts
 * @tc.type: FUNC
 */
HWTEST_F(VideoEncoderAdapterUnitTest, AddStartPts_001, TestSize.Level1)
{
    videoEncoderAdapter_->isStopKeyFramePts_ = true;
    videoEncoderAdapter_->currentKeyFramePts_ = 1;
    videoEncoderAdapter_->preKeyFramePts_ = 0;
    videoEncoderAdapter_->AddStopPts();
    EXPECT_EQ(videoEncoderAdapter_->keyFramePts_, "");
}

}  // namespace CameraStandard
}  // namespace OHOS