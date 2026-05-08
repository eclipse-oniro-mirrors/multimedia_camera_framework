/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cinttypes>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "movie_file_audio_metadata_buffer_producer.h"
#include "movie_file_consumer.h"
#include "movie_file_controller_video.h"
#include "unified_pipeline_audio_buffer.h"
#include "unified_pipeline_metadata_buffer.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace {
class MetadataBufferListener : public UnifiedPipelineBufferListener {
public:
    void OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer) override
    {
        bufferCount_++;
        lastBuffer_ = std::move(pipelineBuffer);
    }

    void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override
    {
        commandCount_++;
        lastCommand_ = std::move(command);
    }

    int32_t bufferCount_ = 0;
    int32_t commandCount_ = 0;
    std::unique_ptr<UnifiedPipelineBuffer> lastBuffer_ = nullptr;
    std::unique_ptr<UnifiedPipelineCommand> lastCommand_ = nullptr;
};

std::vector<uint8_t> CopyAudioBufferData(const PipelineAudioBufferData& data)
{
    std::vector<uint8_t> copiedData(data.dataSize);
    if (data.data != nullptr && data.dataSize > 0) {
        std::copy(data.data.get(), data.data.get() + data.dataSize, copiedData.begin());
    }
    return copiedData;
}
} // namespace

class MovieFileAudioMetadataUnitTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/*
 * Feature: MovieFileAudioMetadataBufferProducer
 * Function: OnMetaDataArrival
 * SubFunction: NA
 * FunctionPoints: Verify 4+2 audio metadata is converted to a pipeline metadata buffer.
 * EnvConditions: NA
 * CaseDescription: Non-empty metadata should keep its timestamp, type, payload, and 4+2 buffer type.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, OnMetaDataArrival_WrapsAudioMetadata, TestSize.Level0)
{
    auto producer = std::make_shared<MovieFileAudioMetadataBufferProducer>();
    auto listener = std::make_shared<MetadataBufferListener>();
    producer->SetBufferListener(listener);

    constexpr int64_t timestamp = 123456789;
    auto type = static_cast<AudioStandard::CaptureMetaDataType>(7);
    std::vector<uint8_t> metaData = { 0x11, 0x22, 0x33, 0x44 };

    producer->OnMetaDataArrival(type, metaData, timestamp);

    ASSERT_EQ(listener->bufferCount_, 1);
    ASSERT_NE(listener->lastBuffer_, nullptr);
    EXPECT_EQ(listener->lastBuffer_->GetBufferType(), BufferType::CAMERA_AUDIO_4_2_METADATA);

    auto metadataBuffer =
        UnifiedPipelineBuffer::CastPtr<UnifiedPipelineMetadataBuffer>(std::move(listener->lastBuffer_));
    auto data = metadataBuffer->UnwrapData();
    EXPECT_EQ(data.timestamp, timestamp);
    EXPECT_EQ(data.type, static_cast<int32_t>(type));
    EXPECT_EQ(data.metaData, metaData);
}

/*
 * Feature: MovieFileAudioMetadataBufferProducer
 * Function: OnMetaDataArrival
 * SubFunction: NA
 * FunctionPoints: Verify empty callback payloads are dropped before entering the pipeline.
 * EnvConditions: NA
 * CaseDescription: Empty metadata should not notify the downstream buffer listener.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, OnMetaDataArrival_DropsEmptyMetadata, TestSize.Level0)
{
    auto producer = std::make_shared<MovieFileAudioMetadataBufferProducer>();
    auto listener = std::make_shared<MetadataBufferListener>();
    producer->SetBufferListener(listener);

    producer->OnMetaDataArrival(static_cast<AudioStandard::CaptureMetaDataType>(1), {}, 1000);

    EXPECT_EQ(listener->bufferCount_, 0);
    EXPECT_EQ(listener->lastBuffer_, nullptr);
}

/*
 * Feature: UnifiedPipelineMetadataBuffer
 * Function: WrapData/UnwrapData
 * SubFunction: NA
 * FunctionPoints: Verify the metadata buffer owns callback payload independently from the source vector.
 * EnvConditions: NA
 * CaseDescription: Wrapped metadata should retain a copy even if the original vector is modified later.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, MetadataBuffer_RetainsWrappedData, TestSize.Level0)
{
    UnifiedPipelineMetadataBuffer buffer(BufferType::CAMERA_AUDIO_4_2_METADATA);
    std::vector<uint8_t> metaData = { 0x01, 0x02, 0x03 };

    buffer.WrapData({ .timestamp = 2000, .type = 3, .metaData = metaData });
    metaData[0] = 0xff;

    auto data = buffer.UnwrapData();
    std::vector<uint8_t> expectedMetaData = { 0x01, 0x02, 0x03 };
    EXPECT_EQ(buffer.GetBufferType(), BufferType::CAMERA_AUDIO_4_2_METADATA);
    EXPECT_EQ(data.timestamp, 2000);
    EXPECT_EQ(data.type, 3);
    EXPECT_EQ(data.metaData, expectedMetaData);
}

/*
 * Feature: MovieFileConsumer
 * Function: ConsumerTimeKeeper
 * SubFunction: MetadataTimeKeeper
 * FunctionPoints: Verify 4+2 metadata keeps an independent relative timestamp base.
 * EnvConditions: NA
 * CaseDescription: Normal metadata and 4+2 metadata should not share first metadata timestamp state.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, ConsumerTimeKeeper_SeparatesNormalAndAudioMetadataTimeBase, TestSize.Level0)
{
    MovieFileConsumer::ConsumerTimeKeeper timeKeeper;

    EXPECT_FALSE(timeKeeper.IsVideoStarted());
    EXPECT_EQ(timeKeeper.GetVideoRelativeTime(10000), 0);
    EXPECT_TRUE(timeKeeper.IsVideoStarted());

    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime(20000), 0);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime(23000), 3000);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime4_2(50000), 0);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime4_2(54000), 4000);
}

/*
 * Feature: MovieFileConsumer
 * Function: ConsumerTimeKeeper::UpdateStartTime
 * SubFunction: MetadataTimeKeeper
 * FunctionPoints: Verify segmented recording resets the 4+2 metadata base and preserves accumulated video duration.
 * EnvConditions: NA
 * CaseDescription: After a segment reset, 4+2 metadata should align to the new segment with the accumulated duration.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, ConsumerTimeKeeper_ResetClearsAudioMetadataTimeBase, TestSize.Level0)
{
    MovieFileConsumer::ConsumerTimeKeeper timeKeeper;

    EXPECT_EQ(timeKeeper.GetVideoRelativeTime(10000), 0);
    EXPECT_EQ(timeKeeper.GetVideoRelativeTime(13000), 3000);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime4_2(30000), 0);

    timeKeeper.UpdateStartTime(40000);

    EXPECT_FALSE(timeKeeper.IsVideoStarted());
    EXPECT_EQ(timeKeeper.GetVideoRelativeTime(50000), 19000);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime4_2(53000), 19000);
    EXPECT_EQ(timeKeeper.GetMetadataRelativeTime4_2(56000), 22000);
}

/*
 * Feature: MovieFileConsumer
 * Function: OnMetaDataBufferArrivalFor4_2_AUDIO
 * SubFunction: MetadataGuard
 * FunctionPoints: Verify 4+2 metadata is ignored until the video timeline is established.
 * EnvConditions: NA
 * CaseDescription: Metadata arriving before the first video frame should not initialize the 4+2 metadata base.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, OnMetaDataBufferArrivalFor4_2_DropsBeforeVideoStarts, TestSize.Level0)
{
    MovieFileConsumer consumer;
    consumer.metaTrackId4_2_ = 1;

    auto metadataBuffer = std::make_unique<UnifiedPipelineMetadataBuffer>(BufferType::CAMERA_AUDIO_4_2_METADATA);
    metadataBuffer->WrapData({ .timestamp = 60000, .type = 2, .metaData = { 0x08, 0x09 } });

    consumer.OnMetaDataBufferArrivalFor4_2_AUDIO(std::move(metadataBuffer));

    EXPECT_EQ(consumer.timeKeeper_.firstMetadataTimestamp4_2_, MovieFileConsumer::INVALID_TIMESTAMP);
}

/*
 * Feature: MovieFileControllerVideo
 * Function: CreateAudioStreamInfoForSuperListenering
 * SubFunction: AudioStreamInfo
 * FunctionPoints: Verify the 4+2 capturer stream is described as six-channel PCM at the producer sample rate.
 * EnvConditions: NA
 * CaseDescription: Super listening stream info should match the 4 mic-in + 2 processed channel layout.
 */
HWTEST_F(
    MovieFileAudioMetadataUnitTest, CreateAudioStreamInfoForSuperListenering_ReturnsFourChannelPcm, TestSize.Level0)
{
    MovieFileControllerVideo controller(1920, 1080, false, 30, 30000000);

    auto streamInfo = controller.CreateAudioStreamInfoForSuperListenering();

    EXPECT_EQ(streamInfo.samplingRate, UnifiedPipelineAudioCaptureWrap::AUDIO_PRODUCER_SAMPLING_RATE);
    EXPECT_EQ(streamInfo.encoding, AudioStandard::AudioEncodingType::ENCODING_PCM);
    EXPECT_EQ(streamInfo.format, AudioStandard::AudioSampleFormat::SAMPLE_S16LE);
    EXPECT_EQ(streamInfo.channels, AudioStandard::AudioChannel::CHANNEL_4);
}

/*
 * Feature: MovieFileControllerVideo
 * Function: ConfigMicAudioPipeline
 * SubFunction: PipelineSetup
 * FunctionPoints: Verify the mic-in 4+2 path creates an audio producer and two pipeline plugins.
 * EnvConditions: NA
 * CaseDescription: Mic-in audio should pass through raw packaging and encoder plugins before reaching the consumer.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, ConfigMicAudioPipeline_CreatesProducerAndPlugins, TestSize.Level0)
{
    MovieFileControllerVideo controller(1920, 1080, false, 30, 30000000);
    auto streamInfo = controller.CreateAudioStreamInfoForSuperListenering();

    controller.ConfigMicAudioPipeline(streamInfo, nullptr);

    auto producer = controller.movieFileAudioMicBufferProducer_.Get();
    ASSERT_NE(producer, nullptr);
    ASSERT_NE(controller.sharedAudioCaptureStreamInfo_, nullptr);
    EXPECT_EQ(controller.sharedAudioCaptureStreamInfo_->channels, AudioStandard::AudioChannel::CHANNEL_4);

    auto pipeline = controller.movieFilePipelineManager_->GetPipelineWithProducer(producer);
    ASSERT_NE(pipeline, nullptr);
    EXPECT_EQ(pipeline->plugins_.size(), 2);
}

/*
 * Feature: MovieFileControllerVideo
 * Function: ConfigProcessAudioPipeline
 * SubFunction: PipelineSetup
 * FunctionPoints: Verify the processed 2-channel 4+2 path creates an audio producer and encoder plugin.
 * EnvConditions: NA
 * CaseDescription: Wrapped audio should skip raw/effect plugins and enter the encoder directly.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, ConfigProcessAudioPipeline_CreatesProducerAndEncoderPlugin, TestSize.Level0)
{
    MovieFileControllerVideo controller(1920, 1080, false, 30, 30000000);
    auto streamInfo = controller.CreateAudioStreamInfoForSuperListenering();

    controller.ConfigProcessAudioPipeline(streamInfo, nullptr);

    auto producer = controller.movieFileAudioProcessBufferProducer_.Get();
    ASSERT_NE(producer, nullptr);

    auto pipeline = controller.movieFilePipelineManager_->GetPipelineWithProducer(producer);
    ASSERT_NE(pipeline, nullptr);
    EXPECT_EQ(pipeline->plugins_.size(), 2);
}

/*
 * Feature: MovieFileControllerVideo
 * Function: OnSuperListeningDataArrival
 * SubFunction: AudioRouting
 * FunctionPoints: Verify mic-in and processed 4+2 audio buffers are routed to independent producers.
 * EnvConditions: NA
 * CaseDescription: The split callback should copy mic-in data to the mic producer and processed data to the wrap
 * producer.
 */
HWTEST_F(MovieFileAudioMetadataUnitTest, OnSuperListeningDataArrival_RoutesMicAndProcessBuffers, TestSize.Level0)
{
    MovieFileControllerVideo controller(1920, 1080, false, 30, 30000000);
    auto streamInfo = controller.CreateAudioStreamInfoForSuperListenering();
    controller.ConfigMicAudioPipeline(streamInfo, nullptr);
    controller.ConfigProcessAudioPipeline(streamInfo, nullptr);

    auto micListener = std::make_shared<MetadataBufferListener>();
    auto processListener = std::make_shared<MetadataBufferListener>();
    controller.movieFileAudioMicBufferProducer_.Get()->SetBufferListener(micListener);
    controller.movieFileAudioProcessBufferProducer_.Get()->SetBufferListener(processListener);

    constexpr int64_t timestamp = 987654;
    std::vector<uint8_t> processBuffer = { 0x10, 0x11, 0x12 };
    std::vector<uint8_t> micInBuffer = { 0x20, 0x21, 0x22, 0x23 };

    controller.OnSuperListeningDataArrival(
        timestamp, processBuffer.data(), processBuffer.size(), micInBuffer.data(), micInBuffer.size());

    ASSERT_EQ(micListener->bufferCount_, 1);
    ASSERT_EQ(processListener->bufferCount_, 1);
    ASSERT_NE(micListener->lastBuffer_, nullptr);
    ASSERT_NE(processListener->lastBuffer_, nullptr);

    auto micPipelineBuffer =
        UnifiedPipelineBuffer::CastPtr<UnifiedPipelineAudioBuffer>(std::move(micListener->lastBuffer_));
    auto processPipelineBuffer =
        UnifiedPipelineBuffer::CastPtr<UnifiedPipelineAudioBuffer>(std::move(processListener->lastBuffer_));
    auto micData = micPipelineBuffer->UnwrapData();
    auto wrapData = processPipelineBuffer->UnwrapData();

    EXPECT_EQ(micData.timestamp, timestamp);
    EXPECT_EQ(micData.dataSize, micInBuffer.size());
    EXPECT_TRUE(micData.isRawBuffer);
    EXPECT_EQ(CopyAudioBufferData(micData), micInBuffer);

    EXPECT_EQ(wrapData.timestamp, timestamp);
    EXPECT_EQ(wrapData.dataSize, processBuffer.size());
    EXPECT_TRUE(wrapData.isRawBuffer);
    EXPECT_EQ(CopyAudioBufferData(wrapData), processBuffer);
}
} // namespace CameraStandard
} // namespace OHOS