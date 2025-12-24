/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "audio_encoder_filter_unit_test.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace testing::mt;
using namespace testing;
namespace OHOS {
namespace CameraStandard {
static constexpr uint32_t MULTI_THREAD_NUM = 10;

void AudioEncoderFilterUnitTest::SetUpTestCase(void) {}

void AudioEncoderFilterUnitTest::TearDownTestCase(void) {}

void AudioEncoderFilterUnitTest::SetUp(void)
{
    audioEncoderFilter_ =
        std::make_shared<AudioEncoderFilter>("testAudioEncoderFilter", CFilterType::AUDIO_ENC);
    ASSERT_NE(audioEncoderFilter_, nullptr);
}

void AudioEncoderFilterUnitTest::TearDown(void)
{
    audioEncoderFilter_ = nullptr;
}

class EventReceiverMock : public CEventReceiver {
public:
    void OnEvent(const Event &event) override
    {
        (void)event;
    }
};

class FilterCallbackMock : public CFilterCallback {
public:
    Status OnCallback(const std::shared_ptr<CFilter>& filter, CFilterCallBackCommand cmd, CStreamType outType) override
    {
        (void)filter;
        (void)cmd;
        (void)outType;
        return Status::OK;
    }
};

class MediaCodecMock : public OHOS::Media::MediaCodec {
public:
    
    int32_t Init(const std::string &mime, bool isEncoder)
    {
        (void)mime;
        (void)isEncoder;
        return 0;
    }
    int32_t Configure(const std::shared_ptr<Meta> &meta)
    {
        (void)meta;
        return configure_;
    }
    int32_t Start()
    {
        return start_;
    }
    int32_t Stop()
    {
        return stop_;
    }
    int32_t Flush()
    {
        return flush_;
    }
    int32_t Release()
    {
        return release_;
    }
    int32_t NotifyEos()
    {
        return notifyEos_;
    }
    int32_t SetParameter(const std::shared_ptr<Meta> &parameter)
    {
        (void)parameter;
        return 0;
    }
    int32_t GetOutputFormat(std::shared_ptr<Meta> &parameter)
    {
        int32_t ret = 0;
        if (getOutputFormat_) {
            int32_t frameSize = 1024;
            parameter->Set<Tag::AUDIO_SAMPLE_PER_FRAME>(frameSize);
        } else {
            ret = -1;
        }
        return ret;
    }
    int32_t SetOutputBufferQueue(const sptr<AVBufferQueueProducer> &bufferQueueProducer)
    {
        (void)bufferQueueProducer;
        return 0;
    }
    int32_t Prepare()
    {
        return 0;
    }
    sptr<AVBufferQueueProducer> GetInputBufferQueue()
    {
        uint32_t size = 8;
        inputBufferQueue_ = AVBufferQueue::Create(size);
        if (inputBufferQueue_ == nullptr) {
            return nullptr;
        }
        inputBufferQueueProducer_ = inputBufferQueue_->GetProducer();
        return inputBufferQueueProducer_;
    }
protected:
    int32_t configure_ = 0;
    int32_t start_ = 0;
    int32_t stop_ = 0;
    int32_t flush_ = 0;
    int32_t release_ = 0;
    int32_t notifyEos_ = 0;
    bool getOutputFormat_ = false;
    std::shared_ptr<AVBufferQueue> inputBufferQueue_ = nullptr;
    sptr<AVBufferQueueProducer> inputBufferQueueProducer_ = nullptr;
};

class FilterMock : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));

    FilterMock() : CFilter("filterMock", CFilterType::MAX)
    {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
    }

    ~FilterMock() = default;
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback)
    {
        (void)inType;
        (void)meta;
        (void)callback;
        return onLinked_;
    }
protected:
    Status onLinked_;
};

class FilterLinkCallbackMock : public CFilterLinkCallback {
public:
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
    {
        (void)queue;
        (void)meta;
    }
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
    {
        (void)meta;
    }
    void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
    {
        (void)meta;
    }
};

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_Destructor_0100, TestSize.Level1)
{
    audioEncoderFilter_ =
        std::make_shared<AudioEncoderFilter>("testAudioEncoderFilter", CFilterType::AUDIO_ENC);
    EXPECT_NE(audioEncoderFilter_, nullptr);
}

void PrintThreadInfo()
{
    std::thread::id this_id = std::this_thread::get_id();
    std::ostringstream oss;
    oss << this_id;
    std::string this_id_str = oss.str();
    long int thread_id = atol(this_id_str.c_str());
    printf("running thread...: %ld\n", thread_id); // 输出当前线程的id
}

HWMTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_Destructor_0101, TestSize.Level1, MULTI_THREAD_NUM)
{
    printf("AudioEncoderFilter_Destructor_0101 BEGIN\n");
    PrintThreadInfo();
    auto audioEncoderFilter =
        std::make_shared<AudioEncoderFilter>("testAudioEncoderFilter", CFilterType::AUDIO_ENC);
    EXPECT_NE(audioEncoderFilter, nullptr);
    printf("AudioEncoderFilter_Destructor_0101 END\n");
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_SetCodecFormat_0100, TestSize.Level1)
{
    // format == nulllptr
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    EXPECT_EQ(audioEncoderFilter_->SetCodecFormat(format), Status::ERROR_INVALID_PARAMETER);

    // format != nullptr
    format->Set<Tag::MIME_TYPE>(std::string("audio/mp3"));
    EXPECT_EQ(audioEncoderFilter_->SetCodecFormat(format), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_Init_0100, TestSize.Level1)
{
    auto mediaCodecMock = std::make_shared<MediaCodecMock>();
    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    ASSERT_NE(audioEncoderFilter_->mediaCodec_, nullptr);
    auto receiver = std::make_shared<EventReceiverMock>();
    auto callback = std::make_shared<FilterCallbackMock>();
    audioEncoderFilter_->Init(receiver, callback);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_Configure_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    // ret != 0
    EXPECT_NE(audioEncoderFilter_->Configure(parameter), Status::OK);
    // ret = 0
    auto mockCodecPlugin = std::make_shared<MockCodecPlugin>("video/avc");
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::INITIALIZED;
    audioEncoderFilter_->mediaCodec_->codecPlugin_ = mockCodecPlugin;
    EXPECT_CALL(*mockCodecPlugin, SetParameter(testing::_)).WillOnce(Return(Status::OK));
    EXPECT_CALL(*mockCodecPlugin, SetDataCallback(testing::_)).WillOnce(Return(Status::OK));
    EXPECT_EQ(audioEncoderFilter_->Configure(parameter), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoPrepare_0100, TestSize.Level1)
{
    auto mediaCodecMock = std::make_shared<MediaCodecMock>();
    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    auto filterCallback = std::make_shared<FilterCallbackMock>();

    audioEncoderFilter_->filterType_ = CFilterType::AUDIO_ENC;
    audioEncoderFilter_->filterCallback_ = filterCallback;
    EXPECT_EQ(audioEncoderFilter_->DoPrepare(), Status::OK);

    audioEncoderFilter_->filterType_ = CFilterType::AUDIO_DEC;
    EXPECT_EQ(audioEncoderFilter_->DoPrepare(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoStart_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;

    // ret != 0
    EXPECT_NE(audioEncoderFilter_->DoStart(), Status::OK);
    // ret = 0
    auto mockCodecPlugin = std::make_shared<MockCodecPlugin>("video/avc");
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::PREPARED;
    audioEncoderFilter_->mediaCodec_->codecPlugin_ = mockCodecPlugin;
    EXPECT_CALL(*mockCodecPlugin, Start()).WillOnce(Return(Status::OK));
    EXPECT_EQ(audioEncoderFilter_->DoStart(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoPause_0100, TestSize.Level1)
{
    EXPECT_EQ(audioEncoderFilter_->DoPause(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoResume_0100, TestSize.Level1)
{
    EXPECT_EQ(audioEncoderFilter_->DoResume(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoStop_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;

    // ret != 0
    auto mockCodecPlugin = std::make_shared<MockCodecPlugin>("video/avc");
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::RUNNING;
    audioEncoderFilter_->mediaCodec_->codecPlugin_ = mockCodecPlugin;
    EXPECT_CALL(*mockCodecPlugin, Stop()).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_NE(audioEncoderFilter_->DoStop(), Status::OK);
    // ret = 0
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::PREPARED;
    EXPECT_EQ(audioEncoderFilter_->DoStop(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoFlush_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;

    //ret != 0
    EXPECT_NE(audioEncoderFilter_->DoFlush(), Status::OK);
    //ret = 0
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::FLUSHED;
    EXPECT_EQ(audioEncoderFilter_->DoFlush(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_DoRelease_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;

    // ret != 0
    auto mockCodecPlugin = std::make_shared<MockCodecPlugin>("video/avc");
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::RUNNING;
    audioEncoderFilter_->mediaCodec_->codecPlugin_ = mockCodecPlugin;
    EXPECT_CALL(*mockCodecPlugin, Release()).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_NE(audioEncoderFilter_->DoRelease(), Status::OK);
    // ret = 0
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::RELEASING;
    EXPECT_EQ(audioEncoderFilter_->DoRelease(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_NotifyEos_0100, TestSize.Level1)
{
    auto mediaCodec = std::make_shared<MediaCodec>();
    audioEncoderFilter_->mediaCodec_ = mediaCodec;

    // ret != 0
    EXPECT_NE(audioEncoderFilter_->NotifyEos(), Status::OK);

    // ret == 0
    audioEncoderFilter_->mediaCodec_->state_ = CodecState::END_OF_STREAM;
    EXPECT_EQ(audioEncoderFilter_->NotifyEos(), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_SetParameter_0100, TestSize.Level1)
{
    auto mediaCodecMock = std::make_shared<MediaCodecMock>();
    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    ASSERT_NE(parameter, nullptr);
    audioEncoderFilter_->SetParameter(parameter);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_GetParameter_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    ASSERT_NE(parameter, nullptr);
    audioEncoderFilter_->GetParameter(parameter);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_LinkNext_0100, TestSize.Level1)
{
    auto mediaCodecMock = std::make_shared<MediaCodecMock>();
    auto filterMock = std::make_shared<FilterMock>();
    std::shared_ptr<CFilter> nextFilter = filterMock;

    audioEncoderFilter_->mediaCodec_ = nullptr;
    filterMock->onLinked_ = Status::ERROR_INVALID_PARAMETER;
    EXPECT_NE(audioEncoderFilter_->LinkNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);

    audioEncoderFilter_->mediaCodec_ = nullptr;
    filterMock->onLinked_ = Status::OK;
    EXPECT_EQ(audioEncoderFilter_->LinkNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);

    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    mediaCodecMock->getOutputFormat_ = true;
    filterMock->onLinked_ = Status::ERROR_INVALID_PARAMETER;
    EXPECT_NE(audioEncoderFilter_->LinkNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);

    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    mediaCodecMock->getOutputFormat_ = false;
    filterMock->onLinked_ = Status::ERROR_INVALID_PARAMETER;
    EXPECT_NE(audioEncoderFilter_->LinkNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_UpdateNext_0100, TestSize.Level1)
{
    auto filterMock = std::make_shared<FilterMock>();
    std::shared_ptr<CFilter> nextFilter = filterMock;
    EXPECT_EQ(audioEncoderFilter_->UpdateNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_UnLinkNext_0100, TestSize.Level1)
{
    auto filterMock = std::make_shared<FilterMock>();
    std::shared_ptr<CFilter> nextFilter = filterMock;
    EXPECT_EQ(audioEncoderFilter_->UnLinkNext(nextFilter, CStreamType::ENCODED_VIDEO), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_GetFilterType_0100, TestSize.Level1)
{
    audioEncoderFilter_->filterType_ = CFilterType::AUDIO_ENC;
    EXPECT_EQ(audioEncoderFilter_->GetFilterType(), CFilterType::AUDIO_ENC);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnLinked_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    auto callback = std::make_shared<FilterLinkCallbackMock>();
    EXPECT_EQ(audioEncoderFilter_->OnLinked(CStreamType::ENCODED_VIDEO, meta, callback), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnUpdated_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    auto callback = std::make_shared<FilterLinkCallbackMock>();
    EXPECT_EQ(audioEncoderFilter_->OnUpdated(CStreamType::ENCODED_VIDEO, meta, callback), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnUnLinked_0100, TestSize.Level1)
{
    auto callback = std::make_shared<FilterLinkCallbackMock>();
    EXPECT_EQ(audioEncoderFilter_->OnUnLinked(CStreamType::ENCODED_VIDEO, callback), Status::OK);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnLinkedResult_0100, TestSize.Level1)
{
    auto mediaCodecMock = std::make_shared<MediaCodecMock>();
    ASSERT_NE(mediaCodecMock, nullptr);
    audioEncoderFilter_->mediaCodec_ = mediaCodecMock;
    
    audioEncoderFilter_->onLinkedResultCallback_ = std::make_shared<FilterLinkCallbackMock>();
    ASSERT_NE(audioEncoderFilter_->onLinkedResultCallback_, nullptr);
    
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    ASSERT_NE(meta, nullptr);
    sptr<AVBufferQueueProducer> outputBufferQueue = nullptr;
    audioEncoderFilter_->OnLinkedResult(outputBufferQueue, meta);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnUpdatedResult_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    ASSERT_NE(meta, nullptr);
    audioEncoderFilter_->OnUpdatedResult(meta);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_OnUnlinkedResult_0100, TestSize.Level1)
{
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    ASSERT_NE(meta, nullptr);
    audioEncoderFilter_->OnUnlinkedResult(meta);
}

HWTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_SetCallingInfo_0100, TestSize.Level1)
{
    int32_t appUid = 1000;
    int32_t appPid = 1001;
    uint64_t instanceId = 1002;
    std::string bundleName = "bundleName";
    audioEncoderFilter_->SetCallingInfo(appUid, appPid, bundleName, instanceId);
    EXPECT_EQ(audioEncoderFilter_->appUid_, appUid);
    EXPECT_EQ(audioEncoderFilter_->appPid_, appPid);
    EXPECT_EQ(audioEncoderFilter_->bundleName_, bundleName);
    EXPECT_EQ(audioEncoderFilter_->instanceId_, instanceId);
}

HWMTEST_F(AudioEncoderFilterUnitTest, AudioEncoderFilter_SetCallingInfo_0101, TestSize.Level1, MULTI_THREAD_NUM)
{
    printf("AudioEncoderFilter_SetCallingInfo_0101 BEGIN\n");
    int32_t appUid = 1000;
    int32_t appPid = 1001;
    uint64_t instanceId = 1002;
    std::string bundleName = "bundleName";
    auto audioEncoderFilter =
        std::make_shared<AudioEncoderFilter>("testAudioEncoderFilter", CFilterType::AUDIO_ENC);
    audioEncoderFilter->SetCallingInfo(appUid, appPid, bundleName, instanceId);
    EXPECT_EQ(audioEncoderFilter->appUid_, appUid);
    EXPECT_EQ(audioEncoderFilter->appPid_, appPid);
    EXPECT_EQ(audioEncoderFilter->bundleName_, bundleName);
    EXPECT_EQ(audioEncoderFilter->instanceId_, instanceId);
    PrintThreadInfo();
    printf("AudioEncoderFilter_SetCallingInfo_0101 END\n");
}
} // CameraStandard
} // OHOS