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

#include "audio_process_filter_unit_test.h"

#include "camera_log.h"
#include "status.h"

namespace OHOS {
namespace CameraStandard {

void AudioProcessFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void AudioProcessFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void AudioProcessFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    audioProcessFilter_ = std::make_shared<AudioProcessFilter>("test", CFilterType::AUDIO_PROCESS);
}

void AudioProcessFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    CHECK_EXECUTE(audioProcessFilter_, audioProcessFilter_->DoRelease());
    CHECK_EXECUTE(audioProcessFilter_, audioProcessFilter_.reset());
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(AudioProcessFilterUnitTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_NE(audioProcessFilter_->taskPtr_, nullptr);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoStart_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
}


/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoPause_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoResume_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoResume();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoFlush method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoFlush_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoFlush();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoStop_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(AudioProcessFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioProcessFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = audioProcessFilter_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test SetParameter method
 */
HWTEST_F(AudioProcessFilterUnitTest, SetParameter_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioProcessFilter_->SetParameter(param);
    EXPECT_NE(audioProcessFilter_->audioParameter_, nullptr);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test GetParameter method
 */
HWTEST_F(AudioProcessFilterUnitTest, GetParameter_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioProcessFilter_->SetParameter(param);
    std::shared_ptr<Meta> result;
    audioProcessFilter_->GetParameter(result);
    EXPECT_NE(result, nullptr);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(AudioProcessFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    EXPECT_CALL(*nextFilter, OnLinked(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioProcessFilter_->LinkNext(nextFilter, CStreamType::PROCESSED_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(AudioProcessFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = audioProcessFilter_->UpdateNext(nextFilter, CStreamType::PROCESSED_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(AudioProcessFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = audioProcessFilter_->UnLinkNext(nextFilter, CStreamType::PROCESSED_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(AudioProcessFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result = audioProcessFilter_->GetFilterType();
    EXPECT_EQ(result, CFilterType::AUDIO_PROCESS);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnLinkedResult method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnLinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioProcessFilter_->OnLinked(CStreamType::RAW_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
    std::shared_ptr<AVBufferQueue> buffferQueue = AVBufferQueue::Create(1);
    sptr<AVBufferQueueProducer> producer = buffferQueue->GetProducer();
    EXPECT_CALL(*filterLinkCallback, OnLinkedResult(_, _)).WillOnce(Return());
    audioProcessFilter_->OnLinkedResult(producer, param);
    EXPECT_NE(audioProcessFilter_->audioProcessBufferQueue_, nullptr);
    EXPECT_NE(audioProcessFilter_->consumer_, nullptr);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioProcessFilter_->OnLinked(CStreamType::RAW_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioProcessFilter_->OnUpdated(CStreamType::RAW_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioProcessFilter_->OnUnLinked(CStreamType::RAW_AUDIO, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnUnlinkedResult method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnUnlinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioProcessFilter_->OnUnlinkedResult(param);
    EXPECT_EQ(audioProcessFilter_->name_, "test");
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test OnUpdatedResult method
 */
HWTEST_F(AudioProcessFilterUnitTest, OnUpdatedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioProcessFilter_->OnUpdatedResult(param);
    EXPECT_EQ(audioProcessFilter_->name_, "test");
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test CreateOfflineAudioEffectChain method
 */
HWTEST_F(AudioProcessFilterUnitTest, CreateOfflineAudioEffectChain_001, TestSize.Level1)
{
    audioProcessFilter_->CreateOfflineAudioEffectChain();
    EXPECT_NE(audioProcessFilter_->offlineAudioEffectManager_, nullptr);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test SetAudioCaptureOptions method
 */
HWTEST_F(AudioProcessFilterUnitTest, SetAudioCaptureOptions_001, TestSize.Level1)
{
    AudioStandard::AudioStreamInfo streamInfo = {};
    streamInfo.channels = AudioStandard::AudioChannel::STEREO;
    AudioStandard::AudioCapturerOptions options = {};
    options.streamInfo = streamInfo;
    audioProcessFilter_->SetAudioCaptureOptions(options);
    EXPECT_EQ(audioProcessFilter_->inputOptions_.streamInfo.channels, options.streamInfo.channels);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test GetOutputAudioStreamInfo method
 */
HWTEST_F(AudioProcessFilterUnitTest, GetOutputAudioStreamInfo_001, TestSize.Level1)
{
    AudioStandard::AudioStreamInfo result;
    audioProcessFilter_->GetOutputAudioStreamInfo(result);
    EXPECT_EQ(audioProcessFilter_->outputStreamInfo_.channels, result.channels);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test SendRawAudioToEncoder method
 */
HWTEST_F(AudioProcessFilterUnitTest, SendRawAudioToEncoder_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> inputBuffer;
    Status result = audioProcessFilter_->SendRawAudioToEncoder(inputBuffer);
    EXPECT_EQ(result, Status::ERROR_NULL_POINTER);
}

/*
 * Feature: AudioProcessFilter
 * CaseDescription: Test SendPostEditAudioToEncoder method
 */
HWTEST_F(AudioProcessFilterUnitTest, SendPostEditAudioToEncoder_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> inputBuffer;
    Status result = audioProcessFilter_->SendPostEditAudioToEncoder(inputBuffer);
    EXPECT_EQ(result, Status::ERROR_NULL_POINTER);
}

}
}