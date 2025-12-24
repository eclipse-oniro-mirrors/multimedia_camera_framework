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

#include "audio_fork_filter_unit_test.h"

#include "camera_log.h"
#include "status.h"

namespace OHOS {
namespace CameraStandard {

void AudioForkFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void AudioForkFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void AudioForkFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    audioForkFilter_ = std::make_shared<AudioForkFilter>("test", CFilterType::AUDIO_PROCESS);
}

void AudioForkFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    CHECK_EXECUTE(audioForkFilter_, audioForkFilter_->DoRelease());
    CHECK_EXECUTE(audioForkFilter_, audioForkFilter_.reset());
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(AudioForkFilterUnitTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_EQ(audioForkFilter_->receiver_, receiver);
    EXPECT_EQ(audioForkFilter_->filterCallback_, callback);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(AudioForkFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(AudioForkFilterUnitTest, DoStart_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
}


/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(AudioForkFilterUnitTest, DoPause_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(AudioForkFilterUnitTest, DoResume_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoResume();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoFlush method
 */
HWTEST_F(AudioForkFilterUnitTest, DoFlush_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoFlush();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(AudioForkFilterUnitTest, DoStop_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(AudioForkFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    audioForkFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = audioForkFilter_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test SetParameter method
 */
HWTEST_F(AudioForkFilterUnitTest, SetParameter_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioForkFilter_->SetParameter(param);
    EXPECT_EQ(audioForkFilter_->audioParameter_, param);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test GetParameter method
 */
HWTEST_F(AudioForkFilterUnitTest, GetParameter_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioForkFilter_->SetParameter(param);
    std::shared_ptr<Meta> result;
    audioForkFilter_->GetParameter(result);
    EXPECT_EQ(result, param);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(AudioForkFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    EXPECT_CALL(*nextFilter, OnLinked(_, _, _)).WillOnce(Return(Status::OK));
    Status result = audioForkFilter_->LinkNext(nextFilter, CStreamType::FORK_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(AudioForkFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = audioForkFilter_->UpdateNext(nextFilter, CStreamType::FORK_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(AudioForkFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = audioForkFilter_->UnLinkNext(nextFilter, CStreamType::FORK_AUDIO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(AudioForkFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result = audioForkFilter_->GetFilterType();
    EXPECT_EQ(result, CFilterType::AUDIO_FORK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnLinkedResult method
 */
HWTEST_F(AudioForkFilterUnitTest, OnLinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioForkFilter_->OnLinked(CStreamType::FORK_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
    std::shared_ptr<AVBufferQueue> buffferQueue = AVBufferQueue::Create(1);
    sptr<AVBufferQueueProducer> producer = buffferQueue->GetProducer();
    EXPECT_CALL(*filterLinkCallback, OnLinkedResult(_, _)).WillOnce(Return());
    audioForkFilter_->OnLinkedResult(producer, param);
    EXPECT_NE(audioForkFilter_->audioForkBufferQueue_, nullptr);
    EXPECT_NE(audioForkFilter_->consumer_, nullptr);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(AudioForkFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioForkFilter_->OnLinked(CStreamType::FORK_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(AudioForkFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioForkFilter_->OnUpdated(CStreamType::FORK_AUDIO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(AudioForkFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = audioForkFilter_->OnUnLinked(CStreamType::FORK_AUDIO, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnUnlinkedResult method
 */
HWTEST_F(AudioForkFilterUnitTest, OnUnlinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioForkFilter_->OnUnlinkedResult(param);
    EXPECT_EQ(audioForkFilter_->name_, "test");
}

/*
 * Feature: AudioForkFilter
 * CaseDescription: Test OnUpdatedResult method
 */
HWTEST_F(AudioForkFilterUnitTest, OnUpdatedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    audioForkFilter_->OnUpdatedResult(param);
    EXPECT_EQ(audioForkFilter_->name_, "test");
}

}
}