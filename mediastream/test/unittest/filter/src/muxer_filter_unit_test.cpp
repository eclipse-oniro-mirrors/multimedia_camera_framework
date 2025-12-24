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

#include "muxer_filter_unit_test.h"

#include "avbuffer_queue.h"
#include "camera_log.h"
#include "status.h"

namespace OHOS {
namespace CameraStandard {
void MuxerFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void MuxerFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void MuxerFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    muxerFilter_ = std::make_shared<MuxerFilter>("TestMetaDataFilter", CFilterType::MUXER);
}

void MuxerFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    CHECK_EXECUTE(muxerFilter_, muxerFilter_->DoRelease());
    CHECK_EXECUTE(muxerFilter_, muxerFilter_.reset());
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test SetOutputParameter method
 */
HWTEST_F(MuxerFilterUnitTest, SetOutputParameter_001, TestSize.Level1)
{
    Status result = muxerFilter_->SetOutputParameter(0, 0,0, 0);
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test SetTransCoderMode method
 */
HWTEST_F(MuxerFilterUnitTest, SetTransCoderMode_001, TestSize.Level1)
{
    Status result = muxerFilter_->SetTransCoderMode();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test GetCurrentPtsMs method
 */
HWTEST_F(MuxerFilterUnitTest, GetCurrentPtsMs_001, TestSize.Level1)
{
    int64_t result = muxerFilter_->GetCurrentPtsMs();
    EXPECT_EQ(result, 0);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(MuxerFilterUnitTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    muxerFilter_->Init(receiver, callback);
    EXPECT_EQ(muxerFilter_->eventReceiver_, receiver);
    EXPECT_EQ(muxerFilter_->filterCallback_, callback);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(MuxerFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    muxerFilter_->Init(receiver, callback);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(MuxerFilterUnitTest, DoStart_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
}


/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(MuxerFilterUnitTest, DoPause_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(MuxerFilterUnitTest, DoResume_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoResume();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoFlush method
 */
HWTEST_F(MuxerFilterUnitTest, DoFlush_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoFlush();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(MuxerFilterUnitTest, DoStop_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(MuxerFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, Start()).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    Status result = muxerFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = muxerFilter_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(MuxerFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockPrevFilter> nextFilter = std::make_shared<MockPrevFilter>();
    Status result = muxerFilter_->LinkNext(nextFilter, CStreamType::ENCODED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(MuxerFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockPrevFilter> nextFilter = std::make_shared<MockPrevFilter>();
    Status result = muxerFilter_->UpdateNext(nextFilter, CStreamType::ENCODED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(MuxerFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockPrevFilter> nextFilter = std::make_shared<MockPrevFilter>();
    Status result = muxerFilter_->UnLinkNext(nextFilter, CStreamType::ENCODED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(MuxerFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result = muxerFilter_->GetFilterType();
    EXPECT_EQ(result, CFilterType::MUXER);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test HandleAudioMimeType method
 */
HWTEST_F(MuxerFilterUnitTest, HandleAudioMimeType_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    Status result = muxerFilter_->HandleAudioMimeType(param);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test HandleVideoMimeType method
 */
HWTEST_F(MuxerFilterUnitTest, HandleVideoMimeType_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    Status result = muxerFilter_->HandleVideoMimeType(param);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test HandleMetaDataMimeType method
 */
HWTEST_F(MuxerFilterUnitTest, HandleMetaDataMimeType_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    Status result = muxerFilter_->HandleMetaDataMimeType(param);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(MuxerFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<MockMediaMuxer> mockMediaMuxer = std::make_shared<MockMediaMuxer>(0, 0);
    EXPECT_CALL(*mockMediaMuxer, AddTrack(_, _)).WillOnce(Return(Status::OK));
    sptr<MockAVBufferQueueProducer> producer = new (std::nothrow) MockAVBufferQueueProducer();
    EXPECT_CALL(*mockMediaMuxer, GetInputBufferQueue(_)).WillOnce(Return(producer));
    EXPECT_CALL(*producer, SetBufferFilledListener(_)).WillOnce(Return(Status::OK));
    muxerFilter_->mediaMuxer_ = std::static_pointer_cast<MediaMuxer>(mockMediaMuxer);
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    EXPECT_CALL(*filterLinkCallback, OnLinkedResult(_, _)).WillOnce(Return());
    Status result = muxerFilter_->OnLinked(CStreamType::ENCODED_VIDEO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(MuxerFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = muxerFilter_->OnUpdated(CStreamType::ENCODED_VIDEO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MuxerFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(MuxerFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = muxerFilter_->OnUnLinked(CStreamType::ENCODED_VIDEO, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

}
}