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

#include "cinematic_video_cache_filter_unit_test.h"

#include "camera_log.h"
#include "status.h"

namespace OHOS {
namespace CameraStandard {

void CinematicVideoCacheFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void CinematicVideoCacheFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void CinematicVideoCacheFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    cinematicVideoCacheFilter_ = std::make_shared<CinematicVideoCacheFilter>("TestCinematicVideoCacheFilter",
                                                                             CFilterType::CINEMATIC_VIDEO_CACHE);
}

void CinematicVideoCacheFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    CHECK_EXECUTE(cinematicVideoCacheFilter_, cinematicVideoCacheFilter_->DoRelease());
    CHECK_EXECUTE(cinematicVideoCacheFilter_, cinematicVideoCacheFilter_.reset());
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_EQ(cinematicVideoCacheFilter_->eventReceiver_, receiver);
    EXPECT_EQ(cinematicVideoCacheFilter_->filterCallback_, callback);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoStart_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
}


/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoPause_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoResume_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoResume();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoFlush method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoFlush_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoFlush();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoStop_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    cinematicVideoCacheFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = cinematicVideoCacheFilter_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    EXPECT_CALL(*nextFilter, OnLinked(_, _, _)).WillOnce(Return(Status::OK));
    Status result = cinematicVideoCacheFilter_->LinkNext(nextFilter, CStreamType::CACHED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = cinematicVideoCacheFilter_->UpdateNext(nextFilter, CStreamType::CACHED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = cinematicVideoCacheFilter_->UnLinkNext(nextFilter, CStreamType::CACHED_VIDEO);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result = cinematicVideoCacheFilter_->GetFilterType();
    EXPECT_EQ(result, CFilterType::CINEMATIC_VIDEO_CACHE);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = cinematicVideoCacheFilter_->OnLinked(CStreamType::CACHED_VIDEO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = cinematicVideoCacheFilter_->OnUpdated(CStreamType::CACHED_VIDEO, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = cinematicVideoCacheFilter_->OnUnLinked(CStreamType::CACHED_VIDEO, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnLinkedResult method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnLinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<AVBufferQueue> buffferQueue = AVBufferQueue::Create(1);
    sptr<AVBufferQueueProducer> producer = buffferQueue->GetProducer();
    cinematicVideoCacheFilter_->OnLinkedResult(producer, param);
    EXPECT_NE(cinematicVideoCacheFilter_, nullptr);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnUpdatedResult method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnUpdatedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    cinematicVideoCacheFilter_->OnUpdatedResult(param);
    EXPECT_NE(cinematicVideoCacheFilter_, nullptr);
}

/*
 * Feature: CinematicVideoCacheFilter
 * CaseDescription: Test OnUnlinkedResult method
 */
HWTEST_F(CinematicVideoCacheFilterUnitTest, OnUnlinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    cinematicVideoCacheFilter_->OnUnlinkedResult(param);
    EXPECT_NE(cinematicVideoCacheFilter_, nullptr);
}

}
}