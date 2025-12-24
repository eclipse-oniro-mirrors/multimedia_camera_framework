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

#include "metadata_filter_unit_test.h"

#include "avbuffer_queue.h"
#include "camera_log.h"
#include "status.h"

namespace OHOS {
namespace CameraStandard {
void MetaDataFilterUnitTest::SetUpTestCase(void)
{
    std::cout << "[SetUpTestCase] is called" << std::endl;
}

void MetaDataFilterUnitTest::TearDownTestCase(void)
{
    std::cout << "[TearDownTestCase] is called" << std::endl;
}

void MetaDataFilterUnitTest::SetUp()
{
    std::cout << "[SetUp] is called" << std::endl;
    metaDataFilter_ = std::make_shared<MetaDataFilter>("TestMetaDataFilter", CFilterType::TIMED_METADATA);
}

void MetaDataFilterUnitTest::TearDown()
{
    std::cout << "[TearDown] is called" << std::endl;
    CHECK_EXECUTE(metaDataFilter_, metaDataFilter_->DoRelease());
    CHECK_EXECUTE(metaDataFilter_, metaDataFilter_.reset());
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test Init method
 */
HWTEST_F(MetaDataFilterUnitTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_EQ(metaDataFilter_->eventReceiver_, receiver);
    EXPECT_EQ(metaDataFilter_->filterCallback_, callback);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test Configure method
 */
HWTEST_F(MetaDataFilterUnitTest, Configure_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    metaDataFilter_->Configure(param);
    EXPECT_EQ(metaDataFilter_->configureParameter_, param);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test SetInputMetaSurface method
 */
HWTEST_F(MetaDataFilterUnitTest, SetInputMetaSurface_001, TestSize.Level1)
{
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    Status result = metaDataFilter_->SetInputMetaSurface(surface);
    EXPECT_EQ(metaDataFilter_->inputSurface_, surface);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test SetInputMetaSurface method
 */
HWTEST_F(MetaDataFilterUnitTest, SetInputMetaSurface_002, TestSize.Level1)
{
    sptr<Surface> surface;
    Status result = metaDataFilter_->SetInputMetaSurface(surface);
    EXPECT_NE(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test GetInputMetaSurface method
 */
HWTEST_F(MetaDataFilterUnitTest, GetInputMetaSurface_001, TestSize.Level1)
{
    sptr<Surface> surface = metaDataFilter_->GetInputMetaSurface();
    EXPECT_NE(surface, nullptr);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoPrepare method
 */
HWTEST_F(MetaDataFilterUnitTest, DoPrepare_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoStart method
 */
HWTEST_F(MetaDataFilterUnitTest, DoStart_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
}


/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoPause method
 */
HWTEST_F(MetaDataFilterUnitTest, DoPause_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoResume method
 */
HWTEST_F(MetaDataFilterUnitTest, DoResume_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoPause();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoResume();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoFlush method
 */
HWTEST_F(MetaDataFilterUnitTest, DoFlush_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoFlush();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoStop method
 */
HWTEST_F(MetaDataFilterUnitTest, DoStop_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test DoRelease method
 */
HWTEST_F(MetaDataFilterUnitTest, DoRelease_001, TestSize.Level1)
{
    std::shared_ptr<MockCEventReceiver> receiver = std::make_shared<MockCEventReceiver>();
    std::shared_ptr<MockCFilterCallback> callback = std::make_shared<MockCFilterCallback>();
    metaDataFilter_->Init(receiver, callback);
    EXPECT_CALL(*callback, OnCallback(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->DoPrepare();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStart();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoStop();
    EXPECT_EQ(result, Status::OK);
    result = metaDataFilter_->DoRelease();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test NotifyEos method
 */
HWTEST_F(MetaDataFilterUnitTest, NotifyEos_001, TestSize.Level1)
{
    Status result = metaDataFilter_->NotifyEos();
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test LinkNext method
 */
HWTEST_F(MetaDataFilterUnitTest, LinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    EXPECT_CALL(*nextFilter, OnLinked(_, _, _)).WillOnce(Return(Status::OK));
    Status result = metaDataFilter_->LinkNext(nextFilter, CStreamType::RAW_METADATA);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test UpdateNext method
 */
HWTEST_F(MetaDataFilterUnitTest, UpdateNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = metaDataFilter_->UpdateNext(nextFilter, CStreamType::RAW_METADATA);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test UnLinkNext method
 */
HWTEST_F(MetaDataFilterUnitTest, UnLinkNext_001, TestSize.Level1)
{
    std::shared_ptr<MockNextFilter> nextFilter = std::make_shared<MockNextFilter>();
    Status result = metaDataFilter_->UnLinkNext(nextFilter, CStreamType::RAW_METADATA);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test GetFilterType method
 */
HWTEST_F(MetaDataFilterUnitTest, GetFilterType_001, TestSize.Level1)
{
    CFilterType result = metaDataFilter_->GetFilterType();
    EXPECT_EQ(result, CFilterType::TIMED_METADATA);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnLinked method
 */
HWTEST_F(MetaDataFilterUnitTest, OnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = metaDataFilter_->OnLinked(CStreamType::RAW_METADATA, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnUpdated method
 */
HWTEST_F(MetaDataFilterUnitTest, OnUpdated_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = metaDataFilter_->OnUpdated(CStreamType::RAW_METADATA, param, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnUnLinked method
 */
HWTEST_F(MetaDataFilterUnitTest, OnUnLinked_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<MockCFilterLinkCallback> filterLinkCallback =
        std::make_shared<MockCFilterLinkCallback>();
    Status result = metaDataFilter_->OnUnLinked(CStreamType::RAW_METADATA, filterLinkCallback);
    EXPECT_EQ(result, Status::OK);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnLinkedResult method
 */
HWTEST_F(MetaDataFilterUnitTest, OnLinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    std::shared_ptr<AVBufferQueue> buffferQueue = AVBufferQueue::Create(1);
    sptr<AVBufferQueueProducer> producer = buffferQueue->GetProducer();
    metaDataFilter_->OnLinkedResult(producer, param);
    EXPECT_EQ(metaDataFilter_->outputBufferQueueProducer_, producer);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnUpdatedResult method
 */
HWTEST_F(MetaDataFilterUnitTest, OnUpdatedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    metaDataFilter_->OnUpdatedResult(param);
    EXPECT_NE(metaDataFilter_, nullptr);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test OnUnlinkedResult method
 */
HWTEST_F(MetaDataFilterUnitTest, OnUnlinkedResult_001, TestSize.Level1)
{
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    metaDataFilter_->OnUnlinkedResult(param);
    EXPECT_NE(metaDataFilter_, nullptr);
}

/*
 * Feature: MetaDataFilter
 * CaseDescription: Test UpdateBufferConfig method
 */
HWTEST_F(MetaDataFilterUnitTest, UpdateBufferConfig_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    int64_t timestamp = 1;
    metaDataFilter_->UpdateBufferConfig(buffer, timestamp);
    EXPECT_EQ(metaDataFilter_->latestBufferTime_, timestamp);
}

}
}