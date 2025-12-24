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

#ifndef MUXER_FILTER_UNIT_TEST_H
#define MUXER_FILTER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "muxer_filter.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;

class MuxerFilterUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

private:
    std::shared_ptr<MuxerFilter> muxerFilter_ {nullptr};
};

class MockCEventReceiver : public CEventReceiver {
public:
    MOCK_METHOD(void, OnEvent, (const Event& event), (override));

    MockCEventReceiver()
    {
        ON_CALL(*this, OnEvent(_)).WillByDefault(Return());
    }
};

class MockCFilterCallback : public CFilterCallback {
public:
    MOCK_METHOD(Status, OnCallback,
                (const std::shared_ptr<CFilter> &filter, CFilterCallBackCommand cmd, CStreamType outType), (override));

    MockCFilterCallback()
    {
        ON_CALL(*this, OnCallback(_, _, _)).WillByDefault(Return(Status::OK));
    }
};

class MockCFilterLinkCallback : public CFilterLinkCallback {
public:
    MOCK_METHOD(void, OnLinkedResult, (const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta),
                (override));
    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta> &meta), (override));
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta> &meta), (override));

    MockCFilterLinkCallback()
    {
        ON_CALL(*this, OnLinkedResult(_, _)).WillByDefault(Return());
        ON_CALL(*this, OnUnlinkedResult(_)).WillByDefault(Return());
        ON_CALL(*this, OnUpdatedResult(_)).WillByDefault(Return());
    }
};

class MockPrevFilter : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));
    MOCK_METHOD(Status, OnLinked,
            (CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback), (override));
    
    MockPrevFilter() : CFilter("MockPrevFilter", CFilterType::VIDEO_ENC)
    {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, OnLinked(_, _, _)).WillByDefault(Return(Status::OK));
    }
};

class MockMediaMuxer : public MediaMuxer {
public:
    MOCK_METHOD(Status, Start, (), (override));
    MOCK_METHOD(Status, Stop, (), (override));
    MOCK_METHOD(Status, AddTrack, (int32_t &trackIndex, const std::shared_ptr<Meta> &trackDesc), (override));
    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetInputBufferQueue, (uint32_t trackIndex), (override));

    MockMediaMuxer(int32_t appUid, int32_t appPid) : MediaMuxer(appUid, appPid) {
        ON_CALL(*this, Start()).WillByDefault(Return(Status::OK));
        ON_CALL(*this, Stop()).WillByDefault(Return(Status::OK));
        ON_CALL(*this, AddTrack(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, GetInputBufferQueue(_)).WillByDefault(Return(nullptr));
    }
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
}
}

#endif
