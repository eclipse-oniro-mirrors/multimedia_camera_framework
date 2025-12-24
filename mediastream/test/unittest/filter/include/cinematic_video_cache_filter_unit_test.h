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

#ifndef CINEMATIC_VIDEO_CACHE_FILTER_UNIT_TEST_H
#define CINEMATIC_VIDEO_CACHE_FILTER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "cinematic_video_cache_filter.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;

class CinematicVideoCacheFilterUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

private:
    std::shared_ptr<CinematicVideoCacheFilter> cinematicVideoCacheFilter_ {nullptr};
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

class MockNextFilter : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));
    MOCK_METHOD(Status, OnLinked,
            (CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback), (override));

    MockNextFilter(std::string name = "MockVidNextFilter", CFilterType type = CFilterType::VIDEO_ENC)
        : CFilter(name, type)
    {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, OnLinked(_, _, _)).WillByDefault(Return(Status::OK));
    }
};
}
}

#endif
