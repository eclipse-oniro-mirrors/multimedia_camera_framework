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

#ifndef CAMERA_AUDIO_CAPTURE_FILTER_UNIT_TEST_H
#define CAMERA_AUDIO_CAPTURE_FILTER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "audio_capture_adapter.h"
#include "audio_capture_filter.h"
#include "avbuffer_queue_define.h"
#include "avbuffer_queue_producer.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;

class AudioCaptureFilterUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

protected:
    std::shared_ptr<AudioCaptureFilter> audioCaptureFilter_ {nullptr};
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

class MockNextFilter : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));
    MOCK_METHOD(Status, OnLinked,
            (CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback), (override));

    MockNextFilter(std::string name = "MockAudNextFilter", CFilterType type = CFilterType::AUDIO_PROCESS)
        : CFilter(name, type)
    {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, OnLinked(_, _, _)).WillByDefault(Return(Status::OK));
    }
};

class MockAudioCapturerInfoChangeCallback : public OHOS::AudioStandard::AudioCapturerInfoChangeCallback {
public:
    MOCK_METHOD1(OnStateChange, void(const OHOS::AudioStandard::AudioCapturerChangeInfo &captureChangeInfo));
};

class MockAudioCaptureModule : public AudioCaptureAdapter {
public:
    MOCK_METHOD0(Start, Status());
    MOCK_METHOD0(Prepare, Status());
    MOCK_METHOD0(DoDeinit, Status());
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

}  // namespace Media
}  // namespace OHOS
#endif  // CAMERA_AUDIO_CAPTURE_FILTER_UNIT_TEST_H