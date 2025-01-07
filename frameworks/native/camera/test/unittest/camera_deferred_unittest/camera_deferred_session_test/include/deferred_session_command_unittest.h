/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DEFERRED_SESSION_COMMAND_UNITTEST_H
#define DEFERRED_SESSION_COMMAND_UNITTEST_H

#include "deferred_video_processing_session.h"
#include "deferred_video_processor.h"
#include "errors.h"
#include "gtest/gtest.h"
#include "ivideo_job_repository_listener.h"
#include "ivideo_process_callbacks.h"
#include "video_session_info.h"
#include "video_post_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class DeferredSessionCommandUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    void PrepareFd();

    void PrepareVideoInfo(const std::string& videoId);

    void InitProcessor(int32_t userId);

    void InitSessionInfo(int32_t userId);

    sptr<IPCFileDescriptor> srcFd_;
    sptr<IPCFileDescriptor> dstFd_;
    std::unordered_map<std::string, std::shared_ptr<DeferredVideoProcessingSession::VideoInfo>> videoInfoMap_;
    std::shared_ptr<DeferredVideoProcessor> processor_ {nullptr};
    sptr<VideoSessionInfo> sessionInfo_ {nullptr};

    static constexpr int videoSourceFd_ = 1;
    static constexpr int videoDestinationFd_ = 2;
};

class TestIVideoProcCb : public IVideoProcessCallbacks {
public:
    TestIVideoProcCb() = default;
    ~TestIVideoProcCb() = default;
    void OnProcessDone(const int32_t userId,
        const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd) override {}
    void OnError(const int32_t userId, const std::string& videoId, DpsError errorCode) override {}
    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override {}
};

class IRemoteObjectUnitTest : public IRemoteObject {
public:
    using IRemoteObject::IRemoteObject;
    inline int32_t GetObjectRefCount() override
    {
        return 0;
    }
    inline int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
    inline bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }
    inline bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }
    inline int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }
};

} // DeferredProcessing
} // CameraStandard
} // OHOS
#endif // DEFERRED_SESSION_COMMAND_UNITTEST_H
