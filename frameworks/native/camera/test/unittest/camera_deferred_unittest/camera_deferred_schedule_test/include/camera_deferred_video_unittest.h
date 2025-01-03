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

#ifndef CAMERA_FRAMEWORK_DEFERRED_UNITTEST_H
#define CAMERA_FRAMEWORK_DEFERRED_UNITTEST_H

#include "gtest/gtest.h"
#include "ideferred_video_processing_session.h"
#include "dps.h"
#include "deferred_video_proc_session.h"

namespace OHOS {
namespace CameraStandard {
class TestDeferredVideoProcSessionCallback : public DeferredVideoProcessingSessionCallback {
public:
    TestDeferredVideoProcSessionCallback() = default;
    ~TestDeferredVideoProcSessionCallback() = default;

    ErrCode OnProcessVideoDone(const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd);
    ErrCode OnError(const std::string& videoId, int32_t errorCode);
    ErrCode OnStateChanged(int32_t status);
};

class DeferredVideoUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    void NativeAuthorization();
    void BeginSchedule(bool isCharging);
    void PauseSchedule();
    uint64_t g_tokenId_;
    int32_t g_uid_;
    int32_t g_userId_;
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session_ {nullptr};
    std::shared_ptr<DeferredProcessing::SessionManager> sessionManager_ {nullptr};
    std::shared_ptr<DeferredProcessing::SchedulerManager> schedulerManager_ {nullptr};
    std::shared_ptr<DeferredProcessing::VideoJobRepository> jobRepository_ {nullptr};
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_DEFERRED_UNITTEST_H
