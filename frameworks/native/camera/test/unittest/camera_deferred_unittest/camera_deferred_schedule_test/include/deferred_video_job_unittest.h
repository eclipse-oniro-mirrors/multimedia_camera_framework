/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef DEFERRED_VIDEO_JOB_UNITTEST_H
#define DEFERRED_VIDEO_JOB_UNITTEST_H

#include "gtest/gtest.h"
#include "ivideo_job_repository_listener.h"
#include "ideferred_video_processing_session.h"
#include "dps.h"
#include "deferred_video_proc_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoJobUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    DeferredVideoJobPtr CreateTestDeferredVideoJobPtr(const std::string& videoId, VideoJobState curStatus);

    sptr<IPCFileDescriptor> srcFd_;
    sptr<IPCFileDescriptor> dstFd_;
};

class TestVideoJobRepositoryListener : public IVideoJobRepositoryListener {
public:
    explicit TestVideoJobRepositoryListener() {}

    ~TestVideoJobRepositoryListener() {}

    void OnVideoJobChanged(const DeferredVideoJobPtr& jobPtr) override {}
};

} // DeferredProcessing
} // CameraStandard
} // OHOS
#endif // DEFERRED_VIDEO_JOB_UNITTEST_H
