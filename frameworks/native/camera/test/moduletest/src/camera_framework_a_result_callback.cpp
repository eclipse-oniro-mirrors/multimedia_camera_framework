/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera_framework_moduletest.h"

using namespace testing::ext;
using namespace OHOS::HDI::Camera::V1_0;

namespace OHOS {
namespace CameraStandard {

/*
 * Feature: Framework
 * Function: Test Result Callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Result Callback
 */

HWTEST_F(CameraFrameworkModuleTest, Camera_ResultCallback_moduletest, TestSize.Level0)
{
    int32_t intResult = session_->BeginConfig();
    EXPECT_EQ(intResult, 0);

    intResult = session_->AddInput(input_);
    EXPECT_EQ(intResult, 0);

    // Register error callback
    std::shared_ptr<AppCallback> callback = std::make_shared<AppCallback>();
    std::shared_ptr<ResultCallback> resultCallback = callback;
    sptr<CameraInput> camInput = (sptr<CameraInput>&)input_;
    camInput->SetResultCallback(resultCallback);
    EXPECT_EQ(g_camInputOnError, false);

    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();
    ASSERT_NE(previewOutput, nullptr);

    intResult = session_->AddOutput(previewOutput);
    EXPECT_EQ(intResult, 0);

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    ASSERT_NE(videoOutput, nullptr);

    intResult = session_->AddOutput(videoOutput);
    EXPECT_EQ(intResult, 0);

    intResult = session_->CommitConfig();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    intResult = ((sptr<PreviewOutput>&)previewOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Start();
    EXPECT_EQ(intResult, 0);

    sleep(WAIT_TIME_AFTER_START);
    EXPECT_NE(g_metaResult, nullptr);

    intResult = ((sptr<VideoOutput>&)videoOutput)->Stop();
    EXPECT_EQ(intResult, 0);

    TestUtils::SaveVideoFile(nullptr, 0, VideoSaveMode::CLOSE, g_videoFd);

    sleep(WAIT_TIME_BEFORE_STOP);
    ((sptr<PreviewOutput>&)previewOutput)->Stop();
    session_->Stop();
}

} // CameraStandard
} // OHOS