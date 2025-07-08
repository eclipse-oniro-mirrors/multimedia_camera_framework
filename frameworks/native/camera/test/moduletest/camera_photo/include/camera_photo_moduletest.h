/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PHOTO_MODULETEST_H
#define CAMERA_PHOTO_MODULETEST_H

#include <vector>

#include "gtest/gtest.h"
#include "input/camera_manager.h"


namespace OHOS {
namespace CameraStandard {
const int32_t WAIT_TIME_AFTER_CAPTURE = 1;
const int32_t WAIT_TIME_AFTER_START = 1;
const int32_t WAIT_TIME_CALLBACK = 2;

class CameraPhotoModuleTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

protected:
    void UpdataCameraOutputCapability(int32_t modeName = 0);
    int32_t CreatePreviewOutput(Profile &profile, sptr<PreviewOutput> &previewOutput);
    int32_t CreatePhotoOutputWithoutSurface(Profile &profile, sptr<PhotoOutput> &photoOutput);

    uint8_t callbackFlag_ = 0;

    sptr<CameraInput> input_;
    std::vector<sptr<CameraDevice>> cameras_;
    sptr<CameraManager> manager_;
    sptr<CaptureSession> session_;

    sptr<PreviewOutput> previewOutput_;
    sptr<PhotoOutput> photoOutput_;
    std::vector<Profile> previewProfile_ = {};
    std::vector<Profile> photoProfile_ = {};
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PHOTO_MODULETEST_H
