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

#ifndef PHOTO_OUTPUT_UNITTEST_H
#define PHOTO_OUTPUT_UNITTEST_H

#include "gtest/gtest.h"
#include "hcamera_service.h"
#include "input/camera_manager.h"
#include "capture_scene_const.h"
#include "photo_output.h"

namespace OHOS {
namespace CameraStandard {

class TestIBufferConsumerListener : public IBufferConsumerListener {
public:
    void OnBufferAvailable() override {}
};

class CameraPhotoOutputUnit : public testing::Test {
public:
    uint64_t tokenId_;
    int32_t uid_;
    int32_t userId_;
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;
    sptr<CameraManager> cameraManager_;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    void NativeAuthorization(void);
    sptr<CaptureOutput> CreatePhotoOutput(int32_t width = PHOTO_DEFAULT_WIDTH, int32_t height = PHOTO_DEFAULT_HEIGHT);
};

}
}

#endif