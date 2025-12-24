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

#ifndef STITCHING_PHOTO_SESSION_UNITTEST_H
#define STITCHING_PHOTO_SESSION_UNITTEST_H

#include "camera_log.h"
#include "camera_manager.h"
#include "gtest/gtest.h"
#include "stitching_photo_session.h"

namespace OHOS {
namespace CameraStandard {
class CameraStitchingPhotoSessionUnit : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

private:
    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    static constexpr CameraFormat PREVIEW_FORMAT = CAMERA_FORMAT_YUV_420_SP;
    static constexpr Size PREVIEW_SIZE { .width = 1920, .height = 1440 };
    static constexpr CameraFormat PHOTO_FORMAT = CAMERA_FORMAT_HEIC;
    static constexpr Size PHOTO_SIZE { .width = 4000, .height = 20000 };
};

} // namespace CameraStandard
} // namespace OHOS

#endif