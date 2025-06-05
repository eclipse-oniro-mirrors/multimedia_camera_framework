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

#ifndef HSTREAM_OPERATOR_UNITTEST_H
#define HSTREAM_OPERATOR_UNITTEST_H

#include "display_manager_lite.h"
#include "gtest/gtest.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "hstream_capture.h"
#include "hstream_common.h"
#include "hstream_depth_data.h"
#include "hstream_metadata.h"
#include "hstream_operator.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {

class HStreamOperatorUnitTest : public testing::Test {
public:
    sptr<IBufferProducer> producer_;
    sptr<HStreamOperator> streamOp_;
    sptr<IConsumerSurface> surface_;
    static const int32_t PHOTO_DEFAULT_WIDTH = 1280;
    static const int32_t PHOTO_DEFAULT_HEIGHT = 960;

    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    sptr<HStreamCapture> GenStreamCapture(int32_t w = PHOTO_DEFAULT_WIDTH, int32_t h = PHOTO_DEFAULT_HEIGHT);
    sptr<HStreamMetadata> GenSteamMetadata(std::vector<int32_t> metadataTypes = {});
    sptr<HStreamRepeat> GenSteamRepeat(
        RepeatStreamType type, int32_t w = PHOTO_DEFAULT_WIDTH, int32_t h = PHOTO_DEFAULT_HEIGHT);
    sptr<HStreamDepthData> GenSteamDepthData(int32_t w = PHOTO_DEFAULT_WIDTH, int32_t h = PHOTO_DEFAULT_HEIGHT);
};

} // namespace CameraStandard
} // namespace OHOS
#endif // HSTREAM_OPERATOR_UNITTEST_H