/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HSHARED_CAMERA_DEVICE_UNITTEST_H
#define HSHARED_CAMERA_DEVICE_UNITTEST_H

#include <cstdint>
#include "gtest/gtest.h"
#include "hcamera_device.h"
#include "hcamera_device_wrapper.h"
#include "hshared_camera_device.h"
#include "hcamera_service.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {

class HSharedCameraDeviceUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp(void);

    /* TearDown:Execute after each test case */
    void TearDown(void);

    sptr<HCameraDevice> CreateCameraDevice(const std::string& cameraId);

protected:
    uint64_t tokenId_;
    int32_t uid_;
    int32_t userId_;

private:
    sptr<HCameraHostManager> cameraHostManager_ = nullptr;
    sptr<CameraManager> cameraManager_ = nullptr;
    sptr<HCameraService> cameraService_ = nullptr;
};
} // CameraStandard
} // OHOS
#endif // HSHARED_CAMERA_DEVICE_UNITTEST_H