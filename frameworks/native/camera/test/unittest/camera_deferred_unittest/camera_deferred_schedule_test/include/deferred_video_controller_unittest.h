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

#ifndef DEFERRED_VIDEO_CONTROLLER_UNITTEST_H
#define DEFERRED_VIDEO_CONTROLLER_UNITTEST_H

#include "deferred_video_controller.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoControllerUnittest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    std::shared_ptr<DeferredVideoController> controller_ {nullptr};
    std::shared_ptr<DeferredVideoProcessor> processor_ {nullptr};
};
} // DeferredProcessing
} // CameraStandard
} // OHOS
#endif // DEFERRED_VIDEO_CONTROLLER_UNITTEST_H
