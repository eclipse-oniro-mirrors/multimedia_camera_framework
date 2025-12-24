/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef COMPOSITION_FEATURE_UNITTEST_H
#define COMPOSITION_FEATURE_UNITTEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "native_info_callback.h"
#include "features/composition_feature.h"
#include "capture_session.h"
#include "camera_manager.h"
#include "camera_log.h"
namespace OHOS {
namespace CameraStandard {
class CompositionFeatureUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    sptr<CaptureSession> captureSession_ = nullptr;
};

class MockCompositionEffectInfoCallback : public NativeInfoCallback<CompositionEffectInfo> {
public:
    MockCompositionEffectInfoCallback()
    {
        ON_CALL(*this, OnInfoChanged).WillByDefault([this](CompositionEffectInfo info) { isCalled_ = true; });
    };
    virtual ~MockCompositionEffectInfoCallback() = default;
    MOCK_METHOD(void, OnInfoChanged, (CompositionEffectInfo), (override));
    bool isCalled_ = false;
};

class CompositionEffectListenerTest : public testing::Test {
public:
    void SetUp() override
    {
        feature_ = std::make_shared<CompositionFeature>(nullptr);
        surface_ = IConsumerSurface::Create();
        listener_ = sptr<CompositionEffectListener>::MakeSptr(feature_, surface_);
        callback_ = std::make_shared<MockCompositionEffectInfoCallback>();
        feature_->SetCompositionEffectReceiveCallback(callback_);
    }

    void TearDown() override {}

protected:
    std::shared_ptr<MockCompositionEffectInfoCallback> callback_;
    sptr<IConsumerSurface> surface_;
    sptr<CompositionEffectListener> listener_;
    std::shared_ptr<CompositionFeature> feature_;
};

} // namespace CameraStandard
} // namespace OHOS

#endif