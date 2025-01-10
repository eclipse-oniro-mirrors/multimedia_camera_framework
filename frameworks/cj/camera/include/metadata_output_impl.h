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

#ifndef METADATA_OUTPUT_IMPL_H
#define METADATA_OUTPUT_IMPL_H

#include "camera_manager.h"
#include "camera_output_impl.h"
#include "camera_utils.h"
#include "cj_lambda.h"
#include "listener_base.h"
#include "metadata_output.h"

namespace OHOS {
namespace CameraStandard {

class CJMetadataOutputCallback : public MetadataObjectCallback, public ListenerBase<std::vector<sptr<MetadataObject>>> {
public:
    CJMetadataOutputCallback() = default;
    ~CJMetadataOutputCallback() = default;

    void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const override;
};

class CJMetadataStateCallback : public MetadataStateCallback, public ListenerBase<const int32_t> {
public:
    CJMetadataStateCallback() = default;
    ~CJMetadataStateCallback() = default;

    void OnError(const int32_t errorType) const override;
};

class CJMetadataOutput : public CameraOutput {
    DECL_TYPE(CJMetadataOutput, OHOS::FFI::FFIData)
public:
    CJMetadataOutput();
    ~CJMetadataOutput() = default;

    static int32_t CreateMetadataOutput(std::vector<MetadataObjectType> metadataObjectTypes);

    sptr<CameraStandard::CaptureOutput> GetCameraOutput() override;
    int32_t Release() override;

    int32_t Start();
    int32_t Stop();
    void OnMetadataObjectsAvailable(int64_t callbackId);
    void OffMetadataObjectsAvailable(int64_t callbackId);
    void OffAllMetadataObjectsAvailable();
    void OnError(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffAllError();

private:
    sptr<MetadataOutput> metadataOutput_;
    static thread_local sptr<MetadataOutput> sMetadataOutput_;

    std::shared_ptr<CJMetadataOutputCallback> metadataOutputCallback_;
    std::shared_ptr<CJMetadataStateCallback> metadataStateCallback_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif