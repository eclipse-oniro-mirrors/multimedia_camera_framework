/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TRANSFER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TRANSFER_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;

CameraInput CameraInputTransferStaticImpl(uintptr_t input);
uintptr_t CameraInputTransferDynamicImpl(CameraInput input);

PhotoOutput PhotoOutputTransferStaticImpl(uintptr_t input);
uintptr_t PhotoOutputTransferDynamicImpl(PhotoOutput input);

PreviewOutput PreviewOutputTransferStaticImpl(uintptr_t input);
uintptr_t PreviewOutputTransferDynamicImpl(PreviewOutput input);

VideoOutput VideoOutputTransferStaticImpl(uintptr_t input);
uintptr_t VideoOutputTransferDynamicImpl(VideoOutput input);

MetadataOutput MetadataOutputTransferStaticImpl(uintptr_t input);
uintptr_t MetadataOutputTransferDynamicImpl(MetadataOutput input);

VideoSession VideoSessionTransferStaticImpl(uintptr_t input);
uintptr_t VideoSessionTransferDynamicImpl(VideoSession input);

SecureSession SecureSessionTransferStaticImpl(uintptr_t input);
uintptr_t SecureSessionTransferDynamicImpl(SecureSession input);

PhotoSession PhotoSessionTransferStaticImpl(uintptr_t input);
uintptr_t PhotoSessionTransferDynamicImpl(PhotoSession input);

Photo PhotoTransferStaticImpl(uintptr_t input);
uintptr_t PhotoTransferDynamicImpl(Photo input);

} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TRANSFER_TAIHE_H