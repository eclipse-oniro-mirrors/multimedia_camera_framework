/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_SKETCH_WRAPPER_H
#define OHOS_CAMERA_SKETCH_WRAPPER_H

#include "image_receiver.h"
#include "preview_output.h"

namespace OHOS {
namespace CameraStandard {
class SketchWrapper {
public:
    class SketchBufferAvaliableListener : public Media::SurfaceBufferAvaliableListener {
    public:
        explicit SketchBufferAvaliableListener(std::shared_ptr<SketchWrapper>& sketchWrapper)
            : sketchWrapper_(std::weak_ptr(sketchWrapper)) {};
        virtual void OnSurfaceBufferAvaliable() override;

    private:
        std::weak_ptr<SketchWrapper> sketchWrapper_;
    };

    explicit SketchWrapper(PreviewOutput* holder);
    virtual ~SketchWrapper();
    int32_t StartSketchStream();
    int32_t StopSketchStream();
    int32_t Init(
        std::shared_ptr<SketchBufferAvaliableListener>& listener, const Size size, Media::ImageFormat imageFormat);
    int32_t Destory();

private:
    PreviewOutput* holder_;
    sptr<IStreamRepeat> sketchStream_;
    std::shared_ptr<Media::ImageReceiver> sketchImgReceiver_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SKETCH_WRAPPER_H