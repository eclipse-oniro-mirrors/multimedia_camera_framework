/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_TRACK_FACTORY_H
#define OHOS_CAMERA_DPS_TRACK_FACTORY_H

#include "avsource.h"
#include "singleton.h"
#include "track.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class TrackFactory : public Singleton<TrackFactory> {
    DECLARE_SINGLETON(TrackFactory)
public:
    std::shared_ptr<Track> CreateTrack(const std::shared_ptr<AVSource>& source, int trackIndex);
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_TRACK_FACTORY_H