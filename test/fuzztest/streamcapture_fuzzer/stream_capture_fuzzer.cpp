/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#include "camera_log.h"
#include "iconsumer_surface.h"
#include "metadata_utils.h"
#include "stream_capture_fuzzer.h"
#include "test_token.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamCapture";
const size_t LIMITCOUNT = 4;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
static constexpr int32_t MIN_SIZE_NUM = 120;

void StreamCaptureFuzzTest(uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");

    int32_t itemCount = 10;
    int32_t dataSize = 100;
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams.data(), streams.size() / LIMITCOUNT);
    int32_t compensationRange[2] = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
        sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = fdp.ConsumeFloatingPoint<float>();
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

     int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
     ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

     int32_t cameraPosition = fdp.ConsumeIntegral<int32_t>();
     ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
        sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));

     MessageParcel data;
     data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
     CHECK_RETURN_ELOG(!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(ability, data)),
         "StreamCaptureFuzzer: EncodeCameraMetadata Error");
     data.RewindRead(0);

     sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
     CHECK_RETURN_ELOG(!photoSurface, "StreamCaptureFuzzer: Create photoSurface Error");
     sptr<IBufferProducer> producer = photoSurface->GetProducer();
     sptr<HStreamCapture> streamcapture = new HStreamCapture(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
     CHECK_RETURN(streamcapture == nullptr);
     streamcapture->Release();
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamCaptureFuzzTest(data, size);
    return 0;
}