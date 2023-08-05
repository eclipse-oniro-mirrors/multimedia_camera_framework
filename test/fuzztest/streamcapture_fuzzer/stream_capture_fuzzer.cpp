/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "stream_capture_fuzzer.h"
#include "metadata_utils.h"
using namespace std;

namespace OHOS {
namespace CameraStandard {
constexpr int32_t OFFSET = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ICameraDeviceService";
const int32_t LIMITSIZE = 4;
const int32_t SHIFT_LEFT_8 = 8;
const int32_t SHIFT_LEFT_16 = 16;
const int32_t SHIFT_LEFT_24 = 24;
static int32_t g_cnt = 0;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = CAMERA_FORMAT_JPEG;

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /* Move the 0th digit to the left by 24 bits, the 1st digit to the left by 16 bits,
       the 2nd digit to the left by 8 bits, and the 3rd digit not to the left */
    return (ptr[0] << SHIFT_LEFT_24) | (ptr[1] << SHIFT_LEFT_16) | (ptr[2] << SHIFT_LEFT_8) | (ptr[3]);
}
void StreamCaptureFuzzTest(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    cout<<"StreamCaptureFuzzTest begin--------------------------------------- g_cnt = "<<++g_cnt<<endl;
    uint32_t code = StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_START;
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    //开始构造std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings数据
    int32_t itemCount = 0;
    int32_t dataSize = 0;
    uint8_t streams = rawData;
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams,
                      sizeof(streams) / sizeof(streams[0]));
    int32_t compensationRange[2] = {rawData, rawData};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = rawData;
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, sizeof(float));

    int32_t sensorOrientation = 0;
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, sizeof(int32_t));

    int32_t cameraPosition = 0;
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, sizeof(int32_t));

    const camera_rational_t aeCompensationStep[] = {{0, 1}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));
    //结束构造std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings数据

    MessageParcel data;
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    if (photoSurface == nullptr) {
        return 0;
    }
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    std::shared_ptr<HStreamCapture> streamcapture =
        std::make_shared<HStreamCapture>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    streamcapture->OnRemoteRequest(code, data, reply, option);
    cout<<"StreamCaptureFuzzTest begin--------------------------------------- g_cnt = "<<++g_cnt<<endl;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    cout<<"StreamCaptureFuzzTest begin+++++++++++++++++++++++++++++++++"<<endl;
    OHOS::CameraStandard::StreamCaptureFuzzTest(data, size);
    cout<<"StreamCaptureFuzzTest end+++++++++++++++++++++++++++++++++++"<<endl;
    return 0;
}

