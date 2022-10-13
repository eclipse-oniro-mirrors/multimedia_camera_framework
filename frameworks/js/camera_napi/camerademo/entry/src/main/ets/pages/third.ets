// @ts-nocheck
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
import Router from '@system.router';
import {Log} from "../Utils/utils";
import camera from '@ohos.multimedia.camera';
import image from '@ohos.multimedia.image';
import media from '@ohos.multimedia.media';
enum STATUS  {
  INIT = "",
  SUCCESS = " : success",
  NOT_SUPPORTED = ": not support"
}

const TAG = "CAMERA_DEMO "

let cameraManager : camera.CameraManager;
let supportedCameras : Array<camera.CameraDevice>;
let captureSession : camera.CaptureSession;
let cameraInput : camera.CameraInput;
let cameraOutputCapability : camera.CameraOutputCapability;
let cameraPreviewOutput;
let cameraPhotoOutput;
let cameraVideoOutput;
let previewProfiles : Array<camera.Profile>;
let photoProfiles : Array<camera.Profile>;
let videoProfiles;
let videoRecorder : media.VideoRecorder;
let videoConfig: any = {
  audioSourceType: 1,
  videoSourceType: 1,
  profile: {
    audioBitrate: 48000,
    audioChannels: 2,
    audioCodec: 'audio/mp4v-es',
    audioSampleRate: 48000,
    durationTime: 1000,
    fileFormat: 'mp4',
    videoBitrate: 48000,
    videoCodec: 'video/mp4v-es',
    videoFrameWidth: 640,
    videoFrameHeight: 480,
    videoFrameRate: 30
  },
  url: 'file:///data/media/01.mp4',
  orientationHint: 0,
  location: { latitude: 30, longitude: 130 },
  maxSize: 100,
  maxDuration: 500
}
let mXComponentController = new XComponentController()

let isFocusModeSupported : boolean;
let isExposureModeSupported : boolean;
let hasFlash : boolean;
let isFlashModeSupported : boolean;
let isVideoStabilizationModeSupported : boolean;

function printObj(obj){
  let description = "";
  for(let i in cameraInput){
    let property=cameraInput[i];
    description+=i+" = "+property+"\n";
  }
  return description;
}

@Entry
@Component
struct Index {
  @State createCameraManagerResult: string = STATUS.INIT
  @State getSupportedCamerasResult: string = STATUS.INIT
  @State createCaptureSessionResult : string = STATUS.INIT
  @State beginConfigResult : string = STATUS.INIT
  @State CreateCameraInputResult : string = STATUS.INIT

  @State CameraInputOpenResult : string = STATUS.INIT

  @State GetSupportedOutputCapabilityResult : string = STATUS.INIT
  @State GetPreviewProfilesResult : string = STATUS.INIT
  @State GetPhotoProfilesResult : string = STATUS.INIT

  @State AddInputResult : string = STATUS.INIT

  @State CreatePhotoOutputResult : string = STATUS.INIT

  @State CreatePreviewOutputResult : string = STATUS.INIT

  @State CreateVideoOutputResult : string = STATUS.INIT

  @State AddPhotoOutputResult : string = STATUS.INIT

  @State AddPreviewOutputResult : string = STATUS.INIT

  @State AddVideoOutputResult : string = STATUS.INIT

  @State CommitConfigResult : string = STATUS.INIT

  @State StartResult : string = STATUS.INIT

  @State VideoStartResult : string = STATUS.INIT

  @State CaptureResult : string = STATUS.INIT

  @State PhotoOutputReleaseResult : string = STATUS.INIT

  @State VideoOutputReleaseResult : string = STATUS.INIT

  @State SessionReleaseResult : string = STATUS.INIT

  // 3A
  @State getZoomRatioRangeResult : string = STATUS.INIT
  @State getZoomRatioResult : string = STATUS.INIT
  @State setZoomRatioResult : string = STATUS.INIT

  @State isFocusModeSupportedResult : string = STATUS.INIT
  @State getFocusModeResult : string = STATUS.INIT
  @State setFocusModeResult : string = STATUS.INIT

  @State getFocusPointResult : string = STATUS.INIT
  @State setFocusPointResult : string = STATUS.INIT
  @State getFocalLengthResult : string = STATUS.INIT

  @State getMeteringPointResult : string = STATUS.INIT
  @State setMeteringPointResult : string = STATUS.INIT

  @State isExposureModeSupportedResult : string = STATUS.INIT
  @State getExposureModeResult : string = STATUS.INIT
  @State setExposureModeResult : string = STATUS.INIT
  @State getExposureBiasRangeResult : string = STATUS.INIT
  @State setExposureBiasResult : string = STATUS.INIT
  @State getExposureValueResult : string = STATUS.INIT

  @State hasFlashResult : string = STATUS.INIT
  @State isFlashModeSupportedResult : string = STATUS.INIT
  @State getFlashModeResult : string = STATUS.INIT
  @State setFlashModeResult : string = STATUS.INIT

  @State isVideoStabilizationModeSupportedResult : string = STATUS.INIT
  @State getActiveVideoStabilizationModeResult : string = STATUS.INIT
  @State setVideoStabilizationModeResult : string = STATUS.INIT

  //
  private createCameraManagerText: string = "createCameraManager"
  private getSupportedCamerasText: string = "getSupportedCameras"
  private createCaptureSessionText : string = "createCaptureSession"
  private beginConfigText : string = "beginConfig"
  private CreateCameraInputText : string = "CreateCameraInput"

  private CameraInputOpenText : string = "CameraInput Open"

  private GetSupportedOutputCapabilityText : string = "GetSupportedOutputCapability"
  private GetPreviewProfilesText : string = "GetPreviewProfiles"
  private GetPhotoProfilesText : string = "GetPhotoProfiles"

  private AddInputText : string = "AddInput"

  private CreatePhotoOutputText : string = "CreatePhotoOutput"

  private CreatePreviewOutputText : string = "CreatePreviewOutput"

  private CreateVideoOutputText : string = "CreateVideoOutput"

  private AddPhotoOutputText : string = "AddPhotoOutput"

  private AddPreviewOutputText : string = "AddPreviewOutput"

  private AddVideoOutputText : string = "AddPreviewOutput"

  private CommitConfigText : string = "CommitConfig"

  private StartText : string = "Start"

  private VideoStartText : string = "VideoStart"

  private CaptureText : string = "Capture"

  private PhotoOutputReleaseText : string = "PhotoOutputRelease"

  private VideoOutputReleaseText : string = "VideoOutputRelease"

  private SessionReleaseText : string = "SessionRelease"

  // 3A
  private getZoomRatioRangeText : string = "getZoomRatioRange"
  private getZoomRatioText : string = "getZoomRatio"
  private setZoomRatioText : string = "setZoomRatio"

  private isFocusModeSupportedText : string = "isFocusModeSupported"
  private getFocusModeText : string = "getFocusMode"
  private setFocusModeText : string = "setFocusMode"

  private getFocusPointText : string = "getFocusMode"
  private setFocusPointText : string = "setFocusMode"
  private getFocalLengthText : string = "getFocusMode"

  private getMeteringPointText : string = "getMeteringPoint"
  private setMeteringPointText : string = "setMeteringPoint"

  private isExposureModeSupportedText : string = "isExposureModeSupported"
  private getExposureModeText : string = "getExposureMode"
  private setExposureModeText : string = "setExposureMode"
  private getExposureBiasRangeText : string = "getExposureBiasRange"
  private setExposureBiasText : string = "setExposureBias"
  private getExposureValueText : string = "getExposureValue"

  private hasFlashText : string = "hasFlash"
  private isFlashModeSupportedText : string = "isFlashModeSupported"
  private getFlashModeText : string = "getFlashMode"
  private setFlashModeText : string = "setFlashMode"

  private isVideoStabilizationModeSupportedText : string = "isVideoStabilizationModeSupported"
  private getActiveVideoStabilizationModeText : string = "getActiveVideoStabilizationMode"
  private setVideoStabilizationModeText : string = "setVideoStabilizationMode"

  build() {
    Row() {
      Column() {
        Flex({ direction: FlexDirection.Column, alignContent: FlexAlign.Center }) {
          Button(`返回首页`)
            .onClick(()=>{
              Router.back();
              Router.clear();
            })

          Button(`3A Interface`)
            .onClick(async () => {
              cameraManager = await camera.getCameraManager(globalThis.context);
              supportedCameras = await cameraManager.getSupportedCameras();
              captureSession = await cameraManager.createCaptureSession();
              await captureSession.beginConfig();
              cameraInput = await cameraManager.createCameraInput(supportedCameras[0]);
              await cameraInput.open();
              cameraOutputCapability = await cameraManager.getSupportedOutputCapability(supportedCameras[0]);
              await captureSession.addInput(cameraInput);

              previewProfiles = cameraOutputCapability.previewProfiles;
              photoProfiles = cameraOutputCapability.photoProfiles;
              cameraPreviewOutput = await cameraManager.createPreviewOutput(previewProfiles[0], globalThis.surfaceId);

              let height = photoProfiles[0].size.height;
              let width = photoProfiles[0].size.width;
              let format = photoProfiles[0].format;
              const receiver = image.createImageReceiver(width, height, 4, 8);
              let surfaceId = await receiver.getReceivingSurfaceId();
              cameraPhotoOutput = await cameraManager.createPhotoOutput(photoProfiles[0], surfaceId);
              await captureSession.addOutput(cameraPhotoOutput);
              await captureSession.addOutput(cameraPreviewOutput);
              await captureSession.commitConfig();
              await captureSession.start();
            })

          Button(`${this.getZoomRatioRangeText} ${this.getZoomRatioRangeResult}`)
            .onClick(() => {
              Log.info(TAG, "getZoomRatioRange before ");
              captureSession.getZoomRatioRange((err, data) => {
                for (let i = 0; i < data.length; i++) {
                  Log.info(TAG, `getZoomRatioRange index[${i}] = ${data}`);
                  this.getZoomRatioRangeResult = JSON.stringify(data);
                }
              })
            })
          Button(`${this.setZoomRatioText} ${this.setZoomRatioResult}`)
            .onClick(() => {
              Log.info(TAG, "setZoomRatio before ");
              captureSession.setZoomRatio(3, (err) => {
                Log.info(TAG, `setZoomRatio, success`);
                this.setZoomRatioResult = STATUS.SUCCESS;
              })
            })
          Button(`${this.getZoomRatioText} ${this.getZoomRatioResult}`)
            .onClick(() => {
              Log.info(TAG, "getZoomRatio before ");
              captureSession.getZoomRatio((err, data) => {
                Log.info(TAG, `getZoomRatio, success`);
                this.getZoomRatioResult = JSON.stringify(data);
              })
            })

          Button(`${this.getFocusPointText} ${this.getFocusPointResult}`)
            .onClick(() => {
              Log.info(TAG, "getFocusPointResult before ");
              captureSession.getFocusPoint((err, data) => {
                Log.info(TAG, `getFocusPoint, success`);
                this.getFocusPointResult = JSON.stringify(data);
              })
            })
          Button(`${this.setFocusPointText} ${this.setFocusPointResult}`)
            .onClick(() => {
              Log.info(TAG, "setFocusPoint before ");
              let point : camera.Point = {
                x:0,
                y:0
              }
              captureSession.setFocusPoint(point, (err, data) => {
                Log.info(TAG, `setFocusPoint, success`);
                this.setFocusPointResult = STATUS.SUCCESS;
              })
            })
          Button(`${this.getFocalLengthText} ${this.getFocalLengthResult}`)
            .onClick(() => {
              Log.info(TAG, "getFocalLength before ");
              captureSession.getFocalLength((err, data) => {
                Log.info(TAG, `getFocalLength, success`);
                this.getFocalLengthResult = JSON.stringify(data);
              })
            })

          Button(`${this.isFocusModeSupportedText} ${this.isFocusModeSupportedResult}`)
            .onClick(() => {
              Log.info(TAG, "isFocusModeSupported before ");
              let focusMode = camera.FocusMode.FOCUS_MODE_AUTO;
              captureSession.isFocusModeSupported(focusMode, (err, data) => {
                isFocusModeSupported = data;
                Log.info(TAG, `isFocusModeSupported, success`);
                this.isFocusModeSupportedResult = STATUS.SUCCESS;
              })
            })
          Button(`${this.getFocusModeText} ${this.getFocusModeResult}`)
            .onClick(() => {
              Log.info(TAG, "getFocusMode before ");
              captureSession.getFocusMode((err, data) => {
                Log.info(TAG, `getFocusMode, success`);
                this.getFocusModeResult = JSON.stringify(data);
              })
            })
          Button(`${this.setFocusModeText} ${this.setFocusModeResult}`)
            .onClick(() => {
              Log.info(TAG, "setFocusMode before ");
              let focusMode = camera.FocusMode.FOCUS_MODE_AUTO;
              captureSession.setFocusMode(focusMode, (err, data) => {
                Log.info(TAG, `setFocusMode, success`);
                this.setFocusModeResult = STATUS.SUCCESS;
              })
            })

          Button(`${this.getMeteringPointText} ${this.getMeteringPointResult}`)
            .onClick(() => {
              Log.info(TAG, "getMeteringPoint before ");
              let focusMode = camera.FocusMode.FOCUS_MODE_AUTO;
              captureSession.getMeteringPoint((err, data) => {
                Log.info(TAG, `getMeteringPoint, success`);
                this.getMeteringPointResult = JSON.stringify(data);
              })
            })
          Button(`${this.setMeteringPointText} ${this.setMeteringPointResult}`)
            .onClick(() => {
              Log.info(TAG, "setMeteringPoint before ");
              let point : camera.Point = {
                x:0,
                y:0
              }
              captureSession.setMeteringPoint(point, (err, data) => {
                Log.info(TAG, `setMeteringPoint, success`);
                this.setMeteringPointResult = STATUS.SUCCESS;
              })
            })

          //
          Button(`${this.isExposureModeSupportedText} ${this.isExposureModeSupportedResult}`)
            .onClick(() => {
              Log.info(TAG, "isExposureModeSupported before ");
              let exposeMode = camera.ExposureMode.EXPOSURE_MODE_AUTO;
              captureSession.isExposureModeSupported(exposeMode, (err, data) => {
                isExposureModeSupported = data;
                Log.info(TAG, `isExposureModeSupported, success`);
                this.isExposureModeSupportedResult = JSON.stringify(data);
              })
            })
          Button(`${this.getExposureModeText} ${this.getExposureModeResult}`)
            .onClick(() => {
              Log.info(TAG, "getExposureMode before ");
              if (!isExposureModeSupported) {
                this.getExposureModeResult = STATUS.NOT_SUPPORTED;
                return
              };
              captureSession.getExposureMode((err, data) => {
                Log.info(TAG, `getExposureMode, success`);
                this.getExposureModeResult = JSON.stringify(data);
              })
            })
          Button(`${this.setExposureModeText} ${this.setExposureModeResult}`)
            .onClick(() => {
              Log.info(TAG, "setExposureMode before ");
              if (!isExposureModeSupported) {
                this.setExposureModeResult = STATUS.NOT_SUPPORTED;
                return;
              }
              let exposeMode = camera.ExposureMode.EXPOSURE_MODE_AUTO;
              captureSession.setExposureMode(exposeMode, (err, data) => {
                Log.info(TAG, `setExposureMode, success`);
                this.setExposureModeResult = STATUS.SUCCESS;
              })
            })
          Button(`${this.getExposureBiasRangeText} ${this.getExposureBiasRangeResult}`)
            .onClick(() => {
              Log.info(TAG, "getExposureBiasRange before ");
              captureSession.getExposureBiasRange((err, data) => {
                Log.info(TAG, `getExposureBiasRange, success`);
                this.getExposureBiasRangeResult = JSON.stringify(data);
              })
            })
          Button(`${this.setExposureBiasText} ${this.setExposureBiasResult}`)
            .onClick(() => {
              Log.info(TAG, "setExposureBias before ");
              let bias = 1;
              captureSession.setExposureBias(bias, (err, data) => {
                Log.info(TAG, `setExposureBias, success`);
                this.setExposureBiasResult = STATUS.SUCCESS;
              })
            })
          Button(`${this.getExposureValueText} ${this.getExposureValueResult}`)
            .onClick(() => {
              Log.info(TAG, "getExposureValue before ");
              let focusMode = camera.FocusMode.FOCUS_MODE_AUTO;
              captureSession.getExposureValue((err, data) => {
                Log.info(TAG, `getExposureValue, success`);
                this.getExposureValueResult = JSON.stringify(data);
              })
            })

          Button(`${this.hasFlashText} ${this.hasFlashResult}`)
            .onClick(() => {
              Log.info(TAG, "hasFlash before ");
              captureSession.hasFlash((err, data) => {
                Log.info(TAG, `hasFlash, success`);
                this.hasFlashResult = JSON.stringify(data);
              })
            })
          Button(`${this.isFlashModeSupportedText} ${this.isFlashModeSupportedResult}`)
            .onClick(() => {
              Log.info(TAG, "isFlashModeSupported before ");
              let flashMode = camera.FlashMode.FLASH_MODE_AUTO;
              captureSession.isFlashModeSupported(flashMode, (err, data) => {
                Log.info(TAG, `isFlashModeSupported, success`);
                isFlashModeSupported = data;
                this.isFlashModeSupportedResult = JSON.stringify(data);
              })
            })
          Button(`${this.getFlashModeText} ${this.getFlashModeResult}`)
            .onClick(() => {
              Log.info(TAG, "getFlashMode before ");
              if (!isFlashModeSupported) {
                this.getFlashModeResult = STATUS.NOT_SUPPORTED;
                return;
              }
              captureSession.getFlashMode((err, data) => {
                Log.info(TAG, `getFlashMode, success`);
                this.getFlashModeResult = JSON.stringify(data);
              })
            })
          Button(`${this.setFlashModeText} ${this.setFlashModeResult}`)
            .onClick(() => {
              Log.info(TAG, "setFlashMode before ");
              if (!isFlashModeSupported) {
                this.setFlashModeModeResult = STATUS.NOT_SUPPORTED;
                return;
              }
              let flashMode = camera.FlashMode.FLASH_MODE_AUTO;
              captureSession.setFlashMode(flashMode, (err, data) => {
                Log.info(TAG, `setFlashMode, success`);
                this.setFlashModeResult = STATUS.SUCCESS;
              })
            })
          //
          Button(`${this.isVideoStabilizationModeSupportedText} ${this.isVideoStabilizationModeSupportedResult}`)
            .onClick(() => {
              Log.info(TAG, "isVideoStabilizationModeSupported before ");
              let mode = camera.VideoStabilizationMode.AUTO;
              captureSession.isVideoStabilizationModeSupported(mode, (err, data) => {
                Log.info(TAG, `isVideoStabilizationModeSupported, success`);
                isVideoStabilizationModeSupported = data;
                this.isVideoStabilizationModeSupportedResult = JSON.stringify(data);
              })
            })
          Button(`${this.getActiveVideoStabilizationModeText} ${this.getActiveVideoStabilizationModeResult}`)
            .onClick(() => {
              Log.info(TAG, "getActiveVideoStabilizationMode before ");
              if (!isVideoStabilizationModeSupported) {
                this.getActiveVideoStabilizationModeResult = STATUS.NOT_SUPPORTED;
                return;
              }
              captureSession.getActiveVideoStabilizationMode((err, data) => {
                Log.info(TAG, `getActiveVideoStabilizationMode, success`);
                this.getActiveVideoStabilizationModeResult = JSON.stringify(data);
              })
            })
          Button(`${this.setVideoStabilizationModeText} ${this.setVideoStabilizationModeResult}`)
            .onClick(() => {
              Log.info(TAG, "setVideoStabilizationMode before ");
              if (!isVideoStabilizationModeSupported) {
                this.setVideoStabilizationModeResult = STATUS.NOT_SUPPORTED;
                return;
              }
              let mode = camera.VideoStabilizationMode.AUTO;
              captureSession.setVideoStabilizationMode(mode, (err, data) => {
                Log.info(TAG, `setVideoStabilizationMode, success`);
                this.setVideoStabilizationModeResult = STATUS.SUCCESS;
              })
            })
          XComponent({
            id: '',
            type: 'surface',
            libraryname: '',
            controller: mXComponentController
          })
            .onLoad(() => {
              globalThis.surfaceId = mXComponentController.getXComponentSurfaceId()
            })
            .width(320)
            .height(240)
            .animation({
              duration: 100,
              curve: Curve.Sharp,
              delay: 0,
              iterations: 1,
              playMode: PlayMode.Normal
            })
        }
        .height('100%')
      }.width('100%')
    }
  }
  onPageShow(){
    Log.info(TAG, `onPageShow`)
  }
  onPageHide() {
    Log.info(TAG, `onPageHide`)
  }
  onDestroy() {
    Log.info(TAG, `onDestroy`)
  }
}