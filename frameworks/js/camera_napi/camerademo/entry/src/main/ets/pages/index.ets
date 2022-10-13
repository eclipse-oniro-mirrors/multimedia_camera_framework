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
  SUCCESS = " = success"
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

  @State GetProfilesResult : string = STATUS.INIT

  @State GetPreviewProfilesResult : string = STATUS.INIT

  @State AddInputResult : string = STATUS.INIT

  @State CreatePhotoOutputResult : string = STATUS.INIT

  @State CreatePreviewOutputResult : string = STATUS.INIT

  @State CreateVideoOutputResult : string = STATUS.INIT

  @State AddPhotoOutputResult : string = STATUS.INIT

  @State AddPreviewOutputResult : string = STATUS.INIT

  @State AddVideoOutputResult : string = STATUS.INIT

  @State CommitConfigResult : string = STATUS.INIT

  @State StartResult : string = STATUS.INIT

  @State PreviewStartResult : string = STATUS.INIT

  @State StopResult : string = STATUS.INIT

  @State PreviewStopResult : string = STATUS.INIT

  @State VideoStartResult : string = STATUS.INIT

  @State CaptureResult : string = STATUS.INIT

  @State PhotoOutputReleaseResult : string = STATUS.INIT

  @State VideoOutputReleaseResult : string = STATUS.INIT

  @State SessionReleaseResult : string = STATUS.INIT

  //
  private createCameraManagerText: string = "createCameraManager"
  private getSupportedCamerasText: string = "getSupportedCameras"
  private createCaptureSessionText : string = "createCaptureSession"
  private beginConfigText : string = "beginConfig"
  private CreateCameraInputText : string = "CreateCameraInput"

  private CameraInputOpenText : string = "CameraInput Open"

  private GetSupportedOutputCapabilityText : string = "GetSupportedOutputCapability"

  private GetProfilesText : string = "GetProfiles"

  private AddInputText : string = "AddInput"

  private CreatePhotoOutputText : string = "CreatePhotoOutput"

  private CreatePreviewOutputText : string = "CreatePreviewOutput"

  private CreateVideoOutputText : string = "CreateVideoOutput"

  private AddPhotoOutputText : string = "AddPhotoOutput"

  private AddPreviewOutputText : string = "AddPreviewOutput"

  private AddVideoOutputText : string = "AddPreviewOutput"

  private CommitConfigText : string = "CommitConfig"

  private StartText : string = "Start"

  private PreviewStartText : string = "PreviewStart"

  private StopText : string = "Stop"

  private PreviewStopText : string = "PreviewStop"

  private VideoStartText : string = "VideoStart"

  private CaptureText : string = "Capture"

  private PhotoOutputReleaseText : string = "PhotoOutputRelease"

  private VideoOutputReleaseText : string = "VideoOutputRelease"

  private SessionReleaseText : string = "SessionRelease"

  build() {
    Column() {
      Flex({direction:FlexDirection.Row}) {
        Button(`Promise接口`)
          .onClick(() => {
            Router.push({ uri: "pages/second" });
          })
        .width("50%")
        Button(`3A接口`)
          .onClick(() => {
            Router.push({ uri: "pages/third" });
          })
        .width("50%")
      }
      .height("6%")

      Flex({direction:FlexDirection.Column}) {
        Button(`${this.createCameraManagerText} ${this.createCameraManagerResult}`)
          .onClick(() => {
            Log.info(TAG, "getCameraManager before ");
            camera.getCameraManager(globalThis.context, (err: any, manager: camera.CameraManager) => {
              cameraManager = manager;
              Log.info(TAG, "getCameraManager = " + printObj(manager));
              this.createCameraManagerResult = STATUS.SUCCESS;
            });
          })
        Button(`${this.getSupportedCamerasText} ${this.getSupportedCamerasResult}`)
          .onClick(() => {
            Log.info(TAG, "getSupportedCameras before ");
            cameraManager.getSupportedCameras((err, data: Array<camera.CameraDevice>) => {
              supportedCameras = data;
              Log.info(TAG, "getSupportedCameras cameraId = " + supportedCameras[0].cameraId);
              Log.info(TAG, "getSupportedCameras cameraPosition = " + supportedCameras[0].cameraPosition);
              Log.info(TAG, "getSupportedCameras cameraType = " + supportedCameras[0].cameraType);
              this.getSupportedCamerasResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.createCaptureSessionText} ${this.createCaptureSessionResult}`)
          .onClick(() => {
            Log.info(TAG, "createCaptureSession before ");
            cameraManager.createCaptureSession((err, data: camera.CaptureSession) => {
              captureSession = data;
              Log.info(TAG, "createCaptureSession = " + printObj(captureSession));
              this.createCaptureSessionResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.beginConfigText} ${this.beginConfigResult}`)
          .onClick(() => {
            Log.info(TAG, "beginConfig before ");
            captureSession.beginConfig((err, data) => {
              Log.info(TAG, "err.code = " + JSON.stringify(err));
              this.beginConfigResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.CreateCameraInputText} ${this.CreateCameraInputResult}`)
          .onClick(() => {
            Log.info(TAG, "createCameraInput before ");
            cameraManager.createCameraInput(supportedCameras[0], (err, data: camera.CameraInput) => {
              cameraInput = data;

              Log.info(TAG, "createCameraInput = " + printObj(cameraInput));
              this.CreateCameraInputResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.CameraInputOpenText} ${this.CameraInputOpenResult}`)
          .onClick(() => {
            Log.info(TAG, "CameraInputOpen before ");
            cameraInput.open((err, data) => {
              Log.info(TAG, "CameraInputOpen = " + data);
              this.CameraInputOpenResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.GetSupportedOutputCapabilityText} ${this.GetSupportedOutputCapabilityResult}`)
          .onClick(() => {
            Log.info(TAG, "getSupportedOutputCapability before ");
            cameraManager.getSupportedOutputCapability(supportedCameras[0], (err, data) => {
              cameraOutputCapability = data;
              Log.info(TAG, "getSupportedOutputCapability = " + printObj(data));
              this.GetSupportedOutputCapabilityResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.GetProfilesText} ${this.GetProfilesResult}`)
          .onClick(() => {
            Log.info(TAG, "GetPreviewProfiles before ");
            previewProfiles = cameraOutputCapability.previewProfiles;
            let previewProfile = previewProfiles[0];
            printObj(previewProfile);
            Log.info(TAG, `previewProfiles size : ${previewProfiles.length}`)
            Log.info(TAG, `previewProfiles[0] height:${previewProfile.size.height}, width: ${previewProfile.size.width}, format : ${previewProfile.format}`)

            photoProfiles = cameraOutputCapability.photoProfiles;
            let photoProfile = photoProfiles[0];
            Log.info(TAG, `photoProfiles size : ${photoProfiles.length}`)
            Log.info(TAG, `photoProfile[0] height : ${photoProfile.size.height}, width: ${photoProfile.size.width}, format : ${photoProfile.format}`)

            videoProfiles = cameraOutputCapability.videoProfiles;
            let videoProfile = videoProfiles[0];
            Log.info(TAG , `videoProfiles size : ${videoProfiles.length}`)
            Log.info(TAG , `videoProfile[0] height : ${videoProfile.size.height}, width: ${videoProfile.size.width}, format : ${videoProfile.format}`)
            let rateRanges = videoProfile.frameRateRanges;
            Log.info(TAG , `rateRange min : ${rateRanges.min}, max: ${rateRanges.max}`)
            this.GetProfilesResult = STATUS.SUCCESS;
          })
        Button(`${this.AddInputText} ${this.AddInputResult}`)
          .onClick(() => {
            Log.info(TAG, "addInput before ");
            captureSession.addInput(cameraInput, (err, data) => {
              Log.info(TAG, `addInput success = ${data}`);
              this.AddInputResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.CreatePhotoOutputText} ${this.CreatePhotoOutputResult}`)
          .onClick(async () => {
            Log.info(TAG, "createPhotoOutput before ");
            let height = photoProfiles[0].size.height;
            let width = photoProfiles[0].size.width;
            let format = photoProfiles[0].format;
            const receiver = image.createImageReceiver(width, height, 4, 8)
            Log.info(TAG, `createPhotoOutput receiver: ${receiver}.`)
            let surfaceId = await receiver.getReceivingSurfaceId()
            Log.info(TAG, `createPhotoOutput width: ${width}, height:${height}, format: ${format}, surfaceId: ${surfaceId}`)
            cameraManager.createPhotoOutput(photoProfiles[0], surfaceId, (err, data) => {
              cameraPhotoOutput = data;
              Log.info(TAG, `createPhotoOutput success = ${data}`);
              this.CreatePhotoOutputResult = STATUS.SUCCESS;
            })
          })

        Button(`${this.CreatePreviewOutputText} ${this.CreatePreviewOutputResult}`)
          .onClick(() => {
            Log.info(TAG, "createPreviewOutput before ");

            let width = previewProfiles[0].size.width;
            let height = previewProfiles[0].size.height;
            let format = previewProfiles[0].format;
            Log.info(TAG, `createPreviewOutput width: ${width}, height:${height}, format : ${format}, surfaceId: ${globalThis.surfaceId}`)

            cameraManager.createPreviewOutput(previewProfiles[0], globalThis.surfaceId, (err, data) => {
              cameraPreviewOutput = data;
              Log.info(TAG, `createPreviewOutput success = ${data}`);
              this.CreatePreviewOutputResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.AddPhotoOutputText} ${this.AddPhotoOutputResult}`)
          .onClick(() => {
            Log.info(TAG, "addPhotoOutput before ");
            captureSession.addOutput(cameraPhotoOutput, (err, data) => {
              Log.info(TAG, `addPhotoOutput success = ${data}`);
              this.AddPhotoOutputResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.AddPreviewOutputText} ${this.AddPreviewOutputResult}`)
          .onClick(() => {
            Log.info(TAG, "AddPreviewOutput before ");
            captureSession.addOutput(cameraPreviewOutput, (err, data) => {
              Log.info(TAG, `AddPreviewOutput success = ${data}`);
              this.AddPreviewOutputResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.CommitConfigText} ${this.CommitConfigResult}`)
          .onClick(() => {
            Log.info(TAG, "commitConfig before ");
            captureSession.commitConfig((err, data) => {
              Log.info(TAG, `commitConfig success = ${data}`);
              this.CommitConfigResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.PreviewStartText} ${this.StartResult}`)
          .onClick(() => {
            Log.info(TAG, "start before ");
            captureSession.start((err, data) => {
              Log.info(TAG, `start success = ${data}`);
              this.StartResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.PreviewStopText} ${this.PreStopResult}`)
          .onClick(() => {
            Log.info(TAG, "stop before ");
            captureSession.stop((err, data) => {
              Log.info(TAG, `stop success = ${data}`);
              this.StopResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.StartText} ${this.StartResult}`)
          .onClick(() => {
            Log.info(TAG, "start before ");
            captureSession.start((err, data) => {
              Log.info(TAG, `start success = ${data}`);
              this.StartResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.StopText} ${this.StopResult}`)
          .onClick(() => {
            Log.info(TAG, "stop before ");
            captureSession.stop((err, data) => {
              Log.info(TAG, `stop success = ${data}`);
              this.StopResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.CaptureText} ${this.CaptureResult}`)
          .onClick(() => {
            Log.info(TAG, "CaptureResult before ");
            let tempCaptureSetting: any = {
              rotation: 0,
              quality: 1
            }
            cameraPhotoOutput.capture(tempCaptureSetting, (err, data) => {
              Log.info(TAG, `CaptureResult success = ${data}`);
              this.CaptureResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.PhotoOutputReleaseText} ${this.PhotoOutputReleaseResult}`)
          .onClick(() => {
            Log.info(TAG, "PhotoOutputReleaseResult before ");
            cameraPhotoOutput.release((err, data) => {
              Log.info(TAG, `PhotoOutputReleaseResult success = ${data}`);
              this.PhotoOutputReleaseResult = STATUS.SUCCESS;
            })
          })
        Button(`${this.SessionReleaseText} ${this.SessionReleaseResult}`)
          .onClick(() => {
            Log.info(TAG, "SessionReleaseResult before ");
            captureSession.release((err, data) => {
              Log.info(TAG, `SessionReleaseResult success = ${data}`);
              this.SessionReleaseResult = STATUS.SUCCESS;
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
          .width("128")
          .height("96")
          .animation({
            duration: 100,
            curve: Curve.Sharp,
            delay: 0,
            iterations: 1,
            playMode: PlayMode.Normal
          })
      }
    }
    .align(Alignment.Center)
    .alignItems(VerticalAlign.Center)
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