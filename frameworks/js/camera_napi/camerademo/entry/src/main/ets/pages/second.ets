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

const TAG = "lvxiaoqiang second "

enum STATUS  {
  INIT = "",
  SUCCESS = " : success"
}

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
export default struct Next {
  @State createCameraManagerText: string = STATUS.INIT
  @State getSupportedCamerasText: string = STATUS.INIT
  @State createCaptureSessionText : string = STATUS.INIT
  @State beginConfigText : string = STATUS.INIT
  @State CreateCameraInputText : string = STATUS.INIT

  @State CameraInputOpenText : string = STATUS.INIT

  @State GetSupportedOutputCapabilityText : string = STATUS.INIT
  @State GetProfilesText : string = STATUS.INIT
  @State GetPhotoProfilesText : string = STATUS.INIT

  @State AddInputText : string = STATUS.INIT

  @State CreatePhotoOutputText : string = STATUS.INIT

  @State CreatePreviewOutputText : string = STATUS.INIT

  @State CreateVideoOutputText : string = STATUS.INIT

  @State AddPhotoOutputText : string = STATUS.INIT

  @State AddPreviewOutputText : string = STATUS.INIT

  @State AddVideoOutputText : string = STATUS.INIT

  @State CommitConfigText : string = STATUS.INIT

  @State StartText : string = STATUS.INIT

  @State VideoStartText : string = STATUS.INIT

  @State CaptureText : string = STATUS.INIT

  @State PhotoOutputReleaseText : string = STATUS.INIT

  @State VideoOutputReleaseText : string = STATUS.INIT

  @State SessionReleaseText : string = STATUS.INIT

  //
  private createCameraManagerResult: string = "createCameraManager"
  private getSupportedCamerasResult: string = "getSupportedCameras"
  private createCaptureSessionResult : string = "createCaptureSession"
  private beginConfigResult : string = "beginConfig"
  private CreateCameraInputResult : string = "CreateCameraInput"

  private CameraInputOpenResult : string = "CameraInput Open"

  private GetSupportedOutputCapabilityResult : string = "GetSupportedOutputCapability"
  private GetProfilesResult : string = "GetPreviewProfiles"

  private AddInputResult : string = "AddInput"

  private CreatePhotoOutputResult : string = "CreatePhotoOutput"

  private CreatePreviewOutputResult : string = "CreatePreviewOutput"

  private CreateVideoOutputResult : string = "CreateVideoOutput"

  private AddPhotoOutputResult : string = "AddPhotoOutput"

  private AddPreviewOutputResult : string = "AddPreviewOutput"

  private AddVideoOutputResult : string = "AddPreviewOutput"

  private CommitConfigResult : string = "CommitConfig"

  private StartResult : string = "Start"

  private VideoStartResult : string = "VideoStart"

  private CaptureResult : string = "Capture"

  private PhotoOutputReleaseResult : string = "PhotoOutputRelease"

  private VideoOutputReleaseResult : string = "VideoOutputRelease"

  private SessionReleaseResult : string = "SessionRelease"

  onPageShow(){
    console.log(TAG+"onPageShow")
  }
  onPageHide() {
    console.log(TAG+"onPageHide")
  }
  onDestroy() {
    console.log(TAG+"onDestroy")
  }
  build() {
    Row() {
      Column() {
        Flex({direction: FlexDirection.Column, alignContent: FlexAlign.Center}) {
          Button(`返回首页`)
            .onClick(()=>{
              Router.back();
              Router.clear();
            })
          Button(`${this.createCameraManagerText} ${this.createCameraManagerResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "getCameraManager before ");
              cameraManager = await camera.getCameraManager(globalThis.context);
              Log.info(TAG, "getCameraManager = "+printObj(cameraManager));
              this.createCameraManagerResult = STATUS.SUCCESS;
            })
          Button(`${this.getSupportedCamerasText} ${this.getSupportedCamerasResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "getSupportedCameras before ");
              supportedCameras = await cameraManager.getSupportedCameras();
              Log.info(TAG, "getSupportedCameras cameraId = " + supportedCameras[0].cameraId);
              Log.info(TAG, "getSupportedCameras cameraPosition = " + supportedCameras[0].cameraPosition);
              Log.info(TAG, "getSupportedCameras cameraType = " + supportedCameras[0].cameraType);
              this.getSupportedCamerasResult = STATUS.SUCCESS;
            })
          Button(`${this.createCaptureSessionText} ${this.createCaptureSessionResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "createCaptureSession before ");
              captureSession = await cameraManager.createCaptureSession();
              Log.info(TAG , "createCaptureSession = "+printObj(captureSession));
              this.createCaptureSessionResult = STATUS.SUCCESS;
            })
          Button(`${this.beginConfigText} ${this.beginConfigResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "beginConfig before ");
              await captureSession.beginConfig()
              Log.info(TAG , "beginConfig after");
              this.beginConfigResult = STATUS.SUCCESS;
            })
          Button(`${this.CreateCameraInputText} ${this.CreateCameraInputResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "createCameraInput before ");
              cameraInput = await cameraManager.createCameraInput(supportedCameras[0])
              Log.info(TAG , "createCameraInput = "+printObj(cameraInput));
              this.CreateCameraInputResult = STATUS.SUCCESS;
            })
          Button(`${this.CameraInputOpenText} ${this.CameraInputOpenResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "CameraInputOpen before ");
              await cameraInput.open()
              Log.info(TAG , "CameraInputOpen after");
              this.CameraInputOpenResult = STATUS.SUCCESS;
            })
          Button(`${this.GetSupportedOutputCapabilityText} ${this.GetSupportedOutputCapabilityResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "getSupportedOutputCapability before ");
              cameraOutputCapability = await cameraManager.getSupportedOutputCapability(supportedCameras[0])
              Log.info(TAG , "getSupportedOutputCapability = "+printObj(cameraOutputCapability));
              this.GetSupportedOutputCapabilityResult = STATUS.SUCCESS;
            })
          Button(`${this.GetProfilesText} ${this.GetProfilesResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "GetPreviewProfiles before ");
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
            .onClick(async ()=>{
              Log.info(TAG , "addInput before ");
              await captureSession.addInput(cameraInput);
              Log.info(TAG , `addInput success`);
              this.AddInputResult = STATUS.SUCCESS;
            })
          Button(`${this.CreatePhotoOutputText} ${this.CreatePhotoOutputResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "createPhotoOutput before ");
              let height = photoProfiles[0].size.height;
              let width = photoProfiles[0].size.width;
              let format = photoProfiles[0].format;
              const receiver = image.createImageReceiver(width, height, 4, 8)
              Log.info(TAG , `createPhotoOutput receiver: ${receiver}.`)
              let surfaceId = await receiver.getReceivingSurfaceId()
              Log.info(TAG , `createPhotoOutput width: ${width}, height:${height}, format: ${format}, surfaceId: ${surfaceId}`)
              let msize : camera.Size = {
                width:1280,
                height:960
              }
              let fakeProfile: camera.Profile = {
                size : msize,
                format: 1
              }
              cameraPhotoOutput = await cameraManager.createPhotoOutput(photoProfiles[0], surfaceId)
              Log.info(TAG , `createPhotoOutput success = ${cameraPhotoOutput}`);
              this.CreatePhotoOutputResult = STATUS.SUCCESS;
            })

          Button(`${this.CreatePreviewOutputText} ${this.CreatePreviewOutputResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "createPreviewOutput before ");

              let width = previewProfiles[0].size.width;
              let height = previewProfiles[0].size.height;
              let format = previewProfiles[0].format;
              Log.info(TAG , `createPreviewOutput width: ${width}, height:${height}, format : ${format}, surfaceId: ${globalThis.surfaceId}`)
              let msize : camera.Size = {
                width:640,
                height:480
              }
              let fakeProfile: camera.Profile = {
                size : msize,
                format: 1
              }
              cameraPreviewOutput = await cameraManager.createPreviewOutput(previewProfiles[0], globalThis.surfaceId)
              Log.info(TAG , `createPreviewOutput success = ${cameraPreviewOutput}` );
              this.CreatePreviewOutputResult = STATUS.SUCCESS;
            })
          Button(`${this.AddPhotoOutputText} ${this.AddPhotoOutputResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "addPhotoOutput before ");
              await captureSession.addOutput(cameraPhotoOutput);
              Log.info(TAG , `addPhotoOutput success`);
              this.AddPhotoOutputResult = STATUS.SUCCESS;
            })
          Button(`${this.AddPreviewOutputText} ${this.AddPreviewOutputResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "AddPreviewOutput before ");
              await captureSession.addOutput(cameraPreviewOutput)
              Log.info(TAG , `AddPreviewOutput success`);
              this.AddPreviewOutputResult = STATUS.SUCCESS;
            })
          Button(`${this.CommitConfigText} ${this.CommitConfigResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "commitConfig before ");
              await captureSession.commitConfig()
              Log.info(TAG , `commitConfig success`);
              this.CommitConfigResult = STATUS.SUCCESS;
            })
          Button(`${this.StartText} ${this.StartResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "start before ");
              await captureSession.start()
              Log.info(TAG , `start success`);
              this.StartResult = STATUS.SUCCESS;
            })
          Button(`${this.CaptureText} ${this.CaptureResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "CaptureResult before ");
              let tempCaptureSetting: any = {
                rotation: 1,
                quality: 1
              }
              await cameraPhotoOutput.capture(tempCaptureSetting)
              Log.info(TAG , `CaptureResult success`);
              this.StartResult = STATUS.SUCCESS;
            })
          Button(`${this.PhotoOutputReleaseText} ${this.PhotoOutputReleaseResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "PhotoOutputReleaseResult before ");
              await cameraPhotoOutput.release()
              Log.info(TAG , `PhotoOutputReleaseResult success `);
              this.StartResult = STATUS.SUCCESS;
            })
          Button(`${this.SessionReleaseText} ${this.SessionReleaseResult}`)
            .onClick(async ()=>{
              Log.info(TAG , "SessionReleaseResult before ");
              await captureSession.release()
              Log.info(TAG , `SessionReleaseResult success `);
              this.StartResult = STATUS.SUCCESS;
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
            .width(64)
            .height(48)
            .animation({
              duration: 100,
              curve: Curve.Sharp,
              delay: 0,
              iterations: 1,
              playMode: PlayMode.Normal
            })
        }
      }
      .height('100%')
      .width('100%')

    }
    .height('100%')
  }
}
