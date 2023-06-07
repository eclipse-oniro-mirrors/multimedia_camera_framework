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

import Logger from '../model/Logger';

const TAG: string = 'CountdownPage';

// 倒计时页面
@Component
export struct CountdownPage {
  @Link countdownNum: number; // 倒计时的值
  private countdownListData: Array<string> = ['2', '5', '10']; // 循环渲染
  @StorageLink('countdownBol') countdownBol: boolean = true;

  build() {
    Row() {
      if (this.countdownBol && !this.countdownNum) {
        Row() {
          Button() {
            Image($r('app.media.icon_camera_setting_timer'))
              .width('35vp')
              .height('35vp')
          }
          .width('45vp')
          .height('45vp')
          .backgroundColor('rgba(255,255,255,0.20)')
          .borderRadius('50px')
          .onClick(() => {
            Logger.debug(TAG, 'onClick');
            AppStorage.SetOrCreate<boolean>('flashingBol', true);
            this.countdownBol = false;
          })
        }
      }
      if (this.countdownNum && this.countdownBol) {
        Column() {
          Image($r('app.media.icon_camera_setting_timer_on'))
            .width('35vp')
            .height('35vp')
            .margin({ top: 5 })
          Text(this.countdownNum + '')
            .fontSize(21)
            .fontWeight(500)
            .margin({ top: 5 })
            .fontColor(Color.White)
        }
        .backgroundColor('rgba(255,255,255,0.20)')
        .borderRadius('45vp')
        .width('45vp')
        .height('80vp')
        .onClick(() => {
          this.countdownBol = false;
        })
      }
      if (!this.countdownBol) {
        Column() {
          Image($r('app.media.icon_camera_setting_timer_on_balk'))
            .width('35vp')
            .height('35vp')
            .margin({ top: 10 })
          ForEach(this.countdownListData, (item) => {
            Text(item)
              .fontSize(21)
              .fontWeight(500)
              .margin({
                top: 10
              })
              .fontColor(this.countdownNum == item ? $r('app.color.theme_color') : '#182431')
              .onClick(() => {
                this.countdownNum = item;
                this.countdownBol = true;
              })
          }, item => item)
          Text('OFF')
            .fontSize(18)
            .fontWeight(500)
            .margin({
              top: 10
            })
            .fontColor(this.countdownNum == 0 ? $r('app.color.theme_color') : '#182431')
            .onClick(() => {
              this.countdownNum = 0;
              this.countdownBol = true;
            })
        }
        .backgroundColor('#FFFFFF')
        .borderRadius('45vp')
        .width('45vp')
        .height('680px')
        .zIndex(999)
      }
    }
    .position({ x: 130, y: 30 })
  }
}