# PWM - Buzzer Play Melody

## Preparation
* HUB 8735 or HUB 8735 Ultra [連結] x 1
* Buzzer x 1

## Example
A sound is composed of volume, tone and timbre. Volume is determined by the amplitude of the sound wave. Tone is determined by the frequency of the sound wave. Timbre is determined by the waveform of the sound wave.

In this example, we use PWM to control the buzzer to emit sound with desired tone. As PWM outputs square wave, if we wish to emit tone C4 (frequency=262Hz), we have to make PWM to output square wave with wavelength 1/262 = 3.8ms:

![](https://www.amebaiot.com/wp-content/uploads/2023/01/pwm/buzzerP01.png) 

We use PWM to output sound wave with different frequency, so as to play music by the buzzer. </br>
Connect the buzzer to the PWM output pin shown in the following diagrams.

HUB 8735 Ultra wiring diagram:
![](https://www.amebaiot.com/wp-content/uploads/2023/01/pwm/buzzerP02.png)
Open the example code in “Examples” -> “AmebaAnalog” -> “PWM_BuzzerPlayMelody” </br>
Compile and upload to Ameba, press the reset button. Then you can hear the buzzer playing music.

## Code Reference
Ameba implement the tone() and noTone() API of Arduino: </br>
https://www.arduino.cc/en/Reference/Tone </br>
https://www.arduino.cc/en/Reference/NoTone </br>
In the sample code, we initiate a melody array, which stores the tones to make. Another array, noteDurations, contains the length of each tone, 4 represents quarter note (equals to 3000ms/4 = 750ms, and plus an extra 30% time pause), 8 represents eighth note.
