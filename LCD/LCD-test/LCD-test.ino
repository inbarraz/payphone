// Reporter - based on the SSD1306SimpleDemo file and modified from there

#include <LiquidCrystal.h>

// initialize the LCD library with the numbers of the interface pins
/*
  The circuit:
 * LCD RS pin to digital pin 12       (c11)
 * LCD Enable pin to digital pin 11   (c22)
 * LCD D4 pin to digital pin 5        (c07)
 * LCD D5 pin to digital pin 4        (c10)
 * LCD D6 pin to digital pin 3        (c09)
 * LCD D7 pin to digital pin 2        (c12)
 * LCD R/W pin to ground              (c14)
 * LCD VSS pin to ground
 * LCD VCC pin to 5V
 * 10K resistor:
 * ends to +5V and ground
 * wiper to LCD VO pin (pin 3)
*/
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);

void setup() {

  // LCD setup
  // set up the LCD's number of columns and rows:
  lcd.begin(16, 2);
  // Print a message to the LCD.
  lcd.print("hello, world!");

  // Serial setup
  Serial.begin(115200);
  Serial.println();
  Serial.println("Test");

}

void loop() {

  // Print on the LCD
  // set the cursor to column 0, line 1
  // (note: line 1 is the second row, since counting begins with 0):
  lcd.setCursor(0, 1);
  // print the number of seconds since reset:
  lcd.print(millis() / 1000);

  delay(500);
}
