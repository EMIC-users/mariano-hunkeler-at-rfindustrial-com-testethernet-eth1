#include <xc.h>
#include "inc/led_Led1.h"
#include "inc/gpio.h"
#include "inc/systemTimer.h"

void LEDs_Led1_init (void)
{
	HAL_GPIO_PinCfg(Led1, GPIO_OUTPUT);
}

void LEDs_Led1_state(uint8_t status)
{
	switch (status)
	{
		case 0:
			HAL_GPIO_PinSet(Led1, GPIO_LOW); // es mal
			break;
		case 1:
			HAL_GPIO_PinSet(Led1, GPIO_HIGH);
			break;
		case 2:
			if (HAL_GPIO_PinGet(Led1))
            {
				HAL_GPIO_PinSet(Led1,GPIO_LOW);
			}
			else 
			{
				HAL_GPIO_PinSet(Led1,GPIO_HIGH);
			}
			break;
	}
}



