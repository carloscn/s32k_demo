#include <stdint.h>
#include <stdlib.h> // For rand()
#include "Siul2_Port_Ip.h"
#include "Siul2_Dio_Ip.h"
#include "osal_utils.h"
#include "test_led.h"

// Configuration macros
#define LED_CYCLES 20       // Number of pattern cycles
#define FAST_DELAY_MS 150   // Delay for fast patterns (ms)
#define SLOW_DELAY_MS 400   // Delay for slow patterns (ms)
#define STROBE_DELAY_MS 50  // Delay for strobe and random toggle (ms)

// Pattern types
typedef enum {
    PATTERN_ALTERNATE,
    PATTERN_SIMULTANEOUS,
    PATTERN_CHASE,
    PATTERN_TOGGLE_WAVE,
    PATTERN_BINARY_COUNTER,
    PATTERN_RANDOM_TOGGLE,
    PATTERN_ROTATING_PAIR,
    PATTERN_STROBE,
    PATTERN_PING_PONG,
    PATTERN_COUNT
} LedPattern;

// Pattern 1: Alternate (green, blue, red in sequence)
static void led_pattern_alternate(void)
{
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 1U);
    osal_utils_delay_ms(FAST_DELAY_MS);
}

// Pattern 2: Simultaneous (all LEDs blink together using TogglePins)
static void led_pattern_simultaneous(void)
{
    uint32_t all_pins = (1U << LED_GREEN_PIN) | (1U << LED_BLUE_PIN) | (1U << LED_RED_PIN);
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, all_pins); // Toggle all on
    osal_utils_delay_ms(SLOW_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, all_pins); // Toggle all off
    osal_utils_delay_ms(SLOW_DELAY_MS);
}

// Pattern 3: Chase (green → blue → red)
static void led_pattern_chase(void)
{
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 1U);
    osal_utils_delay_ms(FAST_DELAY_MS);
}

// Pattern 4: Toggle Wave (toggles each LED in sequence)
static void led_pattern_toggle_wave(void)
{
    // Start with all off
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    // Toggle in sequence
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, 1U << LED_GREEN_PIN); // Green on
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_BLUE_PORT, 1U << LED_BLUE_PIN); // Blue on
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_RED_PORT, 1U << LED_RED_PIN); // Red on
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, 1U << LED_GREEN_PIN); // Green off
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_BLUE_PORT, 1U << LED_BLUE_PIN); // Blue off
    osal_utils_delay_ms(FAST_DELAY_MS);
    Siul2_Dio_Ip_TogglePins(LED_RED_PORT, 1U << LED_RED_PIN); // Red off
    osal_utils_delay_ms(FAST_DELAY_MS);
}

// Pattern 5: Binary Counter (3-bit counter: 000 to 111)
static void led_pattern_binary_counter(void)
{
    for (uint8_t count = 0; count < 8; count++) {
        Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, (count & 0x01) ? 1U : 0U);
        Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, (count & 0x02) ? 1U : 0U);
        Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, (count & 0x04) ? 1U : 0U);
        osal_utils_delay_ms(FAST_DELAY_MS);
    }
}

// Pattern 6: Random Toggle (toggles 1 or 2 LEDs randomly)
static void led_pattern_random_toggle(void)
{
    for (uint8_t i = 0; i < 8; i++) {
        // Randomly select 1 or 2 LEDs
        uint32_t pins = 0;
        uint8_t num_leds = (rand() % 2) + 1; // 1 or 2 LEDs
        for (uint8_t j = 0; j < num_leds; j++) {
            uint8_t led = rand() % 3;
            if (led == 0) pins |= (1U << LED_GREEN_PIN);
            else if (led == 1) pins |= (1U << LED_BLUE_PIN);
            else pins |= (1U << LED_RED_PIN);
        }
        Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, pins);
        osal_utils_delay_ms(STROBE_DELAY_MS);
    }
}

// Pattern 7: Rotating Pair (two LEDs on: GB, BR, RG)
static void led_pattern_rotating_pair(void)
{
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(SLOW_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 1U);
    osal_utils_delay_ms(SLOW_DELAY_MS);
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 1U);
    osal_utils_delay_ms(SLOW_DELAY_MS);
}

// Pattern 8: Strobe (rapid on/off for all LEDs)
static void led_pattern_strobe(void)
{
    uint32_t all_pins = (1U << LED_GREEN_PIN) | (1U << LED_BLUE_PIN) | (1U << LED_RED_PIN);
    for (uint8_t i = 0; i < 10; i++) {
        Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, all_pins);
        osal_utils_delay_ms(STROBE_DELAY_MS);
    }
}

// Pattern 9: Ping-Pong (toggles back and forth: green ↔ blue ↔ red)
static void led_pattern_ping_pong(void)
{
    // Start with green on
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
    osal_utils_delay_ms(FAST_DELAY_MS);
    // Toggle green off, blue on
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, (1U << LED_GREEN_PIN) | (1U << LED_BLUE_PIN));
    osal_utils_delay_ms(FAST_DELAY_MS);
    // Toggle blue off, red on
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, (1U << LED_BLUE_PIN) | (1U << LED_RED_PIN));
    osal_utils_delay_ms(FAST_DELAY_MS);
    // Toggle red off, blue on
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, (1U << LED_BLUE_PIN) | (1U << LED_RED_PIN));
    osal_utils_delay_ms(FAST_DELAY_MS);
    // Toggle blue off, green on
    Siul2_Dio_Ip_TogglePins(LED_GREEN_PORT, (1U << LED_GREEN_PIN) | (1U << LED_BLUE_PIN));
    osal_utils_delay_ms(FAST_DELAY_MS);
}

/**
 * Enhanced LED test function with three LEDs and multiple patterns.
 * Randomly selects from nine patterns, emphasizing Siul2_Dio_Ip_TogglePins.
 */
void test_led(void)
{
    uint8_t count = 0;

    // Seed random number generator (replace with tick for true randomness)
    srand(0); // Static seed for reproducibility

    // Ensure LEDs are off initially
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);

    while (count++ < LED_CYCLES)
    {
        // Randomly select a pattern
        LedPattern pattern = (LedPattern)(rand() % PATTERN_COUNT);

        switch (pattern) {
            case PATTERN_ALTERNATE:
                led_pattern_alternate();
                break;
            case PATTERN_SIMULTANEOUS:
                led_pattern_simultaneous();
                break;
            case PATTERN_CHASE:
                led_pattern_chase();
                break;
            case PATTERN_TOGGLE_WAVE:
                led_pattern_toggle_wave();
                break;
            case PATTERN_BINARY_COUNTER:
                led_pattern_binary_counter();
                break;
            case PATTERN_RANDOM_TOGGLE:
                led_pattern_random_toggle();
                break;
            case PATTERN_ROTATING_PAIR:
                led_pattern_rotating_pair();
                break;
            case PATTERN_STROBE:
                led_pattern_strobe();
                break;
            case PATTERN_PING_PONG:
                led_pattern_ping_pong();
                break;
            default:
                break;
        }

        // Short pause between patterns
        osal_utils_delay_ms(200);
    }

    // Ensure LEDs are off at the end
    Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
    Siul2_Dio_Ip_WritePin(LED_RED_PORT, LED_RED_PIN, 0U);
}
