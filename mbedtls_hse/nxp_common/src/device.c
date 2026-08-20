/*==================================================================================================
*
*   Copyright 2022, 2024 NXP
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/


#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#include "Mcal.h"
#include "device.h"
#if defined(LWIP_APP)
#include "Eth_43_GMAC.h"
#endif
#include "global_variables.h"
#include "hse_interface.h"
#include "std_typedefs.h"
#include "hse_platform.h"
#include "Clock_Ip.h"
#include "Siul2_Port_Ip.h"
#include "IntCtrl_Ip.h"
#include "OsIf.h"
#if defined(CPU_SAF8544) && defined (LWIP_APP)
#include "Osif_rtd_port.h"
#include "Clock_Ip_Specific.h"

#endif
#include "mbedtls/platform.h"

#if defined(CPU_S32R47)
#include "Clock_Ip_Specific.h"
#include "Mcu.h"
#include "S32R47.h"
#include "Platform.h"
#endif

#if defined(CPU_S32R47) && defined(LWIP_APP)
#include "EthIf.h"
#include "Osif_rtd_port.h"
#include "CDD_Serdes.h"
#endif

/*Includes for K389*/
#if defined(CPU_S32K389) && defined(LWIP_APP)
#include "S32K389.h"
#include "device.h"
#include "Mcal.h"
#include "Mcu.h"
#include "EthIf.h"
#include "OsIf.h"
#include "Platform.h"
#include "Eth_43_GMAC.h"
#endif

#if defined(S32N55) && (defined (TEST_SUITE) || defined(LWIP_APP) || defined(BENCHMARK))
#include "Mcu.h"
#include "CDD_Uart.h"
#include "Gpt.h"
#include "Platform.h"
#include "Pit_Ip.h"
#include "Scmi_Agent.h"
#include "S32N55.h"
#include "S32N55_SIUL2.h"
#include "Mcal.h"
#include "OsIf.h"
#include "Messaging.h"
#endif
#if defined(LWIP_APP) && defined(S32N55)
#include "EthSwt_43_NETC.h"
#include "Eth_43_NETC.h"
#include "Netc_Eth_Ip_Features.h"
#endif

#if defined (BENCHMARK) && (defined (CPU_SAF8544) || defined (CPU_S32K388) || defined(CPU_S32K389)|| defined(CPU_S32R47))
#include "Pit_Ip.h"
#endif

#ifdef LWIP_APP
#include "Pit_Ip.h"
#if !defined(S32N55)
#include "Gmac_Ip.h"
#include "Gmac_Ip_Irq.h"
#endif
#endif


#ifdef UART_SUPPORT
#include "Serial.h"
#include "printf.h"
#endif


#if defined(USING_OS_FREERTOS)
/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#endif /* defined(USING_OS_FREERTOS) */

#include "hse_host_timing.h"

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 * ===============================================================================================*/
#if defined(CPU_SAF8544) && defined(LWIP_APP)
#define SGMII_FMU_CLOCK_NAME_LEN	30
struct clock_info
{
	uint8_t id;
	float target_freq;
	char name[SGMII_FMU_CLOCK_NAME_LEN];
};

/* GMAC MII mode - keep enum values in sync with GMAC DT bindings */
enum eth_s32_mii_mode
{
	/* Standard Media Independent Interface */
	S32_GMAC_MII_MODE = 0,
	/* Reduced Media Independent Interface */
	S32_GMAC_RMII_MODE = 1,
	/* Reduced Gigabit Media Independent Interface */
	S32_GMAC_RGMII_MODE = 2,
	/* Serial Gigabit Media Independent Interface */
	S32_GMAC_SGMII_MODE = 3,
};
#endif /* CPU_SAF8544 && LWIP */

/*==================================================================================================
 *                                       LOCAL MACROS
 * ===============================================================================================*/
#if defined (BENCHMARK) && defined (CPU_SAF8544)
/* PIT instance used */
#define PIT_INST                (0U)
/* PIT timeout period */
#define PIT_PERIOD              (12000U)

#ifndef CH_0
#define CH_0 0U
#endif /* CH_0 */
#endif /*defined (BENCHMARK) && defined (CPU_SAF8544)*/

#if (defined (BENCHMARK)|| defined(TEST_SUITE) || defined(LWIP_APP)) && defined (S32N55)
/* PIT instance used */
#define PIT_INST                (11U)
/* PIT timeout period */
#define PIT_PERIOD              (12000U)

#ifndef CH_0
#define CH_0 0U
#endif /* CH_0 */
#endif /*defined (BENCHMARK) && defined (S32N55)*/
#if !defined(S32N55)
#ifdef LWIP_APP
/* PIT instance used */
#define PIT_INST                (0U)
/* PIT timeout period */
#if defined (CPU_SAF8544)
#define PIT_PERIOD              (31250U) /* base on PIT clock of 31.25MHz */
#else
#define PIT_PERIOD              (133333U)
#endif /* CPU_SAF8544 */

#ifndef CH_0
#define CH_0 0U
#endif /* CH_0 */
#endif

#if defined(BENCHMARK) && (defined(CPU_S32K388) || defined(CPU_S32R47))
#define PIT_INSTANCE          (0U)
#ifndef CH_0
#define CH_0 0U
#endif /* CH_0 */
#define PIT_0_CH_0 &PIT_0_ChannelConfig_PB[0U]
#define PIT_PERIOD 40000
#endif

#if defined(BENCHMARK) && defined(CPU_S32K389)
#define PIT_INSTANCE          (0U)
#ifndef CH_0
#define CH_0 0U
#endif /* CH_0 */
#define PIT_0_CH_0 &PIT_0_ChannelConfig_PB_VS_0[0U]
#define PIT_PERIOD 40000
#endif

#if defined(CPU_S32G274A) || defined(CPU_S32G399A)
#define CFG_PHY_CTRL_IDX        (0U)
#define ENABLE_PHY_LOOPBACK     (0U)   /* Set to 1 to enable PHY loop-back */
#define ENABLE_PHY_FULL_DUPLEX  (1U)   /* Set to 0 to enable PHY Half-duplex mode */

#define PHY_ID1                 (0x0022U)
#define PHY_ID2                 (0x1622U)

#define PHY_LED_ON              (1U)
#endif /*CPU_S32K344*/

#ifdef CPU_S32K344

#define CFG_PHY_CTRL_IDX        (0U)
#define ENABLE_PHY_LOOPBACK     (0U)   /* Set to 1 to enable PHY loopback*/
#define TJA1100_PHY_ID0         (0x0180U)
#define TJA1100_PHY_ID1         (0xDC41U)
#define TJA1101_PHY_ID1         (0xDD01U)

#define DP83848_PHY_ID0         (0x2000U)
#define DP83848_PHY_ID1         (0x5C90U)

#define PHY_ID1                 DP83848_PHY_ID0
#define PHY_ID2                 DP83848_PHY_ID1

#define PHY_LED_ON              (1U)

#endif /*CPU_S32K344*/

#if defined(CPU_SAF8544)
#define CFG_PHY_CTRL_IDX        	(0U)
#define ENABLE_PHY_LOOPBACK     	(0U)   /* Set to 1 to enable PHY loop-back */
#define ENABLE_PHY_FULL_DUPLEX  	(1U)   /* Set to 0 to enable PHY Half-duplex mode */

#define PHY_ID1                 	(0x0022U)
#define PHY_ID2                 	(0x1622U)

#define PHY_LED_ON              	(1U)

/* For 125MHz ref clk, divider enabled and MPLL multiplier 40 */
#define SGMII_125MHZ_REF_DIV		0x01U
#define SGMII_125MHZ_MPLL_MUL		0x28U
#define RESET_TIMEOUT 				10

#define GMAC_DEV_NAME DT_LABEL(DT_NODELABEL(gmac0))

/* Clock source mapping */
#define GMAC_0_REF_DIV_CLK_ID		45
#define GMAC_0_SGMII_TX_CLK_ID		59
#define GMAC_0_SGMII_RX_CLK_ID		60
#define GMAC_0_SGMII_REF_CLK_ID		61
#endif /*CPU_SAF8544*/


#if defined(CPU_S32K358)

#define CFG_PHY_CTRL_IDX        (0U)
#define ENABLE_PHY_LOOPBACK     (0U)   /* Set to 1 to enable PHY loopback*/
#define TJA1100_PHY_ID0         (0x0180U)
#define TJA1100_PHY_ID1         (0xDC41U)
#define TJA1101_PHY_ID1         (0xDD01U)
#define TJA1103_PHY_ID1         (0xDC13U)

#define DP83848_PHY_ID0         (0x2000U)
#define DP83848_PHY_ID1         (0x5C90U)
#define TLK110_PHY_ID1          (0xA210U)

#define PHY_ID1                 DP83848_PHY_ID0
#define PHY_ID2                 DP83848_PHY_ID1

#define PHY_LED_ON              (1U)
#endif
#if defined(CPU_S32K396)
#define CFG_PHY_CTRL_IDX        (0U)
#define ENABLE_PHY_LOOPBACK     (0U)   /* Set to 1 to enable PHY loopback*/
#define TJA1100_PHY_ID0         (0x0180U)
#define TJA1100_PHY_ID1         (0xDC41U)
#define TJA1101_PHY_ID1         (0xDD01U)
#define TJA1103_PHY_ID1         (0xDC13U)

#define DP83848_PHY_ID0         (0x2000U)
#define DP83848_PHY_ID1         (0x5C90U)
#define TLK110_PHY_ID1          (0xA210U)

#define PHY_ID1                 DP83848_PHY_ID0
#define PHY_ID2                 DP83848_PHY_ID1

#define PHY_LED_ON              (1U)
#endif
#endif /*LWIP_APP*/
#if defined(S32N55) && defined(LWIP_APP)

	/** Peripheral EMDIO_BASE base address */
	#define IP_EMDIO_BASE_BASE                          (0x4DB60000u)
	/** Peripheral EMDIO_BASE base pointer */
	#define IP_EMDIO_BASE                               ((NETC_F1_Type *)IP_EMDIO_BASE_BASE)
	/** MMD Access Control Register */
	#define MII_MMD_CTRL                                0x0d
	/** Address */
	#define MII_MMD_CTRL_ADDR                           0x0000
	/** Mask MMD DEVAD*/
	#define MII_MMD_CTRL_DEVAD_MASK                     0x1f
	/** MMD Access Data Register */
	#define MII_MMD_DATA                                0x0e
	/** no post increment */
	#define MII_MMD_CTRL_NOINCR                         0x4000
	/** PHY IDs */
	#define MAC0_PHY_ID                                 0x1
	/** PHY IDs */
	#define MAC1_PHY_ID                                 0x4
	/**
	* @brief Gets the Phy ID for each mac
	*/
static uint8_t KSZ9131_GetPhyIdForMac(uint8_t mac_port)
{
		uint8_t phy_id = 0xFF;
		switch(mac_port)
		{
			case 0:
			{
				phy_id = MAC0_PHY_ID;
			} break;
			case 1:
			{
				phy_id = MAC1_PHY_ID;
			} break;
			default:
			{
				phy_id = 0xFF;
			} break;
		}

		return phy_id;
}
	/**
	* @brief Writes to the EMDIO registers
	*/
static void NETC_MDIO_Write(uint8_t phy_address, uint8_t reg_address, uint16_t reg_value)
{
		// Select PHY Control Register (0x0)
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_DEV_ADDR_MASK;
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_PORT_ADDR_MASK;

		/* 5-bit MDIO port address (Clause 45) / PHY address (Clause 22) */
		IP_EMDIO_BASE->EMDIO_CTL |= NETC_F1_EMDIO_CTL_PORT_ADDR(phy_address);

		/* 5-bit MDIO device address (Clause 45) / register address (Clause 22) */
		IP_EMDIO_BASE->EMDIO_CTL |= NETC_F1_EMDIO_CTL_DEV_ADDR(reg_address);

		// Select writing operation
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_READ_MASK;
		// Disable increment
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_POST_INC_MASK;
		// Value to be written (Reset PHY, Bring link up, etc.)
		IP_EMDIO_BASE->EMDIO_DATA = reg_value;
		// Wait for end of the writing
		while(((IP_EMDIO_BASE->EMDIO_CFG & NETC_F1_EMDIO_CFG_BSY1_MASK) >> NETC_F1_EMDIO_CFG_BSY1_SHIFT) == 1);
}

	/**
	* @brief Reads the EMDIO registers
	*/
static void NETC_MDIO_Read(uint8_t phy_address, uint8_t reg_address, uint16_t * reg_value)
{
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_DEV_ADDR_MASK;
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_PORT_ADDR_MASK;

		/* 5-bit MDIO port address (Clause 45) / PHY address (Clause 22) */
		IP_EMDIO_BASE->EMDIO_CTL |= NETC_F1_EMDIO_CTL_PORT_ADDR(phy_address);

		/* 5-bit MDIO device address (Clause 45) / register address (Clause 22) */
		IP_EMDIO_BASE->EMDIO_CTL |= NETC_F1_EMDIO_CTL_DEV_ADDR(reg_address);

		// Select reading operation
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_READ_MASK;
		IP_EMDIO_BASE->EMDIO_CTL &= ~NETC_F1_EMDIO_CTL_POST_INC_MASK;

		// Read status register (0x1 address)
		IP_EMDIO_BASE->EMDIO_CTL |= NETC_F1_EMDIO_CTL_READ(0x1);
		// Wait for end of the reading
		while(((IP_EMDIO_BASE->EMDIO_CFG & NETC_F1_EMDIO_CFG_BSY1_MASK) >> NETC_F1_EMDIO_CFG_BSY1_SHIFT) == 1);
		*reg_value = (IP_EMDIO_BASE->EMDIO_DATA & NETC_F1_EMDIO_DATA_MDIO_DATA_MASK);
}
	/*
	 * Reads the MMD controlled register
	 */
static void KSZ9131_ReadMmdRegister(uint8_t mac_port, uint8_t mmd_device, uint8_t mmd_reg, uint16_t* reg_value)
{
		/* Check referenced MAC and get PHY ID */
		uint8_t phy_id = KSZ9131_GetPhyIdForMac(mac_port);

		/* Write the MMD access control register with device address */
		NETC_MDIO_Write(phy_id, MII_MMD_CTRL, MII_MMD_CTRL_ADDR | (mmd_device & MII_MMD_CTRL_DEVAD_MASK));
		/* Write MMD address/data register with register address */
		NETC_MDIO_Write(phy_id, MII_MMD_DATA, mmd_reg);
		/* Write MMD control register with data, no post increment */
		NETC_MDIO_Write(phy_id, MII_MMD_CTRL, MII_MMD_CTRL_NOINCR | (mmd_device & MII_MMD_CTRL_DEVAD_MASK));
		/* Write MMD address/data register with register value */
		NETC_MDIO_Read(phy_id, MII_MMD_DATA, reg_value);
}

	/*
	 * Writes the MMD controlled register
	 */
static void KSZ9131_WriteMmdRegister(uint8_t mac_port, uint8_t mmd_device, uint8_t mmd_reg, uint16_t reg_value)
{
		/* Check referenced MAC and get PHY ID */
		uint8_t phy_id = KSZ9131_GetPhyIdForMac(mac_port);

		/* Write the MMD access control register with device address */
		NETC_MDIO_Write(phy_id, MII_MMD_CTRL, MII_MMD_CTRL_ADDR | (mmd_device & MII_MMD_CTRL_DEVAD_MASK));
		/* Write MMD address/data register with register address */
		NETC_MDIO_Write(phy_id, MII_MMD_DATA, mmd_reg);
		/* Write MMD control register with data, no post increment */
		NETC_MDIO_Write(phy_id, MII_MMD_CTRL, MII_MMD_CTRL_NOINCR | (mmd_device & MII_MMD_CTRL_DEVAD_MASK));
		/* Write MMD address/data register with register value */
		NETC_MDIO_Write(phy_id, MII_MMD_DATA, reg_value);
}

	/**
	* @brief RGMII Phy Initialization
	*/
void NETC_Phy_RGMII_Init(void)
{
		volatile uint16_t reg;

		KSZ9131_ReadMmdRegister(0, 0x02, 0x4d, (uint16_t *)&reg);
		reg &= ~0x1000;
		KSZ9131_WriteMmdRegister(0, 0x02, 0x4d, reg);

		KSZ9131_ReadMmdRegister(1, 0x02, 0x4d, (uint16_t *)&reg);
		reg &= ~0x1000;
		KSZ9131_WriteMmdRegister(1, 0x02, 0x4d, reg);
}
#endif
/*==================================================================================================
 *                                      LOCAL CONSTANTS
 * ===============================================================================================*/

/*==================================================================================================
 *                                      LOCAL VARIABLES
 * ===============================================================================================*/

/*==================================================================================================
 *                                      GLOBAL CONSTANTS
 * ===============================================================================================*/

/*==================================================================================================
 *                                      GLOBAL VARIABLES
 * ===============================================================================================*/

/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 * ===============================================================================================*/
#if defined(CPU_SAF8544) && defined (LWIP_APP)
static void Eth_wait_link(void);
static int eth_config_clk_0(enum eth_s32_mii_mode mii_mode);
static int eth_select_phy_interface(uint8_t instance, enum eth_s32_mii_mode mii_mode);
static StatusType Eth_SGMII_init(void);


#endif /* CPU_SAF8544 && LWIP_APP */

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 * ===============================================================================================*/
#if (defined (TEST_SUITE) || defined(BENCHMARK) || defined(LWIP_APP)) && defined (S32N55)
extern ISR(RTU0_PIT_0_ISR);
#endif
#if defined (BENCHMARK) && defined (CPU_SAF8544) || defined (CPU_S32K388) || defined(CPU_S32K389) || defined(CPU_S32R47)
extern ISR(PIT_0_ISR);
#endif
#ifdef LWIP_APP

extern ISR(PIT_0_ISR);


#if defined(CPU_SAF8544)

static void Eth_wait_link(void)
{
	while(0 == (IP_SGMII->VR_MII_AN_INTR_STS & SGMII_VR_MII_AN_INTR_STS_CL37_ANCMPLT_INTR_MASK))
	{}
	IP_SGMII->VR_MII_AN_INTR_STS = IP_SGMII->VR_MII_AN_INTR_STS & ~SGMII_VR_MII_AN_INTR_STS_CL37_ANCMPLT_INTR_MASK;
}

static int eth_config_clk_0(enum eth_s32_mii_mode mii_mode)
{
	volatile uint32_t tout = 0xFFFFFFFF;

	if (mii_mode == S32_GMAC_SGMII_MODE) {
		/* GMAC_0_TX_CLK = GMAC_0_SGMII_TX_CLK = 125 MHz */
		while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWIP_MASK) != 0) && (tout > 0)) {
			--tout;
		}
		IP_MC_CGM_3->MUX_2_CSC = (IP_MC_CGM_3->MUX_2_CSC & ~MC_CGM_MUX_2_CSC_SELCTL_MASK)
				| MC_CGM_MUX_2_CSC_SELCTL(GMAC_0_SGMII_TX_CLK_ID);
		IP_MC_CGM_3->MUX_2_CSC = (IP_MC_CGM_3->MUX_2_CSC & ~MC_CGM_MUX_2_CSC_CLK_SW_MASK)
				| MC_CGM_MUX_2_CSC_CLK_SW(1);
		while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_CLK_SW_MASK) == 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWIP_MASK) != 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWTRG_MASK)
				>> MC_CGM_MUX_2_CSS_SWTRG_SHIFT != 1) && (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SELSTAT_MASK)
				>> MC_CGM_MUX_2_CSS_SELSTAT_SHIFT != GMAC_0_SGMII_TX_CLK_ID)
				&& (tout > 0)) {
			--tout;
		}

		/*
		 * GMAC_0_REF_CLK = GMAC_0_SGMII_REF_CLK = 25 MHz
		 * GMAC_0_REF_DIV_CLK = GMAC_0_SGMII_REF_CLK / 1 = 25 MHz
		 */
#ifndef CPU_SAF8544
		while (((IP_MC_CGM_3->MUX_3_CSS & MC_CGM_MUX_3_CSS_SWIP_MASK) != 0) && (tout > 0)) {
			--tout;
		}
		IP_MC_CGM_3->MUX_3_CSC = (IP_MC_CGM_3->MUX_3_CSC & ~MC_CGM_MUX_3_CSC_SELCTL_MASK)
				| MC_CGM_MUX_3_CSC_SELCTL(GMAC_0_SGMII_REF_CLK_ID);
		IP_MC_CGM_3->MUX_3_CSC = (IP_MC_CGM_3->MUX_3_CSC & ~MC_CGM_MUX_3_CSC_CLK_SW_MASK)
				| MC_CGM_MUX_3_CSC_CLK_SW(1);
		while (((IP_MC_CGM_3->MUX_3_CSS & MC_CGM_MUX_3_CSS_CLK_SW_MASK) == 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_3_CSS & MC_CGM_MUX_3_CSS_SWIP_MASK) != 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_3_CSS & MC_CGM_MUX_3_CSS_SWTRG_MASK)
				>> MC_CGM_MUX_3_CSS_SWTRG_SHIFT != 1)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_3_CSS & MC_CGM_MUX_3_CSS_SELSTAT_MASK)
				>> MC_CGM_MUX_3_CSS_SELSTAT_SHIFT != GMAC_0_SGMII_REF_CLK_ID)
				&& (tout > 0)) {
			--tout;
		}

		IP_MC_CGM_3->MUX_3_DC_0 = (IP_MC_CGM_3->MUX_3_DC_0 & ~MC_CGM_MUX_3_DC_0_DE_MASK)
				| MC_CGM_MUX_3_DC_0_DE(0);
		IP_MC_CGM_3->MUX_3_DC_0 = (IP_MC_CGM_3->MUX_3_DC_0 & ~MC_CGM_MUX_3_DC_0_DIV_MASK)
				| MC_CGM_MUX_3_DC_0_DIV(0);
		while (((IP_MC_CGM_3->MUX_3_DIV_UPD_STAT
				& MC_CGM_MUX_3_DIV_UPD_STAT_DIV_STAT_MASK) != 0)
				&& (tout > 0))  {
			--tout;
		}
		IP_MC_CGM_3->MUX_3_DC_0 = (IP_MC_CGM_3->MUX_3_DC_0 & ~MC_CGM_MUX_3_DC_0_DE_MASK)
				| MC_CGM_MUX_3_DC_0_DE(1);
#endif
		/* GMAC_0_RX_CLK = GMAC_0_SGMII_RX_CLK = 125 MHz */
		IP_MC_CGM_3->MUX_4_CSC = (IP_MC_CGM_3->MUX_4_CSC & ~MC_CGM_MUX_4_CSC_SELCTL_MASK)
				| MC_CGM_MUX_4_CSC_SELCTL(GMAC_0_SGMII_RX_CLK_ID);
		IP_MC_CGM_3->MUX_4_CSC = (IP_MC_CGM_3->MUX_4_CSC & ~MC_CGM_MUX_4_CSC_CLK_SW_MASK)
				| MC_CGM_MUX_4_CSC_CLK_SW(1);
		while (((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_CLK_SW_MASK) == 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SWIP_MASK) != 0)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SWTRG_MASK)
				>> MC_CGM_MUX_4_CSS_SWTRG_SHIFT != 1)
				&& (tout > 0)) {
			--tout;
		}
		while (((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SELSTAT_MASK)
				>> MC_CGM_MUX_4_CSS_SELSTAT_SHIFT != GMAC_0_SGMII_RX_CLK_ID)
				&& (tout > 0)) {
			--tout;
		}
	} else {
		return -1;
	}

	return (tout <= 0 ? -1 : 0);
}

static int eth_select_phy_interface(uint8_t instance, enum eth_s32_mii_mode mii_mode)
{
	if ((instance != 0) || (mii_mode != S32_GMAC_SGMII_MODE))
	{
		return -1;
	}

	IP_SRC->GMAC_0_CTRL_STS = 0;

	return 0;
}

static StatusType Eth_SGMII_init(void)
{
	StatusType ret = E_OK;
	uint64_t start_time;
	uint32_t reg_data;

	IP_SGMII->PHY_CONFIG = SGMII_PHY_CONFIG_PHY_MODE_SEL(0x00U)
			| SGMII_PHY_CONFIG_PHY_REF_USE_PAD(0x00U);

	IP_SGMII->PHY_PLL_CTRL =
		SGMII_PHY_PLL_CTRL_PHY_REF_CLK_DIV2(SGMII_125MHZ_REF_DIV)
		| SGMII_PHY_PLL_CTRL_PHY_MPLL_MULTIPLIER(SGMII_125MHZ_MPLL_MUL);

	/* Enable Ref Clk, APB clk and MPLL */
	IP_SGMII->PHY_CONFIG |= SGMII_PHY_CONFIG_PHY_REF_SSP_EN(1U)
			| SGMII_PHY_CONFIG_PHY_APB_CLK_EN(1U)
			| SGMII_PHY_CONFIG_PHY_MPLL_EN(1U);

	/* Configure Vboost and LOS - expected values as per RM */
	IP_SGMII->PHY_VBOOST_LOS = SGMII_PHY_VBOOST_LOS_PHY_LOS_LEVEL(0x09U)
			| SGMII_PHY_VBOOST_LOS_PHY_LOS_BIAS(0x02U);

	IP_SGMII->PHY_VBOOST_LOS = (IP_SGMII->PHY_VBOOST_LOS
			& ~(SGMII_PHY_VBOOST_LOS_TX_VBOOST_LVL_MASK))
			| SGMII_PHY_VBOOST_LOS_TX_VBOOST_LVL(0x4U);

	IP_SGMII->PHY_VBOOST_LOS = (IP_SGMII->PHY_VBOOST_LOS
			& ~(SGMII_PHY_VBOOST_LOS_TX_VBOOST_EN_MASK))
			| SGMII_PHY_VBOOST_LOS_TX_VBOOST_EN(0U);

	/* Config Signal conditions */
	IP_SGMII->SGMII_SIGNAL_CONDITION = SGMII_SGMII_SIGNAL_CONDITION_SGMII_TX_AMPLITUDE(0x7FU)
			| SGMII_SGMII_SIGNAL_CONDITION_SGMII_TX_PREEMPH(0x0AU);

	/* SGMII Reset */

	/* Reset PHY */
	IP_SGMII->PHY_RESET_CTRL = SGMII_PHY_RESET_CTRL_PHY_RESET_N(1U);

	/* Reset PHY and PIPE */
	IP_SGMII->PHY_RESET_CTRL = SGMII_PHY_RESET_CTRL_PHY_RESET_N(1U)
			| SGMII_PHY_RESET_CTRL_PIPE_RESET_N(1U);

	/* Wait for Phy MPLL to stabilize */
	start_time = OsIf_GetMilliseconds();
	while ((IP_SGMII->PHY_CONFIG & SGMII_PHY_CONFIG_PHY_MPLL_STATE_MASK) == 0U) {
		if (OsIf_GetMilliseconds() - start_time >= RESET_TIMEOUT) {
			ret = E_NOT_OK;
			break;
		}
	}

	if (E_OK == ret) {
		/* Wait for XPCS to achieve Power Good state (TX/RX stable) */
		reg_data = 0;
		start_time = OsIf_GetMilliseconds();
		while ((reg_data != 0x0CU) && (reg_data != 0x10U)) {
			reg_data = IP_SGMII->VR_MII_DIG_STS & SGMII_VR_MII_DIG_STS_PSEQ_STATE_MASK;
			if (OsIf_GetMilliseconds() - start_time >= RESET_TIMEOUT) {
				ret = E_NOT_OK;
				break;
			}
		}
	}


	/*
	 * Configure Clause 37 auto-negotiation for SGMII.
	 * MAC side SGMII will receive AN TX config from PHY after Clause 28 AN between
	 * PHY and link partner completes. Therefore it's not needed to configure
	 * SR_MII_AN_ADV. It's also not needed to trigger AN restart, the HW will
	 * reconfigure when a new AN takes place.
	 */

	if (E_OK == ret)
	{
		/* Disable CL37 AN */
		IP_SGMII->SR_MII_CTRL = IP_SGMII->SR_MII_CTRL & ~(SGMII_SR_MII_CTRL_AN_ENABLE_MASK);

		/* PCS mode is SGMII mode (CL37 auto-neg is as per SGMII) */
		IP_SGMII->VR_MII_AN_CTRL = (IP_SGMII->VR_MII_AN_CTRL
				& ~(SGMII_VR_MII_AN_CTRL_PCS_MODE_MASK))
				| SGMII_VR_MII_AN_CTRL_PCS_MODE(0x2U);

		/* Configures the DWC_xpcs as the MAC side SGMII (TX_CONFIG = 0) */
		IP_SGMII->VR_MII_AN_CTRL = (IP_SGMII->VR_MII_AN_CTRL
				& ~(SGMII_VR_MII_AN_CTRL_TX_CONFIG_MASK))
				| SGMII_VR_MII_AN_CTRL_TX_CONFIG(0U);

		/* Enable CL37 AN Complete Interrupt */
		IP_SGMII->VR_MII_AN_CTRL = (IP_SGMII->VR_MII_AN_CTRL
				& ~(SGMII_VR_MII_AN_CTRL_MII_AN_INTR_EN_MASK))
				| SGMII_VR_MII_AN_CTRL_MII_AN_INTR_EN(1U);

		/*
		 * DWC_pcs automatically switches the negotiated speed mode after completion of CL37 AN
		 * The AN results will be available at VR_MII_AN_INTR_STS:CL37_ANSGM_STST
		 */
		IP_SGMII->VR_MII_DIG_CTRL1 = (IP_SGMII->VR_MII_DIG_CTRL1
				& ~(SGMII_VR_MII_DIG_CTRL1_MAC_AUTO_SW_MASK))
				| SGMII_VR_MII_DIG_CTRL1_MAC_AUTO_SW(1U);

		/* Program Clause37 Link Timer */
		IP_SGMII->VR_MII_LINK_TIMER_CTRL = 0x2FAFU;
		IP_SGMII->VR_MII_DIG_CTRL1 = (IP_SGMII->VR_MII_DIG_CTRL1
				& ~(SGMII_VR_MII_DIG_CTRL1_CL37_TMR_OVR_RIDE_MASK))
				| SGMII_VR_MII_DIG_CTRL1_CL37_TMR_OVR_RIDE(1U);

		/* Program MII_CTRL, depends on speed and GMII/MII clock rate */
		/* 8-bit */
		IP_SGMII->VR_MII_AN_CTRL = IP_SGMII->VR_MII_AN_CTRL | SGMII_VR_MII_AN_CTRL_MII_CTRL(1U);

		/* DWC_pcs is initially configured at speed/duplex specified in SR_MII_CTRL */
		/* Full-duplex */
		IP_SGMII->SR_MII_CTRL = IP_SGMII->SR_MII_CTRL | SGMII_SR_MII_CTRL_DUPLEX_MODE(1U);
		/* 1000Mbps */
		IP_SGMII->SR_MII_CTRL = (IP_SGMII->SR_MII_CTRL
				& ~(SGMII_SR_MII_CTRL_SS13_MASK | SGMII_SR_MII_CTRL_SS6_MASK))
				| SGMII_SR_MII_CTRL_SS13(0U)
				| SGMII_SR_MII_CTRL_SS6(1U);

		/* Enable CL37 AN */
		IP_SGMII->SR_MII_CTRL = (IP_SGMII->SR_MII_CTRL | SGMII_SR_MII_CTRL_AN_ENABLE(1U));
	}

	return ret;
}
#endif /* CPU_SAF8544 */

#ifdef CPU_S32K344

static void Eth_T_InitPhys(void)
{
    uint16 rmii_sel = 0;
    uint16 phy_reg_val0, phy_reg_val1;
    uint16 phy_addr;

    Gmac_Ip_EnableMDIO(CFG_PHY_CTRL_IDX, FALSE, 80000000U);

    /* Search for the PHY address */
    for (phy_addr = 0U; phy_addr < 32U; ++phy_addr)
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 2U, &phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 3U, &phy_reg_val1, 1U);

        /* check for PHY ID */
        if (((phy_reg_val0 == TJA1100_PHY_ID0) && ((phy_reg_val1 == TJA1100_PHY_ID1) || (phy_reg_val1 == TJA1101_PHY_ID1))) ||
            ((phy_reg_val0 == DP83848_PHY_ID0) && (phy_reg_val1 == DP83848_PHY_ID1)))
        {
            break; /* found the PHY ID*/
        }
    }

    /* Reset the PHY */
    Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, 0x8000U, 1U);

    /* Wait until the PHY is out of reset */
    while (Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U) & 0x8000U)
    { /* Busy Wait */
    }

    phy_reg_val0 |= (ENABLE_PHY_LOOPBACK << 14U);  /* Enable Loopback */
    phy_reg_val0 &= ~(1U << 12U); /* Disable AN */

    phy_reg_val0 |= (1U << 13U);  /* Speed_Select Lsb = 1 100Mbs */

    rmii_sel = 1;

    phy_reg_val0 |= (1U << 8U); /* Full-Duplex mode */

    /* Configure the PHY */
    if (DP83848_PHY_ID1 == phy_reg_val1)
    {
        phy_reg_val0 &= ~(1U << 12U); /* Enable auto-negotiation */
        phy_reg_val0 &= ~(1U << 9U); /* Enable auto-negotiation restart */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, &phy_reg_val0, 1U);
        phy_reg_val0 |= rmii_sel << 5; // RMII Enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, phy_reg_val0, 1U);
    }
    else
    {
        phy_reg_val0 &= ~(1U << 6U);  /* Speed_Select Msb = 0 100Mbs */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, &phy_reg_val0, 1U);
        phy_reg_val0 = (phy_reg_val0 | 0x4); // PHY configuration register access enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, &phy_reg_val0, 1U);
        phy_reg_val0 = phy_reg_val0 & 0xFCF7;          // Mask to set MII_MODE bits 9:8 to 0 and set LED_EN bit 3
        phy_reg_val0 = phy_reg_val0 | (rmii_sel << 9) | (PHY_LED_ON << 3); // If RMII mode: [MII_MODE]-> 10b (RMII mode enabled, 50 MHz output on REF_CLK)
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, phy_reg_val0, 1U);
    }
    /* Wait to establish link */
    do
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 1U, &phy_reg_val0, 1U);
    } while ((0U == (phy_reg_val0 & (1U << 2U))));
}
#endif

#if defined(S32K358)

static void Eth_T_InitPhys(void)
{
    uint16 rmii_sel = 0;
    uint16 phy_reg_val0, phy_reg_val1;
    uint16 phy_addr;

    Gmac_Ip_EnableMDIO(CFG_PHY_CTRL_IDX, FALSE, 48000000U);

    /* Search for the PHY address */
    for (phy_addr = 0U; phy_addr < 32U; ++phy_addr)
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 2U, &phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 3U, &phy_reg_val1, 1U);

        /* check for PHY ID */
        if (((phy_reg_val0 == TJA1100_PHY_ID0) && ((phy_reg_val1 == TJA1100_PHY_ID1) || (phy_reg_val1 == TJA1101_PHY_ID1 || phy_reg_val1 == TJA1103_PHY_ID1))) ||
            ((phy_reg_val0 == DP83848_PHY_ID0) && ((phy_reg_val1 & 0xFFF0U) == DP83848_PHY_ID1 || (phy_reg_val1 & 0xFFF0U) == TLK110_PHY_ID1)))
        {
            break; /* found the PHY ID*/
        }
    }

    /* Reset the PHY */
    Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, 0x8000U, 1U);

    /* Wait until the PHY is out of reset */
    while (Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U) & 0x8000U)
    { /* Busy Wait */
    }

    phy_reg_val0 |= (ENABLE_PHY_LOOPBACK << 14U);  /* Enable Loopback */
    phy_reg_val0 &= ~(1U << 12U); /* Disable AN */

    phy_reg_val0 |= (1U << 13U);  /* Speed_Select Lsb = 1 100Mbs */

    rmii_sel = 1;

    phy_reg_val0 |= (1U << 8U); /* Full-Duplex mode */

    /* Configure the PHY */
    if ((phy_reg_val1 & 0xFFF0U) == DP83848_PHY_ID1 || (phy_reg_val1 & 0xFFF0U) == TLK110_PHY_ID1)
    {
        phy_reg_val0 &= ~(1U << 12U); /* Enable auto-negotiation */
        phy_reg_val0 &= ~(1U << 9U); /* Enable auto-negotiation restart */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, &phy_reg_val0, 1U);
        phy_reg_val0 |= rmii_sel << 5; // RMII Enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, phy_reg_val0, 1U);
    }
    else
    {
        phy_reg_val0 &= ~(1U << 6U);  /* Speed_Select Msb = 0 100Mbs */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, &phy_reg_val0, 1U);
        phy_reg_val0 = (phy_reg_val0 | 0x4); // PHY configuration register access enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, &phy_reg_val0, 1U);
        phy_reg_val0 = phy_reg_val0 & 0xFCF7;          // Mask to set MII_MODE bits 9:8 to 0 and set LED_EN bit 3
        phy_reg_val0 = phy_reg_val0 | (rmii_sel << 9) | (PHY_LED_ON << 3); // If RMII mode: [MII_MODE]-> 10b (RMII mode enabled, 50 MHz output on REF_CLK)
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, phy_reg_val0, 1U);
    }
    /* Wait to establish link */
    do
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 1U, &phy_reg_val0, 1U);
    } while ((0U == (phy_reg_val0 & (1U << 2U))));
}

#endif
#if defined(S32K396)

static void Eth_T_InitPhys(void)
{
    uint16 rmii_sel = 0;
    uint16 phy_reg_val0, phy_reg_val1;
    uint16 phy_addr;

    Gmac_Ip_EnableMDIO(CFG_PHY_CTRL_IDX, FALSE, 48000000U);

    /* Search for the PHY address */
    for (phy_addr = 0U; phy_addr < 32U; ++phy_addr)
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 2U, &phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 3U, &phy_reg_val1, 1U);

        /* check for PHY ID */
        if (((phy_reg_val0 == TJA1100_PHY_ID0) && ((phy_reg_val1 == TJA1100_PHY_ID1) || (phy_reg_val1 == TJA1101_PHY_ID1 || phy_reg_val1 == TJA1103_PHY_ID1))) ||
            ((phy_reg_val0 == DP83848_PHY_ID0) && ((phy_reg_val1 & 0xFFF0U) == DP83848_PHY_ID1 || (phy_reg_val1 & 0xFFF0U) == TLK110_PHY_ID1)))
        {
            break; /* found the PHY ID*/
        }
    }

    /* Reset the PHY */
    Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, 0x8000U, 1U);

    /* Wait until the PHY is out of reset */
    while (Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U) & 0x8000U)
    { /* Busy Wait */
    }

    phy_reg_val0 |= (ENABLE_PHY_LOOPBACK << 14U);  /* Enable Loopback */
    phy_reg_val0 &= ~(1U << 12U); /* Disable AN */

    phy_reg_val0 |= (1U << 13U);  /* Speed_Select Lsb = 1 100Mbs */

    rmii_sel = 1;

    phy_reg_val0 |= (1U << 8U); /* Full-Duplex mode */

    /* Configure the PHY */
    if ((phy_reg_val1 & 0xFFF0U) == DP83848_PHY_ID1 || (phy_reg_val1 & 0xFFF0U) == TLK110_PHY_ID1)
    {
        phy_reg_val0 &= ~(1U << 12U); /* Enable auto-negotiation */
        phy_reg_val0 &= ~(1U << 9U); /* Enable auto-negotiation restart */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0U, &phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, &phy_reg_val0, 1U);
        phy_reg_val0 |= rmii_sel << 5; // RMII Enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x17U, phy_reg_val0, 1U);
    }
    else
    {
        phy_reg_val0 &= ~(1U << 6U);  /* Speed_Select Msb = 0 100Mbs */
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, &phy_reg_val0, 1U);
        phy_reg_val0 = (phy_reg_val0 | 0x4); // PHY configuration register access enable
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x11U, phy_reg_val0, 1U);

        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, &phy_reg_val0, 1U);
        phy_reg_val0 = phy_reg_val0 & 0xFCF7;          // Mask to set MII_MODE bits 9:8 to 0 and set LED_EN bit 3
        phy_reg_val0 = phy_reg_val0 | (rmii_sel << 9) | (PHY_LED_ON << 3); // If RMII mode: [MII_MODE]-> 10b (RMII mode enabled, 50 MHz output on REF_CLK)
        Gmac_Ip_MDIOWrite(CFG_PHY_CTRL_IDX, phy_addr, 0x12U, phy_reg_val0, 1U);
    }
    /* Wait to establish link */
    do
    {
        Gmac_Ip_MDIORead(CFG_PHY_CTRL_IDX, phy_addr, 1U, &phy_reg_val0, 1U);
    } while ((0U == (phy_reg_val0 & (1U << 2U))));
}
#endif


void Eth_T_EnableIRQs(void)
{
	unsigned int instance;
#if defined(FEATURE_ETH_RX_IRQS) || defined(FEATURE_ETH_TX_IRQS)
    unsigned int channel;
#endif /* FEATURE_ETH_RX_IRQS || FEATURE_ETH_TX_IRQS */

#ifdef FEATURE_ETH_COMMON_IRQS
    /*! @brief ETH common IRQ number for each instance. */
    const IRQn_Type ethCommonIrqId[FEATURE_ETH_NUM_INSTANCES] = FEATURE_ETH_COMMON_IRQS;
    /*! @brief ETH common IRQ handler for each instance. */
    void (*ethCommonIrqHandler[FEATURE_ETH_NUM_INSTANCES])(void) = FEATURE_GMAC_COMMON_IRQ_HDLRS;
#endif /* FEATURE_ETH_COMMON_IRQS */

#ifdef FEATURE_ETH_SAFETY_IRQS
    /*! @brief ETH safety IRQ number for each instance. */
    const IRQn_Type ethSafetyIrqId[FEATURE_ETH_NUM_INSTANCES] = FEATURE_ETH_SAFETY_IRQS;
    /*! @brief ETH safety IRQ handler for each instance. */
    void (*ethSafetyIrqHandler[FEATURE_ETH_NUM_INSTANCES])(void) = FEATURE_GMAC_SAFETY_IRQ_HDLRS;
#endif /* FEATURE_ETH_COMMON_IRQS */

#ifdef FEATURE_ETH_TX_IRQS
    /*! @brief ETH transmit IRQ number for each channel and each instance. */
    const IRQn_Type ethTxIrqId[FEATURE_ETH_NUM_INSTANCES][FEATURE_ETH_NUM_CHANNELS] = FEATURE_ETH_TX_IRQS;
    /*! @brief ETH transmit IRQ handler for each channel and each instance. */
    void (*ethTxIrqHandler[FEATURE_ETH_NUM_INSTANCES][FEATURE_ETH_NUM_CHANNELS])(void) = FEATURE_ETH_TX_IRQ_HDLRS;
#endif /* FEATURE_ETH_TX_IRQS */

#ifdef FEATURE_ETH_RX_IRQS
    /*! @brief ETH receive IRQ number for each channel and each instance. */
    const IRQn_Type ethRxIrqId[FEATURE_ETH_NUM_INSTANCES][FEATURE_ETH_NUM_CHANNELS] = FEATURE_ETH_RX_IRQS;
    /*! @brief ETH receive IRQ handler for each channel and each instance. */
    void (*ethRxIrqHandler[FEATURE_ETH_NUM_INSTANCES][FEATURE_ETH_NUM_CHANNELS])(void) = FEATURE_ETH_RX_IRQ_HLDRS;
#endif /* FEATURE_GMAC_RX_IRQS */

    /* Enable IRQs in a platform-specific way */
#if defined(S32N55)

    for (instance = 0U; instance < FEATURE_NETC_ETH_NUMBER_OF_CTRLS ; ++instance)
#else
    for (instance = 0U; instance < FEATURE_GMAC_NUM_INSTANCES; ++instance)
#endif
    {
    #ifdef FEATURE_ETH_COMMON_IRQS
        ((volatile uint32*)S32_SCB->VTOR)[ethCommonIrqId[instance] + 16] = (uint32)ethCommonIrqHandler[instance];
        S32_NVIC->ISER[(uint32)(ethCommonIrqId[instance]) >> 5U] = (uint32)(1UL << ((uint32)(ethCommonIrqId[instance]) & (uint32)0x1FU));
    #endif /* FEATURE_ETH_COMMON_IRQS */

    #ifdef FEATURE_ETH_SAFETY_IRQS
        ((volatile uint32*)S32_SCB->VTOR)[ethSafetyIrqId[instance] + 16] = (uint32)ethSafetyIrqHandler[instance];
        S32_NVIC->ISER[(uint32)(ethSafetyIrqId[instance]) >> 5U] = (uint32)(1UL << ((uint32)(ethSafetyIrqId[instance]) & (uint32)0x1FU));
    #endif /* FEATURE_ETH_COMMON_IRQS */

    #ifdef FEATURE_ETH_RX_IRQS
        for (channel = 0U; channel < FEATURE_ETH_NUM_CHANNELS; ++channel)
        {
            ((volatile uint32*)S32_SCB->VTOR)[ethRxIrqId[instance][channel] + 16] = (uint32)ethRxIrqHandler[instance][channel];
            S32_NVIC->ISER[(uint32)(ethRxIrqId[instance][channel]) >> 5U] = (uint32)(1UL << ((uint32)(ethRxIrqId[instance][channel]) & (uint32)0x1FU));
        }
    #endif /* FEATURE_ETH_RX_IRQS */

    #ifdef FEATURE_ETH_TX_IRQS
        for (channel = 0U; channel < FEATURE_ETH_NUM_CHANNELS; ++channel)
        {
            ((volatile uint32*)S32_SCB->VTOR)[ethTxIrqId[instance][channel] + 16] = (uint32)ethTxIrqHandler[instance][channel];
            S32_NVIC->ISER[(uint32)(ethTxIrqId[instance][channel]) >> 5U] = (uint32)(1UL << ((uint32)(ethTxIrqId[instance][channel]) & (uint32)0x1FU));
        }
    #endif /* FEATURE_ETH_TX_IRQS */
    }
}

#endif /*LWIP_APP*/

/*!
 * @brief     This function configures MUX clocking of SGMII Rx and Tx channels.
 */
extern void Serdes_MainFunction(void);
#ifdef CPU_SAF8544


static void SGMII_SetClock(void)
{
    /* GMAC_0_TX_CLK = GMAC_0_SGMII_TX_CLK = 125 MHz */
    while (((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWIP_MASK) == MC_CGM_MUX_2_CSS_SWIP_MASK)) {
        /* Do nothing */
    }
    IP_MC_CGM_3->MUX_2_CSC = (IP_MC_CGM_3->MUX_2_CSC & ~MC_CGM_MUX_2_CSC_SELCTL_MASK) | MC_CGM_MUX_2_CSC_SELCTL(GMAC_0_SGMII_TX_CLK_ID);
    IP_MC_CGM_3->MUX_2_CSC = (IP_MC_CGM_3->MUX_2_CSC & ~MC_CGM_MUX_2_CSC_CLK_SW_MASK) | MC_CGM_MUX_2_CSC_CLK_SW(1);

    while ((IP_MC_CGM_3->MUX_2_CSC & MC_CGM_MUX_2_CSC_CLK_SW_MASK) == MC_CGM_MUX_2_CSC_CLK_SW(1U)) {
        /* Do nothing */
    }
    while ((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWIP_MASK) == MC_CGM_MUX_2_CSS_SWIP_MASK) {
        /* Do nothing */
    }

    while ((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SWTRG_MASK) != MC_CGM_MUX_2_CSS_SWTRG(1U)) {
        /* Do nothing */
    }

    while ((IP_MC_CGM_3->MUX_2_CSS & MC_CGM_MUX_2_CSS_SELSTAT_MASK) != MC_CGM_MUX_2_CSS_SELSTAT(GMAC_0_SGMII_TX_CLK_ID)) {
        /* Do nothing */
    }

    /* GMAC_0_RX_CLK = GMAC_0_SGMII_RX_CLK = 125 MHz */
    IP_MC_CGM_3->MUX_4_CSC = (IP_MC_CGM_3->MUX_4_CSC & ~MC_CGM_MUX_4_CSC_SELCTL_MASK) | MC_CGM_MUX_4_CSC_SELCTL(GMAC_0_SGMII_RX_CLK_ID);
    IP_MC_CGM_3->MUX_4_CSC = (IP_MC_CGM_3->MUX_4_CSC & ~MC_CGM_MUX_4_CSC_CLK_SW_MASK) | MC_CGM_MUX_4_CSC_CLK_SW(1);

    while (((IP_MC_CGM_3->MUX_4_CSC & MC_CGM_MUX_4_CSC_CLK_SW_MASK) == MC_CGM_MUX_4_CSC_CLK_SW(1U))) {
        /* Do nothing */
    }
    while ((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SWIP_MASK) == MC_CGM_MUX_4_CSS_SWIP_MASK) {
        /* Do nothing */
    }
    while ((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SWTRG_MASK) != MC_CGM_MUX_4_CSS_SWTRG(1U)) {
        /* Do nothing */
    }
    while ((IP_MC_CGM_3->MUX_4_CSS & MC_CGM_MUX_4_CSS_SELSTAT_MASK) != MC_CGM_MUX_4_CSS_SELSTAT(GMAC_0_SGMII_RX_CLK_ID)) {
        /* Do nothing */
    }
}


/*!
 * @brief     This function configures ATP IP block.
 *
 * @details   This function configures ATP IP block, which is responsible for clocking all parts
 *            of platform for this gPTP example.
 */
static void ATP_SetClock(void)
{
    /* ATP IP block */
    volatile  Clock_Ip_ATPType* prAuroraClk = (volatile Clock_Ip_ATPType*)IP_ATP;

    /* Loopfilter misscellaneous */
    prAuroraClk->L_FILT_M = 0x08000C70;
    /* DCO gain control during acquisition */
    prAuroraClk->D_G_CTR_ACQ = 0x00000030;
    /* DCO gain control during tracking  */
    prAuroraClk->D_G_CTR_TR = 0x000002EE;
    /* Loopfilter */
    prAuroraClk->LP_FLTR = 0x0EB198EB;
    /* Drift compensation coefficients */
    prAuroraClk->DC_COEF = 0x0000FCEB;
    /* TR timer value */
    prAuroraClk->TR_T_VAL = 0x0000B7FF;
    /* Lock detector control part 1 */
    prAuroraClk->L_D_CTR_1 = 0x010007A0;
    /* Lock detector control part 2 */
    prAuroraClk->L_D_CT_2 = 0x00A91A00;

    /* Data strobe */
    prAuroraClk->D_STROBE = ATP_DATA_STROBE_STROBE(1U);
}
#endif

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 * ===============================================================================================*/

/*************************************************************************************************
* Description: This function initialize peripherals.
************************************************************************************************/

void Init_Peripherals(void)
{
#if defined(CPU_S32G274A) || defined (CPU_S32G399A)
    /* Init mode for PHY node and PHY interface with RGMII mode, speed 1G */
    IP_SRC->GMAC_0_CTRL_STS |= (SRC_GMAC_0_CTRL_STS_PHY_MODE(0U) | SRC_GMAC_0_CTRL_STS_PHY_INTF_SEL(1U));
#elif defined (CPU_SAF8544)
    StatusType err;
    /* Init mode for PHY node and PHY interface with RGMII mode, speed 1G */
	IP_SRC->GMAC_0_CTRL_STS |= (SRC_GMAC_0_CTRL_STS_PHY_INTF_SEL(0U) | SRC_GMAC_0_CTRL_STS_PHY_INTF_SEL(1U));
#elif defined (CPU_S32K342)
	IP_DCM_GPR->DCMRWF1 = (IP_DCM_GPR->DCMRWF1 & ~DCM_GPR_DCMRWF1_EMAC_CONF_SEL_MASK) | DCM_GPR_DCMRWF1_EMAC_CONF_SEL(2U);
#elif defined (CPU_S32K396)
    IP_DCM_GPR->DCMRWF1 |= DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK;
#elif defined (CPU_S32K344)
	/* Set RMII configuration for EMAC in DCM module */
    IP_DCM_GPR->DCMRWF1 |= DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK;
#elif defined (CPU_S32K358)
    /* Set RMII configuration for EMAC in DCM module */
	IP_DCM_GPR->DCMRWF1 = (IP_DCM_GPR->DCMRWF1 & ~DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK) | DCM_GPR_DCMRWF1_MAC_CONF_SEL(2U);
#elif defined (CPU_S32K388) || defined(CPU_S32K389)
	/* Set RMII configuration for EMAC in DCM module */
	IP_DCM_GPR->DCMRWF1 = (IP_DCM_GPR->DCMRWF1 & ~DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK) | DCM_GPR_DCMRWF1_MAC_CONF_SEL(2U);
	IP_DCM_GPR->DCMRWF4 = (IP_DCM_GPR->DCMRWF4 & ~DCM_GPR_DCMRWF4_MAC2_CONF_SEL_MASK) | DCM_GPR_DCMRWF4_MAC2_CONF_SEL(2U);
#elif defined(CPU_S32R47) && defined(LWIP_APP)
    StatusType err;
    uint32_t timeout = 1000000UL;
    Serdes_StatusType SerdesStatus = SERDES_ERROR;
    Serdes_StatusType SerdesStatus1 = SERDES_ERROR;

    /* Initialize Os Interface */
    OsIf_Init(NULL_PTR);

    /* Initialize all pins using the Port driver */
    err = Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_VS_0, g_pin_mux_InitConfigArr_PortContainer_0_VS_0);
    DevAssert((StatusType)E_OK == err);

    /* Initialize the Mcu driver */
    Mcu_Init(NULL_PTR);

    /* Initialize the clock tree and apply PLL as system clock */
    Mcu_InitClock(McuClockSettingConfig_0);

    while (MCU_PLL_LOCKED != Mcu_GetPllStatus())
    {
    	/* Busy wait until the System PLL is locked */
    }
    Mcu_DistributePllClock();

    IP_GMAC_0->MAC_MDIO_ADDRESS |= GMAC_0_MAC_MDIO_ADDRESS_CR(0x6);

    /* Reset required for PCIE_APB_ENET*/
    Mcu_SetMode(Serdes_Netc_Assert);
    /* Reset required for PCIE_APB_2XENET*/
    Mcu_SetMode(Serdes_Netc_Deassert);
    /* Init Serdes in SGMII mode 3 */
    Serdes_Init(NULL_PTR);

    IP_SIUL2_1->GPDO14 &= ~SIUL2_GPDO14_PDO_n_MASK;
    IP_SIUL2_1->GPDO14 |= SIUL2_GPDO14_PDO_n_MASK;

    while (((SerdesStatus != SERDES_SUCCESS) || (SerdesStatus1 != SERDES_SUCCESS)) && (timeout > 0U))
    {
        Serdes_MainFunction();
        SerdesStatus = Serdes_GetStatus(0U);
        SerdesStatus1 = Serdes_GetStatus(1U);
        timeout = timeout - 1;
    }

    Platform_Init(NULL_PTR);

    EthIf_Init(NULL_PTR);

#endif



    /* Initialize all pins using the Port driver */
    /* Initialize all pins using the Port driver */
	/*If Using Old RTD Uncomment this and comment the later part*/
/*#if defined(CPU_SAF8544)

    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_BOARD_InitPins, g_pin_mux_InitConfigArr_BOARD_InitPins);*/
#if defined(CPU_SAF8544)
    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals, g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);
#elif defined(CPU_SAF8644)
    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals, g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);
#elif defined (CPU_S32K396) || defined(CPU_S32K388) ||defined(CPU_S32K344) || defined(CPU_S32R47) || defined(CPU_S32K389)
   Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_VS_0, g_pin_mux_InitConfigArr_PortContainer_0_VS_0);
//#elif defined(CPU_S32K389)
//   Port_Init(NULL_PTR);
#elif defined(CPU_S32K358)
#if defined(LWIP_APP)
   Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_VS_0, g_pin_mux_InitConfigArr_PortContainer_0_VS_0);
#else
   Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals, g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);
#endif
#elif defined(S32N55)
   //Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS, g_pin_mux_InitConfigArr);
#else
   Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS0, g_pin_mux_InitConfigArr0);
#endif

#ifndef TEST_SUITE
	/* Initialize clock */
#if defined(CPU_S32G274A) || defined(CPU_S32G399A)
	Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
#elif (defined(CPU_S32K358) || defined(CPU_S32K388)) && defined(BENCHMARK)
	Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
#elif (defined(CPU_S32K396) || defined(CPU_S32K389)) && defined(BENCHMARK)
	Clock_Ip_Init(&Mcu_aClockConfigPB_VS_0[0]);
#elif defined(CPU_SAF8544)
	Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
    ATP_SetClock();
#elif defined(S32N55)
    Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
#elif defined(CPU_S32K388)
	Clock_Ip_Init(&Mcu_aClockConfigPB_VS_0[0U]);
#elif defined(CPU_S32R47) || defined(CPU_S32K389)
    Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
#elif defined(S32K344) && defined(LWIP_APP)
    Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
//#elif defined(CPU_S32K389)
//    Mcu_Init(NULL_PTR);
//    /* Initialize Mcu clock */
//    Mcu_InitClock(McuClockSettingConfig_0);
//
//    while (Mcu_GetPllStatus() != MCU_PLL_LOCKED){};
//
//    /* Use PLL clock */
//    Mcu_DistributePllClock();
//
//    Mcu_SetMode(McuModeSettingConf_0);
#else
	Clock_Ip_Init(&Clock_Ip_aClockConfig[0]);
#endif
#endif

#ifdef TEST_SUITE
#if defined(CPU_S32K342)
	Clock_Ip_Init(&Mcu_aClockConfigPB_BOARD_InitPeripherals[0]);
#endif
#if defined(CPU_S32K358) || defined(CPU_S32K388)
	Clock_Ip_Init(&Mcu_aClockConfigPB[0]);
#endif
#if defined(CPU_S32K396) || defined(CPU_S32K389)
	Clock_Ip_Init(&Mcu_aClockConfigPB_VS_0[0]);
#endif

#if defined(CPU_SAF8544)
	Clock_Ip_Init(&Clock_Ip_aClockConfig[0]);

#endif
#endif


#if defined (BENCHMARK)
	nxp_hse_config_lifecycle_timer();
#if defined(CPU_SAF8544) || defined(CPU_S32R47)
    /* Install interrupt handlers for PIT */
    IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_EnableIrq(PIT0_IRQn);
#elif defined(S32N55)
    /* Install interrupt handlers for PIT */
    IntCtrl_Ip_InstallHandler(RTU_PIT0_IRQn, RTU0_PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_EnableIrq(RTU_PIT0_IRQn);
#endif
#endif

	/* Initialize RTC Timer */
	nxp_hse_timer_init();

	  /* Initialize Os Interface */
		OsIf_Init(NULL_PTR);

#ifdef LWIP_APP
    /* Install interrupt handlers for PIT and EMAC */
	#ifdef CPU_S32K342
	 IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
	        IntCtrl_Ip_SetPriority(PIT0_IRQn, 4);
	        IntCtrl_Ip_EnableIrq(PIT0_IRQn);

	        IntCtrl_Ip_InstallHandler(EMAC_1_IRQn, GMAC0_CH_TX_IRQHandler, NULL_PTR);
	        IntCtrl_Ip_SetPriority(EMAC_1_IRQn, 7);
	        IntCtrl_Ip_EnableIrq(EMAC_1_IRQn);

	        IntCtrl_Ip_InstallHandler(EMAC_2_IRQn, GMAC0_CH_RX_IRQHandler, NULL_PTR);
	        IntCtrl_Ip_SetPriority(EMAC_2_IRQn, 8);
	        IntCtrl_Ip_EnableIrq(EMAC_2_IRQn);

	        IntCtrl_Ip_InstallHandler(EMAC_0_IRQn, GMAC0_Common_IRQHandler, NULL_PTR);
	        IntCtrl_Ip_SetPriority(EMAC_0_IRQn, 6);
	        IntCtrl_Ip_EnableIrq(EMAC_0_IRQn);
#endif
#ifdef CPU_S32K344


    /* Install interrupt handlers for PIT and EMAC */
    IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_EnableIrq(PIT0_IRQn);

#endif

  /*  Uncomment if required
    IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_EnableIrq(PIT0_IRQn);  */
#if defined(CPU_S32K389)
    Platform_Init(NULL_PTR);
#endif

#if defined(S32G3XX) || defined(S32G2XX)
    IntCtrl_Ip_InstallHandler(GMAC0_CH0_TX_IRQn, GMAC0_CH0_TX_IRQHandler, NULL_PTR);
    IntCtrl_Ip_SetPriority(GMAC0_CH0_TX_IRQn, 8);
    IntCtrl_Ip_EnableIrq(GMAC0_CH0_TX_IRQn);

    IntCtrl_Ip_InstallHandler(GMAC0_CH0_RX_IRQn, GMAC0_CH0_RX_IRQHandler, NULL_PTR);
    IntCtrl_Ip_SetPriority(GMAC0_CH0_RX_IRQn, 7);
    IntCtrl_Ip_EnableIrq(GMAC0_CH0_RX_IRQn);
#endif
#if defined(CPU_S32K388)
    /* Install interrupt handlers for PIT and EMAC */
		IntCtrl_Ip_InstallHandler(GMAC1_CH0_TX_IRQn, GMAC1_CH0_TX_IRQHandler, NULL_PTR);
		IntCtrl_Ip_SetPriority(GMAC1_CH0_TX_IRQn, 7);
		IntCtrl_Ip_EnableIrq(GMAC1_CH0_TX_IRQn);

		IntCtrl_Ip_InstallHandler(GMAC1_CH0_RX_IRQn, GMAC1_CH0_RX_IRQHandler, NULL_PTR);
		IntCtrl_Ip_SetPriority(GMAC1_CH0_RX_IRQn, 8);
		IntCtrl_Ip_EnableIrq(GMAC1_CH0_RX_IRQn);

#endif
#if defined(S32K358)
    IntCtrl_Ip_InstallHandler(GMAC0_CH0_TX_IRQn, GMAC0_CH0_TX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(GMAC0_CH0_TX_IRQn, 8);
       IntCtrl_Ip_EnableIrq(GMAC0_CH0_TX_IRQn);

       IntCtrl_Ip_InstallHandler(GMAC0_CH0_RX_IRQn, GMAC0_CH0_RX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(GMAC0_CH0_RX_IRQn, 7);
       IntCtrl_Ip_EnableIrq(GMAC0_CH0_RX_IRQn);

       IntCtrl_Ip_InstallHandler(GMAC0_Common_IRQn, GMAC0_Common_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(GMAC0_Common_IRQn, 6);
       IntCtrl_Ip_EnableIrq(GMAC0_Common_IRQn);

#endif
#if defined(S32K396)
       IntCtrl_Ip_InstallHandler(EMAC_1_IRQn, GMAC0_CH_TX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(EMAC_1_IRQn, 8);
       IntCtrl_Ip_EnableIrq(EMAC_1_IRQn);

       IntCtrl_Ip_InstallHandler(EMAC_2_IRQn, GMAC0_CH_RX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(EMAC_2_IRQn, 7);
       IntCtrl_Ip_EnableIrq(EMAC_2_IRQn);

       IntCtrl_Ip_InstallHandler(EMAC_0_IRQn, GMAC0_Common_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(EMAC_0_IRQn, 6);
       IntCtrl_Ip_EnableIrq(EMAC_0_IRQn);
#endif
#if defined(SAF8544)
       /* Install interrupt handlers for PIT and EMAC */
/*      IntCtrl_Ip_InstallHandler(SGMII_IRQn, SGMII_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(SGMII_IRQn, 10);
       IntCtrl_Ip_EnableIrq(SGMII_IRQn);

       IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
       IntCtrl_Ip_SetPriority(PIT0_IRQn, 9);
       IntCtrl_Ip_EnableIrq(PIT0_IRQn);

       IntCtrl_Ip_InstallHandler(GMAC0_CH0_TX_IRQn, GMAC0_CH0_TX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(GMAC0_CH0_TX_IRQn, 7);
       IntCtrl_Ip_EnableIrq(GMAC0_CH0_TX_IRQn);

       IntCtrl_Ip_InstallHandler(GMAC0_CH0_RX_IRQn, GMAC0_CH0_RX_IRQHandler, NULL_PTR);
       IntCtrl_Ip_SetPriority(GMAC0_CH0_RX_IRQn, 8);
       IntCtrl_Ip_EnableIrq(GMAC0_CH0_RX_IRQn); */


#endif
   // Eth_T_EnableIRQs();
#endif/* CPU_SAF8544 */


#if defined (BENCHMARK) && defined (CPU_SAF8544)
    /* Initialize PIT driver and start the timer */
	Pit_Ip_Init(PIT_INST, &PIT_0_InitConfig_PB);
	Pit_Ip_InitChannel(PIT_INST, PIT_0_ChannelConfig_PB);
	Pit_Ip_EnableChannelInterrupt(PIT_INST, CH_0);
	Pit_Ip_StartChannel(PIT_INST, CH_0, PIT_PERIOD);
#endif

#if defined (BENCHMARK) && defined (CPU_S32K388)
	IntCtrl_Ip_Init(&IntCtrlConfig_0);
//	IntCtrl_Ip_EnableIrq(PIT0_IRQn);
    /* Initialize PIT driver and start the timer */
	Pit_Ip_Init(PIT_INSTANCE, &PIT_0_InitConfig_PB);
	Pit_Ip_InitChannel(PIT_INSTANCE, PIT_0_CH_0);
	Pit_Ip_EnableChannelInterrupt(PIT_INSTANCE, CH_0);
	Pit_Ip_StartChannel(PIT_INSTANCE, CH_0, PIT_PERIOD);
#endif

#if defined (BENCHMARK) && defined (CPU_S32R47)
	IntCtrl_Ip_Init(&intCtrlConfig);
//	IntCtrl_Ip_EnableIrq(PIT0_IRQn);
    /* Initialize PIT driver and start the timer */
	Pit_Ip_Init(PIT_INSTANCE, &PIT_0_InitConfig_PB);
	Pit_Ip_InitChannel(PIT_INSTANCE, PIT_0_CH_0);
	Pit_Ip_EnableChannelInterrupt(PIT_INSTANCE, CH_0);
	Pit_Ip_StartChannel(PIT_INSTANCE, CH_0, PIT_PERIOD);
#endif

#if defined (BENCHMARK) && defined (CPU_S32K389)
	IntCtrl_Ip_Init(&IntCtrlConfig_0);
//	IntCtrl_Ip_EnableIrq(PIT0_IRQn);
    /* Initialize PIT driver and start the timer */
	Pit_Ip_Init(PIT_INSTANCE, &PIT_0_InitConfig_PB_VS_0);
	Pit_Ip_InitChannel(PIT_INSTANCE, PIT_0_CH_0);
	Pit_Ip_EnableChannelInterrupt(PIT_INSTANCE, CH_0);
	Pit_Ip_StartChannel(PIT_INSTANCE, CH_0, PIT_PERIOD);

	IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
	IntCtrl_Ip_EnableIrq(PIT0_IRQn);
#endif


#if (defined (BENCHMARK) || defined(TEST_SUITE)) && defined (S32N55)

	Mcu_Init(&Mcu_PreCompileConfig);
	Uart_Init(NULL_PTR); /* Initializes an UART driver*/

	Mcu_InitClock(McuClockSettingConfig_1);
	Platform_Init(NULL_PTR);
	Gpt_Init(&Gpt_Config);

    /* Initialize PIT driver and start the timer */
	Pit_Ip_Init(PIT_INST, &RTU0_PIT_0_InitConfig_PB);
	Pit_Ip_InitChannel(PIT_INST, RTU0_PIT_0_ChannelConfig_PB);

	//Pit_Ip_EnableChannelInterrupt(PIT_INST, CH_0);
	//Pit_Ip_StartChannel(PIT_INST, CH_0, PIT_PERIOD);
	Gpt_StartTimer(CH_0,PIT_PERIOD);
	Gpt_EnableNotification(CH_0);
#endif

#ifdef LWIP_APP
    /* Initialize PIT driver and start the timer */

	uint16 PitPeriod;
#if defined(S32N55)
	/* MCU initialization. */
	    //Mcu_Init(NULL_PTR);
	    Mcu_Init(&Mcu_PreCompileConfig);
	    Uart_Init(NULL_PTR);
	    Mcu_InitClock(McuClockSettingConfig_0);
	    while ( MCU_PLL_LOCKED != Mcu_GetPllStatus() )
	    {
	        /* Busy wait until the System PLL is locked */
	    }

	    Mcu_DistributePllClock();

	    /* Initialize Platform driver */
	    Platform_Init(NULL_PTR);

	    //Eth_T_EnableIRQs();

	    Gpt_Init(&Gpt_Config);

	        /* Initialize PIT driver and start the timer */
	    	Pit_Ip_Init(PIT_INST, &RTU0_PIT_0_InitConfig_PB);
	    	Pit_Ip_InitChannel(PIT_INST, RTU0_PIT_0_ChannelConfig_PB);
            Gpt_StartTimer(CH_0,PIT_PERIOD);
	    	Gpt_EnableNotification(CH_0);
	        Messaging_Init(NULL_PTR);


#endif
#if defined(CPU_SAF8544)

    /* Initialize PIT driver and start the timer */
           Pit_Ip_Init(PIT_INST, &PIT_0_InitConfig_PB_BOARD_InitPeripherals);
           Pit_Ip_InitChannel(PIT_INST, PIT_0_CH_0);
           Pit_Ip_EnableChannelInterrupt(PIT_INST, CH_0);

           pitPeriod = Clock_Ip_GetClockFrequency(PIT0_CLK) / 1000;
           err = Pit_Ip_StartChannel(PIT_INST, CH_0, pitPeriod);
           DevAssert((StatusType)E_OK == err);


#elif defined(CPU_S32K342)
    Pit_Ip_Init(PIT_INST, &PIT_0_InitConfig_PB_BOARD_InitPeripherals);
#elif defined(CPU_S32K344)
    /* Initialize PIT driver and start the timer */
    Pit_Ip_Init(PIT_INST, &PIT_0_InitConfig_PB);
#endif /* CPU_SAF8544 */
#if (!(defined(S32K358) || defined(S32K396) || defined(S32K344) || defined(CPU_S32R47) || defined(CPU_S32K389)))
    IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_SetPriority(PIT0_IRQn, 9);
    IntCtrl_Ip_EnableIrq(PIT0_IRQn);

    Pit_Ip_InitChannel(PIT_INST, PIT_0_CH_0);
    Pit_Ip_EnableChannelInterrupt(PIT_INST, CH_0);
    PitPeriod = Clock_Ip_GetClockFrequency(PIT0_CLK) / 1000;
    Pit_Ip_StartChannel(PIT_INST, CH_0, PitPeriod);
#endif
#if defined(CPU_S32R47)
    IntCtrl_Ip_InstallHandler(PIT0_IRQn, PIT_0_ISR, NULL_PTR);
    IntCtrl_Ip_SetPriority(PIT0_IRQn, 9);
    IntCtrl_Ip_EnableIrq(PIT0_IRQn);

    Pit_Ip_InitChannel(PIT_INST, PIT_0_CH_0);
    Pit_Ip_EnableChannelInterrupt(PIT_INST, CH_0);
    PitPeriod = Clock_Ip_GetClockFrequency(SPT0_CLK) / 1000;
    Pit_Ip_StartChannel(PIT_INST, CH_0, PitPeriod);
#endif
#endif

#ifndef USING_OS_FREERTOS
#if defined (CPU_S32K344)
    OsIf_SetTimerFrequency(160000000U,  OSIF_USE_SYSTEM_TIMER);
#elif defined(CPU_SAF8544)
    OsIf_SetTimerFrequency(400000000U,  OSIF_COUNTER_DUMMY);
#else
    //OsIf_SetTimerFrequency(400000000U,  OSIF_USE_SYSTEM_TIMER);
#endif
#endif /* USING_OS_FREERTOS */

#ifdef LWIP_APP
#if defined (CPU_SAF8544)
   Eth_SGMII_init();
   eth_select_phy_interface(0, S32_GMAC_SGMII_MODE);
   eth_config_clk_0(S32_GMAC_SGMII_MODE);
   Eth_wait_link();
#endif /* CPU_SAF8544 */

#if defined(S32K358)
   /* Initialize and enable the GMAC module */
   Gmac_Ip_Init(INST_GMAC_0, &Gmac_0_ConfigPB_VS_0);
#elif defined(S32K396)
   Gmac_Ip_Init(INST_GMAC_0, &Gmac_0_ConfigPB_VS_0);
#elif defined(S32N55)
   EthSwt_43_NETC_Init(NULL_PTR);
   Eth_43_NETC_Init(NULL_PTR);
   NETC_Phy_RGMII_Init();
#elif defined(S32K389) || defined(CPU_S32R47)
   Eth_43_GMAC_Init(NULL_PTR);
#elif defined(S32K344)
   Eth_43_GMAC_Init(NULL_PTR);
#else
   /* Initialize and enable the GMAC module */
   Gmac_Ip_Init(INST_GMAC_1, &Gmac_1_ConfigPB_VS_0);
#endif
#if defined(CPU_S32K344) || defined(CPU_S32K358)
    /* Initialize Ethernet Phy */
	Eth_T_InitPhys();
#endif /* CPU_S32K344 */
#endif /* LWIP_APP */

    /* Init UART driver */
#if !defined(S32N55)
#ifdef UART_SUPPORT
    UART_init();
#endif /* UART_SUPPORT */
#endif
}

#if defined(USING_OS_FREERTOS)

void vAssertCalled(uint32_t ulLine, const char * const pcFileName)
{
  /* Called if an assertion passed to configASSERT() fails.  See
  www.freertos.org/a00110.html#configASSERT for more information. */

#ifdef UART_SUPPORT
  mbedtls_printf("ASSERT! Line %d, file %s\r\n", ulLine, pcFileName);
#else
//  /* Parameters are not used. */
//  LWIP_UNUSED_ARG(ulLine);
//  LWIP_UNUSED_ARG(pcFileName);
#endif

  taskENTER_CRITICAL();
  {
    //LWIP_ASSERT("configASSERT():", 0);
  }
  taskEXIT_CRITICAL();
}

/* Dummy functions needed by FreeRTOS to avoid compiler error*/
void vMainConfigureTimerForRunTimeStats( void )
{
  ;
}
uint32_t ulMainGetRunTimeCounterValue( void )
{
  return 0UL;
}

#endif /* defined(USING_OS_FREERTOS) */

#ifdef __cplusplus
}
#endif

/** @} */
