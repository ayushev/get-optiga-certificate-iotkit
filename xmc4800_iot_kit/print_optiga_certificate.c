/*
 * FreeRTOS V202002.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */


/**
 * @file get_optiga_certificate.c
 * @brief Get the per-provisioned certificate from your SE using PKCS #11
 *
 * A simple example to extract pre-provisioned certificate from the chip and print it out
 */

/* Standard includes. */
#include <stdio.h>
#include <string.h>
#include "print_optiga_certificate.h"

/* OPTIGA includes. */
#include "optiga/optiga_util.h"
#include "optiga/common/optiga_lib_logger.h"
#include "optiga/pal/pal_logger.h"

/* mbedTLS includes. */
#include "mbedtls/base64.h"



/**
 * Callback when optiga_util_xxxx operation is completed asynchronously
 */
static volatile optiga_lib_status_t optiga_lib_status;
//lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}
extern pal_logger_t logger_console;

/*-----------------------------------------------------------*/

/* Attempt to extract the certificate out of the default certificate slot and convert it to PEM */
uint32_t __extract_certificate( uint8_t * p_der_cert, uint16_t * p_der_cert_length )
{
    uint16_t offset = 9, bytes_to_read;
    uint16_t optiga_oid;
    optiga_lib_status_t return_status = 0;
    optiga_util_t * me = NULL;

    do
    {
		/**
		  * 1. Create OPTIGA Util Instance
		  */
		 me = optiga_util_create(0, optiga_util_callback, NULL);
		 if (NULL == me)
		 {
			 break;
		 }

		 //Read device end entity certificate from OPTIGA
		 optiga_oid = 0xE0E0;
		 bytes_to_read = *p_der_cert_length;

		 /**
		  * 2. Read data from a data object (e.g. certificate data object)
		  *    using optiga_util_read_data.
		  */
		 optiga_lib_status = OPTIGA_LIB_BUSY;
		 return_status = optiga_util_read_data(me,
											   optiga_oid,
											   offset,
											   p_der_cert,
											   &bytes_to_read);

		 if (OPTIGA_LIB_SUCCESS != return_status)
		 {
			 break;
		 }

		 while (OPTIGA_LIB_BUSY == optiga_lib_status)
		 {
			 //Wait until the optiga_util_read_data operation is completed
		 }

		 if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
		 {
			 //Reading the data object failed.
			 return_status = optiga_lib_status;
			 break;
		 }

		 *p_der_cert_length = bytes_to_read;

    } while(0);

    return return_status;
}

uint32_t __print_pem_certificate( uint8_t * p_der_cert, uint16_t der_cert_length )
{
	optiga_lib_status_t return_status = 0;
	uint8_t p_pem_cert[2000];
	size_t pem_cert_length = 2000;
	uint16_t read_offset = 0;
	uint8_t newline[] = {0x0d, 0x0a};

	if ( 0 != der_cert_length )
	{
		if(  p_der_cert == NULL || p_pem_cert == NULL)
		{
			return_status = 1;
		}
		else
		{
			mbedtls_base64_encode(p_pem_cert, pem_cert_length, &pem_cert_length,
								  p_der_cert, der_cert_length);

			optiga_lib_print_string_with_newline("-----BEGIN CERTIFICATE-----");
			//Properly copy certificate and format it as pkcs expects
			for (read_offset = 0; read_offset < pem_cert_length; read_offset += 64)
			{
				pal_logger_write(&logger_console, p_pem_cert + read_offset, 64);
				pal_logger_write(&logger_console, newline, 2);
			}
			optiga_lib_print_string_with_newline("-----END CERTIFICATE-----");
		}
	}

	return return_status;
}


/*-----------------------------------------------------------*/

/* Perform certificate extraction and print it out*/
uint32_t optiga_print_certificate( void )
{
	uint32_t result = 0;
    uint8_t der_cert[1600];
	uint16_t der_cert_length = 1600;

	result = __extract_certificate( der_cert, &der_cert_length);

	if (0 == result)
	{
		result = __print_pem_certificate( der_cert, der_cert_length );
	}

    return result;
}

