/**
 * MIT License
 *
 * Copyright (c) 2020 acrosafe technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.acrosafe.wallet.hot.btc.web.rest.response;

public enum Result
{
    SUCCESS(2000),

    // HTTP 4xx error
    WALLET_ALREADY_EXISTED(4001),
    WALLET_NOT_FOUND(4002),
    INVALID_PASSPHRASE(4003),
    INVALID_WALLET_NAME(4004),
    INVALID_COIN_SYMBOL(4005),
    INVALID_RECIPIENT(4006),
    TRANSACTION_ALREADY_BROADCASTED(4007),

    // HTTP 5xx error
    UNKNOWN_ERROR(5000),
    SERVICE_NOT_READY(5001),
    INVALID_CRYPTO_OPERATION(5002),
    INSUFFICIENT_BALANCE(5003),
    INVALID_FEE_INFORMATION(5004),
    TRANSACTION_SIGNING_FAILED(5005),
    BROADCAST_FAILED(5006);

    private int code;

    /**
     * Constructs new Result enum instance.
     *
     * @param code
     */
    Result(int code)
    {
        this.code = code;
    }

    public static Result valueOf(int code)
    {
        for (Result response : Result.values())
        {
            if (response.code == code)
            {
                return response;
            }
        }

        return UNKNOWN_ERROR;
    }

    public int getCode()
    {
        return code;
    }
}
