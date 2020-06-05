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

import com.fasterxml.jackson.annotation.JsonProperty;

public class TransactionOutput
{
    @JsonProperty("amount_string")
    private String value;

    @JsonProperty("amount_in_smallest_unit_string")
    private String valueInSmallestUnit;

    @JsonProperty("receive_address")
    private String receiveAddress;

    @JsonProperty("index")
    private Integer index;

    public String getValue()
    {
        return value;
    }

    public void setValue(String value)
    {
        this.value = value;
    }

    public String getValueInSmallestUnit()
    {
        return valueInSmallestUnit;
    }

    public void setValueInSmallestUnit(String valueInSmallestUnit)
    {
        this.valueInSmallestUnit = valueInSmallestUnit;
    }

    public String getReceiveAddress()
    {
        return receiveAddress;
    }

    public void setReceiveAddress(String receiveAddress)
    {
        this.receiveAddress = receiveAddress;
    }

    public Integer getIndex()
    {
        return index;
    }

    public void setIndex(Integer index)
    {
        this.index = index;
    }
}
