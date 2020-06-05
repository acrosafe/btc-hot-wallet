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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.acrosafe.wallet.core.btc.TransactionType;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class GetTransactionResponse extends Response
{
    @JsonProperty("transactionId")
    private String transactionId;

    @JsonProperty("status")
    private String status;

    @JsonProperty("fee_string")
    private String fee;

    @JsonProperty("created_date")
    private Instant createdDate;

    @JsonProperty("wallet_id")
    private String walletId;

    @JsonProperty("receive_address")
    private String receiveAddress;

    @JsonProperty("transaction_type")
    private TransactionType type;

    @JsonProperty("outputs")
    private List<TransactionOutput> outputs;

    public String getTransactionId()
    {
        return transactionId;
    }

    public void setTransactionId(String transactionId)
    {
        this.transactionId = transactionId;
    }

    public String getStatus()
    {
        return status;
    }

    public void setStatus(String status)
    {
        this.status = status;
    }

    public String getFee()
    {
        return fee;
    }

    public void setFee(String fee)
    {
        this.fee = fee;
    }

    public Instant getCreatedDate()
    {
        return createdDate;
    }

    public void setCreatedDate(Instant createdDate)
    {
        this.createdDate = createdDate;
    }

    public String getWalletId()
    {
        return walletId;
    }

    public void setWalletId(String walletId)
    {
        this.walletId = walletId;
    }

    public String getReceiveAddress()
    {
        return receiveAddress;
    }

    public void setReceiveAddress(String receiveAddress)
    {
        this.receiveAddress = receiveAddress;
    }

    public TransactionType getType()
    {
        return type;
    }

    public void setType(TransactionType type)
    {
        this.type = type;
    }

    public List<TransactionOutput> getOutputs()
    {
        return outputs;
    }

    public void setOutputs(List<TransactionOutput> outputs)
    {
        this.outputs = outputs;
    }

    public void addOutput(TransactionOutput output)
    {
        if (outputs == null)
        {
            outputs = new ArrayList<>();
        }

        outputs.add(output);
    }
}
